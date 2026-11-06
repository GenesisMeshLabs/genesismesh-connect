//! Qualification-only durable client pairing commands. Never a host approval.
use super::{
    protocol::{live, uuid_id},
    store::check_path,
    *,
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use genesis_mesh_sdk::parse_strict_json;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
const MAX_BYTES: u64 = 256 * 1024;
const MAX_RECORDS: usize = 32;
pub(crate) const CLIENT_COMMAND_FILE: &str = "owner-commands.json";
pub(crate) fn commands_qualified() -> Result<()> {
    ensure!(
        cfg!(feature = "owner-requests-qualification"),
        "Phone pairing Requests are not enabled in this build"
    );
    Ok(())
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandBinding {
    pub profile_id: String,
    pub enrollment: EnrollmentBinding,
}
impl CommandBinding {
    fn require(&self, grant: &Grant, command: &OwnerCommand) -> Result<()> {
        uuid_id(&self.profile_id)?;
        let enrollment = &grant.enrollment.intent;
        grant.enrollment.verify()?;
        command.verify(&self.enrollment.administrative_key)?;
        ensure!(
            self.enrollment.scope == enrollment.scope
                && self.enrollment.controller_node == enrollment.controller_node
                && self.enrollment.administrative_key == enrollment.administrative_key
                && command.intent.scope == enrollment.scope
                && command.intent.controller_node == enrollment.controller_node
                && command.intent.grant_id == enrollment.id
                && grant.approval_digest == grant.enrollment.digest()?
                && enrollment
                    .permissions
                    .contains(&command.intent.action.permission()),
            "Command belongs to another native profile, host, grant or permission"
        );
        live(
            enrollment.created_at,
            enrollment.expires_at,
            grant.approved_at,
        )?;
        ensure!(
            command.intent.created_at >= grant.approved_at
                && command.intent.expires_at <= enrollment.grant_expires_at
                && grant.revoked_at.is_none(),
            "Command exceeds its original approved grant"
        );
        Ok(())
    }
}
pub(crate) fn same_active_grant(
    expected: &Grant,
    actual: &Grant,
    now: DateTime<Utc>,
) -> Result<()> {
    ensure!(
        serde_json::to_value(expected)? == serde_json::to_value(actual)?
            && actual.revoked_at.is_none()
            && actual.approved_at <= now
            && now < actual.enrollment.intent.grant_expires_at,
        "Administrative grant changed, expired or was revoked"
    );
    Ok(())
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientCommandStatus {
    Reviewed,
    Observed,
    Uncertain,
    Archived,
}
#[derive(Clone, Debug, Serialize)]
pub struct ClientCommandView {
    pub nonce: String,
    pub digest: String,
    pub action: OwnerAction,
    pub network: String,
    pub command_expires_at: DateTime<Utc>,
    pub grant_expires_at: DateTime<Utc>,
    pub status: ClientCommandStatus,
    /// Host record observed on this check; not fresh membership/queue state.
    pub current_observation: Option<ControlResult>,
    pub last_observed: Option<ControlResult>,
    pub observed_at: Option<DateTime<Utc>>,
    pub retained_outcome: Option<ControlResult>,
    pub retained_at: Option<DateTime<Utc>>,
}
/// Trusted native seam only. A UI boolean, unlocked key store or agent is not
/// qualified presence. No implementation is registered by the application.
pub trait ClientCommandPresence: Send {
    fn available(&self) -> bool;
    fn confirm(&mut self, review: &ClientCommandView) -> Result<()>;
}
pub struct UnavailableCommandPresence;
impl ClientCommandPresence for UnavailableCommandPresence {
    fn available(&self) -> bool {
        false
    }
    fn confirm(&mut self, _: &ClientCommandView) -> Result<()> {
        anyhow::bail!("Native presence for pairing Requests is unavailable")
    }
}
fn terminal(result: &ControlResult) -> bool {
    matches!(
        result,
        ControlResult::Approved { .. }
            | ControlResult::Rejected { .. }
            | ControlResult::PairingList { .. }
    )
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    grant: Grant,
    command: OwnerCommand,
    digest: String,
    submitted: bool,
    archived: bool,
    serial: u64,
    last_observed: Option<ControlResult>,
    observed_at: Option<DateTime<Utc>>,
    retained_outcome: Option<ControlResult>,
    retained_at: Option<DateTime<Utc>>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    binding: CommandBinding,
    high_water: DateTime<Utc>,
    records: Vec<Record>,
}
impl State {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.records.len() <= MAX_RECORDS,
            "Unsupported or oversized command history"
        );
        uuid_id(&self.binding.profile_id)?;
        self.binding.enrollment.scope.validate()?;
        super::public_key(&self.binding.enrollment.controller_node)?;
        super::public_key(&self.binding.enrollment.administrative_key)?;
        let mut ids = std::collections::BTreeSet::new();
        for (index, record) in self.records.iter().enumerate() {
            self.binding.require(&record.grant, &record.command)?;
            ensure!(
                record.digest == record.command.digest()?
                    && ids.insert(&record.command.intent.nonce)
                    && record.command.intent.created_at <= self.high_water
                    && ((record.submitted && record.serial > 0)
                        || (!record.submitted
                            && record.serial == 0
                            && record.last_observed.is_none()
                            && record.retained_outcome.is_none()))
                    && (!record.archived
                        || record.submitted
                        || self.high_water >= record.command.intent.expires_at)
                    && (index + 1 == self.records.len() || record.archived),
                "Invalid or ambiguous command history"
            );
            for (result, at) in [
                (&record.last_observed, record.observed_at),
                (&record.retained_outcome, record.retained_at),
            ] {
                match (result, at) {
                    (Some(result), Some(at)) => {
                        result.validate_for(&record.command.intent.action)?;
                        ensure!(
                            at >= record.command.intent.created_at && at <= self.high_water,
                            "Invalid command observation time"
                        );
                    }
                    (None, None) => (),
                    _ => anyhow::bail!("Incomplete command observation"),
                }
            }
            ensure!(
                record.retained_outcome.as_ref().is_none_or(terminal)
                    && (!record.archived
                        || !record.submitted
                        || (record.last_observed.as_ref().is_some_and(terminal)
                            && record.last_observed == record.retained_outcome)),
                "Uncertain commands cannot be archived"
            );
        }
        Ok(())
    }
}
pub(crate) struct CommandExchange {
    session: uuid::Uuid,
    serial: u64,
    nonce: String,
    digest: String,
    envelope: ControlEnvelope,
}
impl CommandExchange {
    pub fn envelope(&self) -> &ControlEnvelope {
        &self.envelope
    }
}
pub(crate) struct ClientCommands {
    path: PathBuf,
    state: State,
    _lock: File,
    session: uuid::Uuid,
    usable: bool,
    observed: bool,
}
impl ClientCommands {
    pub(crate) fn initialized(path: &Path) -> Result<bool> {
        check_path(path)?;
        let marker = path.with_extension("owner-commands-lock");
        check_path(&marker)?;
        Ok(path.try_exists()? || marker.try_exists()?)
    }
    pub fn open(
        path: &Path,
        binding: &CommandBinding,
        create: bool,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        commands_qualified()?;
        check_path(path)?;
        let marker = path.with_extension("owner-commands-lock");
        check_path(&marker)?;
        let initialized = marker.try_exists()?;
        ensure!(
            create || path.try_exists()?,
            "Saved command is missing; no replacement was created"
        );
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&marker)?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .context("Another phone Requests operation is running")?;
        let exists = path.try_exists()?;
        let state = if exists {
            let mut bytes = Vec::new();
            File::open(path)?
                .take(MAX_BYTES + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= MAX_BYTES,
                "Saved command history is too large"
            );
            serde_json::from_value(parse_strict_json(std::str::from_utf8(&bytes)?)?)?
        } else {
            ensure!(
                !initialized,
                "Saved command history is missing; it was not recreated"
            );
            State {
                version: 1,
                binding: binding.clone(),
                high_water: now,
                records: vec![],
            }
        };
        let mut value = Self {
            path: path.into(),
            state,
            _lock: lock,
            session: uuid::Uuid::new_v4(),
            usable: true,
            observed: false,
        };
        value.state.validate()?;
        ensure!(
            &value.state.binding == binding,
            "Saved command belongs to another native profile"
        );
        value.clock(now)?;
        if !exists {
            value.save()?;
        }
        Ok(value)
    }
    pub fn require_new(&self) -> Result<()> {
        ensure!(
            self.state.records.len() < MAX_RECORDS
                && self.state.records.last().is_none_or(|r| r.archived),
            "Check the saved operation; no replacement command was generated"
        );
        Ok(())
    }
    fn record(&self) -> Result<&Record> {
        self.state
            .records
            .last()
            .context("No saved pairing command")
    }
    pub fn grant(&self) -> Result<&Grant> {
        Ok(&self.record()?.grant)
    }
    pub fn retain(
        &mut self,
        grant: Grant,
        command: OwnerCommand,
        now: DateTime<Utc>,
    ) -> Result<ClientCommandView> {
        self.clock(now)?;
        self.require_new()?;
        self.state.binding.require(&grant, &command)?;
        same_active_grant(&grant, &grant, now)?;
        live(command.intent.created_at, command.intent.expires_at, now)?;
        let digest = command.digest()?;
        self.state.records.push(Record {
            grant,
            command,
            digest,
            submitted: false,
            archived: false,
            serial: 0,
            last_observed: None,
            observed_at: None,
            retained_outcome: None,
            retained_at: None,
        });
        self.state.high_water = now;
        self.observed = false;
        self.save()?;
        self.view()
    }
    pub fn review(&self, digest: &str, now: DateTime<Utc>) -> Result<ClientCommandView> {
        self.clock(now)?;
        let record = self.record()?;
        ensure!(
            !record.submitted && !record.archived && record.digest == digest,
            "Command was already reserved or review changed; check its saved result without executing again"
        );
        live(
            record.command.intent.created_at,
            record.command.intent.expires_at,
            now,
        )?;
        same_active_grant(&record.grant, &record.grant, now)?;
        self.view()
    }
    pub fn reserve(&mut self, digest: Option<&str>, now: DateTime<Utc>) -> Result<CommandExchange> {
        self.clock(now)?;
        if let Some(digest) = digest {
            self.review(digest, now)?;
        } else {
            ensure!(
                self.record()?.submitted && !self.record()?.archived,
                "No submitted command to check"
            );
        }
        let record = self.state.records.last_mut().context("No saved command")?;
        record.submitted = true;
        record.serial = record
            .serial
            .checked_add(1)
            .context("Command sequence exhausted")?;
        let request = if digest.is_some() {
            ControlExchange::Execute {
                command: record.command.clone(),
            }
        } else {
            ControlExchange::Result {
                nonce: record.command.intent.nonce.clone(),
                digest: record.digest.clone(),
            }
        };
        let exchange = CommandExchange {
            session: self.session,
            serial: record.serial,
            nonce: record.command.intent.nonce.clone(),
            digest: record.digest.clone(),
            envelope: ControlEnvelope {
                version: 1,
                request,
            },
        };
        self.observed = false;
        self.state.high_water = now;
        self.save()?;
        Ok(exchange)
    }
    pub fn reply(
        &mut self,
        exchange: CommandExchange,
        reply: ControlReply,
        now: DateTime<Utc>,
    ) -> Result<ClientCommandView> {
        self.clock(now)?;
        let record = self.record()?;
        ensure!(
            exchange.session == self.session
                && exchange.serial == record.serial
                && exchange.nonce == record.command.intent.nonce
                && exchange.digest == record.digest,
            "Reply belongs to another or superseded command check"
        );
        let ControlReply::Result(result) = reply else {
            anyhow::bail!("Enrollment is not a command outcome")
        };
        result.validate_for(&record.command.intent.action)?;
        if terminal(&result)
            && let Some(retained) = &record.retained_outcome
        {
            ensure!(
                retained == &result,
                "Host returned conflicting retained outcomes"
            );
        }
        let record = self.state.records.last_mut().expect("checked record");
        if terminal(&result) {
            record.retained_outcome = Some(result.clone());
            record.retained_at = Some(now);
        }
        record.last_observed = Some(result);
        record.observed_at = Some(now);
        self.state.high_water = now;
        self.save()?;
        self.observed = true;
        self.view()
    }
    /// Explicit local retirement of an expired never-submitted review, or after
    /// this call's fresh terminal readback for a submitted operation.
    /// History remains; another operation needs another separate native review.
    pub fn archive(&mut self, digest: &str, now: DateTime<Utc>) -> Result<ClientCommandView> {
        self.clock(now)?;
        let record = self.record()?;
        ensure!(
            !record.archived
                && record.digest == digest
                && ((!record.submitted && now >= record.command.intent.expires_at)
                    || (record.submitted
                        && self.observed
                        && record.last_observed.as_ref().is_some_and(terminal))),
            "Retire only the exact expired unsent review or a freshly confirmed submitted result"
        );
        self.state
            .records
            .last_mut()
            .expect("checked record")
            .archived = true;
        self.state.high_water = now;
        self.save()?;
        self.view()
    }
    pub fn uncertain_view(&mut self) -> Result<ClientCommandView> {
        self.observed = false;
        self.view()
    }
    pub fn view(&self) -> Result<ClientCommandView> {
        let record = self.record()?;
        let status = if !self.usable {
            ClientCommandStatus::Uncertain
        } else if record.archived {
            ClientCommandStatus::Archived
        } else if !record.submitted {
            ClientCommandStatus::Reviewed
        } else if self.observed && record.last_observed.as_ref().is_some_and(terminal) {
            ClientCommandStatus::Observed
        } else {
            ClientCommandStatus::Uncertain
        };
        Ok(ClientCommandView {
            nonce: record.command.intent.nonce.clone(),
            digest: record.digest.clone(),
            action: record.command.intent.action.clone(),
            network: record.command.intent.scope.pin.network_name.clone(),
            command_expires_at: record.command.intent.expires_at,
            grant_expires_at: record.grant.enrollment.intent.grant_expires_at,
            status,
            current_observation: self
                .observed
                .then(|| record.last_observed.clone())
                .flatten(),
            last_observed: record.last_observed.clone(),
            observed_at: record.observed_at,
            retained_outcome: record.retained_outcome.clone(),
            retained_at: record.retained_at,
        })
    }
    fn clock(&self, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            self.usable && now >= self.state.high_water,
            "Command persistence failed or clock moved backwards; saved work was preserved"
        );
        Ok(())
    }
    fn save(&mut self) -> Result<()> {
        ensure!(
            self.usable,
            "Reopen preserved command history before continuing"
        );
        self.usable = false;
        self.state.validate()?;
        let bytes = serde_json::to_vec(&self.state)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "Command history exceeded its limit"
        );
        check_path(&self.path)?;
        let parent = self
            .path
            .parent()
            .context("Missing native command directory")?;
        let mut pending = tempfile::NamedTempFile::new_in(parent)?;
        pending.write_all(&bytes)?;
        pending.as_file().sync_all()?;
        pending.persist(&self.path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        self.usable = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "owner-requests-qualification")]
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    #[cfg(feature = "owner-requests-qualification")]
    use chrono::Duration;
    #[cfg(feature = "owner-requests-qualification")]
    use ed25519_dalek::SigningKey;
    #[cfg(feature = "owner-requests-qualification")]
    fn fixture(
        action: OwnerAction,
    ) -> Result<(CommandBinding, Grant, OwnerCommand, DateTime<Utc>)> {
        let now = Utc::now();
        let key = SigningKey::from_bytes(&[11; 32]);
        let public =
            |n| STANDARD.encode(SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes());
        let enrollment = EnrollmentRequest::sign(
            EnrollmentIntent {
                version: 1,
                id: uuid::Uuid::new_v4().to_string(),
                scope: ControlScope {
                    pin: crate::authority::TrustPin {
                        network_name: "Fixture".into(),
                        root_public_key: public(1),
                    },
                    host_node: public(2),
                },
                controller_node: public(3),
                administrative_key: public(11),
                permissions: [
                    Permission::ListPairing,
                    Permission::ApprovePairing,
                    Permission::RejectPairing,
                ]
                .into_iter()
                .collect(),
                created_at: now,
                expires_at: now + Duration::seconds(120),
                grant_expires_at: now + Duration::seconds(600),
            },
            &key,
        )?;
        let grant = Grant {
            approval_digest: enrollment.digest()?,
            enrollment,
            approved_at: now,
            revoked_at: None,
        };
        let binding = CommandBinding {
            profile_id: uuid::Uuid::new_v4().to_string(),
            enrollment: EnrollmentBinding {
                scope: grant.enrollment.intent.scope.clone(),
                controller_node: public(3),
                administrative_key: public(11),
            },
        };
        let command = OwnerCommand::sign(
            CommandIntent {
                version: 1,
                grant_id: grant.enrollment.intent.id.clone(),
                nonce: uuid::Uuid::new_v4().to_string(),
                scope: binding.enrollment.scope.clone(),
                controller_node: public(3),
                action,
                created_at: now,
                expires_at: now + Duration::seconds(60),
            },
            &key,
        )?;
        Ok((binding, grant, command, now))
    }
    #[cfg(not(feature = "owner-requests-qualification"))]
    #[test]
    fn commands_and_presence_remain_unavailable_in_production() {
        assert!(commands_qualified().is_err());
        assert!(!UnavailableCommandPresence.available());
    }
    #[cfg(feature = "owner-requests-qualification")]
    #[test]
    fn interruption_retains_exact_command_and_readback_cannot_become_execute() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("commands.json");
        let (binding, grant, command, now) = fixture(OwnerAction::ListPairing)?;
        let mut workflow = ClientCommands::open(&path, &binding, true, now)?;
        let view = workflow.retain(grant, command, now)?;
        let dispatch = workflow.reserve(Some(&view.digest), now)?;
        assert!(matches!(
            dispatch.envelope().request,
            ControlExchange::Execute { .. }
        ));
        drop(workflow);
        let mut workflow = ClientCommands::open(&path, &binding, false, now)?;
        assert_eq!(workflow.view()?.status, ClientCommandStatus::Uncertain);
        assert!(workflow.require_new().is_err());
        assert!(workflow.reserve(Some(&view.digest), now).is_err());
        let check = workflow.reserve(None, now)?;
        let ControlExchange::Result { nonce, digest } = &check.envelope.request else {
            panic!("Recovery replayed Execute")
        };
        assert_eq!(nonce, &view.nonce);
        assert_eq!(digest, &view.digest);
        assert!(
            workflow
                .reply(
                    dispatch,
                    ControlReply::Result(ControlResult::PairingList { request: None }),
                    now
                )
                .is_err()
        );
        workflow.reply(check, ControlReply::Result(ControlResult::Unconfirmed), now)?;
        assert!(workflow.view()?.retained_outcome.is_none());
        assert!(workflow.archive(&view.digest, now).is_err());
        Ok(())
    }
    #[cfg(feature = "owner-requests-qualification")]
    #[test]
    fn current_observation_and_retained_outcome_are_separate_and_only_fresh_terminal_check_can_archive()
    -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("commands.json");
        let (binding, grant, command, now) = fixture(OwnerAction::ListPairing)?;
        let mut workflow = ClientCommands::open(&path, &binding, true, now)?;
        let review = workflow.retain(grant, command, now)?;
        let send = workflow.reserve(Some(&review.digest), now)?;
        workflow.reply(
            send,
            ControlReply::Result(ControlResult::PairingList { request: None }),
            now,
        )?;
        drop(workflow);
        let mut workflow = ClientCommands::open(&path, &binding, false, now)?;
        let historical = workflow.view()?;
        assert!(historical.current_observation.is_none());
        assert!(historical.retained_outcome.is_some());
        assert_eq!(historical.status, ClientCommandStatus::Uncertain);
        assert!(workflow.archive(&review.digest, now).is_err());
        let check = workflow.reserve(None, now)?;
        workflow.reply(check, ControlReply::Result(ControlResult::Unconfirmed), now)?;
        assert!(workflow.view()?.retained_outcome.is_some());
        assert_eq!(workflow.view()?.status, ClientCommandStatus::Uncertain);
        assert!(workflow.archive(&review.digest, now).is_err());
        let check = workflow.reserve(None, now)?;
        workflow.reply(
            check,
            ControlReply::Result(ControlResult::PairingList { request: None }),
            now,
        )?;
        workflow.archive(&review.digest, now)?;
        workflow.require_new()?;
        assert_eq!(workflow.state.records.len(), 1);
        assert_eq!(workflow.view()?.status, ClientCommandStatus::Archived);
        Ok(())
    }
    #[cfg(feature = "owner-requests-qualification")]
    #[test]
    fn bindings_review_expiry_revocation_reply_order_and_corruption_refuse_without_replacement()
    -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("commands.json");
        let (binding, grant, command, now) = fixture(OwnerAction::ListPairing)?;
        let mut workflow = ClientCommands::open(&path, &binding, true, now)?;
        let view = workflow.retain(grant.clone(), command, now)?;
        assert!(workflow.review("different-review", now).is_err());
        assert!(
            workflow
                .review(&view.digest, now + Duration::seconds(61))
                .is_err()
        );
        let mut revoked = grant.clone();
        revoked.revoked_at = Some(now);
        assert!(same_active_grant(&grant, &revoked, now).is_err());
        assert!(same_active_grant(&grant, &grant, now + Duration::seconds(601)).is_err());
        workflow.reserve(Some(&view.digest), now)?;
        let older = workflow.reserve(None, now)?;
        let latest = workflow.reserve(None, now)?;
        assert!(
            workflow
                .reply(
                    older,
                    ControlReply::Result(ControlResult::PairingList { request: None }),
                    now
                )
                .is_err()
        );
        assert!(
            workflow
                .reply(
                    latest,
                    ControlReply::Result(ControlResult::Approved {
                        node: binding.enrollment.controller_node.clone()
                    }),
                    now
                )
                .is_err()
        );
        drop(workflow);
        let before = std::fs::read(&path)?;
        for field in ["profile", "host", "member", "key", "network"] {
            let mut wrong = binding.clone();
            match field {
                "profile" => wrong.profile_id = uuid::Uuid::new_v4().to_string(),
                "host" => {
                    wrong.enrollment.scope.host_node = wrong.enrollment.controller_node.clone()
                }
                "member" => {
                    wrong.enrollment.controller_node = wrong.enrollment.scope.host_node.clone()
                }
                "key" => {
                    wrong.enrollment.administrative_key = wrong.enrollment.controller_node.clone()
                }
                _ => wrong.enrollment.scope.pin.network_name = "Other".into(),
            }
            assert!(ClientCommands::open(&path, &wrong, false, now).is_err());
            assert_eq!(std::fs::read(&path)?, before);
        }
        let mut impossible: serde_json::Value = serde_json::from_slice(&before)?;
        impossible["records"][0]["serial"] = serde_json::json!(0);
        std::fs::write(&path, serde_json::to_vec(&impossible)?)?;
        assert!(
            ClientCommands::open(&path, &binding, false, now).is_err(),
            "Submitted work must retain its durable sequence"
        );
        std::fs::write(&path, &before)?;
        let mut damaged: serde_json::Value = serde_json::from_slice(&before)?;
        damaged["records"][0]["command"]["intent"]["nonce"] =
            serde_json::json!(uuid::Uuid::new_v4().to_string());
        std::fs::write(&path, serde_json::to_vec(&damaged)?)?;
        assert!(ClientCommands::open(&path, &binding, false, now).is_err());
        std::fs::remove_file(&path)?;
        assert!(
            ClientCommands::open(&path, &binding, true, now).is_err(),
            "Lost initialized history must not be recreated"
        );
        Ok(())
    }
    #[cfg(feature = "owner-requests-qualification")]
    #[test]
    fn expired_unsent_review_archives_locally_and_preserves_history_without_dispatch() -> Result<()>
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("commands.json");
        let (binding, grant, command, now) = fixture(OwnerAction::ListPairing)?;
        let mut workflow = ClientCommands::open(&path, &binding, true, now)?;
        let review = workflow.retain(grant.clone(), command.clone(), now)?;
        assert!(workflow.archive(&review.digest, now).is_err());
        let expired = command.intent.expires_at;
        assert!(workflow.reserve(Some(&review.digest), expired).is_err());
        assert!(workflow.reserve(None, expired).is_err());
        assert!(workflow.archive("different-review", expired).is_err());
        drop(workflow);
        let mut workflow = ClientCommands::open(&path, &binding, false, expired)?;
        let archived = workflow.archive(&review.digest, expired)?;
        assert_eq!(archived.status, ClientCommandStatus::Archived);
        assert!(archived.current_observation.is_none());
        assert!(archived.retained_outcome.is_none());
        let first = &workflow.state.records[0];
        assert!(!first.submitted && first.serial == 0);
        assert_eq!(first.digest, review.digest);
        assert!(workflow.reserve(Some(&review.digest), expired).is_err());
        assert!(workflow.reserve(None, expired).is_err());
        drop(workflow);
        let mut workflow = ClientCommands::open(&path, &binding, false, expired)?;
        workflow.require_new()?;
        let mut intent = command.intent;
        intent.nonce = uuid::Uuid::new_v4().to_string();
        intent.created_at = expired;
        intent.expires_at = expired + Duration::seconds(60);
        let next = OwnerCommand::sign(intent, &SigningKey::from_bytes(&[11; 32]))?;
        let next = workflow.retain(grant, next, expired)?;
        assert_ne!(next.nonce, review.nonce);
        assert_eq!(workflow.state.records.len(), 2);
        assert!(workflow.state.records[0].archived);
        assert!(!workflow.state.records[0].submitted);
        assert!(matches!(
            workflow
                .reserve(Some(&next.digest), expired)?
                .envelope
                .request,
            ControlExchange::Execute { .. }
        ));
        Ok(())
    }
    #[cfg(feature = "owner-requests-qualification")]
    #[test]
    fn expired_submitted_uncertainty_cannot_be_archived_as_an_unsent_review() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("commands.json");
        let (binding, grant, command, now) = fixture(OwnerAction::ListPairing)?;
        let expired = command.intent.expires_at;
        let mut workflow = ClientCommands::open(&path, &binding, true, now)?;
        let review = workflow.retain(grant, command, now)?;
        workflow.reserve(Some(&review.digest), now)?;
        drop(workflow);
        let mut workflow = ClientCommands::open(&path, &binding, false, expired)?;
        assert!(workflow.archive(&review.digest, expired).is_err());
        assert!(workflow.require_new().is_err());
        assert!(workflow.reserve(Some(&review.digest), expired).is_err());
        assert!(matches!(
            workflow.reserve(None, expired)?.envelope.request,
            ControlExchange::Result { .. }
        ));
        Ok(())
    }
    #[cfg(feature = "owner-requests-qualification")]
    #[test]
    fn failed_durable_reservation_returns_no_execute_and_fences_live_retry() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("commands.json");
        let (binding, grant, command, now) = fixture(OwnerAction::ListPairing)?;
        let mut workflow = ClientCommands::open(&path, &binding, true, now)?;
        let review = workflow.retain(grant, command, now)?;
        let backup = dir.path().join("preserved.json");
        std::fs::rename(&path, &backup)?;
        std::fs::create_dir(&path)?;
        assert!(workflow.reserve(Some(&review.digest), now).is_err());
        assert_eq!(workflow.view()?.status, ClientCommandStatus::Uncertain);
        std::fs::remove_dir(&path)?;
        std::fs::rename(backup, &path)?;
        assert!(
            workflow.reserve(Some(&review.digest), now).is_err(),
            "Failed persistence must fence the live session"
        );
        drop(workflow);
        let reopened = ClientCommands::open(&path, &binding, false, now)?;
        assert_eq!(reopened.view()?.nonce, review.nonce);
        assert!(reopened.require_new().is_err());
        Ok(())
    }
}
