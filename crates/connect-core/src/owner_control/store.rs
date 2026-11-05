use super::protocol::*;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use genesis_mesh_sdk::parse_strict_json;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_GRANTS: usize = 64;
const MAX_RESERVATIONS: usize = 256;

/// Host-local delegation, not a core operator key or portable capability.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub enrollment: EnrollmentRequest,
    pub approval_digest: String,
    pub approved_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Observation {
    Unconfirmed,
    ReplyObserved,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UsedRequest {
    command: OwnerCommand,
    digest: String,
    reserved_at: DateTime<Utc>,
    observation: Observation,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    scope: ControlScope,
    high_water: DateTime<Utc>,
    grants: Vec<Grant>,
    used: Vec<UsedRequest>,
}
impl State {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.grants.len() <= MAX_GRANTS
                && self.used.len() <= MAX_RESERVATIONS,
            "Unsupported or oversized owner-control state"
        );
        self.scope.validate()?;
        let mut ids = BTreeSet::new();
        for grant in &self.grants {
            let intent = &grant.enrollment.intent;
            grant.enrollment.verify()?;
            ensure!(
                ids.insert(&intent.id)
                    && intent.scope == self.scope
                    && grant.approval_digest == grant.enrollment.digest()?,
                "Invalid saved owner enrollment"
            );
            live(intent.created_at, intent.expires_at, grant.approved_at)?;
            ensure!(
                grant.approved_at <= self.high_water
                    && grant
                        .revoked_at
                        .is_none_or(|t| t >= grant.approved_at && t <= self.high_water),
                "Invalid saved owner-control time"
            );
        }
        let mut nonces = BTreeSet::new();
        for used in &self.used {
            let command = &used.command;
            let grant = self
                .grants
                .iter()
                .find(|g| g.enrollment.intent.id == command.intent.grant_id)
                .context("Missing saved administrative grant")?;
            command.verify(&grant.enrollment.intent.administrative_key)?;
            ensure!(
                nonces.insert(&command.intent.nonce)
                    && used.digest == command.digest()?
                    && command.intent.scope == self.scope
                    && command.intent.controller_node == grant.enrollment.intent.controller_node
                    && grant
                        .enrollment
                        .intent
                        .permissions
                        .contains(&command.intent.action.permission()),
                "Invalid saved owner request"
            );
            live(
                command.intent.created_at,
                command.intent.expires_at,
                used.reserved_at,
            )?;
            ensure!(
                used.reserved_at >= grant.approved_at
                    && used.reserved_at < grant.enrollment.intent.grant_expires_at
                    && used.reserved_at <= self.high_water,
                "Invalid saved request time"
            );
        }
        Ok(())
    }
}

/// A request reserved durably before a fixed adapter may dispatch it. Not Clone
/// or Deserialize. A returned action is not proof of execution or core approval.
pub struct Reservation {
    nonce: String,
    digest: String,
    action: OwnerAction,
}
impl Reservation {
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn action(&self) -> &OwnerAction {
        &self.action
    }
}

/// Caller must hold this exclusive host lock through the final live target and
/// core-role checks and immediate dispatch. There is no remote enrollment API.
/// OS storage is the host trust boundary; restoring an old whole file is not
/// detected as cryptographic rollback and must not be used as a recovery flow.
pub struct ControlStore {
    path: PathBuf,
    state: State,
    _lock: File,
    usable: bool,
}
impl ControlStore {
    pub fn create(path: &Path, scope: ControlScope, now: DateTime<Utc>) -> Result<Self> {
        scope.validate()?;
        let (lock, initialized) = lock(path)?;
        ensure!(
            !path.exists() && !initialized,
            "Owner-control state already exists or needs recovery; it has not been reset"
        );
        let mut store = Self {
            path: path.into(),
            state: State {
                version: 1,
                scope,
                high_water: now,
                grants: vec![],
                used: vec![],
            },
            _lock: lock,
            usable: true,
        };
        store.save()?;
        Ok(store)
    }
    pub fn open(path: &Path, expected: &ControlScope) -> Result<Self> {
        expected.validate()?;
        let (lock, _) = lock(path)?;
        ensure!(
            path.is_file(),
            "Owner-control state is missing; restore or explicitly reset it locally"
        );
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "Owner-control state is too large; it was preserved"
        );
        let state: State =
            serde_json::from_value(parse_strict_json(std::str::from_utf8(&bytes)?)?)?;
        state.validate()?;
        ensure!(
            &state.scope == expected,
            "Owner-control state belongs to a different network or host"
        );
        Ok(Self {
            path: path.into(),
            state,
            _lock: lock,
            usable: true,
        })
    }
    fn clock(&self, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            self.usable,
            "Owner-control persistence failed; reopen before continuing"
        );
        ensure!(
            now >= self.state.high_water,
            "The host clock moved backwards; synchronize it before owner control"
        );
        Ok(())
    }
    fn save(&mut self) -> Result<()> {
        ensure!(
            self.usable,
            "Owner-control persistence failed; reopen before continuing"
        );
        self.usable = false;
        // Untrusted disk state is fully verified on open. Each mutation checks
        // its new proof and invariants before reaching save; re-verifying all
        // historical signatures here would make a bounded burst quadratic.
        ensure!(
            self.state.grants.len() <= MAX_GRANTS && self.state.used.len() <= MAX_RESERVATIONS,
            "Owner-control state is full; nothing was dispatched"
        );
        let bytes = serde_json::to_vec(&self.state)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "Owner-control state is full; nothing was dispatched"
        );
        check_path(&self.path)?;
        let parent = self
            .path
            .parent()
            .context("Missing owner-control directory")?;
        let mut pending = tempfile::NamedTempFile::new_in(parent)?;
        pending.write_all(&bytes)?;
        pending.as_file().sync_all()?;
        pending.persist(&self.path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        self.usable = true;
        Ok(())
    }
    pub fn grants(&self) -> &[Grant] {
        &self.state.grants
    }

    /// Called only after fresh, explicit approval on the authority host. The
    /// expected digest must come from the exact native review shown locally.
    /// No member/owner command is allowed to call this method on another device.
    pub fn enroll_locally(
        &mut self,
        request: EnrollmentRequest,
        reviewed_digest: &str,
        peer: &VerifiedController,
        now: DateTime<Utc>,
    ) -> Result<Grant> {
        self.clock(now)?;
        request.verify()?;
        let intent = &request.intent;
        ensure!(
            intent.scope == self.state.scope,
            "Wrong enrollment audience"
        );
        peer.require(&self.state.scope, &intent.controller_node, now)?;
        live(intent.created_at, intent.expires_at, now)?;
        let digest = request.digest()?;
        ensure!(
            digest == reviewed_digest,
            "Enrollment changed after local review"
        );
        ensure!(
            !self
                .state
                .grants
                .iter()
                .any(|g| g.enrollment.intent.id == intent.id),
            "Enrollment was already used; review its existing result"
        );
        ensure!(
            self.state.grants.len() < MAX_GRANTS,
            "Owner enrollment history is full; no access was granted"
        );
        let grant = Grant {
            enrollment: request,
            approval_digest: digest,
            approved_at: now,
            revoked_at: None,
        };
        self.state.grants.push(grant.clone());
        self.state.high_water = now;
        self.save()?;
        Ok(grant)
    }
    pub fn revoke_locally(&mut self, grant_id: &str, now: DateTime<Utc>) -> Result<()> {
        self.clock(now)?;
        let grant = self
            .state
            .grants
            .iter_mut()
            .find(|g| g.enrollment.intent.id == grant_id)
            .context("Unknown administrative enrollment")?;
        if grant.revoked_at.is_none() {
            grant.revoked_at = Some(now);
        }
        self.state.high_water = now;
        self.save()
    }
    pub fn reserve(
        &mut self,
        command: &OwnerCommand,
        peer: &VerifiedController,
        now: DateTime<Utc>,
    ) -> Result<Reservation> {
        self.clock(now)?;
        command.intent.validate()?;
        ensure!(
            command.intent.scope == self.state.scope,
            "Wrong owner request audience"
        );
        peer.require(&self.state.scope, &command.intent.controller_node, now)?;
        live(command.intent.created_at, command.intent.expires_at, now)?;
        let grant = self
            .state
            .grants
            .iter()
            .find(|g| g.enrollment.intent.id == command.intent.grant_id)
            .context("This device is not enrolled for owner control")?;
        let intent = &grant.enrollment.intent;
        ensure!(
            grant.revoked_at.is_none() && now >= grant.approved_at && now < intent.grant_expires_at,
            "Administrative access expired or was revoked"
        );
        ensure!(
            intent.controller_node == command.intent.controller_node
                && intent
                    .permissions
                    .contains(&command.intent.action.permission()),
            "Administrative scope does not allow this operation"
        );
        command.verify(&intent.administrative_key)?;
        // The persisted high-water time prevents expiry pruning followed by a
        // clock rollback from making a consumed command valid again.
        self.state
            .used
            .retain(|r| now < r.command.intent.expires_at);
        ensure!(
            !self
                .state
                .used
                .iter()
                .any(|r| r.command.intent.nonce == command.intent.nonce),
            "Owner request was already reserved; do not resend it"
        );
        ensure!(
            self.state.used.len() < MAX_RESERVATIONS,
            "Too many active owner requests; nothing was dispatched"
        );
        let digest = command.digest()?;
        self.state.used.push(UsedRequest {
            command: command.clone(),
            digest: digest.clone(),
            reserved_at: now,
            observation: Observation::Unconfirmed,
        });
        self.state.high_water = now;
        self.save()?;
        Ok(Reservation {
            nonce: command.intent.nonce.clone(),
            digest,
            action: command.intent.action.clone(),
        })
    }
    /// A reply observation is local metadata, never proof of joining completion.
    /// An expired reservation may have been pruned; no replay is enabled by that.
    pub fn observe_reply(&mut self, reserved: Reservation, now: DateTime<Utc>) -> Result<()> {
        self.clock(now)?;
        let used = self
            .state
            .used
            .iter_mut()
            .find(|r| r.command.intent.nonce == reserved.nonce && r.digest == reserved.digest)
            .context("Owner request is no longer retained")?;
        used.observation = Observation::ReplyObserved;
        self.state.high_water = now;
        self.save()
    }
    pub fn observation(&self, nonce: &str) -> Option<Observation> {
        self.state
            .used
            .iter()
            .find(|r| r.command.intent.nonce == nonce)
            .map(|r| r.observation)
    }
}

fn check_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.parent().is_some_and(Path::is_dir),
        "Use an absolute existing native owner-control directory"
    );
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                ensure!(
                    !meta.file_type().is_symlink(),
                    "Owner-control paths must not contain links"
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    ensure!(
                        meta.file_attributes() & 0x400 == 0,
                        "Owner-control paths must not contain reparse points"
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && ancestor == path => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn lock(path: &Path) -> Result<(File, bool)> {
    check_path(path)?;
    let lock_path = path.with_extension("owner-control-lock");
    check_path(&lock_path)?;
    let initialized = lock_path.exists();
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path)?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("Another owner-control operation is running")?;
    Ok((lock, initialized))
}
