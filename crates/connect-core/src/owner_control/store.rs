use super::protocol::*;
use super::{ControlResult, EnrollmentState, PendingEnrollment};
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
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;

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
    #[serde(default)]
    result: Option<ControlResult>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    scope: ControlScope,
    high_water: DateTime<Utc>,
    grants: Vec<Grant>,
    used: Vec<UsedRequest>,
    #[serde(default)]
    pending: Vec<PendingEnrollment>,
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
        ensure!(
            self.pending.len() <= 8,
            "Too many administrative enrollment requests"
        );
        let mut pending_ids = BTreeSet::new();
        for pending in &self.pending {
            pending.request.verify()?;
            ensure!(
                serde_json::to_vec(&pending.certificate)?.len() <= MAX_CERTIFICATE_BYTES,
                "Saved enrollment certificate is too large"
            );
            ensure!(
                pending_ids.insert(&pending.request.intent.id)
                    && pending.request.intent.scope == self.scope
                    && pending.certificate["node_public_key"]
                        == pending.request.intent.controller_node,
                "Invalid saved enrollment request"
            );
        }
        let mut ids = BTreeSet::new();
        for grant in &self.grants {
            let intent = &grant.enrollment.intent;
            grant.enrollment.verify()?;
            ensure!(
                ids.insert(&intent.id)
                    && !pending_ids.contains(&intent.id)
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
            if let Some(result) = &used.result {
                result.validate_for(&command.intent.action)?;
                ensure!(
                    used.observation == Observation::ReplyObserved,
                    "Saved result has no observed reply"
                );
            }
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
/// core-role checks and immediate dispatch. Remote enrollment requests cannot
/// approve themselves; approval remains a separate local operation.
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
                pending: vec![],
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
    pub(super) fn check_peer(&self, peer: &VerifiedController, now: DateTime<Utc>) -> Result<()> {
        self.clock(now)?;
        peer.require(&self.state.scope, &peer.node, now)
    }
    /// Readback never dispatches. Revalidate the original grant and permission,
    /// even when the signed execution window has passed or its reply was lost.
    pub fn checked_result(
        &self,
        peer: &VerifiedController,
        nonce: &str,
        digest: &str,
        now: DateTime<Utc>,
    ) -> Result<ControlResult> {
        self.check_peer(peer, now)?;
        let used = self
            .state
            .used
            .iter()
            .find(|r| {
                r.command.intent.nonce == nonce
                    && r.digest == digest
                    && r.command.intent.controller_node == peer.node
            })
            .context("Request result is not retained for this device")?;
        let grant = self
            .state
            .grants
            .iter()
            .find(|g| g.enrollment.intent.id == used.command.intent.grant_id)
            .context("Administrative enrollment is missing")?;
        ensure!(
            grant.revoked_at.is_none()
                && now >= grant.approved_at
                && now < grant.enrollment.intent.grant_expires_at
                && grant
                    .enrollment
                    .intent
                    .permissions
                    .contains(&used.command.intent.action.permission()),
            "Administrative access expired or was revoked"
        );
        Ok(used.result.clone().unwrap_or(ControlResult::Unconfirmed))
    }

    pub fn pending_enrollments(&self, now: DateTime<Utc>) -> Vec<PendingEnrollment> {
        self.state
            .pending
            .iter()
            .filter(|p| !p.declined && now < p.request.intent.expires_at)
            .cloned()
            .collect()
    }
    pub fn enrollment_state(&self, node: &str, id: &str, now: DateTime<Utc>) -> EnrollmentState {
        if let Some(grant) =
            self.state.grants.iter().find(|g| {
                g.enrollment.intent.id == id && g.enrollment.intent.controller_node == node
            })
        {
            if grant.revoked_at.is_some() {
                return EnrollmentState::Revoked;
            }
            if now >= grant.enrollment.intent.grant_expires_at {
                return EnrollmentState::Expired;
            }
            return EnrollmentState::Active {
                grant: grant.clone(),
            };
        }
        if let Some(p) = self
            .state
            .pending
            .iter()
            .find(|p| p.request.intent.id == id && p.request.intent.controller_node == node)
        {
            if now >= p.request.intent.expires_at {
                return EnrollmentState::Expired;
            }
            return if p.declined {
                EnrollmentState::Declined
            } else {
                EnrollmentState::Pending {
                    request: p.request.clone(),
                }
            };
        }
        EnrollmentState::Missing
    }
    /// Narrow same-intent submission idempotency; this never approves a grant.
    pub fn request_enrollment(
        &mut self,
        request: EnrollmentRequest,
        certificate: serde_json::Value,
        peer: &VerifiedController,
        now: DateTime<Utc>,
    ) -> Result<EnrollmentState> {
        self.clock(now)?;
        request.verify()?;
        ensure!(
            serde_json::to_vec(&certificate)?.len() <= MAX_CERTIFICATE_BYTES,
            "Enrollment certificate is too large"
        );
        peer.require(&self.state.scope, &request.intent.controller_node, now)?;
        ensure!(
            request.intent.scope == self.state.scope
                && certificate["node_public_key"] == request.intent.controller_node
                && genesis_mesh_sdk::canonical_digest(&certificate)? == peer.certificate_digest,
            "Wrong enrollment context"
        );
        let digest = request.digest()?;
        for grant in self
            .state
            .grants
            .iter()
            .filter(|g| g.enrollment.intent.id == request.intent.id)
        {
            ensure!(
                grant.enrollment.intent.controller_node == request.intent.controller_node
                    && grant.approval_digest == digest,
                "Enrollment identity was already used"
            );
        }
        for pending in self
            .state
            .pending
            .iter()
            .filter(|p| p.request.intent.id == request.intent.id)
        {
            ensure!(
                pending.request.digest()? == digest,
                "Enrollment intent changed"
            );
        }
        let state = self.enrollment_state(&request.intent.controller_node, &request.intent.id, now);
        match &state {
            EnrollmentState::Active { grant } => ensure!(
                grant.approval_digest == request.digest()?,
                "Enrollment intent changed"
            ),
            EnrollmentState::Pending { request: stored } => ensure!(
                stored.digest()? == request.digest()?,
                "Enrollment intent changed"
            ),
            EnrollmentState::Declined | EnrollmentState::Expired | EnrollmentState::Revoked => {
                return Ok(state);
            }
            EnrollmentState::Missing => {}
        }
        if !matches!(state, EnrollmentState::Missing) {
            return Ok(state);
        }
        live(request.intent.created_at, request.intent.expires_at, now)?;
        self.state
            .pending
            .retain(|p| now < p.request.intent.expires_at);
        ensure!(
            self.state.pending.len() < 8
                && !self
                    .state
                    .pending
                    .iter()
                    .any(
                        |p| p.request.intent.controller_node == request.intent.controller_node
                            && !p.declined
                    ),
            "An administrative request is already waiting or the queue is full"
        );
        let node = request.intent.controller_node.clone();
        let id = request.intent.id.clone();
        self.state.pending.push(PendingEnrollment {
            request,
            certificate,
            declined: false,
        });
        self.state.high_water = now;
        self.save()?;
        Ok(self.enrollment_state(&node, &id, now))
    }
    pub fn decline_locally(&mut self, id: &str, digest: &str, now: DateTime<Utc>) -> Result<()> {
        self.clock(now)?;
        let pending = self
            .state
            .pending
            .iter_mut()
            .find(|p| p.request.intent.id == id)
            .context("Enrollment is no longer waiting")?;
        ensure!(
            pending.request.digest()? == digest && now < pending.request.intent.expires_at,
            "Enrollment changed or expired"
        );
        pending.declined = true;
        self.state.high_water = now;
        self.save()
    }
    pub fn result_for(&self, node: &str, nonce: &str, digest: &str) -> ControlResult {
        self.state
            .used
            .iter()
            .find(|r| {
                r.command.intent.nonce == nonce
                    && r.digest == digest
                    && r.command.intent.controller_node == node
            })
            .and_then(|r| r.result.clone())
            .unwrap_or(ControlResult::Unconfirmed)
    }
    pub fn record_result(
        &mut self,
        nonce: &str,
        digest: &str,
        result: ControlResult,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.clock(now)?;
        let used = self
            .state
            .used
            .iter_mut()
            .find(|r| r.command.intent.nonce == nonce && r.digest == digest)
            .context("Request result is no longer retained")?;
        result.validate_for(&used.command.intent.action)?;
        if let Some(
            terminal @ (ControlResult::Approved { .. }
            | ControlResult::Rejected { .. }
            | ControlResult::PairingList { .. }),
        ) = &used.result
        {
            ensure!(terminal == &result, "A terminal result cannot be replaced");
        }
        used.result = Some(result);
        used.observation = Observation::ReplyObserved;
        self.state.high_water = now;
        self.save()
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
        if let Some(pending) = self
            .state
            .pending
            .iter()
            .find(|p| p.request.intent.id == intent.id)
        {
            ensure!(
                !pending.declined && pending.request.digest()? == digest,
                "Enrollment was declined or changed after submission"
            );
        }
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
        self.state
            .pending
            .retain(|p| p.request.intent.id != grant.enrollment.intent.id);
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
            result: None,
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
