//! Durable native client enrollment only. No host approval or pairing execution.
use super::{protocol::live, store::check_path, *};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use genesis_mesh_sdk::parse_strict_json;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 64 * 1024;
pub(crate) const CLIENT_ENROLLMENT_FILE: &str = "owner-enrollment.json";

/// Derived by the native device adapter, never a caller-selected UI identity.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentBinding {
    pub scope: ControlScope,
    pub controller_node: String,
    pub administrative_key: String,
}
impl EnrollmentBinding {
    fn require(&self, request: &EnrollmentRequest) -> Result<()> {
        request.verify()?;
        let intent = &request.intent;
        ensure!(
            self.scope == intent.scope
                && self.controller_node == intent.controller_node
                && self.administrative_key == intent.administrative_key,
            "Saved enrollment belongs to a different network, host, member or administrative key"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientEnrollmentStatus {
    Reviewed,
    Uncertain,
    Pending,
    Active,
    Declined,
    Expired,
    Revoked,
    Missing,
}

/// Active is an authenticated observation at observed_at, not authorization to
/// execute a pairing action or proof that membership is current at a later time.
#[derive(Clone, Debug, Serialize)]
pub struct ClientEnrollmentView {
    pub request: EnrollmentRequest,
    pub reviewed_digest: String,
    pub status: ClientEnrollmentStatus,
    pub last_observed: Option<ClientEnrollmentStatus>,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Reviewed,
    Submitted,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    binding: EnrollmentBinding,
    request: EnrollmentRequest,
    reviewed_digest: String,
    phase: Phase,
    high_water: DateTime<Utc>,
    exchange: u64,
    uncertain: bool,
    observation: Option<EnrollmentState>,
    observed_at: Option<DateTime<Utc>>,
}
impl State {
    fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "Unsupported saved enrollment workflow");
        self.binding.require(&self.request)?;
        ensure!(
            self.reviewed_digest == self.request.digest()?
                && self.high_water >= self.request.intent.created_at,
            "Saved enrollment review changed"
        );
        ensure!(
            (self.phase == Phase::Reviewed
                && self.exchange == 0
                && !self.uncertain
                && self.observation.is_none())
                || (self.phase == Phase::Submitted && self.exchange > 0),
            "Invalid saved enrollment phase"
        );
        match (&self.observation, self.observed_at) {
            (Some(value), Some(at)) => {
                ensure!(
                    at <= self.high_water && at >= self.request.intent.created_at,
                    "Invalid saved enrollment observation time"
                );
                validate_observation(&self.request, &self.reviewed_digest, value, at)?;
            }
            (None, None) => {}
            _ => anyhow::bail!("Incomplete saved enrollment observation"),
        }
        ensure!(
            self.phase != Phase::Submitted || self.uncertain || self.observation.is_some(),
            "Missing enrollment outcome"
        );
        Ok(())
    }
}
fn observed_status(value: &EnrollmentState) -> ClientEnrollmentStatus {
    match value {
        EnrollmentState::Pending { .. } => ClientEnrollmentStatus::Pending,
        EnrollmentState::Active { .. } => ClientEnrollmentStatus::Active,
        EnrollmentState::Declined => ClientEnrollmentStatus::Declined,
        EnrollmentState::Expired => ClientEnrollmentStatus::Expired,
        EnrollmentState::Revoked => ClientEnrollmentStatus::Revoked,
        EnrollmentState::Missing => ClientEnrollmentStatus::Missing,
    }
}
fn exact_request(
    expected: &EnrollmentRequest,
    actual: &EnrollmentRequest,
    digest: &str,
) -> Result<()> {
    ensure!(
        actual.digest()? == digest
            && serde_json::to_value(expected)? == serde_json::to_value(actual)?,
        "Host returned a different enrollment request"
    );
    Ok(())
}
fn validate_observation(
    request: &EnrollmentRequest,
    digest: &str,
    value: &EnrollmentState,
    at: DateTime<Utc>,
) -> Result<()> {
    match value {
        EnrollmentState::Pending { request: actual } => {
            exact_request(request, actual, digest)?;
            live(request.intent.created_at, request.intent.expires_at, at)?;
        }
        EnrollmentState::Active { grant } => {
            exact_request(request, &grant.enrollment, digest)?;
            ensure!(
                grant.approval_digest == digest && grant.revoked_at.is_none(),
                "Host returned an invalid or revoked grant"
            );
            live(
                request.intent.created_at,
                request.intent.expires_at,
                grant.approved_at,
            )?;
            ensure!(
                grant.approved_at <= at && at < request.intent.grant_expires_at,
                "Host returned future or expired administrative access"
            );
        }
        _ => {} // These states carry no grant; the authenticated status call supplies the exact ID.
    }
    Ok(())
}

/// Native single-use, in-instance exchange correlation, not a grant or signer.
/// Cloning the envelope does not allow the coordinator to reserve another send.
pub struct EnrollmentExchange {
    session: uuid::Uuid,
    serial: u64,
    envelope: ControlEnvelope,
}
impl EnrollmentExchange {
    pub fn envelope(&self) -> &ControlEnvelope {
        &self.envelope
    }
}

/// One bounded workflow per device profile. The native lock covers the exchange.
/// OS storage is the boundary; restoring an old whole journal is not detected as
/// cryptographic rollback. Recovery never resubmits the retained enrollment.
pub struct ClientEnrollment {
    path: PathBuf,
    state: State,
    _lock: File,
    session: uuid::Uuid,
    usable: bool,
}
impl ClientEnrollment {
    pub(crate) fn initialized(path: &Path) -> Result<bool> {
        check_path(path)?;
        Ok(path.try_exists()? || path.with_extension("owner-enrollment-lock").try_exists()?)
    }
    pub fn create(
        path: &Path,
        binding: EnrollmentBinding,
        request: EnrollmentRequest,
        reviewed_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        binding.require(&request)?;
        ensure!(
            reviewed_digest == request.digest()?,
            "Review the exact enrollment before retaining it"
        );
        live(request.intent.created_at, request.intent.expires_at, now)?;
        let (lock, initialized) = lock(path)?;
        ensure!(
            !initialized && !path.try_exists()?,
            "Saved enrollment already exists or needs recovery; it was not replaced"
        );
        let mut value = Self {
            path: path.into(),
            state: State {
                version: 1,
                binding,
                request,
                reviewed_digest: reviewed_digest.into(),
                phase: Phase::Reviewed,
                high_water: now,
                exchange: 0,
                uncertain: false,
                observation: None,
                observed_at: None,
            },
            _lock: lock,
            session: uuid::Uuid::new_v4(),
            usable: true,
        };
        value.save()?;
        Ok(value)
    }
    pub fn open(path: &Path, binding: &EnrollmentBinding, now: DateTime<Utc>) -> Result<Self> {
        // Merely inspecting an absent workflow does not initialize its marker.
        ensure!(
            path.try_exists()?,
            "Saved enrollment is missing; no replacement was created"
        );
        let (lock, _) = lock(path)?;
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "Saved enrollment is too large; it was preserved"
        );
        let state: State =
            serde_json::from_value(parse_strict_json(std::str::from_utf8(&bytes)?)?)?;
        state.validate()?;
        ensure!(
            &state.binding == binding,
            "Saved enrollment belongs to a different native device context"
        );
        let mut value = Self {
            path: path.into(),
            state,
            _lock: lock,
            session: uuid::Uuid::new_v4(),
            usable: true,
        };
        value.clock(now)?;
        if value.state.phase == Phase::Submitted {
            value.state.uncertain = true;
            value.state.high_water = now;
            value.save()?;
        }
        Ok(value)
    }
    pub fn view(&self) -> ClientEnrollmentView {
        ClientEnrollmentView {
            request: self.state.request.clone(),
            reviewed_digest: self.state.reviewed_digest.clone(),
            status: if !self.usable {
                ClientEnrollmentStatus::Uncertain
            } else if self.state.phase == Phase::Reviewed {
                ClientEnrollmentStatus::Reviewed
            } else if self.state.uncertain {
                ClientEnrollmentStatus::Uncertain
            } else {
                observed_status(
                    self.state
                        .observation
                        .as_ref()
                        .expect("validated observation"),
                )
            },
            last_observed: self.state.observation.as_ref().map(observed_status),
            observed_at: self.state.observed_at,
        }
    }
    pub fn reserve_submission(
        &mut self,
        reviewed_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<EnrollmentExchange> {
        self.clock(now)?;
        ensure!(
            self.state.phase == Phase::Reviewed && reviewed_digest == self.state.reviewed_digest,
            "This exact enrollment was already reserved or its review changed; check status without resending"
        );
        live(
            self.state.request.intent.created_at,
            self.state.request.intent.expires_at,
            now,
        )?;
        self.state.phase = Phase::Submitted;
        self.reserve(
            ControlExchange::Enroll {
                request: self.state.request.clone(),
            },
            now,
        )
    }
    pub fn status_query(&mut self, now: DateTime<Utc>) -> Result<EnrollmentExchange> {
        self.clock(now)?;
        ensure!(
            self.state.phase == Phase::Submitted,
            "This enrollment has not been submitted"
        );
        self.reserve(
            ControlExchange::EnrollmentStatus {
                id: self.state.request.intent.id.clone(),
            },
            now,
        )
    }
    fn reserve(
        &mut self,
        request: ControlExchange,
        now: DateTime<Utc>,
    ) -> Result<EnrollmentExchange> {
        self.state.exchange = self
            .state
            .exchange
            .checked_add(1)
            .context("Enrollment check sequence is exhausted")?;
        self.state.uncertain = true;
        self.state.high_water = now;
        self.save()?;
        Ok(EnrollmentExchange {
            session: self.session,
            serial: self.state.exchange,
            envelope: ControlEnvelope {
                version: 1,
                request,
            },
        })
    }
    pub fn record_reply(
        &mut self,
        exchange: EnrollmentExchange,
        reply: ControlReply,
        now: DateTime<Utc>,
    ) -> Result<ClientEnrollmentView> {
        self.clock(now)?;
        ensure!(
            exchange.session == self.session && exchange.serial == self.state.exchange,
            "Enrollment reply belongs to an abandoned or superseded check"
        );
        let ControlReply::Enrollment(observation) = reply else {
            anyhow::bail!("Expected an enrollment observation, not a pairing result")
        };
        validate_observation(
            &self.state.request,
            &self.state.reviewed_digest,
            &observation,
            now,
        )?;
        self.state.observation = Some(observation);
        self.state.observed_at = Some(now);
        self.state.uncertain = false;
        self.state.high_water = now;
        self.save()?;
        Ok(self.view())
    }
    fn clock(&self, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            self.usable,
            "Enrollment persistence failed; reopen before continuing"
        );
        ensure!(
            now >= self.state.high_water,
            "The device clock moved backwards; synchronize it before checking enrollment"
        );
        Ok(())
    }
    fn save(&mut self) -> Result<()> {
        ensure!(
            self.usable,
            "Enrollment persistence failed; reopen before continuing"
        );
        self.usable = false;
        self.state.validate()?;
        let bytes = serde_json::to_vec(&self.state)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "Saved enrollment exceeded its limit"
        );
        check_path(&self.path)?;
        let parent = self.path.parent().context("Missing enrollment directory")?;
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
fn lock(path: &Path) -> Result<(File, bool)> {
    check_path(path)?;
    let marker = path.with_extension("owner-enrollment-lock");
    check_path(&marker)?;
    let initialized = marker.try_exists()?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(marker)?;
    fs2::FileExt::try_lock_exclusive(&file)
        .context("Another client enrollment operation is running")?;
    Ok((file, initialized))
}
