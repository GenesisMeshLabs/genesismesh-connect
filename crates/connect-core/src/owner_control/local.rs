//! Bounded native local administration. These operations never cross the member bridge.
use super::*;
use crate::{device::DeviceController, owner::OwnerRuntime};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};
use genesis_mesh_sdk::canonical_digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalAdminAction {
    Enable,
    Approve,
    Decline,
    Revoke,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAdminInput {
    pub action: LocalAdminAction,
    pub enrollment_id: Option<String>,
}
impl LocalAdminInput {
    fn validate(&self) -> Result<()> {
        match (&self.action, &self.enrollment_id) {
            (LocalAdminAction::Enable, None) => Ok(()),
            (LocalAdminAction::Enable, _) | (_, None) => {
                anyhow::bail!("Choose one supported administrator action")
            }
            (_, Some(id)) => super::protocol::uuid_id(id),
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalAdminDecision {
    Pending,
    Approved,
    Declined,
    Revoked,
    Expired,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LocalAdminEntry {
    pub id: String,
    pub device_name: String,
    pub device_fingerprint: String,
    pub known_device: bool,
    pub permissions: Vec<Permission>,
    pub access_ends: DateTime<Utc>,
    pub request_ends: DateTime<Utc>,
    pub decision: LocalAdminDecision,
    pub enrollment_digest: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct LocalAdminView {
    pub scope: String,
    pub network: String,
    pub enabled: bool,
    pub pending: Vec<LocalAdminEntry>,
    pub administrators: Vec<LocalAdminEntry>,
}
/// Public readback reference, not an authorization. Commit must find an exact
/// native-held review; readback only observes current state in this same scope.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalAdminReference {
    pub review_id: String,
    pub review_digest: String,
    pub scope: String,
    pub action: LocalAdminAction,
    pub enrollment_id: Option<String>,
    pub enrollment_digest: Option<String>,
}
impl LocalAdminReference {
    fn validate(&self) -> Result<()> {
        super::protocol::uuid_id(&self.review_id)?;
        LocalAdminInput {
            action: self.action,
            enrollment_id: self.enrollment_id.clone(),
        }
        .validate()?;
        ensure!(
            !self.scope.is_empty()
                && self.scope.len() <= 128
                && !self.review_digest.is_empty()
                && self.review_digest.len() <= 128
                && self
                    .enrollment_digest
                    .as_ref()
                    .is_none_or(|d| !d.is_empty() && d.len() <= 128),
            "Invalid administrator review reference"
        );
        ensure!(
            (self.action == LocalAdminAction::Enable) == self.enrollment_digest.is_none(),
            "Invalid reviewed enrollment binding"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct LocalAdminReview {
    pub reference: LocalAdminReference,
    pub network: String,
    pub device: Option<LocalAdminEntry>,
    pub expires_at: DateTime<Utc>,
    pub consequence: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalAdminOutcomeKind {
    Confirmed,
    Refused,
    Uncertain,
}
#[derive(Clone, Debug, Serialize)]
pub struct LocalAdminOutcome {
    pub reference: LocalAdminReference,
    pub kind: LocalAdminOutcomeKind,
    pub observed: Option<LocalAdminDecision>,
    pub detail: String,
}
/// Trusted native integration only. No boolean, secret or provider selector is
/// accepted from IPC. A UI tap/storage unlock is not a qualified presence proof.
pub trait LocalAdminPresence: Send {
    fn available(&self) -> bool;
    fn confirm(&mut self, review: &LocalAdminReview) -> Result<()>;
}
/// Current production adapter: inspection works; mutations stay gated until
/// native presence is implemented and qualified. No environment override.
pub struct UnavailableAdminPresence;
impl LocalAdminPresence for UnavailableAdminPresence {
    fn available(&self) -> bool {
        false
    }
    fn confirm(&mut self, _: &LocalAdminReview) -> Result<()> {
        anyhow::bail!("Device authentication is unavailable for administration in this build")
    }
}
struct StoredReview {
    review: LocalAdminReview,
    consumed: bool,
    outcome: Option<LocalAdminOutcome>,
}
#[derive(Default)]
pub struct LocalAdministration {
    reviews: BTreeMap<String, StoredReview>,
}

fn scope_id(scope: &ControlScope) -> Result<String> {
    Ok(canonical_digest(&serde_json::to_value(scope)?)?)
}
fn outcome(
    reference: &LocalAdminReference,
    kind: LocalAdminOutcomeKind,
    observed: Option<LocalAdminDecision>,
    detail: &str,
) -> LocalAdminOutcome {
    LocalAdminOutcome {
        reference: reference.clone(),
        kind,
        observed,
        detail: detail.into(),
    }
}
fn entry(
    request: &EnrollmentRequest,
    state: &EnrollmentState,
    device: &DeviceController,
) -> Result<LocalAdminEntry> {
    let status = device.status()?;
    let node = &request.intent.controller_node;
    let known = status
        .devices
        .iter()
        .chain(&status.members)
        .find(|p| &p.node == node);
    let decision = match state {
        EnrollmentState::Pending { .. } => LocalAdminDecision::Pending,
        EnrollmentState::Active { .. } => LocalAdminDecision::Approved,
        EnrollmentState::Declined => LocalAdminDecision::Declined,
        EnrollmentState::Revoked => LocalAdminDecision::Revoked,
        EnrollmentState::Expired => LocalAdminDecision::Expired,
        EnrollmentState::Missing => anyhow::bail!("Enrollment is no longer retained"),
    };
    Ok(LocalAdminEntry {
        id: request.intent.id.clone(),
        device_name: known
            .map_or("Unrecognized member", |p| p.name.as_str())
            .into(),
        device_fingerprint: canonical_digest(&serde_json::json!({"device":node}))?,
        known_device: known.is_some(),
        permissions: request.intent.permissions.iter().copied().collect(),
        access_ends: request.intent.grant_expires_at,
        request_ends: request.intent.expires_at,
        decision,
        enrollment_digest: request.digest()?,
    })
}
async fn context(owner: &mut OwnerRuntime, device: &mut DeviceController) -> Result<ControlScope> {
    let scope = device.local_admin_scope().await?;
    owner.pairing_ready(&scope.pin)?;
    Ok(scope)
}
fn local_entry(device: &DeviceController, id: &str) -> Result<Option<LocalAdminEntry>> {
    if !device.local_admin_enabled()? {
        return Ok(None);
    }
    device
        .open_owner_requests()?
        .store
        .local_request(id, Utc::now())?
        .map(|(request, state, _)| entry(&request, &state, device))
        .transpose()
}
async fn eligible(
    device: &mut DeviceController,
    action: LocalAdminAction,
    value: &LocalAdminEntry,
) -> Result<()> {
    let expected = if action == LocalAdminAction::Revoke {
        LocalAdminDecision::Approved
    } else {
        LocalAdminDecision::Pending
    };
    ensure!(
        value.decision == expected,
        "This administrator request or permission changed; refresh before reviewing it again"
    );
    if action == LocalAdminAction::Approve {
        ensure!(
            value.known_device,
            "Identify this member in Devices before approving administration"
        );
        let (request, _, certificate) = device
            .open_owner_requests()?
            .store
            .local_request(&value.id, Utc::now())?
            .context("Enrollment is no longer waiting")?;
        device
            .verify_owner_controller(
                &certificate.context("Missing enrollment member certificate")?,
                &request.intent.controller_node,
            )
            .await?;
    }
    Ok(())
}
impl LocalAdministration {
    pub async fn view(
        &self,
        owner: &mut OwnerRuntime,
        device: &mut DeviceController,
    ) -> Result<LocalAdminView> {
        let scope = context(owner, device).await?;
        let enabled = device.local_admin_enabled()?;
        let mut pending = Vec::new();
        let mut administrators = Vec::new();
        if enabled {
            let control = device.open_owner_requests()?;
            for candidate in control.pending_locally() {
                pending.push(entry(
                    &candidate.request,
                    &EnrollmentState::Pending {
                        request: candidate.request.clone(),
                    },
                    device,
                )?);
            }
            for grant in control.grants_locally() {
                let (_, state, _) = control
                    .store
                    .local_request(&grant.enrollment.intent.id, Utc::now())?
                    .context("Missing saved enrollment")?;
                administrators.push(entry(&grant.enrollment, &state, device)?);
            }
        }
        Ok(LocalAdminView {
            scope: scope_id(&scope)?,
            network: scope.pin.network_name,
            enabled,
            pending,
            administrators,
        })
    }
    pub async fn review(
        &mut self,
        owner: &mut OwnerRuntime,
        device: &mut DeviceController,
        input: LocalAdminInput,
    ) -> Result<LocalAdminReview> {
        input.validate()?;
        let scope = context(owner, device).await?;
        let value = if let Some(id) = &input.enrollment_id {
            let value = local_entry(device, id)?.context("This request is no longer available")?;
            eligible(device, input.action, &value).await?;
            Some(value)
        } else {
            ensure!(
                !device.local_admin_enabled()?,
                "Requests are already enabled here"
            );
            None
        };
        let now = Utc::now();
        self.reviews.retain(|_, r| now < r.review.expires_at);
        ensure!(
            self.reviews.len() < 32,
            "Too many recent administrator reviews; wait for earlier reviews to expire, then refresh"
        );
        let expires_at = value.as_ref().map_or(now + Duration::seconds(120), |v| {
            std::cmp::min(
                now + Duration::seconds(120),
                if input.action == LocalAdminAction::Revoke {
                    v.access_ends
                } else {
                    v.request_ends
                },
            )
        });
        let consequence=match input.action {
            LocalAdminAction::Enable=>"Enrolled devices may ask to manage joining devices. Each administrator still needs your approval on this computer.",
            LocalAdminAction::Approve=>"This device receives exactly the listed pairing permissions until the shown expiry. Individual resource policies still apply. You can revoke these permissions here.",
            LocalAdminAction::Decline=>"This request receives no administrator permissions. The device remains a network member and may submit a new request.",
            LocalAdminAction::Revoke=>"The device loses this pairing-administration grant on its next request. Its network membership and separately granted resource access remain in place.",
        }.to_owned();
        let mut review = LocalAdminReview {
            reference: LocalAdminReference {
                review_id: uuid::Uuid::new_v4().to_string(),
                review_digest: String::new(),
                scope: scope_id(&scope)?,
                action: input.action,
                enrollment_id: input.enrollment_id,
                enrollment_digest: value.as_ref().map(|v| v.enrollment_digest.clone()),
            },
            network: scope.pin.network_name,
            device: value,
            expires_at,
            consequence,
        };
        review.reference.review_digest = canonical_digest(&serde_json::to_value(&review)?)?;
        self.reviews.insert(
            review.reference.review_id.clone(),
            StoredReview {
                review: review.clone(),
                consumed: false,
                outcome: None,
            },
        );
        Ok(review)
    }
    pub async fn commit(
        &mut self,
        owner: &mut OwnerRuntime,
        device: &mut DeviceController,
        reference: LocalAdminReference,
        presence: &mut dyn LocalAdminPresence,
    ) -> Result<LocalAdminOutcome> {
        reference.validate()?;
        let stored = self
            .reviews
            .get_mut(&reference.review_id)
            .context("Reopen the review; checking status never resends a change")?;
        ensure!(
            stored.review.reference == reference && !stored.consumed,
            "Review changed or was already submitted; check its status without resending"
        );
        stored.consumed = true;
        let review = stored.review.clone();
        let preflight = async {
            ensure!(
                scope_id(&context(owner, device).await?)? == reference.scope,
                "The network or host changed after review"
            );
            ensure!(
                Utc::now() < review.expires_at,
                "This review expired; refresh and review the current request"
            );
            if let Some(expected) = &review.device {
                let current = local_entry(device, &expected.id)?
                    .context("The reviewed enrollment is no longer available")?;
                ensure!(
                    &current == expected,
                    "The device or administrator request changed after review"
                );
                eligible(device, reference.action, &current).await?;
            } else {
                ensure!(
                    !device.local_admin_enabled()?,
                    "Requests are already enabled here"
                );
            }
            ensure!(
                presence.available(),
                "Device authentication is unavailable for administration in this build"
            );
            presence.confirm(&review)?;
            // A native prompt can take time: repeat every mutable prerequisite.
            ensure!(
                scope_id(&context(owner, device).await?)? == reference.scope
                    && Utc::now() < review.expires_at,
                "Host context or review validity changed during authentication"
            );
            if let Some(expected) = &review.device {
                let current = local_entry(device, &expected.id)?
                    .context("The reviewed enrollment is no longer available")?;
                ensure!(
                    &current == expected,
                    "The device or administrator request changed during authentication"
                );
                eligible(device, reference.action, &current).await?;
            } else {
                ensure!(
                    !device.local_admin_enabled()?,
                    "Requests became enabled during authentication; refresh their current state"
                );
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let result = if let Err(error) = preflight {
            outcome(
                &reference,
                LocalAdminOutcomeKind::Refused,
                None,
                &error.to_string(),
            )
        } else {
            let dispatch = match reference.action {
                LocalAdminAction::Enable => device.enable_owner_requests(),
                LocalAdminAction::Approve => {
                    let mut control = device.open_owner_requests()?;
                    control
                        .approve_locally(
                            device,
                            reference
                                .enrollment_id
                                .as_deref()
                                .context("Missing enrollment")?,
                            reference
                                .enrollment_digest
                                .as_deref()
                                .context("Missing reviewed digest")?,
                        )
                        .await
                        .map(|_| ())
                }
                LocalAdminAction::Decline => device.open_owner_requests()?.decline_locally(
                    reference
                        .enrollment_id
                        .as_deref()
                        .context("Missing enrollment")?,
                    reference
                        .enrollment_digest
                        .as_deref()
                        .context("Missing reviewed digest")?,
                ),
                LocalAdminAction::Revoke => device.open_owner_requests()?.revoke_locally(
                    reference
                        .enrollment_id
                        .as_deref()
                        .context("Missing enrollment")?,
                ),
            };
            if dispatch.is_err() {
                outcome(
                    &reference,
                    LocalAdminOutcomeKind::Uncertain,
                    None,
                    "The result could not be confirmed. Check status; this change will not be sent again automatically.",
                )
            } else {
                self.observe(owner, device, &reference)
                    .await
                    .unwrap_or_else(|_| {
                        outcome(
                            &reference,
                            LocalAdminOutcomeKind::Uncertain,
                            None,
                            "The change was submitted; check its current status without resending.",
                        )
                    })
            }
        };
        if let Some(stored) = self.reviews.get_mut(&reference.review_id) {
            stored.outcome = Some(result.clone());
        }
        Ok(result)
    }
    async fn observe(
        &self,
        owner: &mut OwnerRuntime,
        device: &mut DeviceController,
        reference: &LocalAdminReference,
    ) -> Result<LocalAdminOutcome> {
        reference.validate()?;
        ensure!(
            scope_id(&context(owner, device).await?)? == reference.scope,
            "This saved review belongs to another network or host"
        );
        if reference.action == LocalAdminAction::Enable {
            return Ok(if device.local_admin_enabled()? {
                outcome(
                    reference,
                    LocalAdminOutcomeKind::Confirmed,
                    None,
                    "Administrator requests are enabled on this computer.",
                )
            } else {
                outcome(
                    reference,
                    LocalAdminOutcomeKind::Uncertain,
                    None,
                    "Requests are off. The earlier change is unconfirmed; it will not be resent.",
                )
            });
        }
        let Some(value) = local_entry(
            device,
            reference
                .enrollment_id
                .as_deref()
                .context("Missing enrollment")?,
        )?
        else {
            return Ok(outcome(
                reference,
                LocalAdminOutcomeKind::Uncertain,
                None,
                "The original record is not retained. Its result cannot be confirmed; no change was resent.",
            ));
        };
        ensure!(
            Some(&value.enrollment_digest) == reference.enrollment_digest.as_ref(),
            "The saved review does not match this enrollment"
        );
        let confirmed = matches!(
            (reference.action, value.decision),
            (LocalAdminAction::Approve, LocalAdminDecision::Approved)
                | (LocalAdminAction::Decline, LocalAdminDecision::Declined)
                | (LocalAdminAction::Revoke, LocalAdminDecision::Revoked)
        );
        let kind = if confirmed {
            LocalAdminOutcomeKind::Confirmed
        } else if matches!(value.decision, LocalAdminDecision::Pending) {
            LocalAdminOutcomeKind::Uncertain
        } else {
            LocalAdminOutcomeKind::Refused
        };
        Ok(outcome(
            reference,
            kind,
            Some(value.decision),
            "Current administrator state checked. This read did not send or repeat a change.",
        ))
    }
    pub async fn check(
        &self,
        owner: &mut OwnerRuntime,
        device: &mut DeviceController,
        reference: LocalAdminReference,
    ) -> Result<LocalAdminOutcome> {
        reference.validate()?;
        ensure!(
            scope_id(&context(owner, device).await?)? == reference.scope,
            "This saved review belongs to another network or host"
        );
        if let Some(stored) = self.reviews.get(&reference.review_id) {
            ensure!(
                stored.review.reference == reference,
                "The saved review reference changed"
            );
            if let Some(result) = &stored.outcome
                && result.kind == LocalAdminOutcomeKind::Refused
            {
                return Ok(result.clone());
            }
        }
        self.observe(owner, device, &reference).await
    }
}
