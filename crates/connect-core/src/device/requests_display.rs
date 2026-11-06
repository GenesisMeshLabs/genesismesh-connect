//! Read-only app projection of the native pairing command. No signing or keys in IPC.
use super::DeviceController;
use crate::owner_control::{
    CLIENT_COMMAND_FILE, ClientCommandStatus, ClientCommandView, ClientCommands, CommandBinding,
    ControlResult, OwnerAction, Permission,
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::Serialize;
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestsAvailability {
    Member,
    Unavailable,
    Unjoined,
    AuthorityHost,
    Disconnected,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestResultKind {
    QueueSnapshot,
    Approved,
    Rejected,
    InProgress,
    Unconfirmed,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RequestResult {
    pub state: RequestResultKind,
    pub waiting_name: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct RequestCandidate {
    pub name: String,
    pub comparison_code: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct RequestDisplayEntry {
    pub nonce: String,
    pub digest: String,
    pub operation: Permission,
    pub candidate: Option<RequestCandidate>,
    pub status: ClientCommandStatus,
    pub current_result: Option<RequestResult>,
    pub last_result: Option<RequestResult>,
    pub observed_at: Option<DateTime<Utc>>,
    pub retained_result: Option<RequestResult>,
    pub retained_at: Option<DateTime<Utc>>,
    pub review_ends: DateTime<Utc>,
    pub access_ends: DateTime<Utc>,
}
#[derive(Debug, Serialize)]
pub struct PairingRequestsOverview {
    pub context: String,
    pub network: String,
    pub host: String,
    pub availability: RequestsAvailability,
    pub attention: bool,
    pub can_check: bool,
    pub entry: Option<RequestDisplayEntry>,
}
fn result(action: &OwnerAction, value: ControlResult) -> Result<RequestResult> {
    value.validate_for(action)?;
    Ok(match value {
        ControlResult::PairingList { request } => RequestResult {
            state: RequestResultKind::QueueSnapshot,
            waiting_name: request.map(|r| r.name),
        },
        ControlResult::Approved { .. } => RequestResult {
            state: RequestResultKind::Approved,
            waiting_name: None,
        },
        ControlResult::Rejected { .. } => RequestResult {
            state: RequestResultKind::Rejected,
            waiting_name: None,
        },
        ControlResult::Started => RequestResult {
            state: RequestResultKind::InProgress,
            waiting_name: None,
        },
        ControlResult::Unconfirmed => RequestResult {
            state: RequestResultKind::Unconfirmed,
            waiting_name: None,
        },
    })
}
fn entry(value: ClientCommandView) -> Result<RequestDisplayEntry> {
    let terminal = |r: &ControlResult| {
        matches!(
            r,
            ControlResult::Approved { .. }
                | ControlResult::Rejected { .. }
                | ControlResult::PairingList { .. }
        )
    };
    ensure!(
        (value.status != ClientCommandStatus::Observed
            || (value.current_observation.as_ref().is_some_and(terminal)
                && value.current_observation == value.retained_outcome
                && value.observed_at.is_some()))
            && (value.status != ClientCommandStatus::Reviewed
                || (value.current_observation.is_none()
                    && value.last_observed.is_none()
                    && value.retained_outcome.is_none()))
            && (value.status != ClientCommandStatus::Uncertain
                || value
                    .current_observation
                    .as_ref()
                    .is_none_or(|r| !terminal(r))),
        "Inconsistent saved request observation"
    );
    let candidate = match &value.action {
        OwnerAction::ListPairing => None,
        OwnerAction::ApprovePairing(t) | OwnerAction::RejectPairing(t) => {
            t.validate()?;
            Some(RequestCandidate {
                name: t.name.clone(),
                comparison_code: t.comparison_code.clone(),
            })
        }
    };
    let map = |v: Option<ControlResult>| v.map(|v| result(&value.action, v)).transpose();
    Ok(RequestDisplayEntry {
        nonce: value.nonce,
        digest: value.digest,
        operation: value.action.permission(),
        candidate,
        status: value.status,
        current_result: map(value.current_observation)?,
        last_result: map(value.last_observed)?,
        observed_at: value.observed_at,
        retained_result: map(value.retained_outcome)?,
        retained_at: value.retained_at,
        review_ends: value.command_expires_at,
        access_ends: value.grant_expires_at,
    })
}
impl DeviceController {
    fn requests_base(&self) -> Result<PairingRequestsOverview> {
        let status = self.status()?;
        let host = status
            .devices
            .iter()
            .chain(&status.members)
            .find(|p| Some(&p.node) == status.bridge_host_node.as_ref())
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "Your network host".into());
        let availability = if !cfg!(feature = "owner-requests-qualification") {
            RequestsAvailability::Unavailable
        } else if status.disconnected {
            RequestsAvailability::Disconnected
        } else if status.certificate_id.is_none() {
            RequestsAvailability::Unjoined
        } else if status.connectivity.network_computer {
            RequestsAvailability::AuthorityHost
        } else if !status.authority_via_bridge {
            RequestsAvailability::Unavailable
        } else {
            RequestsAvailability::Member
        };
        Ok(PairingRequestsOverview {
            context: genesis_mesh_sdk::canonical_digest(
                &serde_json::json!({"profile":self.vault.storage_id(),"network":status.network,"root":status.root_public_key,"host":status.bridge_host_node,"member":status.node_public_key}),
            )?,
            network: status.network,
            host,
            availability,
            attention: false,
            can_check: false,
            entry: None,
        })
    }
    fn requests_context(&self) -> Result<String> {
        Ok(genesis_mesh_sdk::canonical_digest(&serde_json::to_value(
            CommandBinding {
                profile_id: self.vault.storage_id().into(),
                enrollment: self.enrollment_binding()?,
            },
        )?)?)
    }
    /// Never creates an administrative key, command, request or empty journal.
    pub fn owner_requests_overview(&self) -> Result<PairingRequestsOverview> {
        let mut view = self.requests_base()?;
        if view.availability != RequestsAvailability::Member {
            return Ok(view);
        }
        let outcome = (|| -> Result<Option<RequestDisplayEntry>> {
            if !ClientCommands::initialized(&self.state_directory.join(CLIENT_COMMAND_FILE))? {
                return Ok(None);
            }
            let value = entry(self.saved_owner_action()?)?;
            view.context = self.requests_context()?;
            Ok(Some(value))
        })();
        match outcome {
            Ok(value) => {
                view.can_check = value.as_ref().is_some_and(|v| {
                    matches!(
                        v.status,
                        ClientCommandStatus::Uncertain | ClientCommandStatus::Observed
                    )
                });
                view.entry = value;
            }
            Err(_) => view.attention = true,
        }
        Ok(view)
    }
    /// The only remote operation is the coordinator's original Result readback
    /// and its fixed current-grant checks. No caller identity/reference overrides.
    pub async fn check_owner_requests_overview(&mut self) -> Result<PairingRequestsOverview> {
        let expected = self.owner_requests_overview()?;
        ensure!(
            expected.availability == RequestsAvailability::Member
                && expected.can_check
                && !expected.attention,
            "This saved device request cannot be checked yet"
        );
        let reference = expected.entry.as_ref().expect("checkable request");
        let value = entry(self.check_owner_action().await?)?;
        let mut view = self.requests_base()?;
        view.context = self.requests_context()?;
        ensure!(
            view.availability == RequestsAvailability::Member
                && view.context == expected.context
                && value.nonce == reference.nonce
                && value.digest == reference.digest
                && value.operation == reference.operation,
            "Native network or original device request changed during readback"
        );
        view.can_check = matches!(
            value.status,
            ClientCommandStatus::Uncertain | ClientCommandStatus::Observed
        );
        view.entry = Some(value);
        Ok(view)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner_control::PairingTarget;
    fn view() -> ClientCommandView {
        let now = Utc::now();
        let target = PairingTarget {
            request_id: uuid::Uuid::new_v4().to_string(),
            node: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                ed25519_dalek::SigningKey::from_bytes(&[2; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            name: "Living room tablet".into(),
            comparison_code: "123456".into(),
        };
        ClientCommandView {
            nonce: uuid::Uuid::new_v4().to_string(),
            digest: "a".repeat(64),
            action: OwnerAction::ApprovePairing(target),
            network: "Home".into(),
            command_expires_at: now,
            grant_expires_at: now,
            status: ClientCommandStatus::Uncertain,
            current_observation: None,
            last_observed: None,
            observed_at: None,
            retained_outcome: None,
            retained_at: None,
        }
    }
    #[test]
    fn projection_separates_current_confirmation_history_and_unknown_without_keys_or_signed_commands()
    -> Result<()> {
        let mut source = view();
        let OwnerAction::ApprovePairing(target) = &source.action else {
            unreachable!()
        };
        let approved = ControlResult::Approved {
            node: target.node.clone(),
        };
        source.retained_outcome = Some(approved.clone());
        source.last_observed = Some(approved.clone());
        source.observed_at = Some(Utc::now());
        source.retained_at = source.observed_at;
        let history = entry(source.clone())?;
        assert!(history.current_result.is_none());
        assert_eq!(
            history.retained_result.as_ref().unwrap().state,
            RequestResultKind::Approved
        );
        let wire = serde_json::to_string(&history)?;
        for secret in [
            "host_node",
            "root_public_key",
            "administrative_key",
            "signature",
            "grant_id",
            "intent",
        ] {
            assert!(!wire.contains(secret));
        }
        source.status = ClientCommandStatus::Observed;
        source.current_observation = Some(approved);
        assert_eq!(
            entry(source)?.current_result.unwrap().state,
            RequestResultKind::Approved
        );
        Ok(())
    }
    #[test]
    fn wrong_target_or_inconsistent_success_cannot_be_projected() -> Result<()> {
        let mut source = view();
        source.status = ClientCommandStatus::Observed;
        assert!(entry(source.clone()).is_err());
        source.current_observation = Some(ControlResult::Approved {
            node: "other".into(),
        });
        assert!(entry(source.clone()).is_err());
        source.current_observation = Some(ControlResult::Unconfirmed);
        assert!(entry(source).is_err());
        let mut source = view();
        source.status = ClientCommandStatus::Reviewed;
        source.retained_outcome = Some(ControlResult::Unconfirmed);
        assert!(entry(source).is_err());
        Ok(())
    }
    #[test]
    fn a_list_observation_is_an_original_queue_snapshot_not_a_device_approval() -> Result<()> {
        let mut source = view();
        source.action = OwnerAction::ListPairing;
        source.status = ClientCommandStatus::Observed;
        source.current_observation = Some(ControlResult::PairingList { request: None });
        source.retained_outcome = source.current_observation.clone();
        source.last_observed = source.current_observation.clone();
        source.observed_at = Some(Utc::now());
        source.retained_at = source.observed_at;
        let projected = entry(source)?;
        assert!(projected.candidate.is_none());
        assert_eq!(
            projected.current_result.unwrap().state,
            RequestResultKind::QueueSnapshot
        );
        Ok(())
    }
}
