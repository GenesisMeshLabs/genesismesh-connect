use super::{EnrollmentRequest, Grant, OwnerCommand, PairingTarget};
use serde::{Deserialize, Serialize};

/// Fixed, versioned operations. Session identity is supplied by the transport,
/// never read from this envelope as authentication or local owner approval.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlExchange {
    Enroll { request: EnrollmentRequest },
    EnrollmentStatus { id: String },
    Execute { command: OwnerCommand },
    Result { nonce: String, digest: String },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEnvelope {
    pub version: u8,
    pub request: ControlExchange,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollmentState {
    Pending { request: EnrollmentRequest },
    Active { grant: Grant },
    Declined,
    Expired,
    Revoked,
    Missing,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlResult {
    PairingList { request: Option<PairingTarget> },
    Started,
    Approved { node: String },
    Rejected { node: String },
    Unconfirmed,
}
impl ControlResult {
    pub(crate) fn validate_for(&self, action: &super::OwnerAction) -> anyhow::Result<()> {
        use super::OwnerAction;
        match (action, self) {
            (OwnerAction::ListPairing, Self::PairingList { request }) => {
                if let Some(target) = request {
                    target.validate()?;
                }
            }
            (OwnerAction::ApprovePairing(t), Self::Approved { node })
            | (OwnerAction::RejectPairing(t), Self::Rejected { node }) => {
                anyhow::ensure!(&t.node == node, "Result names a different device")
            }
            (_, Self::Started | Self::Unconfirmed) => {}
            _ => anyhow::bail!("Result does not match the reserved operation"),
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ControlReply {
    Enrollment(EnrollmentState),
    Result(ControlResult),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingEnrollment {
    pub request: EnrollmentRequest,
    pub certificate: serde_json::Value,
    pub declined: bool,
}
