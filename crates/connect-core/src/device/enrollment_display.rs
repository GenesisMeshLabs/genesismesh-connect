//! Minimal read-only app projection. No signed requests, grants or keys in IPC.
use super::{DeviceController, DeviceStatus};
use crate::owner_control::{ClientEnrollmentStatus, ClientEnrollmentView, Permission};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentAvailability {
    Member,
    NetworkComputer,
    Unjoined,
    Disconnected,
    Unavailable,
}
#[derive(Debug, Serialize)]
pub struct EnrollmentDisplayEntry {
    pub request_id: String,
    pub status: ClientEnrollmentStatus,
    pub last_observed: Option<ClientEnrollmentStatus>,
    pub observed_at: Option<DateTime<Utc>>,
    pub permissions: Vec<Permission>,
    pub request_ends: DateTime<Utc>,
    pub access_ends: DateTime<Utc>,
}
#[derive(Debug, Serialize)]
pub struct EnrollmentOverview {
    pub context: String,
    pub network: String,
    pub host: String,
    pub availability: EnrollmentAvailability,
    pub attention: bool,
    pub can_check: bool,
    pub entry: Option<EnrollmentDisplayEntry>,
}
impl EnrollmentOverview {
    fn base(status: DeviceStatus) -> Result<Self> {
        let host = status
            .devices
            .iter()
            .chain(status.members.iter())
            .find(|p| Some(&p.node) == status.bridge_host_node.as_ref())
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "Your network computer".into());
        let availability = if status.disconnected {
            EnrollmentAvailability::Disconnected
        } else if status.certificate_id.is_none() {
            EnrollmentAvailability::Unjoined
        } else if status.connectivity.network_computer {
            EnrollmentAvailability::NetworkComputer
        } else if !status.authority_via_bridge {
            EnrollmentAvailability::Unavailable
        } else {
            EnrollmentAvailability::Member
        };
        Ok(Self {
            context: genesis_mesh_sdk::canonical_digest(
                &serde_json::json!({"network":status.network,"root":status.root_public_key,"host":status.bridge_host_node,"member":status.node_public_key}),
            )?,
            network: status.network,
            host,
            availability,
            attention: false,
            can_check: false,
            entry: None,
        })
    }
    fn with_entry(mut self, value: ClientEnrollmentView) -> Self {
        self.can_check = value.status != ClientEnrollmentStatus::Reviewed;
        self.entry = Some(EnrollmentDisplayEntry {
            request_id: value.request.intent.id,
            status: value.status,
            last_observed: value.last_observed,
            observed_at: value.observed_at,
            permissions: value.request.intent.permissions.into_iter().collect(),
            request_ends: value.request.intent.expires_at,
            access_ends: value.request.intent.grant_expires_at,
        });
        self
    }
}
impl DeviceController {
    /// Local saved-state inspection. No key, workflow marker or enrollment is created.
    pub fn owner_enrollment_overview(&self) -> Result<EnrollmentOverview> {
        let mut overview = EnrollmentOverview::base(self.status()?)?;
        if overview.availability != EnrollmentAvailability::Member {
            return Ok(overview);
        }
        match self.retained_owner_enrollment() {
            Ok(Some(value)) => Ok(overview.with_entry(value)),
            Ok(None) => Ok(overview),
            Err(_) => {
                overview.attention = true;
                Ok(overview)
            }
        }
    }
    /// Read the retained ID over the authenticated bridge; never enrollment/execute.
    pub async fn check_owner_enrollment_overview(&mut self) -> Result<EnrollmentOverview> {
        let overview = self.owner_enrollment_overview()?;
        ensure!(
            overview.availability == EnrollmentAvailability::Member
                && overview.can_check
                && !overview.attention,
            "This saved request cannot be checked yet; keep the existing network and device identity"
        );
        let value = self.check_owner_enrollment().await?;
        // Do not reopen the journal here: preserve the fresh observation from
        // this exact readback, rather than immediately marking it historical.
        Ok(EnrollmentOverview::base(self.status()?)?.with_entry(value))
    }
}
