//! A closed registry of implemented Connect operations, not arbitrary core
//! HTTP/CLI dispatch. Schema validation never supplies actor rights or approval.
use crate::{
    access_workflow::{AccessRecord, normalize},
    owner::AccessPolicy,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum OperationId {
    #[serde(rename = "connect.history.list.v1")]
    LocalHistory,
    #[serde(rename = "connect.history.record.v1")]
    LocalRecord,
    #[serde(rename = "connect.history.export.v1")]
    ExportLocalRecord,
    #[serde(rename = "connect.resource.capabilities.v1")]
    ResourceCapabilities,
    #[serde(rename = "connect.access.inspect.v1")]
    InspectAccess,
    #[serde(rename = "connect.access.update.v1")]
    UpdateAccess,
}
impl OperationId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalHistory => "connect.history.list.v1",
            Self::LocalRecord => "connect.history.record.v1",
            Self::ExportLocalRecord => "connect.history.export.v1",
            Self::ResourceCapabilities => "connect.resource.capabilities.v1",
            Self::InspectAccess => "connect.access.inspect.v1",
            Self::UpdateAccess => crate::access_workflow::OPERATION,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationClass {
    Read,
    Write,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    None,
    ExactIntentConfirmation,
    NativeSaveDestination,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Retry {
    FreshRead,
    ReconcileNeverAutomaticallyResend,
}

#[derive(Clone, Debug, Serialize)]
pub struct OperationDescriptor {
    pub id: OperationId,
    pub title: &'static str,
    pub class: OperationClass,
    pub actor: &'static str,
    pub key_tier: &'static str,
    pub execution: &'static str,
    pub approval: Approval,
    pub retry: Retry,
    pub evidence: &'static str,
    pub input_schema: &'static str,
    pub review_schema: Option<&'static str>,
    pub commit_schema: Option<&'static str>,
    pub output_schema: &'static str,
    pub manual: bool,
    pub assisted: bool,
}

pub fn resource_operation_ids() -> [OperationId; 3] {
    [
        OperationId::ResourceCapabilities,
        OperationId::InspectAccess,
        OperationId::UpdateAccess,
    ]
}

pub fn registry() -> [OperationDescriptor; 6] {
    [
        OperationDescriptor {
            id: OperationId::LocalHistory,
            title: "View this device's access activity",
            class: OperationClass::Read,
            actor: "current_device_profile",
            key_tier: "local_profile",
            execution: "this_device",
            approval: Approval::None,
            retry: Retry::FreshRead,
            evidence: "Unsigned local workflow history, including settled archives; not authority audit evidence",
            input_schema: "#/schemas/history_query",
            review_schema: None,
            commit_schema: None,
            output_schema: "#/schemas/history_page",
            manual: true,
            assisted: false,
        },
        OperationDescriptor {
            id: OperationId::LocalRecord,
            title: "Inspect a saved local access record",
            class: OperationClass::Read,
            actor: "current_device_profile",
            key_tier: "local_profile",
            execution: "this_device",
            approval: Approval::None,
            retry: Retry::FreshRead,
            evidence: "Original local intent and observations; not an authority signature",
            input_schema: "#/schemas/local_record_query",
            review_schema: None,
            commit_schema: None,
            output_schema: "#/schemas/local_access_record",
            manual: true,
            assisted: false,
        },
        OperationDescriptor {
            id: OperationId::ExportLocalRecord,
            title: "Save a local access record",
            class: OperationClass::Write,
            actor: "current_device_profile",
            key_tier: "local_profile",
            execution: "this_device",
            approval: Approval::NativeSaveDestination,
            retry: Retry::FreshRead,
            evidence: "Local metadata export only; opening a mobile share sheet does not prove external saving",
            input_schema: "#/schemas/local_record_query",
            review_schema: None,
            commit_schema: None,
            output_schema: "#/schemas/record_export",
            manual: true,
            assisted: false,
        },
        OperationDescriptor {
            id: OperationId::ResourceCapabilities,
            title: "Check this item's available features",
            class: OperationClass::Read,
            actor: "authenticated_resource_host",
            key_tier: "member_device",
            execution: "authority_host_via_fixed_adapter",
            approval: Approval::None,
            retry: Retry::FreshRead,
            evidence: "Authenticated, current resource-scoped adapter metadata; not a grant or signed core evidence",
            input_schema: "#/schemas/resource_query",
            review_schema: None,
            commit_schema: None,
            output_schema: "#/schemas/resource_capabilities",
            manual: true,
            assisted: false,
        },
        OperationDescriptor {
            id: OperationId::InspectAccess,
            title: "Inspect this item's access",
            class: OperationClass::Read,
            actor: "authenticated_resource_host",
            key_tier: "member_device",
            execution: "authority_host_via_fixed_adapter",
            approval: Approval::None,
            retry: Retry::FreshRead,
            evidence: "Current authority state; not signed audit evidence",
            input_schema: "#/schemas/resource_query",
            review_schema: None,
            commit_schema: None,
            output_schema: "#/schemas/access_policy",
            manual: true,
            assisted: false,
        },
        OperationDescriptor {
            id: OperationId::UpdateAccess,
            title: "Change this item's access",
            class: OperationClass::Write,
            actor: "authenticated_resource_host",
            key_tier: "member_device",
            execution: "authority_host_via_fixed_adapter",
            approval: Approval::ExactIntentConfirmation,
            retry: Retry::ReconcileNeverAutomaticallyResend,
            evidence: "Core reply and independent state readback tracked separately; no mutation attribution after a lost reply",
            input_schema: "#/schemas/access_review_input",
            review_schema: Some("#/schemas/access_review"),
            commit_schema: Some("#/schemas/access_commit_input"),
            output_schema: "#/schemas/access_outcome",
            manual: true,
            assisted: false,
        },
    ]
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceQuery {
    #[cfg_attr(feature = "operation-schemas", schemars(with = "uuid::Uuid"))]
    pub collection: String,
}
impl ResourceQuery {
    pub fn validate(&self) -> Result<()> {
        uuid::Uuid::parse_str(&self.collection)?;
        Ok(())
    }
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessReviewInput {
    #[cfg_attr(feature = "operation-schemas", schemars(with = "uuid::Uuid"))]
    pub collection: String,
    pub settings: AccessPolicy,
}
impl AccessReviewInput {
    pub fn validate(&self) -> Result<()> {
        uuid::Uuid::parse_str(&self.collection)?;
        normalize(self.settings.clone(), Some(chrono::Utc::now()))?;
        Ok(())
    }
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessCommitInput {
    #[cfg_attr(feature = "operation-schemas", schemars(with = "uuid::Uuid"))]
    pub id: String,
    #[cfg_attr(
        feature = "operation-schemas",
        schemars(regex(pattern = "^[0-9a-f]{64}$"))
    )]
    pub digest: String,
}
impl AccessCommitInput {
    pub fn validate(&self) -> Result<()> {
        uuid::Uuid::parse_str(&self.id)?;
        ensure!(
            self.digest.len() == 64
                && self
                    .digest
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "Invalid exact-intent digest"
        );
        Ok(())
    }
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", content = "input", deny_unknown_fields)]
pub enum OperationRequest {
    #[serde(rename = "connect.history.list.v1")]
    LocalHistory(crate::access_workflow::history::HistoryQuery),
    #[serde(rename = "connect.history.record.v1")]
    LocalRecord(crate::access_workflow::history::LocalRecordQuery),
    #[serde(rename = "connect.history.export.v1")]
    ExportLocalRecord(crate::access_workflow::history::LocalRecordQuery),
    #[serde(rename = "connect.resource.capabilities.v1")]
    ResourceCapabilities(ResourceQuery),
    #[serde(rename = "connect.access.inspect.v1")]
    InspectAccess(ResourceQuery),
    #[serde(rename = "connect.access.update.v1")]
    UpdateAccess(AccessReviewInput),
}
impl OperationRequest {
    pub fn parse(text: &str) -> Result<Self> {
        ensure!(text.len() <= 24 * 1024, "Operation request is too large");
        let request: Self = serde_json::from_value(genesis_mesh_sdk::parse_strict_json(text)?)?;
        match &request {
            Self::LocalHistory(input) => input.validate()?,
            Self::LocalRecord(input) | Self::ExportLocalRecord(input) => input.validate()?,
            Self::ResourceCapabilities(input) => input.validate()?,
            Self::InspectAccess(input) => input.validate()?,
            Self::UpdateAccess(input) => input.validate()?,
        }
        Ok(request)
    }
    pub fn id(&self) -> OperationId {
        match self {
            Self::LocalHistory(_) => OperationId::LocalHistory,
            Self::LocalRecord(_) => OperationId::LocalRecord,
            Self::ExportLocalRecord(_) => OperationId::ExportLocalRecord,
            Self::ResourceCapabilities(_) => OperationId::ResourceCapabilities,
            Self::InspectAccess(_) => OperationId::InspectAccess,
            Self::UpdateAccess(_) => OperationId::UpdateAccess,
        }
    }
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceProfile {
    ConnectManaged,
    ConnectRestricted,
    ExternalUnverified,
}

/// A fresh authenticated snapshot for one resource host. It is NOT a bearer
/// capability: every mutation rechecks it and still needs core authorization.
#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCapabilities {
    pub schema: u8,
    pub pin: crate::authority::TrustPin,
    pub actor: String,
    pub collection: String,
    pub core_version: Option<String>,
    pub profile: ResourceProfile,
    pub policy_version: u64,
    pub operations: Vec<OperationId>,
}
impl ResourceCapabilities {
    pub fn require(
        &self,
        pin: &crate::authority::TrustPin,
        actor: &str,
        collection: &str,
        operation: OperationId,
    ) -> Result<()> {
        ensure!(
            self.schema == 1,
            "Update Connect on the network computer to check this feature"
        );
        ensure!(
            &self.pin == pin && self.actor == actor && self.collection == collection,
            "Resource prerequisites answered for a different network, device or item"
        );
        ensure!(
            self.policy_version > 0 && self.policy_version < (1 << 53),
            "Invalid resource policy version"
        );
        if self.profile != ResourceProfile::ExternalUnverified {
            ensure!(
                self.core_version.as_deref() == Some(crate::owner::required_core_version()?),
                "Update Connect on the network computer: incompatible Genesis Mesh release"
            );
        }
        if operation == OperationId::UpdateAccess {
            ensure!(
                self.profile == ResourceProfile::ConnectManaged,
                "Access is read-only here: the authority deployment and policy enforcement must be verified on the network computer"
            );
        }
        ensure!(
            self.operations.len() <= resource_operation_ids().len()
                && self
                    .operations
                    .iter()
                    .all(|id| resource_operation_ids().contains(id))
                && self
                    .operations
                    .iter()
                    .enumerate()
                    .all(|(i, id)| !self.operations[..i].contains(id))
                && self
                    .operations
                    .iter()
                    .filter(|id| **id == operation)
                    .count()
                    == 1,
            "This network computer has not enabled this operation for this resource"
        );
        Ok(())
    }
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessOutcome {
    pub record: AccessRecord,
    pub local_applied: bool,
    pub problem: Option<String>,
}

#[cfg(feature = "operation-schemas")]
pub mod schemas {
    use super::*;
    use serde_json::{Value, json};

    /// Structural shapes come from the same types as IPC and journal records.
    /// Cross-field identity/time/version/permission rules remain native/core checks.
    pub fn contract() -> Value {
        json!({"schema_version":1,"scope":"Implemented Connect resource operations; not full public-core parity or authorization",
        "semantic_validation":"Native intent/context/version/time checks and core ownership/gate validation are mandatory. Shapes alone do not authorize actions.",
        "operations": registry(),
        "schemas": {
            "request":schemars::schema_for!(OperationRequest),
            "resource_query":schemars::schema_for!(ResourceQuery),
            "access_review_input":schemars::schema_for!(AccessReviewInput),
            "access_commit_input":schemars::schema_for!(AccessCommitInput),
            "access_policy":schemars::schema_for!(AccessPolicy),
            "access_review":schemars::schema_for!(AccessRecord),
            "access_outcome":schemars::schema_for!(AccessOutcome),
            "resource_capabilities":schemars::schema_for!(ResourceCapabilities),
            "history_query":schemars::schema_for!(crate::access_workflow::history::HistoryQuery),
            "history_page":schemars::schema_for!(crate::access_workflow::history::HistoryPage),
            "local_record_query":schemars::schema_for!(crate::access_workflow::history::LocalRecordQuery),
            "local_access_record":schemars::schema_for!(crate::access_workflow::history::LocalAccessRecord),
            "record_export":schemars::schema_for!(crate::access_workflow::history::RecordExport)
        }})
    }
    fn sorted(value: Value) -> Value {
        match value {
            Value::Object(object) => Value::Object(
                object
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(array) => Value::Array(array.into_iter().map(sorted).collect()),
            other => other,
        }
    }
    pub fn document() -> Result<String> {
        Ok(serde_json::to_string_pretty(&sorted(contract()))? + "\n")
    }
}
