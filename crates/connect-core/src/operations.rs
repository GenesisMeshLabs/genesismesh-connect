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
    #[serde(rename = "connect.access.inspect.v1")]
    InspectAccess,
    #[serde(rename = "connect.access.update.v1")]
    UpdateAccess,
}
impl OperationId {
    pub const fn as_str(self) -> &'static str {
        match self {
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

pub fn registry() -> [OperationDescriptor; 2] {
    [
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
            Self::InspectAccess(input) => input.validate()?,
            Self::UpdateAccess(input) => input.validate()?,
        }
        Ok(request)
    }
    pub fn id(&self) -> OperationId {
        match self {
            Self::InspectAccess(_) => OperationId::InspectAccess,
            Self::UpdateAccess(_) => OperationId::UpdateAccess,
        }
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
            "access_outcome":schemars::schema_for!(AccessOutcome)
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
