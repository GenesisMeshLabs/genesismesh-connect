//! Bounded read-only renewal observations. None of these types authorizes recovery.
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InspectionStatus {
    MatchingRecordedOutcome,
    NoRecordedIssuanceObserved,
    AmbiguousOrInvalidEvidence,
    NoPendingUpdate,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InspectionReason {
    SignedExactOutcomeReference,
    NoNewCertificateInSnapshot,
    NoPendingIntent,
    SnapshotUnavailable,
    InvalidEvidence,
    ProfileBusyOrUnavailable,
    InspectionLimit,
    SnapshotChanged,
    DatabaseRequiresSettlement,
    RecordedMembershipRevoked,
    ReferencedOutcomeMissing,
    MultipleRecordedIssuances,
    LegacyIntentHasNoExactOutcomeLink,
    ReferencedOutcomeMismatch,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionBinding {
    pub instance: String,
    pub network_name: String,
    pub root_public_key: String,
    pub authority_public_key: String,
    pub operator_public_key: String,
    pub member_public_key: String,
    pub certificate_id: String,
    pub previous_certificate_id: String,
    pub operation: String,
    pub intent_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedCertificate {
    pub certificate_id: String,
    pub certificate_sha256: String,
    pub issued_at: String,
    pub expires_at: String,
    pub expired: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipInspection {
    pub schema: u8,
    pub observed_at: String,
    pub status: InspectionStatus,
    pub reason: InspectionReason,
    pub binding: Option<InspectionBinding>,
    pub outcome: Option<ObservedCertificate>,
}

fn uuid(value: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(value)?.to_string() == value,
        "Noncanonical inspection identifier"
    );
    Ok(())
}
fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Invalid inspection digest"
    );
    Ok(())
}

impl MembershipInspection {
    pub fn parse(value: serde_json::Value) -> Result<Self> {
        ensure!(
            serde_json::to_vec(&value)?.len() <= 4096,
            "Inspection report is too large"
        );
        let result: Self = serde_json::from_value(value)?;
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == 1, "Unsupported inspection report");
        let observed = DateTime::parse_from_rfc3339(&self.observed_at)?;
        if let Some(binding) = &self.binding {
            for value in [
                &binding.instance,
                &binding.certificate_id,
                &binding.previous_certificate_id,
                &binding.operation,
            ] {
                uuid(value)?;
            }
            digest(&binding.intent_sha256)?;
            ensure!(
                (1..=80).contains(&binding.network_name.chars().count())
                    && !binding.network_name.chars().any(char::is_control),
                "Invalid inspected network name"
            );
            for value in [
                &binding.root_public_key,
                &binding.authority_public_key,
                &binding.operator_public_key,
                &binding.member_public_key,
            ] {
                let bytes = STANDARD.decode(value)?;
                ensure!(
                    bytes.len() == 32 && STANDARD.encode(bytes) == *value,
                    "Invalid inspected public identity"
                );
            }
        }
        match self.status {
            InspectionStatus::MatchingRecordedOutcome => {
                ensure!(
                    self.reason == InspectionReason::SignedExactOutcomeReference
                        && self.binding.is_some(),
                    "Unbound inspection outcome"
                );
                let outcome = self
                    .outcome
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing exact inspection outcome"))?;
                uuid(&outcome.certificate_id)?;
                digest(&outcome.certificate_sha256)?;
                let issued = DateTime::parse_from_rfc3339(&outcome.issued_at)?;
                let expires = DateTime::parse_from_rfc3339(&outcome.expires_at)?;
                let binding = self.binding.as_ref().expect("binding checked above");
                ensure!(
                    issued <= observed
                        && issued < expires
                        && outcome.expired == (expires <= observed),
                    "Invalid inspected certificate time"
                );
                ensure!(
                    outcome.certificate_id != binding.previous_certificate_id
                        && (binding.certificate_id == binding.previous_certificate_id
                            || binding.certificate_id == outcome.certificate_id),
                    "Inspection outcome does not match the saved membership transition"
                );
            }
            InspectionStatus::NoRecordedIssuanceObserved => ensure!(
                self.reason == InspectionReason::NoNewCertificateInSnapshot
                    && self.binding.is_some()
                    && self.outcome.is_none(),
                "Invalid empty issuance observation"
            ),
            InspectionStatus::NoPendingUpdate => ensure!(
                self.reason == InspectionReason::NoPendingIntent
                    && self.binding.is_none()
                    && self.outcome.is_none(),
                "Invalid no-pending observation"
            ),
            InspectionStatus::AmbiguousOrInvalidEvidence => ensure!(
                self.outcome.is_none()
                    && !matches!(
                        self.reason,
                        InspectionReason::SignedExactOutcomeReference
                            | InspectionReason::NoNewCertificateInSnapshot
                            | InspectionReason::NoPendingIntent
                    ),
                "Ambiguous evidence cannot confirm an outcome"
            ),
        }
        Ok(())
    }

    /// Presentation binding only. It does not permit retry, adoption, cancellation or access.
    pub fn require_binding(
        &self,
        pin: &crate::authority::TrustPin,
        member: &str,
        instance: &str,
        operation: &str,
        intent_digest: &str,
    ) -> Result<()> {
        self.validate()?;
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Inspection has no authenticated operation binding"))?;
        ensure!(
            binding.root_public_key == pin.root_public_key
                && binding.network_name == pin.network_name
                && binding.member_public_key == member
                && binding.instance == instance
                && binding.operation == operation
                && binding.intent_sha256 == intent_digest,
            "Inspection belongs to a different network, device or update"
        );
        Ok(())
    }
}
