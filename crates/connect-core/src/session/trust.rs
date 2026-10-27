use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use genesis_mesh_sdk::{
    key_history::{NaKeyHistory, verify_key_history, vouching_grace},
    verify::{verify_crl, verify_join_certificate},
};
use serde_json::Value;

/// Supplied locally, never learned from a connecting peer. The authority module
/// persists sequence watermarks before publishing a refreshed snapshot.
#[derive(Clone)]
pub struct TrustPolicy {
    pub root_public_key: String,
    pub network_name: String,
    pub minimum_crl_sequence: u64,
    pub minimum_key_sequence: i64,
    pub max_age: Duration,
    pub vouching_grace_seconds: i64,
}

/// Immutable, locally provisioned trust for a short diagnostic session.
/// A fresh receipt alone cannot make an old signed CRL fresh.
#[derive(Clone)]
pub struct TrustSnapshot {
    policy: TrustPolicy,
    history: NaKeyHistory,
    crl: Value,
    observed_at: DateTime<Utc>,
    loaded_at: Instant,
    recent_certificate: bool,
}

/// Devices and the network computer keep separate clocks, so a record the
/// authority signed a moment ago can carry a time ahead of this device's
/// clock. Where a record starts, allow as much as core and the bridge's
/// request check allow. Expiry and age limits stay exact: a device whose
/// clock runs minutes ahead of the network computer still fails.
pub(crate) const CLOCK_SKEW: chrono::Duration = chrono::Duration::seconds(300);

pub(super) fn timestamp(record: &Value, field: &str) -> Result<DateTime<Utc>> {
    Ok(
        DateTime::parse_from_rfc3339(record[field].as_str().context("Missing trust timestamp")?)?
            .with_timezone(&Utc),
    )
}

impl TrustSnapshot {
    pub(crate) fn audience(&self) -> Result<String> {
        self.history
            .keys_at(Utc::now().timestamp_micros())
            .into_iter()
            .next()
            .context("No current authority key")
    }

    pub(crate) fn read_decision(
        &self,
        decision: &Value,
        attestation: &Value,
        context_id: &str,
        policy_id: &str,
        host: &str,
    ) -> Result<()> {
        use genesis_mesh_sdk::verify::{
            VerifyDecisionOptions, VerifyRecordOptions, verify_boundary_decision,
            verify_record_for_present,
        };
        let now = Utc::now();
        self.check_fresh(now)?;
        let check = verify_record_for_present(
            "attestation",
            attestation,
            &VerifyRecordOptions {
                key_history: Some(self.history.clone()),
                ..Default::default()
            },
            now,
            0,
        );
        ensure!(check.verified, "Untrusted read attestation");
        ensure!(
            attestation["subject_public_key"] == host
                && attestation["issuer_sovereign_id"] == self.network(),
            "Wrong sharing identity"
        );
        ensure!(
            timestamp(attestation, "valid_from")? <= now + CLOCK_SKEW
                && now < timestamp(attestation, "expires_at")?,
            "Sharing attestation expired"
        );
        let check = verify_boundary_decision(
            decision,
            &VerifyDecisionOptions {
                key_history: Some(self.history.clone()),
                expected_attestation: Some(attestation.clone()),
                now: Some(now),
                ..Default::default()
            },
        );
        ensure!(
            check.accepted && check.authorized,
            "Read denied by authority"
        );
        ensure!(
            decision["context_id"] == context_id
                && decision["operator_sovereign_id"] == self.network(),
            "Decision does not bind this read"
        );
        let made = timestamp(decision, "decision_made_at")?;
        // Made for this read moments ago, as closely as two clocks can tell;
        // the per-read nonce in the context, not this window, stops replay.
        ensure!(
            made <= now + CLOCK_SKEW
                && now - made < chrono::Duration::seconds(5) + CLOCK_SKEW
                && now < timestamp(decision, "decision_valid_until")?,
            "Read decision stale"
        );
        let binding = &decision["policy_binding"];
        ensure!(
            binding["resolution_status"] == "resolved"
                && binding["policies"]
                    .as_array()
                    .is_some_and(|p| p.iter().any(|p| p["policy_id"] == policy_id)),
            "Required sharing policy not applied"
        );
        Ok(())
    }
    /// Verify the genesis/succession chain against an explicit root pin, then
    /// verify the CRL. `observed_at` is a trusted local fetch/provisioning time.
    pub fn from_records(
        policy: TrustPolicy,
        genesis: &Value,
        successions: &[Value],
        crl: Value,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::build(policy, genesis, successions, crl, observed_at, false)
    }

    pub(crate) fn for_renewed_devices(
        policy: TrustPolicy,
        genesis: &Value,
        successions: &[Value],
        crl: Value,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::build(policy, genesis, successions, crl, observed_at, true)
    }

    fn build(
        policy: TrustPolicy,
        genesis: &Value,
        successions: &[Value],
        crl: Value,
        observed_at: DateTime<Utc>,
        recent_certificate: bool,
    ) -> Result<Self> {
        ensure!(
            !policy.max_age.is_zero() && policy.max_age <= Duration::from_secs(300),
            "Trust age must be between zero and 300 seconds"
        );
        ensure!(policy.minimum_key_sequence >= 1, "Missing key sequence pin");
        let checked = verify_key_history(genesis, successions, Some(&policy.root_public_key));
        ensure!(
            checked.verified,
            "Untrusted authority key history: {}",
            checked
                .failures
                .first()
                .map(|failure| failure.reason.as_str())
                .unwrap_or("missing history")
        );
        let history = checked.history.context("Missing verified key history")?;
        ensure!(history.sovereign_id == policy.network_name, "Wrong network");
        ensure!(
            history
                .keys
                .last()
                .is_some_and(|key| key.key_sequence >= policy.minimum_key_sequence),
            "Key history rollback"
        );
        ensure!(
            crl["sequence"]
                .as_u64()
                .is_some_and(|seq| seq >= policy.minimum_crl_sequence),
            "CRL rollback"
        );
        ensure!(
            crl["revoked_certificates"]
                .as_array()
                .is_some_and(|entries| entries.iter().all(|entry| entry["certificate_id"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty()))),
            "Malformed revocations"
        );
        let snapshot = Self {
            policy,
            history,
            crl,
            observed_at,
            loaded_at: Instant::now(),
            recent_certificate,
        };
        snapshot.check_fresh(Utc::now())?;
        Ok(snapshot)
    }

    pub(super) fn network(&self) -> &str {
        &self.policy.network_name
    }
    pub(super) fn root(&self) -> &str {
        &self.policy.root_public_key
    }

    fn keys_for(&self, record: &Value, now: DateTime<Utc>) -> Result<Vec<String>> {
        Ok(self.history.keys_vouching_at(
            timestamp(record, "issued_at")?.timestamp_micros(),
            now.timestamp_micros(),
            vouching_grace(Some(self.policy.vouching_grace_seconds)),
        ))
    }

    pub(super) fn check_fresh(&self, now: DateTime<Utc>) -> Result<()> {
        let issued = timestamp(&self.crl, "issued_at")?;
        let next = timestamp(&self.crl, "next_update")?;
        let age = chrono::Duration::from_std(self.policy.max_age)?;
        ensure!(
            self.loaded_at.elapsed() < self.policy.max_age,
            "Trust snapshot stale"
        );
        ensure!(
            self.observed_at <= now && now - self.observed_at < age,
            "Trust snapshot stale or future dated"
        );
        let crl_age = if self.recent_certificate {
            chrono::Duration::hours(24)
        } else {
            age
        };
        ensure!(
            issued <= now + CLOCK_SKEW
                && now - issued < crl_age
                && now < next
                && next - issued <= chrono::Duration::hours(24),
            "CRL stale or future dated"
        );
        ensure!(
            verify_crl(&self.crl, &self.keys_for(&self.crl, now)?),
            "Untrusted CRL or authority horizon expired"
        );
        Ok(())
    }

    pub(crate) fn certificate(
        &self,
        cert: &Value,
        expected_node: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.renewable_certificate(cert, expected_node, now)?;
        if self.recent_certificate {
            ensure!(
                now - timestamp(cert, "issued_at")? < chrono::Duration::seconds(300),
                "Certificate needs renewal before a session"
            );
        }
        Ok(())
    }

    pub(crate) fn renewable_certificate(
        &self,
        cert: &Value,
        expected_node: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.check_fresh(now)?;
        ensure!(
            verify_join_certificate(cert, &self.keys_for(cert, now)?),
            "Untrusted certificate or authority horizon expired"
        );
        ensure!(
            cert["network_name"] == self.network(),
            "Wrong certificate network"
        );
        ensure!(
            cert["node_public_key"] == expected_node,
            "Unexpected node key"
        );
        let issued = timestamp(cert, "issued_at")?;
        let expires = timestamp(cert, "expires_at")?;
        // Stricter than core at expiry, which core extends by the skew.
        ensure!(
            issued <= now + CLOCK_SKEW && now < expires,
            "Certificate expired or not yet valid"
        );
        let id = cert["cert_id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .context("Missing certificate ID")?;
        ensure!(
            !self.crl["revoked_certificates"]
                .as_array()
                .context("Missing CRL entries")?
                .iter()
                .any(|entry| entry["certificate_id"] == id),
            "Certificate revoked"
        );
        Ok(())
    }
}
