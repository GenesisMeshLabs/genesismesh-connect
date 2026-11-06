//! Qualification-only recovery of an observed original pairing, never enrollment.
use crate::{authority::TrustPin, owner_control::PairingTarget};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use genesis_mesh_sdk::{canonical_digest, canonical_json, sign_canonical, verify_canonical};
use serde::{Deserialize, Serialize};

pub(crate) fn qualified() -> Result<()> {
    ensure!(
        cfg!(feature = "pairing-completion-recovery"),
        "Pairing recovery is not enabled in this build"
    );
    Ok(())
}

/// Host proof of one exact reviewed ceremony. This is not an authorization grant
/// or evidence of completion: the host must also retain its committed relationship.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompletionReference {
    version: u8,
    pub(crate) pin: TrustPin,
    pub(crate) host: String,
    pub(crate) target: PairingTarget,
    pub(crate) host_endpoint: String,
    signature: String,
}
impl CompletionReference {
    pub(crate) fn issue(
        pin: TrustPin,
        target: PairingTarget,
        ticket: &str,
        key: &SigningKey,
    ) -> Result<Self> {
        qualified()?;
        let mut value = Self {
            version: 1,
            pin,
            host: STANDARD.encode(key.verifying_key().to_bytes()),
            target,
            host_endpoint: crate::session::ticket_endpoint(ticket)?.to_string(),
            signature: String::new(),
        };
        value.signature =
            sign_canonical(&value.payload()?, "connect-pairing-completion", key)["sig"]
                .as_str()
                .context("Missing pairing proof")?
                .into();
        value.check()?;
        Ok(value)
    }
    fn payload(&self) -> Result<String> {
        Ok(canonical_json(
            &serde_json::json!({"domain":"connect-pairing-completion-v1", "version":self.version,
            "pin":self.pin,"host":self.host,"target":self.target,"host_endpoint":self.host_endpoint}),
        )?)
    }
    pub(crate) fn check(&self) -> Result<()> {
        ensure!(
            serde_json::to_vec(self)?.len() <= 4096 && self.version == 1,
            "Unsupported pairing reference"
        );
        let id = uuid::Uuid::parse_str(&self.target.request_id)?;
        ensure!(
            !id.is_nil() && id.to_string() == self.target.request_id,
            "Invalid original pairing identity"
        );
        crate::session::pairing::valid_name(&self.target.name)?;
        ensure!(
            self.target.comparison_code.len() == 6
                && self
                    .target
                    .comparison_code
                    .bytes()
                    .all(|b| b.is_ascii_digit()),
            "Invalid original pairing code"
        );
        for key in [&self.host, &self.target.node, &self.pin.root_public_key] {
            ensure!(
                STANDARD
                    .decode(key)
                    .is_ok_and(|b| b.len() == 32 && STANDARD.encode(b) == *key),
                "Invalid pairing identity"
            );
        }
        let _: iroh::EndpointId = self.host_endpoint.parse()?;
        ensure!(
            self.host != self.target.node
                && self.signature.len() <= 128
                && verify_canonical(&self.payload()?, &self.signature, &[self.host.clone()]),
            "Invalid original pairing proof"
        );
        Ok(())
    }
    pub(crate) fn digest(&self) -> Result<String> {
        self.check()?;
        Ok(canonical_digest(&serde_json::to_value(self)?)?)
    }
    pub(crate) fn require_scope(&self, pin: &TrustPin, host: &str, device: &str) -> Result<()> {
        self.check()?;
        ensure!(
            &self.pin == pin && self.host == host && self.target.node == device,
            "Pairing reference belongs to another relationship"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostCompletion {
    pub reference: CompletionReference,
    /// None is a reserved approval whose original relationship was not committed.
    pub member_endpoint: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientCompletion {
    pub reference: CompletionReference,
    pub host_name: String,
    pub finished: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionQuery {
    pub reference: CompletionReference,
    pub nonce: String,
}
impl CompletionQuery {
    pub(crate) fn check(&self) -> Result<()> {
        self.reference.check()?;
        let id = uuid::Uuid::parse_str(&self.nonce)?;
        ensure!(
            !id.is_nil() && id.to_string() == self.nonce,
            "Invalid completion challenge"
        );
        Ok(())
    }
}
/// An answer on the authenticated bridge. Never accepted as an offline permission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionAnswer {
    pub(crate) digest: String,
    pub(crate) nonce: String,
    pub(crate) host_ticket: String,
    pub(crate) member_endpoint: String,
    pub(crate) host_certificate: serde_json::Value,
}
impl CompletionAnswer {
    pub(crate) fn check(&self, query: &CompletionQuery) -> Result<()> {
        query.check()?;
        ensure!(
            self.digest == query.reference.digest()?
                && self.nonce == query.nonce
                && crate::session::ticket_endpoint(&self.host_ticket)?.to_string()
                    == query.reference.host_endpoint,
            "Completion answer does not match the original pairing challenge"
        );
        let _: iroh::EndpointId = self.member_endpoint.parse()?;
        Ok(())
    }
}

impl super::DeviceController {
    /// Fixed native host readback, called only with identity from the existing
    /// mutually authenticated bridge. It cannot create or complete a relationship.
    pub async fn answer_pairing_completion(
        &mut self,
        node: &str,
        certificate: &serde_json::Value,
        query: CompletionQuery,
    ) -> Result<CompletionAnswer> {
        qualified()?;
        query.check()?;
        let own = self.status()?.node_public_key;
        query
            .reference
            .require_scope(self.vault.pin(), &own, node)?;
        let trust = self.current_owner_trust().await?;
        trust.certificate(certificate, node, chrono::Utc::now())?;
        let digest = query.reference.digest()?;
        let retained = self.vault.host_completion(&digest)?;
        ensure!(
            retained.reference == query.reference,
            "Original pairing evidence conflicts"
        );
        let member_endpoint = retained
            .member_endpoint
            .clone()
            .context("Original pairing was not committed; approval remains uncertain")?;
        self.vault.require_completion_binding(node, &digest)?;
        let peer = self
            .vault
            .peers()
            .iter()
            .find(|p| p.node == node)
            .context("Original paired device was removed")?;
        ensure!(
            crate::session::ticket_endpoint(&peer.ticket)?.to_string() == member_endpoint,
            "Original paired endpoint changed"
        );
        let answer = CompletionAnswer {
            digest,
            nonce: query.nonce.clone(),
            host_ticket: self.session()?.ticket()?,
            member_endpoint,
            host_certificate: self
                .device
                .as_ref()
                .context("Enroll the host first")?
                .certificate()
                .clone(),
        };
        answer.check(&query)?;
        Ok(answer)
    }
    async fn checked_pairing_completion(
        &mut self,
    ) -> Result<(CompletionAnswer, crate::session::TrustSnapshot)> {
        qualified()?;
        self.require_connected()?;
        ensure!(
            !self.network_computer() && !self.vault.pending(),
            "Review the original enrollment before pairing recovery"
        );
        let pending = self.vault.client_completion()?.clone();
        let digest = pending.reference.digest()?;
        if pending.finished {
            self.vault
                .require_completion_binding(&pending.reference.host, &digest)?;
            ensure!(
                self.vault
                    .peers()
                    .iter()
                    .any(|p| p.node == pending.reference.host
                        && crate::session::ticket_endpoint(&p.ticket)
                            .is_ok_and(|e| e.to_string() == pending.reference.host_endpoint)),
                "Saved completion relationship is missing or conflicting"
            );
        } else {
            ensure!(
                self.vault
                    .peers()
                    .iter()
                    .all(|p| p.node != pending.reference.host),
                "Existing relationship does not prove this original completion"
            );
        }
        let device = self
            .device
            .as_ref()
            .context("Original enrolled identity is missing")?;
        let identity = device.session_identity()?;
        let route = self
            .vault
            .bridge_route()
            .context("Original authority route is missing")?;
        pending.reference.require_scope(
            self.vault.pin(),
            &route.host_node,
            &device.public_key(),
        )?;
        ensure!(
            self.vault.peer() == Some(route.host_node.as_str()),
            "Original selected host changed"
        );
        self.vault.existing_transport()?;
        let bridge = self
            .bridge_client
            .clone()
            .context("Original authority bridge is unavailable")?;
        let trust = bridge.refresh(&mut self.trust).await?;
        trust.certificate(
            device.certificate(),
            &device.public_key(),
            chrono::Utc::now(),
        )?;
        let query = CompletionQuery {
            reference: pending.reference,
            nonce: uuid::Uuid::new_v4().to_string(),
        };
        let answer = bridge.pairing_completion(identity, trust, &query).await?;
        ensure!(
            answer.member_endpoint == self.vault.existing_transport()?.key.public().to_string(),
            "Host retained another device transport"
        );
        // Refresh only trust; never renew or enroll as a side effect of recovery.
        let fresh = bridge.refresh(&mut self.trust).await?;
        fresh.certificate(
            device.certificate(),
            &device.public_key(),
            chrono::Utc::now(),
        )?;
        fresh.certificate(
            &answer.host_certificate,
            &query.reference.host,
            chrono::Utc::now(),
        )?;
        Ok((answer, fresh))
    }
    /// Read-only inspection of the exact original relationship. No saved pair,
    /// invitation, enrollment or completion is produced by this call.
    pub async fn inspect_pairing_completion(&mut self) -> Result<()> {
        self.checked_pairing_completion().await?;
        Ok(())
    }
    /// Explicit local action. Inspection results and earlier clicks are never
    /// replayed: fresh authenticated readback and proof are required each time.
    pub async fn finish_pairing_completion(&mut self) -> Result<()> {
        let (answer, trust) = self.checked_pairing_completion().await?;
        let pending = self.vault.client_completion()?.clone();
        let reference = &pending.reference;
        let identity = self
            .device
            .as_ref()
            .context("Original enrolled identity is missing")?
            .session_identity()?;
        let temporary;
        let session = match &self.endpoint {
            Some(endpoint) => endpoint.as_ref(),
            None => {
                temporary = crate::session::SessionEndpoint::bind_with_transport(
                    identity,
                    trust,
                    reference.host.clone(),
                    None,
                    Some(self.vault.existing_transport()?),
                    self.vault.network_connectivity(),
                )
                .await?;
                &temporary
            }
        };
        // A running session must also be the original transport, not merely
        // another endpoint presenting the same membership certificate.
        let original = self.vault.existing_transport()?.key.public();
        let matches_original = crate::session::ticket_endpoint(&session.ticket()?)? == original;
        if !matches_original {
            if self.endpoint.is_none() {
                session.close().await;
            }
            anyhow::bail!("Current session is not the original pairing transport");
        }
        // A fresh QUIC proof authenticates the exact host and existing transport.
        let proof_result = session
            .prove_pairing_to(&reference.host, &answer.host_ticket)
            .await;
        if self.endpoint.is_none() {
            session.close().await;
        }
        let proof = proof_result?;
        let (_, fresh) = self.checked_pairing_completion().await?;
        proof.require_current(&fresh, &reference.host)?;
        let digest = reference.digest()?;
        if pending.finished {
            self.vault
                .require_completion_binding(&reference.host, &digest)?;
            ensure!(
                self.vault.peers().iter().any(|p| p.node == reference.host
                    && crate::session::ticket_endpoint(&p.ticket)
                        .is_ok_and(|e| e.to_string() == reference.host_endpoint)),
                "Saved completion relationship is missing or conflicting"
            );
            return Ok(());
        }
        ensure!(
            self.vault.peers().iter().all(|p| p.node != reference.host),
            "Existing relationship does not prove this original completion"
        );
        // No await between the final fresh checks and this atomic local commit.
        self.vault.save_completed_pairing(
            super::PairedDevice {
                name: pending.host_name,
                node: reference.host.clone(),
                ticket: answer.host_ticket,
            },
            Some(&digest),
            false,
        )?;
        self.publish_members();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Result<(CompletionReference, String)> {
        let key = SigningKey::from_bytes(&[1; 32]);
        let endpoint = iroh::SecretKey::from([7; 32]).public();
        let ticket=serde_json::json!({"version":1,"endpoint":iroh::EndpointAddr::new(endpoint).with_ip_addr(([127,0,0,1],23456).into())}).to_string();
        let reference = CompletionReference::issue(
            TrustPin {
                network_name: "Fixture".into(),
                root_public_key: STANDARD
                    .encode(SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes()),
            },
            PairingTarget {
                request_id: uuid::Uuid::new_v4().to_string(),
                node: STANDARD.encode(SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes()),
                name: "Phone".into(),
                comparison_code: "123456".into(),
            },
            &ticket,
            &key,
        )?;
        Ok((reference, ticket))
    }
    #[cfg(not(feature = "pairing-completion-recovery"))]
    #[test]
    fn production_build_refuses_recovery_before_any_network_or_storage_operation() {
        assert!(qualified().is_err());
        assert!(fixture().is_err());
    }
    #[cfg(feature = "pairing-completion-recovery")]
    #[test]
    fn original_proof_covers_network_host_device_request_name_code_and_endpoint() -> Result<()> {
        let (reference, _) = fixture()?;
        reference.check()?;
        for field in [
            "version",
            "pin",
            "host",
            "request",
            "node",
            "name",
            "code",
            "endpoint",
            "signature",
        ] {
            let mut changed = reference.clone();
            match field {
                "version" => changed.version = 2,
                "pin" => changed.pin.network_name = "Another".into(),
                "host" => changed.host = reference.target.node.clone(),
                "request" => changed.target.request_id = uuid::Uuid::new_v4().to_string(),
                "node" => changed.target.node = reference.pin.root_public_key.clone(),
                "name" => changed.target.name = "Other phone".into(),
                "code" => changed.target.comparison_code = "654321".into(),
                "endpoint" => {
                    changed.host_endpoint = iroh::SecretKey::from([8; 32]).public().to_string()
                }
                _ => changed.signature = "invalid".into(),
            }
            assert!(
                changed.check().is_err(),
                "Unsigned change to {field} accepted"
            );
        }
        let mut pin = reference.pin.clone();
        pin.network_name = "Other".into();
        assert!(
            reference
                .require_scope(&pin, &reference.host, &reference.target.node)
                .is_err()
        );
        assert!(
            reference
                .require_scope(
                    &reference.pin,
                    &reference.target.node,
                    &reference.target.node
                )
                .is_err()
        );
        assert!(
            reference
                .require_scope(&reference.pin, &reference.host, &reference.host)
                .is_err()
        );
        Ok(())
    }
    #[cfg(feature = "pairing-completion-recovery")]
    #[test]
    fn completion_answer_is_bound_to_fresh_challenge_and_exact_original_reference() -> Result<()> {
        let (reference, ticket) = fixture()?;
        let query = CompletionQuery {
            reference,
            nonce: uuid::Uuid::new_v4().to_string(),
        };
        let answer = CompletionAnswer {
            digest: query.reference.digest()?,
            nonce: query.nonce.clone(),
            host_ticket: ticket,
            member_endpoint: iroh::SecretKey::from([9; 32]).public().to_string(),
            host_certificate: serde_json::json!({}),
        };
        answer.check(&query)?;
        let mut other = query.clone();
        other.nonce = uuid::Uuid::new_v4().to_string();
        assert!(
            answer.check(&other).is_err(),
            "A retained reply is not a new readback"
        );
        let (other_reference, _) = fixture()?;
        other = query.clone();
        other.reference = other_reference;
        assert!(
            answer.check(&other).is_err(),
            "Another valid original reference is not this ceremony"
        );
        let mut bad = answer.clone();
        bad.host_ticket=serde_json::json!({"version":1,"endpoint":iroh::EndpointAddr::new(iroh::SecretKey::from([6;32]).public()).with_ip_addr(([127,0,0,1],23456).into())}).to_string();
        assert!(bad.check(&query).is_err());
        let mut wire = serde_json::to_value(&query)?;
        wire["operation"] = serde_json::json!("approve");
        assert!(serde_json::from_value::<CompletionQuery>(wire).is_err());
        Ok(())
    }
}
