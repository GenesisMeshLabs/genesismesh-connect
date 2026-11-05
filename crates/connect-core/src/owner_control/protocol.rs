use crate::{authority::TrustPin, session::TrustSnapshot};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use genesis_mesh_sdk::{
    canonical_digest, canonical_json, parse_strict_json, sign_canonical, verify_canonical,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) const WINDOW: Duration = Duration::seconds(120);
pub(super) const MAX_GRANT: Duration = Duration::days(30);
const MAX_ENVELOPE: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlScope {
    pub pin: TrustPin,
    pub host_node: String,
}
impl ControlScope {
    pub(super) fn validate(&self) -> Result<()> {
        crate::session::pairing::valid_name(&self.pin.network_name)?;
        public_key(&self.pin.root_public_key)?;
        public_key(&self.host_node)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ListPairing,
    ApprovePairing,
    RejectPairing,
}

/// Exact pending target; display names alone never identify an approval.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingTarget {
    pub request_id: String,
    pub node: String,
    pub name: String,
    pub comparison_code: String,
}
impl PairingTarget {
    pub fn from_pending(request: &crate::session::pairing::PairRequest) -> Self {
        Self {
            request_id: request.id.clone(),
            node: request.node.clone(),
            name: request.name.clone(),
            comparison_code: request.code.clone(),
        }
    }
    fn validate(&self) -> Result<()> {
        uuid_id(&self.request_id)?;
        public_key(&self.node)?;
        crate::session::pairing::valid_name(&self.name)?;
        ensure!(
            self.comparison_code.len() == 6
                && self.comparison_code.bytes().all(|b| b.is_ascii_digit()),
            "Invalid comparison code"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "operation",
    content = "target",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OwnerAction {
    ListPairing,
    ApprovePairing(PairingTarget),
    RejectPairing(PairingTarget),
}
impl OwnerAction {
    /// The fixed adapter must run this against the current PairHost request,
    /// under the same host lock, before issuing an invitation or rejecting it.
    pub fn require_pending(&self, current: &crate::session::pairing::PairRequest) -> Result<()> {
        let target = match self {
            Self::ApprovePairing(t) | Self::RejectPairing(t) => t,
            Self::ListPairing => anyhow::bail!("Listing does not approve a device"),
        };
        target.validate()?;
        ensure!(
            *target == PairingTarget::from_pending(current),
            "Pairing request changed after review"
        );
        Ok(())
    }
    pub fn permission(&self) -> Permission {
        match self {
            Self::ListPairing => Permission::ListPairing,
            Self::ApprovePairing(_) => Permission::ApprovePairing,
            Self::RejectPairing(_) => Permission::RejectPairing,
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
        match self {
            Self::ListPairing => Ok(()),
            Self::ApprovePairing(t) | Self::RejectPairing(t) => t.validate(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentIntent {
    pub version: u8,
    pub id: String,
    pub scope: ControlScope,
    pub controller_node: String,
    pub administrative_key: String,
    pub permissions: BTreeSet<Permission>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub grant_expires_at: DateTime<Utc>,
}
impl EnrollmentIntent {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "Unsupported owner enrollment version");
        uuid_id(&self.id)?;
        self.scope.validate()?;
        public_key(&self.controller_node)?;
        public_key(&self.administrative_key)?;
        ensure!(
            self.administrative_key != self.controller_node
                && self.administrative_key != self.scope.host_node
                && self.administrative_key != self.scope.pin.root_public_key,
            "Use a separate administrative signing key"
        );
        ensure!(
            !self.permissions.is_empty(),
            "Choose at least one pairing permission"
        );
        window(self.created_at, self.expires_at)?;
        ensure!(
            self.grant_expires_at > self.expires_at
                && self.grant_expires_at - self.created_at <= MAX_GRANT,
            "Choose administrative access of at most 30 days"
        );
        Ok(())
    }
}

/// The request proof proves possession, not owner approval.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub intent: EnrollmentIntent,
    pub signature: String,
}
impl EnrollmentRequest {
    pub fn sign(intent: EnrollmentIntent, key: &SigningKey) -> Result<Self> {
        intent.validate()?;
        ensure!(
            STANDARD.encode(key.verifying_key().to_bytes()) == intent.administrative_key,
            "Wrong administrative signing key"
        );
        let signature = signature(&intent, "genesismesh-connect/owner-enrollment/v1", key)?;
        Ok(Self { intent, signature })
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        decode(bytes)
    }
    pub fn digest(&self) -> Result<String> {
        self.verify()?;
        Ok(canonical_digest(
            &serde_json::json!({"domain":"genesismesh-connect/owner-enrollment/v1","intent":self.intent}),
        )?)
    }
    pub(super) fn verify(&self) -> Result<()> {
        self.intent.validate()?;
        proof(
            &self.intent,
            "genesismesh-connect/owner-enrollment/v1",
            &self.signature,
            &self.intent.administrative_key,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandIntent {
    pub version: u8,
    pub grant_id: String,
    pub nonce: String,
    pub scope: ControlScope,
    pub controller_node: String,
    pub action: OwnerAction,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
impl CommandIntent {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "Unsupported owner request version");
        uuid_id(&self.grant_id)?;
        uuid_id(&self.nonce)?;
        self.scope.validate()?;
        public_key(&self.controller_node)?;
        self.action.validate()?;
        window(self.created_at, self.expires_at)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerCommand {
    pub intent: CommandIntent,
    pub signature: String,
}
impl OwnerCommand {
    pub fn sign(intent: CommandIntent, key: &SigningKey) -> Result<Self> {
        intent.validate()?;
        let signature = signature(&intent, "genesismesh-connect/owner-command/v1", key)?;
        Ok(Self { intent, signature })
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        decode(bytes)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(canonical_digest(
            &serde_json::json!({"domain":"genesismesh-connect/owner-command/v1","intent":self.intent}),
        )?)
    }
    pub(super) fn verify(&self, key: &str) -> Result<()> {
        self.intent.validate()?;
        proof(
            &self.intent,
            "genesismesh-connect/owner-command/v1",
            &self.signature,
            key,
        )
    }
}

/// Native authenticated context. Never deserialize it from an owner request.
/// `session_node` must come from the existing mutually authenticated connection,
/// and `trust` from the host's fresh pinned authority snapshot.
pub struct VerifiedController {
    pub(super) scope: ControlScope,
    pub(super) node: String,
    pub(super) checked_at: DateTime<Utc>,
}
impl VerifiedController {
    pub fn from_session(
        scope: &ControlScope,
        trust: &TrustSnapshot,
        certificate: &Value,
        session_node: &str,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        ensure!(
            trust.root() == scope.pin.root_public_key && trust.network() == scope.pin.network_name,
            "Wrong owner-control network"
        );
        trust.certificate(certificate, session_node, now)?;
        Ok(Self {
            scope: scope.clone(),
            node: session_node.into(),
            checked_at: now,
        })
    }
    pub(super) fn require(
        &self,
        scope: &ControlScope,
        node: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        ensure!(
            &self.scope == scope && self.node == node,
            "Owner request does not match its authenticated device and host"
        );
        ensure!(
            now >= self.checked_at && now - self.checked_at < Duration::seconds(5),
            "Refresh membership before the owner request"
        );
        Ok(())
    }
}

pub(super) fn public_key(key: &str) -> Result<()> {
    let bytes = STANDARD.decode(key)?;
    ensure!(
        bytes.len() == 32 && STANDARD.encode(&bytes) == key,
        "Invalid public key"
    );
    ensure!(
        !ed25519_dalek::VerifyingKey::from_bytes(bytes.as_slice().try_into()?)?.is_weak(),
        "Invalid weak public key"
    );
    Ok(())
}
pub(super) fn uuid_id(id: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(id)?;
    ensure!(
        parsed.to_string() == id && !parsed.is_nil(),
        "Invalid request identity"
    );
    Ok(())
}
fn window(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<()> {
    ensure!(
        end > start && end - start <= WINDOW,
        "Owner requests expire within two minutes"
    );
    Ok(())
}
pub(super) fn live(start: DateTime<Utc>, end: DateTime<Utc>, now: DateTime<Utc>) -> Result<()> {
    ensure!(
        start <= now && now < end,
        "Owner request is future-dated or expired"
    );
    Ok(())
}
fn payload<T: Serialize>(value: &T, domain: &str) -> Result<String> {
    Ok(canonical_json(
        &serde_json::json!({"domain":domain,"intent":value}),
    )?)
}
fn signature<T: Serialize>(value: &T, domain: &str, key: &SigningKey) -> Result<String> {
    sign_canonical(&payload(value, domain)?, "connect-owner-control", key)["sig"]
        .as_str()
        .map(str::to_owned)
        .context("Missing signature")
}
fn proof<T: Serialize>(value: &T, domain: &str, signature: &str, key: &str) -> Result<()> {
    ensure!(
        signature.len() <= 128
            && verify_canonical(&payload(value, domain)?, signature, &[key.into()]),
        "Invalid owner-control proof"
    );
    Ok(())
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() <= MAX_ENVELOPE, "Owner envelope is too large");
    Ok(serde_json::from_value(parse_strict_json(
        std::str::from_utf8(bytes)?,
    )?)?)
}
