//! Native desktop enrollment and trust refresh. No operator credentials, relay
//! proxy, secret persistence or automatic enrollment retries live here.

mod access;
mod http;
mod store;

pub use access::AuthorityAccess;
pub use http::LocalAuthority;
pub use store::{TrustCheckpointStatus, TrustPin, TrustStore};

use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use genesis_mesh_sdk::node_auth::{node_timestamp, sign_node_request};
use serde_json::{Value, json};

use crate::session::{SessionIdentity, TrustSnapshot};

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustDocuments {
    pub history: Value,
    pub crl: Value,
}

/// In-memory credential; the device controller persists it using platform storage.
pub struct EnrolledDevice {
    key: SigningKey,
    certificate: Value,
}

impl EnrolledDevice {
    pub(crate) fn restore(key: SigningKey, certificate: Value) -> Result<Self> {
        SessionIdentity::new(key.clone(), certificate.clone())?;
        Ok(Self { key, certificate })
    }
    pub fn renewal_due(&self) -> bool {
        self.certificate["issued_at"]
            .as_str()
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .is_none_or(|at| Utc::now() - at.with_timezone(&Utc) >= chrono::Duration::seconds(240))
    }
    pub fn public_key(&self) -> String {
        public_key(&self.key)
    }
    pub fn certificate(&self) -> &Value {
        &self.certificate
    }
    pub fn session_identity(&self) -> Result<SessionIdentity> {
        SessionIdentity::new(self.key.clone(), self.certificate.clone())
    }
    pub(crate) fn accept_enrollment(
        key: SigningKey,
        certificate: Value,
        trust: &TrustSnapshot,
    ) -> Result<Self> {
        trust.certificate(&certificate, &public_key(&key), Utc::now())?;
        SessionIdentity::new(key.clone(), certificate.clone())?;
        Ok(Self { key, certificate })
    }

    pub(crate) fn renewal_request(&self, trust: &TrustSnapshot) -> Result<Value> {
        trust.renewable_certificate(&self.certificate, &self.public_key(), Utc::now())?;
        request(
            &self.key,
            json!({ "cert_id": self.certificate["cert_id"], "node_public_key": self.public_key(), "validity_hours": 24 }),
        )
    }

    pub(crate) fn accept_renewal(
        &mut self,
        certificate: Value,
        trust: &TrustSnapshot,
    ) -> Result<()> {
        trust.certificate(&certificate, &self.public_key(), Utc::now())?;
        let roles = |cert: &Value| -> Result<Vec<String>> {
            let mut roles: Vec<String> = serde_json::from_value(cert["roles"].clone())?;
            roles.sort();
            Ok(roles)
        };
        ensure!(
            roles(&certificate)? == roles(&self.certificate)?,
            "Renewal changed assigned roles"
        );
        SessionIdentity::new(self.key.clone(), certificate.clone())?;
        self.certificate = certificate;
        Ok(())
    }
}

fn public_key(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}

pub(crate) fn request(key: &SigningKey, body: Value) -> Result<Value> {
    Ok(sign_node_request(
        body,
        key,
        &node_timestamp(Utc::now()),
        &uuid::Uuid::new_v4().to_string(),
    )?)
}

pub(crate) fn accept_host_enrollment(
    key: SigningKey,
    executor: &SigningKey,
    mut response: Value,
    trust: &TrustSnapshot,
) -> Result<(EnrolledDevice, Value)> {
    let edge = response
        .as_object_mut()
        .and_then(|v| v.remove("edge"))
        .ok_or_else(|| anyhow::anyhow!("A sharing host requires an edge invitation"))?;
    ensure!(
        edge["executor_key"]["public_key"] == public_key(executor)
            && edge["node_sovereign_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
        "Unexpected edge registration"
    );
    Ok((
        EnrolledDevice::accept_enrollment(key, response, trust)?,
        edge,
    ))
}

impl LocalAuthority {
    pub async fn enroll_host(
        &self,
        key: SigningKey,
        executor: &SigningKey,
        invite: &str,
        store: &mut TrustStore,
    ) -> Result<(EnrolledDevice, Value)> {
        ensure!(
            !invite.is_empty() && invite.len() <= 512,
            "Invalid invite length"
        );
        let trust = self.refresh(store).await?;
        let timestamp = node_timestamp(Utc::now());
        let nonce = uuid::Uuid::new_v4().to_string();
        let body = json!({"node_public_key": public_key(&key), "executor_public_key":public_key(executor), "invite_token":invite, "validity_hours":24, "timestamp":timestamp, "nonce":nonce});
        let body = genesis_mesh_sdk::node_auth::sign_executor_proof(body, executor)?;
        let body = sign_node_request(body, &key, &timestamp, &nonce)?;
        let response = self.post("/join", &body).await?;
        accept_host_enrollment(key, executor, response, &trust)
    }

    pub(crate) async fn evaluate_collection(
        &self,
        identity: &crate::session::SessionIdentity,
        audience: &str,
        attestation: &str,
        context_id: &str,
        parameters: Value,
        capability: &str,
    ) -> Result<Value> {
        ensure!(
            ["connect.collection.read", "connect.collection.list"].contains(&capability),
            "Unsupported collection action"
        );
        let body = request(
            &identity.key,
            json!({"cert_id":identity.certificate["cert_id"],"node_public_key":identity.public_key(),"purpose":"node_boundary_evaluate","audience":audience,"attestation_id":attestation,"requested_capability":capability,"context":{"context_id":context_id,"request_parameters":parameters}}),
        )?;
        self.post("/node/boundary/evaluate", &body).await
    }

    pub(crate) async fn read_attestation(&self, id: &str) -> Result<Value> {
        uuid::Uuid::parse_str(id)?;
        self.exchange_public_attestation(id).await
    }
    pub(crate) async fn documents(&self) -> Result<TrustDocuments> {
        Ok(TrustDocuments {
            history: self.get("/na/key-history").await?,
            crl: self.get("/crl").await?,
        })
    }
    pub(crate) async fn forward_renewal(&self, signed: &Value) -> Result<Value> {
        self.post("/renew", signed).await
    }
    pub(crate) async fn forward_enrollment(&self, signed: &Value) -> Result<Value> {
        self.post("/join", signed).await
    }
    pub(crate) async fn forward_collection_decision(&self, signed: &Value) -> Result<Value> {
        self.post("/node/boundary/evaluate", signed).await
    }
    /// Fetch only the two fixed public routes. Verification failures leave the
    /// checkpoint unchanged; persistence errors require reopening the store.
    /// Any failed refresh returns no usable replacement snapshot.
    pub async fn refresh(&self, store: &mut TrustStore) -> Result<TrustSnapshot> {
        let observed_at = Utc::now();
        let documents = self.documents().await?;
        store.accept(&documents.history, documents.crl, observed_at)
    }

    /// The caller supplies its node key and operator-provisioned single-use
    /// invite. The authority assigns roles; the client cannot request them.
    pub async fn enroll(
        &self,
        key: SigningKey,
        invite: &str,
        store: &mut TrustStore,
    ) -> Result<EnrolledDevice> {
        ensure!(
            !invite.is_empty() && invite.len() <= 512,
            "Invalid invite length"
        );
        let trust = self.refresh(store).await?;
        let body = request(
            &key,
            json!({"node_public_key": public_key(&key), "invite_token": invite, "validity_hours": 24}),
        )?;
        let certificate = self.post("/join", &body).await?;
        EnrolledDevice::accept_enrollment(key, certificate, &trust)
    }

    /// Refuse revoked/expired credentials rather than treating renewal as a
    /// recovery bypass. Never replace the old identity after a bad response.
    pub async fn renew(&self, device: &mut EnrolledDevice, store: &mut TrustStore) -> Result<()> {
        let trust = self.refresh(store).await?;
        let body = device.renewal_request(&trust)?;
        let mut certificate = self.post("/renew", &body).await?;
        if let Some(object) = certificate.as_object_mut() {
            object.remove("edge");
        }
        device.accept_renewal(certificate, &trust)
    }
}
