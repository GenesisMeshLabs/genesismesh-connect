//! Synthetic authority for diagnostics/tests only. Never used by the Tauri app.
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use genesis_mesh_sdk::{canonical::python_timestamp, canonical_json, sign_canonical};
use serde_json::{Value, json};
use std::time::Duration;

pub fn key() -> SigningKey {
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).unwrap();
    SigningKey::from_bytes(&seed)
}

pub fn public(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}

pub fn signed(mut value: Value, keys: &[&SigningKey]) -> Value {
    value.as_object_mut().unwrap().remove("signatures");
    let payload = canonical_json(&value).unwrap();
    value["signatures"] = json!(
        keys.iter()
            .map(|key| sign_canonical(&payload, "spike-only", key))
            .collect::<Vec<_>>()
    );
    value
}

pub struct Fixture {
    pub now: DateTime<Utc>,
    pub root: SigningKey,
    #[allow(dead_code)] // Only the negative tests mutate authority-signed records.
    pub authority: SigningKey,
    pub client: SigningKey,
    pub server: SigningKey,
    pub genesis: Value,
    pub crl: Value,
    pub client_cert: Value,
    pub server_cert: Value,
}

impl Fixture {
    pub fn new() -> Self {
        let now = Utc::now();
        let root = key();
        let authority = key();
        let client = key();
        let server = key();
        let genesis = signed(
            json!({
                "network_name": "connect-spike", "network_version": "v1", "root_public_key": public(&root),
                "network_authority": {"public_key": public(&authority), "valid_from": python_timestamp(now - chrono::Duration::days(1)), "valid_to": python_timestamp(now + chrono::Duration::days(1))},
                "policy_manifest": {"hash": "sha256:spike-only", "url": null},
                "allowed_crypto_suites": ["ed25519"], "allowed_transports": ["quic"], "bootstrap_anchors": []
            }),
            &[&root],
        );
        let crl = signed(
            json!({
                "crl_id": "spike-crl", "sequence": 1, "issued_at": python_timestamp(now),
                "next_update": python_timestamp(now + chrono::Duration::minutes(5)),
                "issuer": "spike-only", "revoked_certificates": []
            }),
            &[&authority],
        );
        let certificate = |key: &SigningKey, id: &str| {
            signed(
                json!({
                    "cert_id": id, "node_public_key": public(key), "network_name": "connect-spike", "roles": ["role:client"],
                    "issued_at": python_timestamp(now - chrono::Duration::seconds(1)),
                    "expires_at": python_timestamp(now + chrono::Duration::hours(1)), "issued_by": "spike-only"
                }),
                &[&authority],
            )
        };
        let client_cert = certificate(&client, "client-cert");
        let server_cert = certificate(&server, "server-cert");
        Self {
            now,
            root,
            authority,
            client,
            server,
            genesis,
            crl,
            client_cert,
            server_cert,
        }
    }

    pub fn policy(&self) -> connect_core::session::TrustPolicy {
        connect_core::session::TrustPolicy {
            root_public_key: public(&self.root),
            network_name: "connect-spike".into(),
            minimum_crl_sequence: 1,
            minimum_key_sequence: 1,
            max_age: Duration::from_secs(300),
            vouching_grace_seconds: 0,
        }
    }

    pub fn trust(&self) -> Result<connect_core::session::TrustSnapshot> {
        connect_core::session::TrustSnapshot::from_records(
            self.policy(),
            &self.genesis,
            &[],
            self.crl.clone(),
            self.now,
        )
    }
}
