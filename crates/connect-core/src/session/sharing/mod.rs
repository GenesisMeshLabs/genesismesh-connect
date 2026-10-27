//! Bounded, policy-authorized reads. Receipts describe preparation and verified
//! client acknowledgements; they are not core ResourceChangeRecords.
pub mod browse;
pub mod catalog;
pub mod download;
pub mod listing;
mod storage;
mod transfer;
use super::*;
use crate::authority::{AuthorityAccess, TrustPin, TrustStore};
use serde_json::json;
use std::path::{Path, PathBuf};
use storage::{Collection, sha};
pub use transfer::ReadReport;
pub(super) use transfer::{receive, serve};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShareConfig {
    pub collection_id: String,
    pub directory: PathBuf,
    pub attestation_id: String,
    pub policy_id: String,
}
pub struct Share {
    config: ShareConfig,
    directory: Arc<Collection>,
    authority: AuthorityAccess,
    trust: tokio::sync::Mutex<TrustStore>,
    receipts: PathBuf,
    released: AtomicU64,
    released_names: AtomicU64,
    budget: Arc<tokio::sync::Semaphore>,
    downloads: download::State,
    requests: Mutex<(std::time::Instant, u32)>,
    browse_requests: Mutex<(std::time::Instant, u32)>,
}
impl Share {
    pub fn open(
        config: ShareConfig,
        authority: impl Into<AuthorityAccess>,
        pin: TrustPin,
        state: &Path,
    ) -> Result<Self> {
        storage::name(&config.collection_id)?;
        uuid::Uuid::parse_str(&config.attestation_id)?;
        ensure!(
            !config.policy_id.is_empty() && config.policy_id.len() <= 128,
            "Missing sharing policy"
        );
        let directory = Arc::new(Collection::open(&config.directory)?);
        std::fs::create_dir_all(state)?;
        let checkpoint = state.join("trust.json");
        let trust = if checkpoint.exists() {
            TrustStore::open(&checkpoint, &pin)?
        } else {
            TrustStore::create(&checkpoint, pin)?
        };
        let receipts = state.join("receipts");
        std::fs::create_dir_all(&receipts)?;
        let downloads = download::State::open(state)?;
        Ok(Self {
            config,
            directory,
            authority: authority.into(),
            trust: tokio::sync::Mutex::new(trust),
            receipts,
            released: AtomicU64::new(0),
            released_names: AtomicU64::new(0),
            budget: Arc::new(tokio::sync::Semaphore::new(1)),
            downloads,
            requests: Mutex::new((std::time::Instant::now(), 0)),
            browse_requests: Mutex::new((std::time::Instant::now(), 0)),
        })
    }
    pub fn released_bytes(&self) -> u64 {
        self.released.load(Ordering::Relaxed)
    }
    pub fn released_names(&self) -> u64 {
        self.released_names.load(Ordering::Relaxed)
    }
    pub fn config(&self) -> &ShareConfig {
        &self.config
    }
    async fn prepare(
        &self,
        credentials: &Credentials,
        peer: &Value,
        request: &ReadRequest,
    ) -> Result<Prepared> {
        {
            let mut window = self.requests.lock().expect("Read budget mutex poisoned");
            if window.0.elapsed() >= Duration::from_secs(60) {
                *window = (std::time::Instant::now(), 0);
            }
            ensure!(window.1 < 16, "Read budget exhausted");
            window.1 += 1;
        }
        storage::name(&request.file_name)?;
        ensure!(
            request.collection_id == self.config.collection_id,
            "Unknown collection"
        );
        let mut store = self.trust.lock().await;
        let trust = self.authority.refresh(&mut store).await?;
        drop(store);
        trust.certificate(peer, &credentials.expected_node, Utc::now())?;
        trust.certificate(
            &credentials.identity.certificate,
            &credentials.identity.public_key(),
            Utc::now(),
        )?;
        let directory = self.directory.clone();
        let file_name = request.file_name.clone();
        let bytes = tokio::task::spawn_blocking(move || directory.snapshot(&file_name)).await??;
        let digest = sha(&bytes);
        ensure!(
            request
                .expected_sha256
                .as_ref()
                .is_none_or(|s| s == &digest),
            "File version changed"
        );
        let intent = json!({"request":request,"host_node":credentials.identity.public_key(),"peer_node":credentials.expected_node,"host_nonce":uuid::Uuid::new_v4().to_string(),"sha256":digest,"size":bytes.len(),"policy_id":self.config.policy_id});
        let context_id = format!(
            "connect-read:{}",
            genesis_mesh_sdk::canonical_digest(&intent)?
        );
        let attestation = self
            .authority
            .attestation(&credentials.identity, &trust, &self.config.attestation_id)
            .await?["attestation"]
            .clone();
        let params = json!({"collection_id":request.collection_id,"file_name":request.file_name,"peer_node":credentials.expected_node,"sha256":digest,"size":bytes.len()});
        let response = self
            .authority
            .evaluate(
                &credentials.identity,
                &trust,
                &self.config.attestation_id,
                &context_id,
                params,
                "connect.collection.read",
            )
            .await?;
        let decision = response["decision"].clone();
        trust.read_decision(
            &decision,
            &attestation,
            &context_id,
            &self.config.policy_id,
            &credentials.identity.public_key(),
        )?;
        let receipt = receipt(
            &credentials.identity,
            &intent,
            &decision,
            "prepared",
            Value::Null,
        )?;
        self.persist(&json!({"receipt":receipt,"intent":intent,"decision":decision,"attestation":attestation,"host_certificate":credentials.identity.certificate,"peer_certificate":peer}))?;
        Ok(Prepared {
            bytes,
            intent,
            decision,
            attestation,
            receipt,
            trust,
            started: std::time::Instant::now(),
        })
    }
    fn persist(&self, evidence: &Value) -> Result<()> {
        use std::io::Write;
        let bytes = serde_json::to_vec(evidence)?;
        ensure!(bytes.len() <= 512 * 1024, "Read evidence too large");
        // Leave room for the largest permitted acknowledgment envelope before
        // releasing bytes. A known-full store must refuse at preparation.
        let reserve = usize::from(evidence["receipt"]["phase"] == "prepared");
        let mut count = 0;
        let mut total = (bytes.len() + reserve * 512 * 1024) as u64;
        for entry in std::fs::read_dir(&self.receipts)? {
            let entry = entry?;
            count += 1;
            ensure!(
                count + reserve < 512,
                "Archive read receipts before sharing more files"
            );
            let metadata = entry.metadata()?;
            ensure!(metadata.is_file(), "Unexpected evidence entry");
            total += metadata.len();
            ensure!(
                total <= 16 * 1024 * 1024,
                "Read evidence storage limit reached"
            );
        }
        let id = evidence["receipt"]["receipt_id"]
            .as_str()
            .context("Missing receipt ID")?;
        uuid::Uuid::parse_str(id)?;
        let mut pending = tempfile::NamedTempFile::new_in(&self.receipts)?;
        pending.write_all(&bytes)?;
        pending.as_file().sync_all()?;
        pending.persist_noclobber(self.receipts.join(format!("{id}.json")))?;
        Ok(())
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    pub request_id: String,
    pub collection_id: String,
    pub file_name: String,
    pub expected_sha256: Option<String>,
}
struct Prepared {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    intent: Value,
    decision: Value,
    attestation: Value,
    receipt: Value,
    trust: TrustSnapshot,
    started: std::time::Instant,
}
fn receipt(
    identity: &SessionIdentity,
    intent: &Value,
    decision: &Value,
    phase: &str,
    ack: Value,
) -> Result<Value> {
    let mut value = json!({"domain":"genesismesh-connect/read-receipt/v1","receipt_id":uuid::Uuid::new_v4().to_string(),"phase":phase,"host_node":identity.public_key(),"intent_digest":genesis_mesh_sdk::canonical_digest(intent)?,"decision_digest":genesis_mesh_sdk::canonical_digest(decision)?,"created_at":genesis_mesh_sdk::canonical::python_timestamp(Utc::now()),"client_ack":ack});
    value["signature"] = genesis_mesh_sdk::sign_canonical(
        &genesis_mesh_sdk::canonical_json(&value)?,
        "connect-node",
        &identity.key,
    );
    Ok(value)
}
fn verify_receipt(
    value: &Value,
    node: &str,
    intent: &Value,
    decision: &Value,
    phase: &str,
) -> Result<()> {
    let mut body = value.clone();
    let signature = body
        .as_object_mut()
        .and_then(|v| v.remove("signature"))
        .context("Missing receipt signature")?;
    ensure!(
        value["domain"] == "genesismesh-connect/read-receipt/v1"
            && value["phase"] == phase
            && value["host_node"] == node
            && value["intent_digest"] == genesis_mesh_sdk::canonical_digest(intent)?
            && value["decision_digest"] == genesis_mesh_sdk::canonical_digest(decision)?,
        "Wrong receipt binding"
    );
    ensure!(
        genesis_mesh_sdk::verify_canonical(
            &genesis_mesh_sdk::canonical_json(&body)?,
            signature["sig"]
                .as_str()
                .context("Invalid receipt signature")?,
            &[node.to_owned()]
        ),
        "Invalid receipt signature"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipts_refuse_wrong_scope_and_tampering() -> Result<()> {
        let key = crate::session::tests::support::key();
        let node = crate::session::tests::support::public(&key);
        let identity = SessionIdentity::new(key, json!({"node_public_key":node}))?;
        let intent = json!({"peer":"peer","sha256":"digest"});
        let decision = json!({"decision_id":"read-decision"});
        let value = receipt(&identity, &intent, &decision, "prepared", Value::Null)?;
        verify_receipt(&value, &node, &intent, &decision, "prepared")?;
        assert!(
            verify_receipt(
                &value,
                &node,
                &json!({"peer":"other"}),
                &decision,
                "prepared"
            )
            .is_err()
        );
        assert!(verify_receipt(&value, &node, &intent, &decision, "client_verified").is_err());
        let mut changed = value;
        changed["created_at"] = json!("modified");
        assert!(verify_receipt(&changed, &node, &intent, &decision, "prepared").is_err());
        Ok(())
    }
}
