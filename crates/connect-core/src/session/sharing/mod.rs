//! Bounded, policy-authorized reads. Receipts describe preparation and verified
//! client acknowledgements; they are not core ResourceChangeRecords.
pub mod browse;
pub mod catalog;
pub mod download;
pub mod listing;
pub mod send;
mod storage;
mod transfer;
use super::*;
use crate::authority::{AuthorityAccess, TrustPin, TrustStore};
use serde_json::json;
use std::path::{Path, PathBuf};
use storage::{Collection, sha};
pub use transfer::ReadReport;
pub(super) use transfer::{receive, serve};

/// Each Space keeps at most this many receipts and bytes of them; rotation
/// keeps it below `ROTATE_*`, oldest first, until Activity keeps the history
/// on the network computer.
const MAX_RECEIPTS: usize = 2048;
const MAX_RECEIPT_BYTES: u64 = 32 * 1024 * 1024;
const ROTATE_RECEIPTS: usize = 1792;
const ROTATE_RECEIPT_BYTES: u64 = 24 * 1024 * 1024;

/// What a Space lets its devices do: read a shared folder, or send files into
/// the host's inbox folder.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SpaceKind {
    #[default]
    Folder,
    Inbox,
}
impl SpaceKind {
    pub(crate) fn is_folder(&self) -> bool {
        *self == Self::Folder
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShareConfig {
    pub collection_id: String,
    pub directory: PathBuf,
    pub attestation_id: String,
    pub policy_id: String,
    /// The Space's name, as the devices it is shared with see it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The devices it is shared with; empty for a folder shared before Spaces.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<String>,
    #[serde(default, skip_serializing_if = "SpaceKind::is_folder")]
    pub kind: SpaceKind,
}
pub struct Share {
    config: ShareConfig,
    /// The host's attestation; the network computer renews it in place.
    attestation: std::sync::RwLock<String>,
    directory: Arc<Collection>,
    authority: AuthorityAccess,
    trust: tokio::sync::Mutex<TrustStore>,
    receipts: PathBuf,
    released: AtomicU64,
    released_names: AtomicU64,
    budget: Arc<tokio::sync::Semaphore>,
    downloads: download::State,
    incoming: Arc<send::Incoming>,
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
        ensure!(
            config.name.chars().count() <= 64
                && !config.name.chars().any(char::is_control)
                && config.recipients.len() <= 31
                && config.recipients.iter().all(|node| {
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, node)
                        .is_ok_and(|key| key.len() == 32)
                }),
            "Invalid shared folder"
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
        let incoming = send::Incoming::open(state)?;
        Ok(Self {
            attestation: std::sync::RwLock::new(config.attestation_id.clone()),
            config,
            directory,
            authority: authority.into(),
            trust: tokio::sync::Mutex::new(trust),
            receipts,
            released: AtomicU64::new(0),
            released_names: AtomicU64::new(0),
            budget: Arc::new(tokio::sync::Semaphore::new(1)),
            downloads,
            incoming,
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
    /// The Space as saved, with its current attestation.
    pub fn config(&self) -> ShareConfig {
        ShareConfig {
            attestation_id: self.attestation_id(),
            ..self.config.clone()
        }
    }
    pub fn collection_id(&self) -> &str {
        &self.config.collection_id
    }
    fn attestation_id(&self) -> String {
        self.attestation
            .read()
            .expect("share attestation lock poisoned")
            .clone()
    }
    /// Use the network computer's renewed attestation for this Space from the
    /// next operation on; running operations keep the one they started with.
    pub fn renew(&self, attestation_id: &str) -> Result<()> {
        uuid::Uuid::parse_str(attestation_id)?;
        *self
            .attestation
            .write()
            .expect("share attestation lock poisoned") = attestation_id.to_owned();
        Ok(())
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
        let attestation_id = self.attestation_id();
        let attestation = self
            .authority
            .attestation(&credentials.identity, &trust, &attestation_id)
            .await?["attestation"]
            .clone();
        let params = json!({"collection_id":request.collection_id,"file_name":request.file_name,"peer_node":credentials.expected_node,"sha256":digest,"size":bytes.len()});
        let response = self
            .authority
            .evaluate(
                &credentials.identity,
                &trust,
                &attestation_id,
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
    /// Keep this device's receipts for 90 days and, within the store's limits,
    /// drop the oldest first, so sharing never stops for lack of room.
    fn rotate(&self) -> Result<()> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&self.receipts)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            ensure!(metadata.is_file(), "Unexpected evidence entry");
            entries.push((metadata.modified()?, metadata.len(), entry.path()));
        }
        entries.sort();
        let kept_since = std::time::SystemTime::now() - Duration::from_secs(90 * 24 * 60 * 60);
        let mut count = entries.len();
        let mut total: u64 = entries.iter().map(|entry| entry.1).sum();
        for (modified, size, path) in entries {
            // Leaves room below the limits `persist` enforces.
            let full = count >= ROTATE_RECEIPTS || total > ROTATE_RECEIPT_BYTES;
            if modified >= kept_since && !full {
                break;
            }
            std::fs::remove_file(&path)?;
            count -= 1;
            total -= size;
        }
        Ok(())
    }
    fn persist(&self, evidence: &Value) -> Result<()> {
        use std::io::Write;
        let bytes = serde_json::to_vec(evidence)?;
        ensure!(bytes.len() <= 512 * 1024, "Read evidence too large");
        self.rotate()?;
        // Leave room for the largest permitted acknowledgment envelope before
        // releasing bytes. A known-full store must refuse at preparation.
        let reserve = usize::from(evidence["receipt"]["phase"] == "prepared");
        let mut count = 0;
        let mut total = (bytes.len() + reserve * 512 * 1024) as u64;
        for entry in std::fs::read_dir(&self.receipts)? {
            let entry = entry?;
            count += 1;
            ensure!(
                count + reserve < MAX_RECEIPTS,
                "Archive read receipts before sharing more files"
            );
            let metadata = entry.metadata()?;
            ensure!(metadata.is_file(), "Unexpected evidence entry");
            total += metadata.len();
            ensure!(
                total <= MAX_RECEIPT_BYTES,
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
/// The Spaces one device shares. Requests name their Space; a request from an
/// app that predates Spaces names none and gets the first Space shared with
/// that device.
pub struct Shares {
    shares: Vec<Arc<Share>>,
}
impl Shares {
    pub fn new(mut shares: Vec<Arc<Share>>) -> Result<Self> {
        ensure!(shares.len() <= 16, "A device shares up to 16 folders");
        shares.sort_by(|a, b| {
            (&a.config.name, &a.config.collection_id)
                .cmp(&(&b.config.name, &b.config.collection_id))
        });
        ensure!(
            shares
                .windows(2)
                .all(|pair| pair[0].config.collection_id != pair[1].config.collection_id),
            "The same folder is shared twice"
        );
        Ok(Self { shares })
    }
    pub fn single(share: Arc<Share>) -> Self {
        Self {
            shares: vec![share],
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = &Arc<Share>> {
        self.shares.iter()
    }
    fn of_kind(&self, collection: &str, kind: SpaceKind) -> Option<&Share> {
        self.shares
            .iter()
            .find(|share| share.config.collection_id == collection && share.config.kind == kind)
            .map(|share| &**share)
    }
    /// A shared folder, to read and list. An inbox is never read from.
    pub(super) fn get(&self, collection: &str) -> Option<&Share> {
        self.of_kind(collection, SpaceKind::Folder)
    }
    /// An inbox, to send into. A shared folder is never written to.
    pub(super) fn inbox(&self, collection: &str) -> Option<&Share> {
        self.of_kind(collection, SpaceKind::Inbox)
    }
    /// The staging areas of these Spaces' inboxes: holding them keeps files
    /// that are arriving while the shares are reopened.
    pub(crate) fn staging(&self) -> Vec<Arc<send::Incoming>> {
        self.shares
            .iter()
            .map(|share| share.incoming.clone())
            .collect()
    }
    /// Whether any Space here is an inbox, so the send protocol is offered.
    pub(super) fn receives(&self) -> bool {
        self.shares
            .iter()
            .any(|share| share.config.kind == SpaceKind::Inbox)
    }
    /// The folder a request names, or for one that names none, the first
    /// folder shared with `peer` (a folder shared before Spaces names everyone).
    pub(super) fn find(&self, collection: Option<&str>, peer: &str) -> Option<&Share> {
        match collection {
            Some(collection) => self.get(collection),
            None => self
                .shares
                .iter()
                .find(|share| {
                    share.config.kind == SpaceKind::Folder
                        && (share.config.recipients.is_empty()
                            || share.config.recipients.iter().any(|node| node == peer))
                })
                .map(|share| &**share),
        }
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

    fn share(root: &Path, name: &str, recipients: &[&str]) -> Result<Arc<Share>> {
        let kind = if name == "Inbox" {
            SpaceKind::Inbox
        } else {
            SpaceKind::Folder
        };
        let folder = root.join(format!("{name}-folder"));
        std::fs::create_dir_all(&folder)?;
        let pin = TrustPin {
            network_name: "disposable-share-test".into(),
            root_public_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [3; 32],
            ),
        };
        Ok(Arc::new(Share::open(
            ShareConfig {
                collection_id: uuid::Uuid::new_v4().to_string(),
                directory: folder,
                attestation_id: uuid::Uuid::new_v4().to_string(),
                policy_id: "connect-test".into(),
                name: name.into(),
                recipients: recipients.iter().map(|r| (*r).to_owned()).collect(),
                kind,
            },
            crate::authority::LocalAuthority::new("http://127.0.0.1:9")?,
            pin,
            &root.join(name),
        )?))
    }

    #[test]
    fn requests_reach_their_space_and_older_apps_the_first_shared_with_them() -> Result<()> {
        let root = tempfile::tempdir()?;
        let key = |byte: u8| {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [byte; 32])
        };
        let (phone, tablet) = (key(1), key(2));
        let photos = share(root.path(), "Photos", &[&phone])?;
        let documents = share(root.path(), "Documents", &[&phone, &tablet])?;
        let shares = Shares::new(vec![photos.clone(), documents.clone()])?;
        let id = |share: Option<&Share>| share.map(|s| s.collection_id().to_owned());
        assert_eq!(
            id(shares.find(Some(photos.collection_id()), &tablet)),
            Some(photos.collection_id().to_owned()),
            "A named Space is found; the authority decides who may read it"
        );
        assert_eq!(id(shares.find(Some("unknown"), &phone)), None);
        assert_eq!(
            id(shares.find(None, &phone)),
            Some(documents.collection_id().to_owned()),
            "Without a name, the first Space by name that names the device"
        );
        assert_eq!(
            id(shares.find(None, &tablet)),
            Some(documents.collection_id().to_owned())
        );
        assert_eq!(id(shares.find(None, &key(3))), None);
        assert!(Shares::new(vec![photos.clone(), photos.clone()]).is_err());
        // An inbox is only written to, a folder only read from.
        let inbox = share(root.path(), "Inbox", &[&phone])?;
        let mixed = Shares::new(vec![photos.clone(), inbox.clone()])?;
        assert!(mixed.get(inbox.collection_id()).is_none());
        assert!(mixed.inbox(photos.collection_id()).is_none());
        assert_eq!(
            id(mixed.inbox(inbox.collection_id())),
            Some(inbox.collection_id().to_owned())
        );
        assert!(mixed.receives() && !shares.receives());
        assert_eq!(
            id(mixed.find(None, &phone)),
            Some(photos.collection_id().to_owned()),
            "An app without Spaces never lands in an inbox"
        );
        // A renewed attestation is used from then on, and saved with the Space.
        let renewed = uuid::Uuid::new_v4().to_string();
        photos.renew(&renewed)?;
        assert_eq!(photos.config().attestation_id, renewed);
        assert!(photos.renew("not an attestation").is_err());
        Ok(())
    }

    #[test]
    fn receipts_rotate_by_age_and_room_instead_of_stopping_sharing() -> Result<()> {
        let root = tempfile::tempdir()?;
        let share = share(root.path(), "Rotating", &[])?;
        let old = std::time::SystemTime::now() - Duration::from_secs(91 * 24 * 60 * 60);
        let write = |name: String, age: std::time::SystemTime| -> Result<()> {
            let path = share.receipts.join(name);
            std::fs::write(&path, b"{}")?;
            std::fs::File::options()
                .write(true)
                .open(&path)?
                .set_modified(age)?;
            Ok(())
        };
        write("expired.json".into(), old)?;
        let recent = std::time::SystemTime::now() - Duration::from_secs(60);
        for index in 0..10 {
            write(format!("recent-{index}.json"), recent)?;
        }
        share.rotate()?;
        let names = |dir: &Path| -> Result<Vec<String>> {
            let mut names: Vec<String> = std::fs::read_dir(dir)?
                .map(|e| Ok(e?.file_name().to_string_lossy().into_owned()))
                .collect::<Result<_>>()?;
            names.sort();
            Ok(names)
        };
        assert!(!names(&share.receipts)?.contains(&"expired.json".to_owned()));
        assert_eq!(names(&share.receipts)?.len(), 10, "Recent receipts stay");
        // A store at its limit drops the oldest receipts, not the newest.
        for index in 10..MAX_RECEIPTS as u64 {
            let age = recent + Duration::from_millis(index);
            write(format!("recent-{index:04}.json"), age)?;
        }
        share.rotate()?;
        let kept = names(&share.receipts)?;
        assert_eq!(kept.len(), ROTATE_RECEIPTS - 1);
        assert!(kept.contains(&format!("recent-{:04}.json", MAX_RECEIPTS - 1)));
        assert!(!kept.contains(&"recent-0.json".to_owned()));
        // Recording another receipt now succeeds where it used to stop.
        share.persist(
            &json!({"receipt":{"receipt_id":uuid::Uuid::new_v4().to_string(),"phase":"prepared"}}),
        )?;
        Ok(())
    }
}
