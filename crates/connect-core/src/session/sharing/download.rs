//! Disk-backed, independently authorized download windows. Every window uses a
//! new session proof and decision for the FULL file size; chunking never bypasses
//! the authority's file-size gate. Unverified bytes remain in a private staging file.
use super::*;
use crate::session::wire::{self, Protocol, Role, authenticate_for, read_frame, write_frame};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    time::Instant,
};

pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_WINDOW_BYTES: u32 = 32 * 1024 * 1024;
pub const MIN_WINDOW_BYTES: u32 = 64 * 1024;
const MAX_HEADER: usize = 512 * 1024;
/// When both places for unfinished downloads are taken, one nobody has
/// continued for this long, for example a canceled one, gives its place to a
/// new download. It can still go on later from a fresh snapshot.
const IDLE_FOR: Duration = Duration::from_secs(60);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: String,
    pub collection_id: String,
    pub file_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directory: Vec<String>,
    pub version: String,
    pub size: u64,
    pub token: Option<String>,
    pub offset: u64,
    pub length: u32,
}
#[derive(Serialize)]
pub struct Window {
    pub token: String,
    pub bytes: usize,
    pub total: u64,
    pub sha256: String,
    pub done: bool,
}

/// A refusal that clears by itself: the requester asks again shortly.
#[derive(Debug)]
struct Busy(&'static str);
impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Busy {}
/// A download this device no longer has: it expired, or the device
/// restarted. The requester asks again without its token.
#[derive(Debug)]
struct Expired;
impl std::fmt::Display for Expired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("This download expired. Start it again.")
    }
}
impl std::error::Error for Expired {}

struct Cached {
    peer: String,
    collection: String,
    file: String,
    directory: Vec<String>,
    version: String,
    touched: Instant,
    finished: bool,
    snapshot: Arc<storage::Snapshot>,
}
pub(super) struct State {
    directory: PathBuf,
    entries: Arc<Mutex<BTreeMap<String, Cached>>>,
    requests: Mutex<(Instant, u32, u32)>,
}
struct PendingSnapshot {
    entries: Arc<Mutex<BTreeMap<String, Cached>>>,
    token: Option<String>,
}
impl Drop for PendingSnapshot {
    fn drop(&mut self) {
        if let Some(token) = &self.token {
            self.entries.lock().expect("download cache").remove(token);
        }
    }
}
impl State {
    pub fn open(state: &Path) -> Result<Self> {
        let directory = state.join("download-snapshots");
        std::fs::create_dir_all(&directory)?;
        let metadata = std::fs::symlink_metadata(&directory)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Invalid download storage"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        }
        // Snapshots belong to the process that made them: the first open in
        // a process removes what an earlier run left behind, for example
        // after a crash. Later opens, when the Spaces change, keep them.
        static OPENED: Mutex<std::collections::BTreeSet<PathBuf>> =
            Mutex::new(std::collections::BTreeSet::new());
        if OPENED
            .lock()
            .expect("download folders")
            .insert(directory.clone())
        {
            for entry in std::fs::read_dir(&directory)? {
                let _ = std::fs::remove_file(entry?.path());
            }
        }
        Ok(Self {
            directory,
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            requests: Mutex::new((Instant::now(), 0, 0)),
        })
    }
    async fn snapshot(
        &self,
        source: Arc<Collection>,
        peer: &str,
        request: &Request,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(
        String,
        Arc<storage::Snapshot>,
        tokio::sync::OwnedSemaphorePermit,
        PendingSnapshot,
    )> {
        source.check_download_version(&request.file_name, &request.version, request.size)?;
        {
            let mut budget = self.requests.lock().expect("download budget");
            if budget.0.elapsed() >= Duration::from_secs(60) {
                *budget = (Instant::now(), 0, 0);
            }
            ensure!(
                budget.1 < 120 && (request.token.is_some() || budget.2 < 8),
                Busy("Too many downloads. Try again in a minute.")
            );
            budget.1 += 1;
            budget.2 += u32::from(request.token.is_none());
        }
        {
            let mut entries = self.entries.lock().expect("download cache");
            entries.retain(|_, entry| entry.touched.elapsed() < Duration::from_secs(900));
            if let Some(token) = &request.token {
                let entry = entries.get_mut(token).ok_or(Expired)?;
                ensure!(
                    entry.peer == peer
                        && entry.collection == request.collection_id
                        && entry.file == request.file_name
                        && entry.directory == request.directory
                        && entry.version == request.version
                        && entry.snapshot.size == request.size,
                    "Download does not belong to this request"
                );
                entry.touched = Instant::now();
                return Ok((
                    token.clone(),
                    entry.snapshot.clone(),
                    permit,
                    PendingSnapshot {
                        entries: self.entries.clone(),
                        token: None,
                    },
                ));
            }
            // The same device asking again for a file without its token, for
            // example after a lost answer, continues the snapshot it has.
            if let Some((token, entry)) = entries.iter_mut().find(|(_, entry)| {
                entry.peer == peer
                    && entry.collection == request.collection_id
                    && entry.file == request.file_name
                    && entry.directory == request.directory
                    && entry.version == request.version
                    && entry.snapshot.size == request.size
            }) {
                entry.touched = Instant::now();
                entry.finished = false;
                return Ok((
                    token.clone(),
                    entry.snapshot.clone(),
                    permit,
                    PendingSnapshot {
                        entries: self.entries.clone(),
                        token: None,
                    },
                ));
            }
            // A download continued later, its snapshot gone, starts a fresh
            // snapshot of the same version at its offset: the version names
            // the file's exact revision, and each window is decided anew.
            entries.retain(|_, entry| !entry.finished);
            if entries.len() >= 2
                && let Some(idle) = entries
                    .iter()
                    .filter(|(_, entry)| {
                        // A window being served holds its snapshot.
                        Arc::strong_count(&entry.snapshot) == 1
                            && entry.touched.elapsed() >= IDLE_FOR
                    })
                    .min_by_key(|(_, entry)| entry.touched)
                    .map(|(token, _)| token.clone())
            {
                entries.remove(&idle);
            }
            ensure!(
                entries.len() < 2,
                Busy("Two downloads are already being prepared. Try again shortly.")
            );
        }
        let file_name = request.file_name.clone();
        let version = request.version.clone();
        let cache = self.directory.clone();
        let mut stored = 0u64;
        for (index, file) in std::fs::read_dir(&cache)?.enumerate() {
            ensure!(index < 16, Busy("Download snapshot cache is full"));
            let metadata = std::fs::symlink_metadata(file?.path())?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "Unexpected download snapshot cache entry"
            );
            stored = stored
                .checked_add(metadata.len())
                .ok_or(Busy("Download snapshot cache is full"))?;
        }
        ensure!(
            stored.saturating_add(request.size) <= 2 * MAX_FILE_BYTES,
            Busy("Download snapshot cache is full")
        );
        // The blocking job retains the permit even if its network task is
        // canceled, preventing concurrent orphan snapshot copies from piling up.
        let (snapshot, permit) = tokio::task::spawn_blocking(move || {
            Ok::<_, anyhow::Error>((
                source.download_snapshot(&file_name, &version, &cache)?,
                permit,
            ))
        })
        .await??;
        ensure!(
            snapshot.size == request.size,
            "File size changed. Refresh the list."
        );
        let token = uuid::Uuid::new_v4().to_string();
        self.entries.lock().expect("download cache").insert(
            token.clone(),
            Cached {
                peer: peer.to_owned(),
                collection: request.collection_id.clone(),
                file: request.file_name.clone(),
                directory: request.directory.clone(),
                version: request.version.clone(),
                touched: Instant::now(),
                finished: false,
                snapshot: snapshot.clone(),
            },
        );
        let pending = PendingSnapshot {
            entries: self.entries.clone(),
            token: Some(token.clone()),
        };
        Ok((token, snapshot, permit, pending))
    }
    /// A window was served: the download went on just now, and is finished
    /// once its last window was.
    fn served(&self, token: &str, done: bool) {
        if let Some(entry) = self.entries.lock().expect("download cache").get_mut(token) {
            entry.touched = Instant::now();
            entry.finished = done;
        }
    }
    /// A snapshot that can no longer be read is not offered again.
    fn forget(&self, token: &str) {
        self.entries.lock().expect("download cache").remove(token);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Header {
    Allowed {
        intent: Value,
        decision: Value,
        attestation: Value,
        prepared: Value,
    },
    Denied,
    /// Not now; ask again shortly.
    Busy,
    /// This device no longer has the download's token.
    Expired,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    body: Value,
    proof: wire::Proof,
}

async fn send_header(send: &mut SendStream, header: &Header) -> Result<()> {
    let bytes = serde_json::to_vec(header)?;
    ensure!(bytes.len() <= MAX_HEADER, "Download header too large");
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}
async fn receive_header(recv: &mut RecvStream) -> Result<Header> {
    let mut size = [0; 4];
    recv.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(
        size > 0 && size <= MAX_HEADER,
        "Invalid download header size"
    );
    let mut bytes = vec![0; size];
    recv.read_exact(&mut bytes).await?;
    Ok(serde_json::from_value(
        genesis_mesh_sdk::parse_strict_json(std::str::from_utf8(&bytes)?)?,
    )?)
}
pub(in crate::session) fn protocol(request: &Request) -> Protocol {
    if request.directory.is_empty() {
        Protocol::Download
    } else {
        Protocol::NestedDownload
    }
}
fn domain(request: &Request) -> &'static str {
    if request.directory.is_empty() {
        "genesismesh-connect/download/v1"
    } else {
        "genesismesh-connect/download/v2"
    }
}
fn relative_name(request: &Request) -> String {
    request
        .directory
        .iter()
        .chain(std::iter::once(&request.file_name))
        .cloned()
        .collect::<Vec<_>>()
        .join("/")
}

fn validate(request: &Request) -> Result<()> {
    uuid::Uuid::parse_str(&request.request_id)?;
    storage::name(&request.file_name)?;
    storage::directory(&request.directory)?;
    storage::name(&request.collection_id)?;
    ensure!(
        request.size <= MAX_FILE_BYTES
            && request.offset <= request.size
            && (MIN_WINDOW_BYTES..=MAX_WINDOW_BYTES).contains(&request.length)
            && request.version.len() == 64
            && request.version.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid download request"
    );
    if let Some(token) = &request.token {
        uuid::Uuid::parse_str(token)?;
    }
    Ok(())
}
fn ack_body(intent: &Value, prepared: &Value) -> Result<Value> {
    Ok(
        json!({"domain":"genesismesh-connect/download-ack/v1","intent_digest":genesis_mesh_sdk::canonical_digest(intent)?,
        "prepared_digest":genesis_mesh_sdk::canonical_digest(prepared)?,"sha256":intent["sha256"],
        "window_sha256":intent["window_sha256"],"offset":intent["offset"],"bytes":intent["length"]}),
    )
}

struct Prepared {
    pending: PendingSnapshot,
    /// Held while the window is served, so its place is not given away.
    _snapshot: Arc<storage::Snapshot>,
    token: String,
    file: File,
    length: usize,
    intent: Value,
    decision: Value,
    attestation: Value,
    receipt: Value,
    trust: TrustSnapshot,
}
impl Share {
    async fn prepare_window(
        &self,
        credentials: &Credentials,
        peer: &Value,
        request: &Request,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(Prepared, tokio::sync::OwnedSemaphorePermit)> {
        validate(request)?;
        ensure!(
            request.collection_id == self.config.collection_id,
            "Unknown shared folder"
        );
        let (token, snapshot, permit, pending) = self
            .downloads
            .snapshot(
                Arc::new(self.directory.nested(&request.directory)?),
                &credentials.expected_node,
                request,
                permit,
            )
            .await?;
        let length = u64::from(request.length).min(snapshot.size - request.offset) as usize;
        let snapshot_sha = snapshot.sha256.clone();
        let held = snapshot.clone();
        let offset = request.offset;
        let read = tokio::task::spawn_blocking(move || {
            let (file, digest) = snapshot.window(offset, length)?;
            Ok::<_, anyhow::Error>((file, digest, permit))
        })
        .await?;
        // A snapshot that can no longer be read is gone: the requester asks
        // again and gets a fresh one.
        let Ok((file, window_sha, permit)) = read else {
            self.downloads.forget(&token);
            return Err(Expired.into());
        };
        let mut store = self.trust.lock().await;
        let trust = self.authority.refresh(&mut store).await?;
        drop(store);
        trust.certificate(peer, &credentials.expected_node, Utc::now())?;
        trust.certificate(
            &credentials.identity.certificate,
            &credentials.identity.public_key(),
            Utc::now(),
        )?;
        let intent = json!({"domain":domain(request),"request":request,
            "host_node":credentials.identity.public_key(),"peer_node":credentials.expected_node,
            "host_nonce":uuid::Uuid::new_v4().to_string(),"token":token,"sha256":snapshot_sha,"window_sha256":window_sha,
            "size":request.size,"offset":request.offset,"length":length,"policy_id":self.config.policy_id});
        let context = format!(
            "connect-download:{}",
            genesis_mesh_sdk::canonical_digest(&intent)?
        );
        let attestation_id = self.attestation_id();
        let attestation = self
            .authority
            .attestation(&credentials.identity, &trust, &attestation_id)
            .await?["attestation"]
            .clone();
        let decision = self.authority.evaluate(&credentials.identity,&trust,&attestation_id,&context,
            json!({"collection_id":request.collection_id,"file_name":relative_name(request),"peer_node":credentials.expected_node,
                "sha256":intent["sha256"],"size":request.size}),"connect.collection.read").await?["decision"].clone();
        trust.read_decision(
            &decision,
            &attestation,
            &context,
            &self.config.policy_id,
            &credentials.identity.public_key(),
        )?;
        let receipt = super::receipt(
            &credentials.identity,
            &intent,
            &decision,
            "prepared",
            Value::Null,
        )?;
        self.persist(
            &json!({"receipt":receipt,"intent":intent,"decision":decision,"attestation":attestation,
            "host_certificate":credentials.identity.certificate,"peer_certificate":peer}),
        )?;
        Ok((
            Prepared {
                pending,
                _snapshot: held,
                token,
                file,
                length,
                intent,
                decision,
                attestation,
                receipt,
                trust,
            },
            permit,
        ))
    }
}

pub(in crate::session) async fn serve(
    connection: &Connection,
    local: iroh::EndpointId,
    credentials: &Credentials,
    shares: &Shares,
) -> Result<()> {
    let (mut send, mut recv) = connection.accept_bi().await?;
    let peer = authenticate_for(
        connection,
        local,
        Role::Server,
        credentials,
        &mut send,
        &mut recv,
        if connection.alpn() == Protocol::NestedDownload.alpn() {
            Protocol::NestedDownload
        } else {
            Protocol::Download
        },
    )
    .await?;
    let selected = credentials.for_authenticated(&peer)?;
    let credentials = &selected;
    let request: Request = read_frame(&mut recv).await?;
    ensure!(
        connection.alpn() == protocol(&request).alpn(),
        "Wrong download protocol for path"
    );
    // An unknown Space is refused like any other denial.
    let share = shares.get(&request.collection_id);
    let prepared = match share {
        Some(share) => match share.budget.clone().try_acquire_owned() {
            Ok(permit) => {
                share
                    .prepare_window(credentials, &peer, &request, permit)
                    .await
            }
            Err(_) => Err(Busy("Another file operation is running").into()),
        },
        None => Err(anyhow::anyhow!("Unknown shared folder")),
    };
    let (mut prepared, _permit) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let header = if error.is::<Expired>() {
                Header::Expired
            } else if error.is::<Busy>() {
                Header::Busy
            } else {
                Header::Denied
            };
            send_header(&mut send, &header).await?;
            send.finish()?;
            connection.closed().await;
            return Ok(());
        }
    };
    let share = share.context("Unknown shared folder")?;
    send_header(
        &mut send,
        &Header::Allowed {
            intent: prepared.intent.clone(),
            decision: prepared.decision.clone(),
            attestation: prepared.attestation.clone(),
            prepared: prepared.receipt.clone(),
        },
    )
    .await?;
    let until = super::super::trust::timestamp(&prepared.decision, "decision_valid_until")?
        .min(Utc::now() + chrono::Duration::seconds(5))
        .min(super::super::trust::timestamp(&peer, "expires_at")?)
        .min(super::super::trust::timestamp(
            &credentials.identity.certificate,
            "expires_at",
        )?);
    let mut buffer = zeroize::Zeroizing::new([0u8; 65536]);
    let mut remaining = prepared.length;
    let mut checked = Instant::now() - Duration::from_secs(1);
    while remaining > 0 {
        if checked.elapsed() >= Duration::from_millis(250) {
            prepared
                .trust
                .certificate(&peer, &credentials.expected_node, Utc::now())?;
            prepared.trust.certificate(
                &credentials.identity.certificate,
                &credentials.identity.public_key(),
                Utc::now(),
            )?;
            checked = Instant::now();
        }
        let remaining_time = (until - Utc::now())
            .to_std()
            .context("File permission expired during download")?;
        ensure!(
            !remaining_time.is_zero(),
            "File permission expired during download"
        );
        let count = prepared.file.read(&mut buffer[..remaining.min(65536)])?;
        ensure!(count > 0, "Download snapshot ended early");
        timeout(remaining_time, send.write_all(&buffer[..count]))
            .await
            .context("File permission expired during download")??;
        remaining -= count;
        share.released.fetch_add(count as u64, Ordering::Relaxed);
    }
    let ack: Ack = read_frame(&mut recv).await?;
    ensure!(
        recv.read_to_end(0).await?.is_empty()
            && ack.body == ack_body(&prepared.intent, &prepared.receipt)?,
        "Wrong download acknowledgment"
    );
    wire::verify(
        &ack.proof,
        &genesis_mesh_sdk::canonical_json(&ack.body)?,
        &credentials.expected_node,
    )?;
    prepared
        .trust
        .certificate(&peer, &credentials.expected_node, Utc::now())?;
    prepared.trust.certificate(
        &credentials.identity.certificate,
        &credentials.identity.public_key(),
        Utc::now(),
    )?;
    let confirmation = super::receipt(
        &credentials.identity,
        &prepared.intent,
        &prepared.decision,
        "client_verified",
        serde_json::to_value(&ack)?,
    )?;
    share.persist(&json!({"receipt":confirmation,"intent":prepared.intent,"decision":prepared.decision,
        "attestation":prepared.attestation,"host_certificate":credentials.identity.certificate,"peer_certificate":peer}))?;
    prepared.pending.token = None;
    share.downloads.served(
        &prepared.token,
        request.offset + prepared.length as u64 == request.size,
    );
    write_frame(&mut send, &confirmation).await?;
    send.finish()?;
    connection.closed().await;
    Ok(())
}

pub(in crate::session) async fn receive(
    connection: &Connection,
    local: iroh::EndpointId,
    credentials: &Credentials,
    request: &Request,
    output: &mut File,
) -> Result<Window> {
    validate(request)?;
    let (mut send, mut recv) = connection.open_bi().await?;
    let peer = authenticate_for(
        connection,
        local,
        Role::Client,
        credentials,
        &mut send,
        &mut recv,
        protocol(request),
    )
    .await?;
    write_frame(&mut send, request).await?;
    let (intent, decision, attestation, prepared) = match receive_header(&mut recv).await? {
        Header::Allowed {
            intent,
            decision,
            attestation,
            prepared,
        } => (intent, decision, attestation, prepared),
        Header::Denied => anyhow::bail!(
            "This file isn't available with the current folder permission. Share the folder again on the computer to allow larger files."
        ),
        Header::Busy => {
            anyhow::bail!("The sharing device is busy with other downloads. Try again shortly.")
        }
        Header::Expired => anyhow::bail!("The sharing device no longer has this download."),
    };
    let expected_length = u64::from(request.length).min(request.size - request.offset) as usize;
    ensure!(
        intent["domain"] == domain(request)
            && intent["request"] == serde_json::to_value(request)?
            && intent["host_node"] == credentials.expected_node
            && intent["peer_node"] == credentials.identity.public_key()
            && intent["size"] == request.size
            && intent["offset"] == request.offset
            && intent["length"] == expected_length,
        "Wrong download response"
    );
    let token = intent["token"]
        .as_str()
        .context("Missing download token")?
        .to_owned();
    uuid::Uuid::parse_str(&token)?;
    ensure!(
        request
            .token
            .as_ref()
            .is_none_or(|expected| expected == &token),
        "Wrong download token"
    );
    let digest = intent["sha256"]
        .as_str()
        .context("Missing file digest")?
        .to_owned();
    ensure!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid file digest"
    );
    let context = format!(
        "connect-download:{}",
        genesis_mesh_sdk::canonical_digest(&intent)?
    );
    credentials.trust.read_decision(
        &decision,
        &attestation,
        &context,
        intent["policy_id"]
            .as_str()
            .context("Missing file permission")?,
        &credentials.expected_node,
    )?;
    super::verify_receipt(
        &prepared,
        &credentials.expected_node,
        &intent,
        &decision,
        "prepared",
    )?;
    output.seek(SeekFrom::Start(request.offset))?;
    let mut hash = Sha256::new();
    let mut count = 0usize;
    let mut data = zeroize::Zeroizing::new([0u8; 65536]);
    while count < expected_length {
        let length = (expected_length - count).min(data.len());
        recv.read_exact(&mut data[..length]).await?;
        output.write_all(&data[..length])?;
        hash.update(&data[..length]);
        count += length;
    }
    ensure!(
        intent["window_sha256"] == storage::hex(&hash.finalize()),
        "Download data did not match its digest"
    );
    credentials
        .trust
        .certificate(&peer, &credentials.expected_node, Utc::now())?;
    credentials.trust.certificate(
        &credentials.identity.certificate,
        &credentials.identity.public_key(),
        Utc::now(),
    )?;
    let body = ack_body(&intent, &prepared)?;
    let ack = Ack {
        proof: wire::sign(
            &credentials.identity,
            &genesis_mesh_sdk::canonical_json(&body)?,
        ),
        body,
    };
    write_frame(&mut send, &ack).await?;
    send.finish()?;
    let confirmation: Value = read_frame(&mut recv).await?;
    ensure!(
        recv.read_to_end(0).await?.is_empty(),
        "Unexpected download data"
    );
    super::verify_receipt(
        &confirmation,
        &credentials.expected_node,
        &intent,
        &decision,
        "client_verified",
    )?;
    ensure!(
        confirmation["client_ack"] == serde_json::to_value(&ack)?,
        "Wrong download confirmation"
    );
    credentials
        .trust
        .certificate(&peer, &credentials.expected_node, Utc::now())?;
    credentials.trust.certificate(
        &credentials.identity.certificate,
        &credentials.identity.public_key(),
        Utc::now(),
    )?;
    Ok(Window {
        token,
        bytes: count,
        total: request.size,
        sha256: digest,
        done: request.offset + count as u64 == request.size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshots_left_behind_go_and_an_idle_download_gives_its_place() -> Result<()> {
        let state = tempfile::tempdir()?;
        let cache = state.path().join("download-snapshots");
        std::fs::create_dir_all(&cache)?;
        std::fs::write(cache.join(".tmpLEFT"), b"left by a crash")?;
        let downloads = State::open(state.path())?;
        assert_eq!(std::fs::read_dir(&cache)?.count(), 0);

        let root = tempfile::tempdir()?;
        for name in ["a.bin", "b.bin", "c.bin"] {
            std::fs::write(root.path().join(name), vec![7u8; 70000])?;
        }
        let collection = Arc::new(Collection::open(root.path())?);
        let (files, _) = collection.catalog(None)?;
        let ask = |file: &super::super::catalog::Entry| Request {
            request_id: uuid::Uuid::new_v4().to_string(),
            collection_id: "space".into(),
            file_name: file.name.clone(),
            directory: Vec::new(),
            version: file.version.clone(),
            size: file.bytes,
            token: None,
            offset: 0,
            length: MIN_WINDOW_BYTES,
        };
        let permits = Arc::new(tokio::sync::Semaphore::new(4));
        let mut tokens = Vec::new();
        let mut serving = None;
        for file in &files[..2] {
            let (token, snapshot, _, mut pending) = downloads
                .snapshot(
                    collection.clone(),
                    "peer",
                    &ask(file),
                    permits.clone().acquire_owned().await?,
                )
                .await?;
            pending.token = None;
            tokens.push(token);
            // The second one is serving a window.
            serving = Some(snapshot);
        }
        let third = || async {
            downloads
                .snapshot(
                    collection.clone(),
                    "peer",
                    &ask(&files[2]),
                    permits.clone().acquire_owned().await?,
                )
                .await
        };
        // Both places are taken by downloads that went on just now.
        let refused = third()
            .await
            .err()
            .context("A third download was prepared")?;
        assert!(refused.is::<Busy>());

        // Both go quiet; only the one not serving a window gives its place.
        for entry in downloads
            .entries
            .lock()
            .expect("download cache")
            .values_mut()
        {
            entry.touched = Instant::now() - IDLE_FOR - Duration::from_secs(1);
        }
        let (token, _, _, mut pending) = third().await?;
        pending.token = None;
        {
            let entries = downloads.entries.lock().expect("download cache");
            assert!(!entries.contains_key(&tokens[0]));
            assert!(entries.contains_key(&tokens[1]) && entries.contains_key(&token));
        }
        drop(serving);

        // Opening again in the same process keeps the snapshots in use.
        let _again = State::open(state.path())?;
        assert_eq!(std::fs::read_dir(&cache)?.count(), 2);
        Ok(())
    }
}
