//! Files a device sends into another device's inbox. The receiving device
//! decides: each window asks the authority whether the sender may write the
//! FULL file into this inbox before any byte is accepted. Bytes land in
//! private staging, and only a file whose whole SHA-256 matches what the
//! sender declared is saved, under a name that never replaces an existing
//! file. The receiving device keeps signed receipts; the sender verifies them.
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

pub use super::download::{MAX_FILE_BYTES, MAX_WINDOW_BYTES, MIN_WINDOW_BYTES};
const MAX_HEADER: usize = 512 * 1024;
/// Unfinished files an inbox keeps for its senders, for one sender, and their
/// total size.
const MAX_STAGED: usize = 4;
const MAX_STAGED_PER_SENDER: usize = 2;
const MAX_STAGED_BYTES: u64 = 2 * MAX_FILE_BYTES;
/// An unfinished file nobody continues is dropped after this long.
const STAGED_FOR: Duration = Duration::from_secs(600);
/// How long a window waits for another sender's window to finish.
const WAIT_FOR_TURN: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: String,
    pub collection_id: String,
    pub file_name: String,
    pub size: u64,
    /// The whole file's SHA-256, checked before it is saved.
    pub sha256: String,
    pub token: Option<String>,
    pub offset: u64,
    pub length: u32,
}
#[derive(Debug, Serialize)]
pub struct Window {
    pub token: String,
    pub bytes: usize,
    pub done: bool,
    /// The name the receiving device saved the file under, once done.
    pub saved_as: Option<String>,
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
    /// Allowed, but the inbox has no room or turn for this file just now.
    Busy,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sent {
    body: Value,
    proof: wire::Proof,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    receipt: Value,
    saved_as: Option<String>,
}

struct Staged {
    peer: String,
    collection: String,
    file_name: String,
    size: u64,
    sha256: String,
    received: u64,
    /// The whole file's hash so far: windows arrive in order, so the last
    /// one needs no second pass over the file.
    hash: Sha256,
    touched: Instant,
    file: tempfile::NamedTempFile,
}
/// Why a window was not taken: not allowed, or not just now.
enum Refusal {
    Denied,
    Busy,
}
pub(crate) struct Incoming {
    directory: PathBuf,
    entries: Mutex<BTreeMap<String, Staged>>,
    /// Per sender, so one device cannot use up another's budget.
    requests: Mutex<BTreeMap<String, (Instant, u32, u32)>>,
}
impl Incoming {
    /// One staging area per inbox for the life of the process, so reopening
    /// shares (after any Space changes) keeps files that are arriving.
    pub fn open(state: &Path) -> Result<Arc<Self>> {
        static OPEN: Mutex<BTreeMap<PathBuf, std::sync::Weak<Incoming>>> =
            Mutex::new(BTreeMap::new());
        let directory = state.join("incoming");
        let mut open = OPEN.lock().expect("incoming registry");
        open.retain(|_, incoming| incoming.strong_count() > 0);
        if let Some(incoming) = open.get(&directory).and_then(std::sync::Weak::upgrade) {
            return Ok(incoming);
        }
        // Unfinished files from an earlier run cannot be continued yet.
        if directory.exists() {
            std::fs::remove_dir_all(&directory)?;
        }
        std::fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        }
        let incoming = Arc::new(Self {
            directory: directory.clone(),
            entries: Mutex::new(BTreeMap::new()),
            requests: Mutex::new(BTreeMap::new()),
        });
        open.insert(directory, Arc::downgrade(&incoming));
        Ok(incoming)
    }
    /// Rate limits for one sender, before anything else.
    fn admit(&self, peer: &str, request: &Request) -> Result<()> {
        let mut requests = self.requests.lock().expect("incoming budget");
        requests.retain(|_, budget| budget.0.elapsed() < Duration::from_secs(60));
        let budget = requests
            .entry(peer.to_owned())
            .or_insert((Instant::now(), 0, 0));
        ensure!(
            budget.1 < 120 && (request.token.is_some() || budget.2 < 8),
            "Too many files at once. Try again in a minute."
        );
        budget.1 += 1;
        budget.2 += u32::from(request.token.is_none());
        Ok(())
    }
    /// The token a window carries, or a new one. A continuing window must
    /// match its file exactly; a new file must fit now, checked before any
    /// budget or authority request is spent. Nothing is staged yet.
    fn token(&self, peer: &str, request: &Request) -> std::result::Result<String, Refusal> {
        let mut entries = self.entries.lock().expect("incoming files");
        entries.retain(|_, entry| entry.touched.elapsed() < STAGED_FOR);
        let Some(token) = &request.token else {
            if request.offset != 0 {
                return Err(Refusal::Denied);
            }
            if !room(&entries, peer, request.size) {
                return Err(Refusal::Busy);
            }
            return Ok(uuid::Uuid::new_v4().to_string());
        };
        let entry = entries.get(token).ok_or(Refusal::Denied)?;
        if entry.peer == peer
            && entry.collection == request.collection_id
            && entry.file_name == request.file_name
            && entry.size == request.size
            && entry.sha256 == request.sha256
            && entry.received == request.offset
        {
            Ok(token.clone())
        } else {
            Err(Refusal::Denied)
        }
    }
    /// After the authority allowed the file: its staging file, positioned at
    /// the window, and the file's hash so far. A first window gets a new
    /// staging file if the inbox has room.
    fn claim(
        &self,
        peer: &str,
        token: &str,
        request: &Request,
    ) -> std::result::Result<(File, Sha256), Refusal> {
        let mut entries = self.entries.lock().expect("incoming files");
        entries.retain(|_, entry| entry.touched.elapsed() < STAGED_FOR);
        if let Some(entry) = entries.get_mut(token) {
            // Checked again here: a window that waited its turn may have been
            // overtaken by one for the same offset.
            if entry.peer != peer || entry.received != request.offset {
                return Err(Refusal::Denied);
            }
            entry.touched = Instant::now();
            let mut file = entry.file.reopen().map_err(|_| Refusal::Busy)?;
            file.seek(SeekFrom::Start(request.offset))
                .map_err(|_| Refusal::Busy)?;
            return Ok((file, entry.hash.clone()));
        }
        if request.token.is_some() {
            return Err(Refusal::Denied);
        }
        if !room(&entries, peer, request.size) {
            return Err(Refusal::Busy);
        }
        let file = tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| Refusal::Busy)?;
        let handle = file.reopen().map_err(|_| Refusal::Busy)?;
        entries.insert(
            token.to_owned(),
            Staged {
                peer: peer.to_owned(),
                collection: request.collection_id.clone(),
                file_name: request.file_name.clone(),
                size: request.size,
                sha256: request.sha256.clone(),
                received: 0,
                hash: Sha256::new(),
                touched: Instant::now(),
                file,
            },
        );
        Ok((handle, Sha256::new()))
    }
    /// Record a verified window and the file's hash after it. The finished
    /// file leaves staging with its whole digest.
    fn received(
        &self,
        token: &str,
        offset: u64,
        bytes: u64,
        hash: Sha256,
    ) -> Result<Option<(Staged, String)>> {
        let mut entries = self.entries.lock().expect("incoming files");
        let entry = entries.get_mut(token).context("This transfer expired")?;
        ensure!(
            entry.received == offset,
            "This window does not continue its file"
        );
        entry.received += bytes;
        entry.hash = hash;
        if entry.received < entry.size {
            return Ok(None);
        }
        let staged = entries.remove(token).context("This transfer expired")?;
        let digest = storage::hex(&staged.hash.clone().finalize());
        Ok(Some((staged, digest)))
    }
    fn forget(&self, token: &str) {
        self.entries.lock().expect("incoming files").remove(token);
    }
}

/// Whether the inbox has room for one more unfinished file from `peer`.
fn room(entries: &BTreeMap<String, Staged>, peer: &str, size: u64) -> bool {
    let staged: u64 = entries.values().map(|entry| entry.size).sum();
    let own = entries.values().filter(|entry| entry.peer == peer).count();
    entries.len() < MAX_STAGED
        && own < MAX_STAGED_PER_SENDER
        && staged.saturating_add(size) <= MAX_STAGED_BYTES
}

fn validate(request: &Request) -> Result<()> {
    uuid::Uuid::parse_str(&request.request_id)?;
    // Refused before any byte: a name with no room for " (2)".
    storage::receivable(&request.file_name)?;
    storage::name(&request.collection_id)?;
    ensure!(
        request.size <= MAX_FILE_BYTES
            && request.offset <= request.size
            && (MIN_WINDOW_BYTES..=MAX_WINDOW_BYTES).contains(&request.length)
            && request.sha256.len() == 64
            && request.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid file to send"
    );
    if let Some(token) = &request.token {
        uuid::Uuid::parse_str(token)?;
    }
    Ok(())
}
fn length(request: &Request) -> usize {
    u64::from(request.length).min(request.size - request.offset) as usize
}
fn sent_body(intent: &Value, prepared: &Value, window_sha256: &str) -> Result<Value> {
    Ok(
        json!({"domain":"genesismesh-connect/send-window/v1","intent_digest":genesis_mesh_sdk::canonical_digest(intent)?,
        "prepared_digest":genesis_mesh_sdk::canonical_digest(prepared)?,"sha256":intent["sha256"],
        "window_sha256":window_sha256,"offset":intent["offset"],"bytes":intent["length"]}),
    )
}
fn phase(request: &Request) -> &'static str {
    if request.offset + length(request) as u64 == request.size {
        "received"
    } else {
        "window_received"
    }
}
async fn send_header(send: &mut SendStream, header: &Header) -> Result<()> {
    let bytes = serde_json::to_vec(header)?;
    ensure!(bytes.len() <= MAX_HEADER, "Send header too large");
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}
async fn receive_header(recv: &mut RecvStream) -> Result<Header> {
    let mut size = [0; 4];
    recv.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(size > 0 && size <= MAX_HEADER, "Invalid send header size");
    let mut bytes = vec![0; size];
    recv.read_exact(&mut bytes).await?;
    Ok(serde_json::from_value(
        genesis_mesh_sdk::parse_strict_json(std::str::from_utf8(&bytes)?)?,
    )?)
}
/// Refuse a window: no bytes are read, nothing is staged, and the inbox's
/// turn is given up before waiting for the sender to hang up.
async fn refuse(
    connection: &Connection,
    mut send: SendStream,
    header: Header,
    turn: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<()> {
    drop(turn);
    send_header(&mut send, &header).await?;
    send.finish()?;
    connection.closed().await;
    Ok(())
}

struct Decided {
    intent: Value,
    decision: Value,
    attestation: Value,
    receipt: Value,
    trust: TrustSnapshot,
}
impl Share {
    /// The authority's decision for the whole file, before anything is staged.
    async fn decide_incoming(
        &self,
        credentials: &Credentials,
        peer: &Value,
        request: &Request,
        token: &str,
    ) -> Result<Decided> {
        let mut store = self.trust.lock().await;
        let trust = self.authority.refresh(&mut store).await?;
        drop(store);
        trust.certificate(peer, &credentials.expected_node, Utc::now())?;
        trust.certificate(
            &credentials.identity.certificate,
            &credentials.identity.public_key(),
            Utc::now(),
        )?;
        let intent = json!({"domain":"genesismesh-connect/send/v1","request":request,
            "host_node":credentials.identity.public_key(),"peer_node":credentials.expected_node,
            "host_nonce":uuid::Uuid::new_v4().to_string(),"token":token,"sha256":request.sha256,
            "size":request.size,"offset":request.offset,"length":length(request),
            "policy_id":self.config.policy_id});
        let context = format!(
            "connect-send:{}",
            genesis_mesh_sdk::canonical_digest(&intent)?
        );
        let attestation_id = self.attestation_id();
        let attestation = self
            .authority
            .attestation(&credentials.identity, &trust, &attestation_id)
            .await?["attestation"]
            .clone();
        // The whole file, never the window: chunking never bypasses a size gate.
        let decision = self
            .authority
            .evaluate(
                &credentials.identity,
                &trust,
                &attestation_id,
                &context,
                json!({"collection_id":request.collection_id,"file_name":request.file_name,
                    "peer_node":credentials.expected_node,"sha256":request.sha256,"size":request.size}),
                "connect.inbox.write",
            )
            .await?["decision"]
            .clone();
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
        self.persist(&json!({"receipt":receipt,"intent":intent,"decision":decision,
            "attestation":attestation,"host_certificate":credentials.identity.certificate,"peer_certificate":peer}))?;
        Ok(Decided {
            intent,
            decision,
            attestation,
            receipt,
            trust,
        })
    }
}

/// The receiving side of one window.
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
        Protocol::Send,
    )
    .await?;
    let selected = credentials.for_authenticated(&peer)?;
    let credentials = &selected;
    let request: Request = read_frame(&mut recv).await?;
    let sender = credentials.expected_node.clone();
    // An unknown inbox is refused like any other denial.
    let Some(share) = shares.inbox(&request.collection_id) else {
        return refuse(connection, send, Header::Denied, None).await;
    };
    if validate(&request).is_err() {
        return refuse(connection, send, Header::Denied, None).await;
    }
    // A full inbox says so before the sender's budget or the authority is
    // asked, so a sender waiting for room spends neither.
    let token = match share.incoming.token(&sender, &request) {
        Ok(token) => token,
        Err(Refusal::Denied) => return refuse(connection, send, Header::Denied, None).await,
        Err(Refusal::Busy) => return refuse(connection, send, Header::Busy, None).await,
    };
    if share.incoming.admit(&sender, &request).is_err() {
        return refuse(connection, send, Header::Denied, None).await;
    }
    // Windows from several senders take turns.
    let Ok(Ok(turn)) = timeout(WAIT_FOR_TURN, share.budget.clone().acquire_owned()).await else {
        return refuse(connection, send, Header::Busy, None).await;
    };
    let Ok(decided) = share
        .decide_incoming(credentials, &peer, &request, &token)
        .await
    else {
        return refuse(connection, send, Header::Denied, Some(turn)).await;
    };
    let (mut file, mut whole) = match share.incoming.claim(&sender, &token, &request) {
        Ok(claimed) => claimed,
        Err(Refusal::Denied) => {
            return refuse(connection, send, Header::Denied, Some(turn)).await;
        }
        Err(Refusal::Busy) => return refuse(connection, send, Header::Busy, Some(turn)).await,
    };
    let staged = async {
        send_header(
            &mut send,
            &Header::Allowed {
                intent: decided.intent.clone(),
                decision: decided.decision.clone(),
                attestation: decided.attestation.clone(),
                prepared: decided.receipt.clone(),
            },
        )
        .await?;
        // Bytes are accepted only while the decision and both certificates hold.
        let until = super::super::trust::timestamp(&decided.decision, "decision_valid_until")?
            .min(Utc::now() + chrono::Duration::seconds(30))
            .min(super::super::trust::timestamp(&peer, "expires_at")?)
            .min(super::super::trust::timestamp(
                &credentials.identity.certificate,
                "expires_at",
            )?);
        let expected = length(&request);
        let mut window = Sha256::new();
        let mut buffer = zeroize::Zeroizing::new([0u8; 65536]);
        let mut count = 0;
        while count < expected {
            let remaining_time = (until - Utc::now())
                .to_std()
                .context("The permission to send ended")?;
            let chunk = (expected - count).min(buffer.len());
            timeout(remaining_time, recv.read_exact(&mut buffer[..chunk]))
                .await
                .context("The permission to send ended")??;
            file.write_all(&buffer[..chunk])?;
            window.update(&buffer[..chunk]);
            whole.update(&buffer[..chunk]);
            count += chunk;
        }
        let window_sha256 = storage::hex(&window.finalize());
        let sent: Sent = read_frame(&mut recv).await?;
        ensure!(
            recv.read_to_end(0).await?.is_empty()
                && sent.body == sent_body(&decided.intent, &decided.receipt, &window_sha256)?,
            "The window does not match what was sent"
        );
        wire::verify(
            &sent.proof,
            &genesis_mesh_sdk::canonical_json(&sent.body)?,
            &credentials.expected_node,
        )?;
        decided
            .trust
            .certificate(&peer, &credentials.expected_node, Utc::now())?;
        decided.trust.certificate(
            &credentials.identity.certificate,
            &credentials.identity.public_key(),
            Utc::now(),
        )?;
        file.sync_data()?;
        let finished = share
            .incoming
            .received(&token, request.offset, expected as u64, whole)?;
        Ok::<_, anyhow::Error>((sent, finished))
    }
    .await;
    // The next window may start while this one saves and confirms.
    drop(turn);
    let (sent, finished) = match staged {
        Ok(staged) => staged,
        Err(error) => {
            share.incoming.forget(&token);
            return Err(error);
        }
    };
    // A window the sender cannot learn the outcome of ends its file, so
    // nothing waits in staging for a window that will not come.
    let confirmed = async {
        let mut saved_as = None;
        if let Some((mut finished, digest)) = finished {
            // The whole file must be what the sender declared before it is saved.
            ensure!(
                digest == finished.sha256
                    && finished.file.as_file().metadata()?.len() == finished.size,
                "The file did not match its digest and was not saved"
            );
            let directory = share.directory.clone();
            saved_as = Some(
                tokio::task::spawn_blocking(move || {
                    let name = finished.file_name.clone();
                    directory.commit(&name, finished.file.as_file_mut())
                })
                .await??,
            );
        }
        let confirmation = super::receipt(
            &credentials.identity,
            &decided.intent,
            &decided.decision,
            phase(&request),
            serde_json::to_value(&sent)?,
        )?;
        share.persist(
            &json!({"receipt":confirmation,"intent":decided.intent,"decision":decided.decision,
        "attestation":decided.attestation,"host_certificate":credentials.identity.certificate,
        "peer_certificate":peer,"saved_as":saved_as}),
        )?;
        write_frame(
            &mut send,
            &Confirmation {
                receipt: confirmation,
                saved_as,
            },
        )
        .await?;
        send.finish()?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if confirmed.is_err() {
        share.incoming.forget(&token);
    }
    confirmed?;
    connection.closed().await;
    Ok(())
}

/// The sending side of one window: `input` holds the whole file.
pub(in crate::session) async fn transmit(
    connection: &Connection,
    local: iroh::EndpointId,
    credentials: &Credentials,
    request: &Request,
    input: &mut File,
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
        Protocol::Send,
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
        Header::Denied => anyhow::bail!("This device isn't accepting files from you."),
        Header::Busy => {
            anyhow::bail!("This device is receiving other files. Try again shortly.")
        }
    };
    let expected = length(request);
    // The decision must be for this inbox's own permission.
    let policy_id = format!("connect-{}", request.collection_id);
    ensure!(
        intent["domain"] == "genesismesh-connect/send/v1"
            && intent["request"] == serde_json::to_value(request)?
            && intent["host_node"] == credentials.expected_node
            && intent["peer_node"] == credentials.identity.public_key()
            && intent["sha256"] == request.sha256
            && intent["size"] == request.size
            && intent["offset"] == request.offset
            && intent["length"] == expected
            && intent["policy_id"] == policy_id,
        "Wrong send response"
    );
    let token = intent["token"]
        .as_str()
        .context("Missing transfer token")?
        .to_owned();
    uuid::Uuid::parse_str(&token)?;
    ensure!(
        request.token.as_ref().is_none_or(|t| t == &token),
        "Wrong transfer token"
    );
    let context = format!(
        "connect-send:{}",
        genesis_mesh_sdk::canonical_digest(&intent)?
    );
    credentials.trust.read_decision(
        &decision,
        &attestation,
        &context,
        &policy_id,
        &credentials.expected_node,
    )?;
    super::verify_receipt(
        &prepared,
        &credentials.expected_node,
        &intent,
        &decision,
        "prepared",
    )?;
    input.seek(SeekFrom::Start(request.offset))?;
    let mut hash = Sha256::new();
    let mut buffer = zeroize::Zeroizing::new([0u8; 65536]);
    let mut count = 0;
    while count < expected {
        let chunk = (expected - count).min(buffer.len());
        input.read_exact(&mut buffer[..chunk])?;
        send.write_all(&buffer[..chunk]).await?;
        hash.update(&buffer[..chunk]);
        count += chunk;
    }
    let body = sent_body(&intent, &prepared, &storage::hex(&hash.finalize()))?;
    let sent = Sent {
        proof: wire::sign(
            &credentials.identity,
            &genesis_mesh_sdk::canonical_json(&body)?,
        ),
        body,
    };
    write_frame(&mut send, &sent).await?;
    send.finish()?;
    let confirmation: Confirmation = read_frame(&mut recv).await?;
    ensure!(
        recv.read_to_end(0).await?.is_empty(),
        "Unexpected send data"
    );
    super::verify_receipt(
        &confirmation.receipt,
        &credentials.expected_node,
        &intent,
        &decision,
        phase(request),
    )?;
    ensure!(
        confirmation.receipt["client_ack"] == serde_json::to_value(&sent)?
            && confirmation.saved_as.is_some() == (phase(request) == "received"),
        "Wrong send confirmation"
    );
    if let Some(name) = &confirmation.saved_as {
        storage::name(name)?;
    }
    credentials
        .trust
        .certificate(&peer, &credentials.expected_node, Utc::now())?;
    Ok(Window {
        token,
        bytes: count,
        done: phase(request) == "received",
        saved_as: confirmation.saved_as,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(token: Option<&str>, offset: u64, size: u64) -> Request {
        Request {
            request_id: uuid::Uuid::new_v4().to_string(),
            collection_id: "inbox".into(),
            file_name: "photo.jpg".into(),
            size,
            sha256: "0".repeat(64),
            token: token.map(str::to_owned),
            offset,
            length: MIN_WINDOW_BYTES,
        }
    }

    #[test]
    fn staging_follows_its_file_in_order_and_within_its_limits() -> Result<()> {
        let state = tempfile::tempdir()?;
        let incoming = Incoming::open(state.path())?;
        assert!(
            Arc::ptr_eq(&incoming, &Incoming::open(state.path())?),
            "Reopening an inbox keeps the files arriving in it"
        );
        let size = 3 * u64::from(MIN_WINDOW_BYTES);
        let first = request(None, 0, size);
        let token = incoming.token("phone", &first).ok().context("token")?;
        let (_, hash) = incoming
            .claim("phone", &token, &first)
            .ok()
            .context("claim")?;
        assert!(
            incoming
                .received(&token, 0, u64::from(MIN_WINDOW_BYTES), hash)?
                .is_none()
        );
        // A window must continue exactly where the file stands, for its sender.
        let stale = request(Some(&token), 0, size);
        assert!(incoming.token("phone", &stale).is_err());
        assert!(matches!(
            incoming.claim("phone", &token, &stale),
            Err(Refusal::Denied)
        ));
        let next = request(Some(&token), u64::from(MIN_WINDOW_BYTES), size);
        assert!(incoming.token("tablet", &next).is_err());
        assert!(matches!(
            incoming.claim("tablet", &token, &next),
            Err(Refusal::Denied)
        ));
        assert!(incoming.claim("phone", &token, &next).is_ok());
        assert!(
            incoming
                .received(&token, 0, u64::from(MIN_WINDOW_BYTES), Sha256::new())
                .is_err(),
            "A window recorded at the wrong offset is refused"
        );
        // One sender keeps at most two unfinished files; the inbox, four.
        let other = incoming
            .token("phone", &request(None, 0, 10))
            .ok()
            .context("token")?;
        assert!(
            incoming
                .claim("phone", &other, &request(None, 0, 10))
                .is_ok()
        );
        assert!(
            matches!(
                incoming.token("phone", &request(None, 0, 10)),
                Err(Refusal::Busy)
            ),
            "A full inbox says so before a budget or a decision is spent"
        );
        for sender in ["tablet", "laptop"] {
            let token = incoming
                .token(sender, &request(None, 0, 10))
                .ok()
                .context("token")?;
            let _ = incoming.claim(sender, &token, &request(None, 0, 10));
        }
        assert!(matches!(
            incoming.token("watch", &request(None, 0, 10)),
            Err(Refusal::Busy)
        ));
        // An abandoned file goes, and its window is refused after that.
        incoming
            .entries
            .lock()
            .unwrap()
            .get_mut(&token)
            .context("entry")?
            .touched = Instant::now() - STAGED_FOR;
        assert!(incoming.token("phone", &next).is_err());
        assert!(matches!(
            incoming.claim("phone", &token, &next),
            Err(Refusal::Denied)
        ));
        // Each sender has its own budget of new files.
        for _ in 0..8 {
            incoming.admit("phone", &request(None, 0, 10))?;
        }
        assert!(incoming.admit("phone", &request(None, 0, 10)).is_err());
        assert!(incoming.admit("tablet", &request(None, 0, 10)).is_ok());
        Ok(())
    }
}
