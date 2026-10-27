//! Files a device sends into another device's inbox. The receiving device
//! decides: each window asks the authority whether the sender may write the
//! FULL file into this inbox before any byte is accepted. Bytes land in
//! private staging, and only a file whose whole SHA-256 matches what the
//! sender declared is saved, under a name that never replaces an existing
//! file. Both sides keep signed receipts.
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
/// Unfinished files a device keeps for its senders, and their total size.
const MAX_STAGED: usize = 4;
const MAX_STAGED_BYTES: u64 = 2 * MAX_FILE_BYTES;
/// An unfinished file nobody continues is dropped after this long.
const STAGED_FOR: Duration = Duration::from_secs(3600);

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
    touched: Instant,
    file: tempfile::NamedTempFile,
}
pub(super) struct Incoming {
    directory: PathBuf,
    entries: Mutex<BTreeMap<String, Staged>>,
    requests: Mutex<(Instant, u32, u32)>,
}
impl Incoming {
    pub fn open(state: &Path) -> Result<Self> {
        let directory = state.join("incoming");
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
        Ok(Self {
            directory,
            entries: Mutex::new(BTreeMap::new()),
            requests: Mutex::new((Instant::now(), 0, 0)),
        })
    }
    /// The staged file a window continues, or a new one for a first window.
    /// Returns its token and the staging file, positioned at the window.
    fn window(&self, peer: &str, request: &Request) -> Result<(String, File)> {
        {
            let mut budget = self.requests.lock().expect("incoming budget");
            if budget.0.elapsed() >= Duration::from_secs(60) {
                *budget = (Instant::now(), 0, 0);
            }
            ensure!(
                budget.1 < 120 && (request.token.is_some() || budget.2 < 8),
                "Too many files at once. Try again in a minute."
            );
            budget.1 += 1;
            budget.2 += u32::from(request.token.is_none());
        }
        let mut entries = self.entries.lock().expect("incoming files");
        entries.retain(|_, entry| entry.touched.elapsed() < STAGED_FOR);
        if let Some(token) = &request.token {
            let entry = entries
                .get_mut(token)
                .context("This transfer expired. Send the file again.")?;
            ensure!(
                entry.peer == peer
                    && entry.collection == request.collection_id
                    && entry.file_name == request.file_name
                    && entry.size == request.size
                    && entry.sha256 == request.sha256
                    && entry.received == request.offset,
                "This window does not continue its file"
            );
            entry.touched = Instant::now();
            let mut file = entry.file.reopen()?;
            file.seek(SeekFrom::Start(request.offset))?;
            return Ok((token.clone(), file));
        }
        ensure!(request.offset == 0, "Start a new file from the beginning");
        let staged: u64 = entries.values().map(|entry| entry.size).sum();
        ensure!(
            entries.len() < MAX_STAGED && staged.saturating_add(request.size) <= MAX_STAGED_BYTES,
            "This device is receiving other files. Try again shortly."
        );
        let file = tempfile::NamedTempFile::new_in(&self.directory)?;
        let handle = file.reopen()?;
        let token = uuid::Uuid::new_v4().to_string();
        entries.insert(
            token.clone(),
            Staged {
                peer: peer.to_owned(),
                collection: request.collection_id.clone(),
                file_name: request.file_name.clone(),
                size: request.size,
                sha256: request.sha256.clone(),
                received: 0,
                touched: Instant::now(),
                file,
            },
        );
        Ok((token, handle))
    }
    /// Record a received window; the finished file leaves staging.
    fn received(&self, token: &str, bytes: u64) -> Result<Option<Staged>> {
        let mut entries = self.entries.lock().expect("incoming files");
        let entry = entries.get_mut(token).context("This transfer expired")?;
        entry.received += bytes;
        if entry.received == entry.size {
            return Ok(entries.remove(token));
        }
        Ok(None)
    }
    fn forget(&self, token: &str) {
        self.entries.lock().expect("incoming files").remove(token);
    }
}

fn validate(request: &Request) -> Result<()> {
    uuid::Uuid::parse_str(&request.request_id)?;
    storage::name(&request.file_name)?;
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

struct Prepared {
    token: String,
    file: File,
    intent: Value,
    decision: Value,
    attestation: Value,
    receipt: Value,
    trust: TrustSnapshot,
}
impl Share {
    async fn prepare_incoming(
        &self,
        credentials: &Credentials,
        peer: &Value,
        request: &Request,
    ) -> Result<Prepared> {
        validate(request)?;
        ensure!(
            request.collection_id == self.config.collection_id
                && self.config.kind == SpaceKind::Inbox,
            "Unknown inbox"
        );
        let (token, file) = self.incoming.window(&credentials.expected_node, request)?;
        let prepared = async {
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
            Ok::<_, anyhow::Error>(Prepared {
                token: token.clone(),
                file,
                intent,
                decision,
                attestation,
                receipt,
                trust,
            })
        }
        .await;
        if prepared.is_err() {
            self.incoming.forget(&token);
        }
        prepared
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
    // An unknown inbox is refused like any other denial.
    let share = shares.inbox(&request.collection_id);
    let prepared = match share {
        Some(share) => {
            let permit = share
                .budget
                .clone()
                .try_acquire_owned()
                .context("Another file operation is running")?;
            share
                .prepare_incoming(credentials, &peer, &request)
                .await
                .map(|prepared| (prepared, permit))
        }
        None => Err(anyhow::anyhow!("Unknown inbox")),
    };
    let (mut prepared, _permit) = match prepared {
        Ok(prepared) => prepared,
        Err(_) => {
            send_header(&mut send, &Header::Denied).await?;
            send.finish()?;
            connection.closed().await;
            return Ok(());
        }
    };
    let share = share.context("Unknown inbox")?;
    let staged = async {
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
        // Bytes are accepted only while the decision and both certificates hold.
        let until = super::super::trust::timestamp(&prepared.decision, "decision_valid_until")?
            .min(Utc::now() + chrono::Duration::seconds(30))
            .min(super::super::trust::timestamp(&peer, "expires_at")?)
            .min(super::super::trust::timestamp(
                &credentials.identity.certificate,
                "expires_at",
            )?);
        let expected = length(&request);
        let mut hash = Sha256::new();
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
            prepared.file.write_all(&buffer[..chunk])?;
            hash.update(&buffer[..chunk]);
            count += chunk;
        }
        let window_sha256 = storage::hex(&hash.finalize());
        let sent: Sent = read_frame(&mut recv).await?;
        ensure!(
            recv.read_to_end(0).await?.is_empty()
                && sent.body == sent_body(&prepared.intent, &prepared.receipt, &window_sha256)?,
            "The window does not match what was sent"
        );
        wire::verify(
            &sent.proof,
            &genesis_mesh_sdk::canonical_json(&sent.body)?,
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
        prepared.file.sync_data()?;
        Ok::<_, anyhow::Error>(sent)
    }
    .await;
    let sent = match staged {
        Ok(sent) => sent,
        Err(error) => {
            share.incoming.forget(&prepared.token);
            return Err(error);
        }
    };
    let mut saved_as = None;
    if let Some(mut finished) = share
        .incoming
        .received(&prepared.token, length(&request) as u64)?
    {
        // The whole file must be what the sender declared before it is saved.
        let directory = share.directory.clone();
        let name = finished.file_name.clone();
        let declared = finished.sha256.clone();
        saved_as = Some(
            tokio::task::spawn_blocking(move || {
                let file = finished.file.as_file_mut();
                file.seek(SeekFrom::Start(0))?;
                let mut hash = Sha256::new();
                let mut buffer = vec![0u8; 65536];
                loop {
                    let count = file.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    hash.update(&buffer[..count]);
                }
                ensure!(
                    storage::hex(&hash.finalize()) == declared
                        && file.metadata()?.len() == finished.size,
                    "The file did not match its digest and was not saved"
                );
                directory.commit(&name, file)
            })
            .await??,
        );
    }
    let confirmation = super::receipt(
        &credentials.identity,
        &prepared.intent,
        &prepared.decision,
        phase(&request),
        serde_json::to_value(&sent)?,
    )?;
    share.persist(
        &json!({"receipt":confirmation,"intent":prepared.intent,"decision":prepared.decision,
        "attestation":prepared.attestation,"host_certificate":credentials.identity.certificate,
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
    let Header::Allowed {
        intent,
        decision,
        attestation,
        prepared,
    } = receive_header(&mut recv).await?
    else {
        anyhow::bail!("This device isn't accepting files from you.");
    };
    let expected = length(request);
    ensure!(
        intent["domain"] == "genesismesh-connect/send/v1"
            && intent["request"] == serde_json::to_value(request)?
            && intent["host_node"] == credentials.expected_node
            && intent["peer_node"] == credentials.identity.public_key()
            && intent["sha256"] == request.sha256
            && intent["size"] == request.size
            && intent["offset"] == request.offset
            && intent["length"] == expected,
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
        intent["policy_id"]
            .as_str()
            .context("Missing inbox permission")?,
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
