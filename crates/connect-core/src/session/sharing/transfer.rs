use super::super::wire::{self, Protocol, Role, authenticate_for, read_frame, write_frame};
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iroh::endpoint::{Connection, RecvStream, SendStream};
const MAX_HEADER: usize = 512 * 1024;
#[derive(Deserialize, Serialize)]
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
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    data: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    body: Value,
    proof: wire::Proof,
}
#[derive(Serialize)]
pub struct ReadReport {
    pub collection_id: String,
    pub file_name: String,
    pub sha256: String,
    pub bytes: usize,
    pub text: Option<String>,
    pub receipt_id: String,
}
async fn header(send: &mut SendStream, value: &Header) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_HEADER, "Read header too large");
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}
async fn read_header(recv: &mut RecvStream) -> Result<Header> {
    let mut size = [0; 4];
    recv.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(size > 0 && size <= MAX_HEADER, "Invalid read header size");
    let mut bytes = vec![0; size];
    recv.read_exact(&mut bytes).await?;
    Ok(serde_json::from_value(
        genesis_mesh_sdk::parse_strict_json(std::str::from_utf8(&bytes)?)?,
    )?)
}
fn ack_body(intent: &Value, prepared: &Value) -> Result<Value> {
    Ok(
        json!({"domain":"genesismesh-connect/read-ack/v1","intent_digest":genesis_mesh_sdk::canonical_digest(intent)?,"prepared_digest":genesis_mesh_sdk::canonical_digest(prepared)?,"sha256":intent["sha256"],"bytes":intent["size"]}),
    )
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
        Protocol::Read,
    )
    .await?;
    let request: ReadRequest = read_frame(&mut recv).await?;
    let selected = credentials.for_authenticated(&peer)?;
    let credentials = &selected;
    uuid::Uuid::parse_str(&request.request_id)?;
    // An unknown Space is refused like any other denial: nothing tells the
    // peer whether it exists.
    let share = shares.get(&request.collection_id);
    let _permit = match share {
        Some(share) => Some(
            share
                .budget
                .try_acquire()
                .context("Another read is in progress")?,
        ),
        None => None,
    };
    let prepared = match async {
        share
            .context("Unknown shared folder")?
            .prepare(credentials, &peer, &request)
            .await
    }
    .await
    {
        Ok(prepared) => prepared,
        Err(_) => {
            header(&mut send, &Header::Denied).await?;
            send.finish()?;
            connection.closed().await;
            return Ok(());
        }
    };
    let share = share.context("Unknown shared folder")?;
    header(
        &mut send,
        &Header::Allowed {
            intent: prepared.intent.clone(),
            decision: prepared.decision.clone(),
            attestation: prepared.attestation.clone(),
            prepared: prepared.receipt.clone(),
        },
    )
    .await?;
    for bytes in prepared.bytes.chunks(8192) {
        ensure!(
            prepared.started.elapsed() < Duration::from_secs(5),
            "Read release window ended"
        );
        prepared
            .trust
            .certificate(&peer, &credentials.expected_node, Utc::now())?;
        prepared.trust.certificate(
            &credentials.identity.certificate,
            &credentials.identity.public_key(),
            Utc::now(),
        )?;
        ensure!(
            Utc::now()
                < super::super::trust::timestamp(&prepared.decision, "decision_valid_until")?,
            "Read decision expired"
        );
        write_frame(
            &mut send,
            &Chunk {
                data: STANDARD.encode(bytes),
            },
        )
        .await?;
        share
            .released
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    }
    let ack: Ack = read_frame(&mut recv).await?;
    ensure!(
        recv.read_to_end(0).await?.is_empty(),
        "Unexpected read acknowledgement data"
    );
    ensure!(
        ack.body == ack_body(&prepared.intent, &prepared.receipt)?,
        "Wrong read acknowledgement"
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
    let confirmation = receipt(
        &credentials.identity,
        &prepared.intent,
        &prepared.decision,
        "client_verified",
        serde_json::to_value(&ack)?,
    )?;
    share.persist(&json!({"receipt":confirmation,"intent":prepared.intent,"decision":prepared.decision,"attestation":prepared.attestation,"host_certificate":credentials.identity.certificate,"peer_certificate":peer}))?;
    write_frame(&mut send, &confirmation).await?;
    send.finish()?;
    connection.closed().await;
    Ok(())
}

pub(in crate::session) async fn receive(
    connection: &Connection,
    local: iroh::EndpointId,
    credentials: &Credentials,
    request: &ReadRequest,
) -> Result<ReadReport> {
    storage::name(&request.file_name)?;
    uuid::Uuid::parse_str(&request.request_id)?;
    let (mut send, mut recv) = connection.open_bi().await?;
    let peer = authenticate_for(
        connection,
        local,
        Role::Client,
        credentials,
        &mut send,
        &mut recv,
        Protocol::Read,
    )
    .await?;
    write_frame(&mut send, request).await?;
    let Header::Allowed {
        intent,
        decision,
        attestation,
        prepared,
    } = read_header(&mut recv).await?
    else {
        anyhow::bail!("Read unavailable or denied")
    };
    ensure!(
        intent["request"] == serde_json::to_value(request)?
            && intent["host_node"] == credentials.expected_node
            && intent["peer_node"] == credentials.identity.public_key(),
        "Wrong read response"
    );
    let size = intent["size"]
        .as_u64()
        .filter(|n| *n <= storage::MAX_FILE as u64)
        .context("Invalid read size")? as usize;
    let context_id = format!(
        "connect-read:{}",
        genesis_mesh_sdk::canonical_digest(&intent)?
    );
    credentials.trust.read_decision(
        &decision,
        &attestation,
        &context_id,
        intent["policy_id"]
            .as_str()
            .context("Missing read policy")?,
        &credentials.expected_node,
    )?;
    verify_receipt(
        &prepared,
        &credentials.expected_node,
        &intent,
        &decision,
        "prepared",
    )?;
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(size));
    while bytes.len() < size {
        let chunk: Chunk = read_frame(&mut recv).await?;
        let chunk = STANDARD.decode(chunk.data)?;
        ensure!(
            !chunk.is_empty() && chunk.len() <= 8192 && bytes.len() + chunk.len() <= size,
            "Invalid read data size"
        );
        bytes.extend_from_slice(&chunk);
    }
    let digest = sha(&bytes);
    ensure!(
        intent["sha256"] == digest
            && request
                .expected_sha256
                .as_ref()
                .is_none_or(|v| v == &digest),
        "File digest mismatch"
    );
    let body = ack_body(&intent, &prepared)?;
    credentials
        .trust
        .certificate(&peer, &credentials.expected_node, Utc::now())?;
    credentials.trust.certificate(
        &credentials.identity.certificate,
        &credentials.identity.public_key(),
        Utc::now(),
    )?;
    let ack = Ack {
        proof: wire::sign(
            &credentials.identity,
            &genesis_mesh_sdk::canonical_json(&body)?,
        ),
        body,
    };
    write_frame(&mut send, &ack).await?;
    send.finish()?;
    let confirmed: Value = read_frame(&mut recv).await?;
    ensure!(
        recv.read_to_end(0).await?.is_empty(),
        "Unexpected read response data"
    );
    verify_receipt(
        &confirmed,
        &credentials.expected_node,
        &intent,
        &decision,
        "client_verified",
    )?;
    ensure!(
        confirmed["client_ack"] == serde_json::to_value(&ack)?,
        "Wrong receipt acknowledgement"
    );
    credentials
        .trust
        .certificate(&peer, &credentials.expected_node, Utc::now())?;
    credentials.trust.certificate(
        &credentials.identity.certificate,
        &credentials.identity.public_key(),
        Utc::now(),
    )?;
    Ok(ReadReport {
        collection_id: request.collection_id.clone(),
        file_name: request.file_name.clone(),
        sha256: digest,
        bytes: size,
        text: std::str::from_utf8(&bytes).ok().map(str::to_owned),
        receipt_id: confirmed["receipt_id"]
            .as_str()
            .context("Missing receipt")?
            .to_owned(),
    })
}
