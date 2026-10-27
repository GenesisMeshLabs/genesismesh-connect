use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use genesis_mesh_sdk::{
    canonical_digest, canonical_json, parse_strict_json, sign_canonical, verify_canonical,
};
use iroh::{
    EndpointId,
    endpoint::{Connection, RecvStream, SendStream},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use super::{Credentials, SessionIdentity, TrustSnapshot};

pub(super) const ALPN: &[u8] = b"genesismesh-connect/session/1";
pub(super) const MAX_FRAME: usize = 16 * 1024;
const EXPORTER_LABEL: &[u8] = b"EXPORTER-GenesisMesh-Connect-session-v1";

#[derive(Clone, Copy)]
pub(super) enum Protocol {
    Diagnostic,
    Authority,
    Enrollment,
    Read,
    Pair,
    List,
    Catalog,
    Download,
    Browse,
    NestedDownload,
    Send,
}
impl Protocol {
    pub fn alpn(self) -> &'static [u8] {
        match self {
            Self::Diagnostic => ALPN,
            Self::Authority => b"genesismesh-connect/authority/1",
            Self::Enrollment => b"genesismesh-connect/enroll/1",
            Self::Read => b"genesismesh-connect/read/1",
            Self::Pair => b"genesismesh-connect/pair/1",
            Self::List => b"genesismesh-connect/list/1",
            Self::Catalog => b"genesismesh-connect/catalog/1",
            Self::Download => b"genesismesh-connect/download/1",
            Self::Browse => b"genesismesh-connect/browse/1",
            Self::NestedDownload => b"genesismesh-connect/download/2",
            Self::Send => b"genesismesh-connect/send/1",
        }
    }
    pub(super) fn domain(self) -> &'static str {
        match self {
            Self::Diagnostic => "genesismesh-connect/session-proof",
            Self::Authority => "genesismesh-connect/authority-proof",
            Self::Enrollment => "genesismesh-connect/enrollment-proof",
            Self::Read => "genesismesh-connect/read-proof",
            Self::Pair => "genesismesh-connect/pair-proof",
            Self::List => "genesismesh-connect/list-proof",
            Self::Catalog => "genesismesh-connect/catalog-proof",
            Self::Download => "genesismesh-connect/download-proof",
            Self::Browse => "genesismesh-connect/browse-proof",
            Self::NestedDownload => "genesismesh-connect/download-proof/v2",
            Self::Send => "genesismesh-connect/send-proof",
        }
    }
    fn certificate(self, trust: &TrustSnapshot, cert: &Value, node: &str) -> Result<()> {
        match self {
            Self::Diagnostic
            | Self::Read
            | Self::Pair
            | Self::List
            | Self::Catalog
            | Self::Browse
            | Self::NestedDownload
            | Self::Send
            | Self::Download => trust.certificate(cert, node, Utc::now()),
            Self::Authority | Self::Enrollment => {
                trust.renewable_certificate(cert, node, Utc::now())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Role {
    Client,
    Server,
}

impl Role {
    fn other(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Hello {
    pub version: u8,
    pub role: Role,
    pub endpoint: EndpointId,
    pub network: String,
    pub root: String,
    pub nonce: [u8; 32],
    pub certificate: Value,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    pub signature: String,
}

pub(super) async fn write_frame<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_FRAME, "Frame too large");
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_FRAME,
        "Invalid frame length"
    );
    let value = parse_strict_json(std::str::from_utf8(bytes)?)?;
    Ok(serde_json::from_value(value)?)
}

pub(super) async fn read_frame<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let mut size = [0; 4];
    recv.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(size > 0 && size <= MAX_FRAME, "Invalid frame length");
    let mut bytes = vec![0; size];
    recv.read_exact(&mut bytes).await?;
    decode(&bytes)
}

pub(super) fn hello(
    role: Role,
    endpoint: EndpointId,
    identity: &SessionIdentity,
    trust: &TrustSnapshot,
) -> Result<Hello> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).context("Cannot generate session challenge")?;
    Ok(Hello {
        version: 1,
        role,
        endpoint,
        network: trust.network().to_owned(),
        root: trust.root().to_owned(),
        nonce,
        certificate: identity.certificate.clone(),
    })
}

fn check_hello(
    peer: &Hello,
    role: Role,
    connection: &Connection,
    trust: &TrustSnapshot,
    expected_node: &str,
    protocol: Protocol,
) -> Result<()> {
    ensure!(peer.version == 1, "Unsupported session version");
    ensure!(peer.role == role.other(), "Wrong session role");
    ensure!(
        peer.endpoint == connection.remote_id(),
        "Wrong transport endpoint"
    );
    ensure!(
        peer.network == trust.network() && peer.root == trust.root(),
        "Wrong session network or root"
    );
    protocol.certificate(trust, &peer.certificate, expected_node)
}

/// The exporter is derived from this completed Iroh TLS connection, never from
/// a peer-supplied value. Credential digests include the exact presented JSON.
#[cfg(test)]
pub(super) fn transcript(
    client: &Hello,
    server: &Hello,
    exporter: &[u8; 32],
    signer: Role,
) -> Result<String> {
    transcript_for(client, server, exporter, signer, Protocol::Diagnostic)
}

pub(super) fn transcript_for(
    client: &Hello,
    server: &Hello,
    exporter: &[u8; 32],
    signer: Role,
    protocol: Protocol,
) -> Result<String> {
    canonical_json(&json!({
        "domain": protocol.domain(), "version": 1,
        "alpn": std::str::from_utf8(protocol.alpn())?, "network": client.network, "root": client.root,
        "client": {"role": client.role, "endpoint": client.endpoint, "nonce": client.nonce, "certificate_digest": canonical_digest(&client.certificate)?},
        "server": {"role": server.role, "endpoint": server.endpoint, "nonce": server.nonce, "certificate_digest": canonical_digest(&server.certificate)?},
        "tls_exporter": STANDARD.encode(exporter), "signer": signer,
    })).map_err(Into::into)
}

#[cfg(test)]
pub(super) fn exporter(connection: &Connection) -> Result<[u8; 32]> {
    exporter_for(connection, Protocol::Diagnostic)
}

pub(super) fn exporter_for(connection: &Connection, protocol: Protocol) -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    connection
        .export_keying_material(
            &mut bytes,
            match protocol {
                Protocol::Diagnostic => EXPORTER_LABEL,
                Protocol::Authority => b"EXPORTER-GenesisMesh-Connect-authority-v1",
                Protocol::Enrollment => b"EXPORTER-GenesisMesh-Connect-enrollment-v1",
                Protocol::Read => b"EXPORTER-GenesisMesh-Connect-read-v1",
                Protocol::Pair => b"EXPORTER-GenesisMesh-Connect-pair-v1",
                Protocol::List => b"EXPORTER-GenesisMesh-Connect-list-v1",
                Protocol::Catalog => b"EXPORTER-GenesisMesh-Connect-catalog-v1",
                Protocol::Download => b"EXPORTER-GenesisMesh-Connect-download-v1",
                Protocol::Browse => b"EXPORTER-GenesisMesh-Connect-browse-v1",
                Protocol::NestedDownload => b"EXPORTER-GenesisMesh-Connect-download-v2",
                Protocol::Send => b"EXPORTER-GenesisMesh-Connect-send-v1",
            },
            protocol.alpn(),
        )
        .map_err(|_| anyhow::anyhow!("TLS exporter unavailable"))?;
    Ok(bytes)
}

pub(super) fn sign(identity: &SessionIdentity, payload: &str) -> Proof {
    sign_key(&identity.key, payload)
}

pub(super) fn sign_key(key: &ed25519_dalek::SigningKey, payload: &str) -> Proof {
    Proof {
        signature: sign_canonical(payload, "connect-node", key)["sig"]
            .as_str()
            .expect("SDK signature")
            .to_owned(),
    }
}

pub(super) fn verify(proof: &Proof, payload: &str, expected_node: &str) -> Result<()> {
    ensure!(
        verify_canonical(payload, &proof.signature, &[expected_node.to_owned()]),
        "Invalid session proof"
    );
    Ok(())
}

pub(super) async fn authenticate(
    connection: &Connection,
    local_id: EndpointId,
    role: Role,
    credentials: &Credentials,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<Value> {
    authenticate_for(
        connection,
        local_id,
        role,
        credentials,
        send,
        recv,
        Protocol::Diagnostic,
    )
    .await
}

pub(super) async fn authenticate_for(
    connection: &Connection,
    local_id: EndpointId,
    role: Role,
    credentials: &Credentials,
    send: &mut SendStream,
    recv: &mut RecvStream,
    protocol: Protocol,
) -> Result<Value> {
    let Credentials {
        identity,
        trust,
        expected_node,
        ..
    } = credentials;
    ensure!(
        connection.alpn() == protocol.alpn(),
        "Wrong session protocol"
    );
    protocol.certificate(trust, &identity.certificate, &identity.public_key())?;
    let local = hello(role, local_id, identity, trust)?;
    write_frame(send, &local).await?;
    let peer: Hello = read_frame(recv).await?;
    let expected_node = if role == Role::Server {
        let node = peer.certificate["node_public_key"]
            .as_str()
            .context("Missing peer identity")?;
        ensure!(
            credentials.permits(node),
            "This device has not been approved"
        );
        node
    } else {
        expected_node.as_str()
    };
    check_hello(&peer, role, connection, trust, expected_node, protocol)?;
    let (client, server) = if role == Role::Client {
        (&local, &peer)
    } else {
        (&peer, &local)
    };
    let binding = exporter_for(connection, protocol)?;
    write_frame(
        send,
        &sign(
            identity,
            &transcript_for(client, server, &binding, role, protocol)?,
        ),
    )
    .await?;
    let proof: Proof = read_frame(recv).await?;
    verify(
        &proof,
        &transcript_for(client, server, &binding, role.other(), protocol)?,
        expected_node,
    )?;
    // Recheck times at completion, not only when the hello arrived.
    protocol.certificate(trust, &identity.certificate, &identity.public_key())?;
    protocol.certificate(trust, &peer.certificate, expected_node)?;
    // Both sides confirm they accepted the proof before any diagnostic bytes.
    write_frame(send, &json!({"authenticated": true})).await?;
    let ready: Value = read_frame(recv).await?;
    ensure!(
        ready == json!({"authenticated": true}),
        "Peer did not confirm authentication"
    );
    Ok(peer.certificate)
}
