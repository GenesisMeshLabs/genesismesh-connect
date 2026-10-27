//! Certificate-free client bootstrap, scoped to the host's selected node key.
//! The host proves its enrolled identity before the client sends an invitation.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use genesis_mesh_sdk::{canonical_digest, canonical_json};
use serde_json::json;
use wire::{Hello, Proof, exporter_for, hello, sign, sign_key, verify};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClientHello {
    version: u8,
    node_public_key: String,
    endpoint: iroh::EndpointId,
    network: String,
    root: String,
    nonce: [u8; 32],
}

fn transcript(
    client: &ClientHello,
    server: &Hello,
    binding: &[u8; 32],
    signer: Role,
) -> Result<String> {
    canonical_json(&json!({
        "domain": Protocol::Enrollment.domain(), "version": 1,
        "alpn": std::str::from_utf8(Protocol::Enrollment.alpn())?,
        "network": client.network, "root": client.root,
        "client": {"node":client.node_public_key,"endpoint":client.endpoint,"nonce":client.nonce},
        "server": {"endpoint":server.endpoint,"nonce":server.nonce,"certificate_digest":canonical_digest(&server.certificate)?},
        "tls_exporter":STANDARD.encode(binding), "signer":signer,
    })).map_err(Into::into)
}

fn check_body(body: &Value, node: &str) -> Result<()> {
    let object = body.as_object().context("Invalid enrollment request")?;
    let mut fields = vec![
        "node_public_key",
        "invite_token",
        "validity_hours",
        "timestamp",
        "nonce",
        "signature",
    ];
    if object.contains_key("executor_public_key") || object.contains_key("executor_signature") {
        fields.extend(["executor_public_key", "executor_signature"]);
        let executor = body["executor_public_key"]
            .as_str()
            .context("Missing executor identity")?;
        ensure!(
            STANDARD.decode(executor).is_ok_and(|k| k.len() == 32),
            "Invalid executor identity"
        );
        ensure!(
            genesis_mesh_sdk::verify_canonical(
                &genesis_mesh_sdk::node_auth::executor_proof_payload(body)?,
                body["executor_signature"]
                    .as_str()
                    .context("Missing executor proof")?,
                &[executor.to_owned()]
            ),
            "Invalid executor proof"
        );
    }
    ensure!(
        object.len() == fields.len() && object.keys().all(|key| fields.contains(&key.as_str())),
        "Unsupported enrollment fields"
    );
    ensure!(
        body["node_public_key"] == node,
        "Enrollment must name the selected device"
    );
    ensure!(
        body["invite_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty() && token.len() <= 512),
        "Invalid invitation"
    );
    ensure!(
        body["validity_hours"]
            .as_u64()
            .is_some_and(|n| (1..=24).contains(&n)),
        "Invalid enrollment validity"
    );
    server::check_request_signature(body, node)
}

impl BridgeAuthority {
    pub async fn enroll(
        &self,
        key: SigningKey,
        invite: &str,
        store: &mut TrustStore,
    ) -> Result<EnrolledDevice> {
        let (certificate, trust) = self.enroll_raw(&key, invite, store, None).await?;
        EnrolledDevice::accept_enrollment(key, certificate, &trust)
    }

    pub async fn enroll_host(
        &self,
        key: SigningKey,
        executor: &SigningKey,
        invite: &str,
        store: &mut TrustStore,
    ) -> Result<(EnrolledDevice, Value)> {
        let (certificate, trust) = self.enroll_raw(&key, invite, store, Some(executor)).await?;
        crate::authority::accept_host_enrollment(key, executor, certificate, &trust)
    }

    async fn enroll_raw(
        &self,
        key: &SigningKey,
        invite: &str,
        store: &mut TrustStore,
        executor: Option<&SigningKey>,
    ) -> Result<(Value, TrustSnapshot)> {
        ensure!(
            !invite.is_empty() && invite.len() <= 512,
            "Invalid invite length"
        );
        let trust = self.refresh(store).await?;
        let timestamp = genesis_mesh_sdk::node_auth::node_timestamp(Utc::now());
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut body = json!({"node_public_key":STANDARD.encode(key.verifying_key().to_bytes()),"invite_token":invite,"validity_hours":24,"timestamp":timestamp,"nonce":nonce});
        if let Some(executor) = executor {
            body["executor_public_key"] =
                json!(STANDARD.encode(executor.verifying_key().to_bytes()));
            body = genesis_mesh_sdk::node_auth::sign_executor_proof(body, executor)?;
        }
        let signed = genesis_mesh_sdk::node_auth::sign_node_request(body, key, &timestamp, &nonce)?;
        let _permit = self
            .outgoing
            .try_acquire()
            .context("Too many authority operations")?;
        let endpoint = self.endpoint().await?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce)?;
        let ours = ClientHello {
            version: 1,
            node_public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            endpoint: endpoint.id(),
            network: trust.network().to_owned(),
            root: trust.root().to_owned(),
            nonce,
        };
        let certificate = timeout(DEADLINE, async {
            let connection = endpoint
                .connect(self.destination.clone(), Protocol::Enrollment.alpn())
                .await?;
            limit_streams(&connection);
            let result = async {
                write_enrollment(
                    &connection,
                    &ours,
                    key,
                    &signed,
                    &trust,
                    &self.route().host_node,
                )
                .await
            }
            .await;
            connection.close(0u32.into(), b"enrollment complete");
            result
        })
        .await
        .context("Desktop enrollment timed out")??;
        Ok((certificate, trust))
    }
}

async fn write_enrollment(
    connection: &Connection,
    ours: &ClientHello,
    key: &SigningKey,
    signed: &Value,
    trust: &TrustSnapshot,
    expected_host: &str,
) -> Result<Value> {
    ensure!(
        connection.alpn() == Protocol::Enrollment.alpn(),
        "Wrong enrollment protocol"
    );
    let (mut send, mut recv) = connection.open_bi().await?;
    write_frame(&mut send, ours).await?;
    let host: Hello = read_frame(&mut recv).await?;
    ensure!(
        host.version == 1 && host.role == Role::Server && host.endpoint == connection.remote_id(),
        "Invalid enrollment host"
    );
    ensure!(
        host.network == trust.network() && host.root == trust.root(),
        "Wrong enrollment network"
    );
    trust.renewable_certificate(&host.certificate, expected_host, Utc::now())?;
    let binding = exporter_for(connection, Protocol::Enrollment)?;
    let proof: Proof = read_frame(&mut recv).await?;
    verify(
        &proof,
        &transcript(ours, &host, &binding, Role::Server)?,
        expected_host,
    )?;
    write_frame(
        &mut send,
        &sign_key(key, &transcript(ours, &host, &binding, Role::Client)?),
    )
    .await?;
    let ready: Value = read_frame(&mut recv).await?;
    ensure!(
        ready == json!({"authenticated":true}),
        "Enrollment proof was refused"
    );
    // Invitation bytes enter the wire only after host identity + proof checks.
    trust.renewable_certificate(&host.certificate, expected_host, Utc::now())?;
    write_frame(&mut send, signed).await?;
    send.finish()?;
    let certificate = response(&mut recv).await?;
    trust.renewable_certificate(&host.certificate, expected_host, Utc::now())?;
    Ok(certificate)
}

pub(super) async fn serve(
    connection: &Connection,
    local_id: iroh::EndpointId,
    credentials: &Credentials,
    authority: &LocalAuthority,
    budget: &Mutex<Budget>,
) -> Result<()> {
    let (mut send, mut recv) = connection.accept_bi().await?;
    let peer: ClientHello = read_frame(&mut recv).await?;
    ensure!(
        peer.version == 1 && peer.endpoint == connection.remote_id(),
        "Invalid enrollment client"
    );
    ensure!(
        credentials.permits(&peer.node_public_key)
            && peer.network == credentials.trust.network()
            && peer.root == credentials.trust.root(),
        "Unexpected enrollment device or network"
    );
    let selected = credentials.for_node(&peer.node_public_key)?;
    let credentials = &selected;
    let ours = hello(
        Role::Server,
        local_id,
        &credentials.identity,
        &credentials.trust,
    )?;
    let binding = exporter_for(connection, Protocol::Enrollment)?;
    write_frame(&mut send, &ours).await?;
    write_frame(
        &mut send,
        &sign(
            &credentials.identity,
            &transcript(&peer, &ours, &binding, Role::Server)?,
        ),
    )
    .await?;
    let proof: Proof = read_frame(&mut recv).await?;
    verify(
        &proof,
        &transcript(&peer, &ours, &binding, Role::Client)?,
        &credentials.expected_node,
    )?;
    own_credential(credentials)?;
    write_frame(&mut send, &json!({"authenticated":true})).await?;
    let signed: Value = read_frame(&mut recv).await?;
    ensure!(
        recv.read_to_end(0).await?.is_empty(),
        "Unexpected enrollment data"
    );
    check_body(&signed, &credentials.expected_node)?;
    ensure!(
        budget
            .lock()
            .expect("enrollment budget mutex poisoned")
            .allow(),
        "Enrollment budget exhausted"
    );
    let result = authority
        .forward_enrollment(&signed)
        .await
        .and_then(|certificate| {
            let mut credential = certificate.clone();
            if let Some(object) = credential.as_object_mut() {
                object.remove("edge");
            }
            credentials
                .trust
                .certificate(&credential, &credentials.expected_node, Utc::now())?;
            Ok(certificate)
        });
    own_credential(credentials)?;
    respond(&mut send, result).await?;
    connection.closed().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrollment_fields_and_signatures_are_strict() -> Result<()> {
        let key = crate::session::tests::support::key();
        let node = STANDARD.encode(key.verifying_key().to_bytes());
        let body = crate::authority::request(
            &key,
            json!({"node_public_key":node,"invite_token":"test-invite","validity_hours":24}),
        )?;
        check_body(&body, &node)?;
        for (field, value) in [
            ("node_public_key", json!("other")),
            ("roles", json!(["role:operator"])),
            ("validity_hours", json!(25)),
            ("signature", json!("bad")),
            ("invite_token", json!("")),
        ] {
            let mut changed = body.clone();
            changed[field] = value;
            assert!(check_body(&changed, &node).is_err(), "{field}");
        }
        Ok(())
    }
}
