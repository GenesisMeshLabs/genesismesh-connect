//! Requires the Python environment containing the real Genesis Mesh authority.
//! No existing network or real user credentials are touched.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use connect_core::{
    authority::{LocalAuthority, TrustPin, TrustStore},
    session::SessionEndpoint,
};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

struct AuthorityProcess {
    child: Child,
    input: ChildStdin,
    replies: mpsc::Receiver<Value>,
}

impl AuthorityProcess {
    fn start() -> Result<(Self, Value)> {
        let python = std::env::var_os("CONNECT_NA_PYTHON")
            .context("Set CONNECT_NA_PYTHON to the native authority venv's Python executable")?;
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/na_fixture.py");
        let mut child = Command::new(python)
            .arg("-u")
            .arg(script)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().context("Missing fixture stdin")?;
        let output = child.stdout.take().context("Missing fixture stdout")?;
        let (sender, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                let Ok(value) = serde_json::from_str(&line) else {
                    continue;
                };
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        let process = Self {
            child,
            input,
            replies,
        };
        let hello = process
            .replies
            .recv_timeout(Duration::from_secs(15))
            .context("Native authority did not start")?;
        Ok((process, hello))
    }
    fn command(&mut self, request: Value) -> Result<Value> {
        writeln!(self.input, "{}", serde_json::to_string(&request)?)?;
        self.input.flush()?;
        self.replies
            .recv_timeout(Duration::from_secs(10))
            .context("Authority fixture command did not complete")
    }
}
impl Drop for AuthorityProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; owner approval, node proof, remote enrollment and final mutual session"]
async fn approved_pairing_enrolls_without_copying_keys_and_requires_final_peer_proof() -> Result<()>
{
    use connect_core::{
        Connectivity,
        session::{
            bridge::{AuthorityBridge, BridgeAuthority, BridgeRoute},
            pairing::{PairCard, PairClient, PairGrant, PairHost},
        },
    };
    let (mut process, info) = AuthorityProcess::start()?;
    let authority = LocalAuthority::new(info["url"].as_str().unwrap())?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let dir = tempfile::tempdir()?;
    let mut host_store = TrustStore::create(&dir.path().join("host.json"), pin.clone())?;
    let host_key = key();
    let invitation = process.command(json!({"op":"invite","node_public_key":public(&host_key)}))?;
    let host = authority
        .enroll(
            host_key,
            invitation["invite"].as_str().unwrap(),
            &mut host_store,
        )
        .await?;
    let pair = PairHost::bind(
        host.session_identity()?,
        authority.refresh(&mut host_store).await?,
        authority.clone(),
        "Home computer".into(),
        Connectivity::LocalNetwork,
    )
    .await?;
    let client_key = key();
    let mut client_store = TrustStore::create(&dir.path().join("client.json"), pin)?;
    let card = PairCard::parse(&pair.card().link()?)?;
    let mut wrong = card.clone();
    wrong.host_node = public(&key());
    assert!(
        PairClient::request(wrong, &client_key, &mut client_store, "My phone".into())
            .await
            .is_err()
    );
    assert!(
        pair.pending().is_none(),
        "No request may reach owner approval before the host proof succeeds"
    );
    let mut declined = PairClient::request(
        card.clone(),
        &client_key,
        &mut client_store,
        "Decline this phone".into(),
    )
    .await?;
    let waiting = pair.pending().context("No request to decline")?;
    pair.reject(&waiting.id)?;
    assert!(
        declined.grant().await.is_err(),
        "Declining must release no invitation"
    );
    declined.close().await;
    assert!(
        PairClient::request(
            card,
            &client_key,
            &mut client_store,
            "Reuse declined link".into()
        )
        .await
        .is_err()
    );
    pair.close().await;
    let pair = PairHost::bind(
        host.session_identity()?,
        authority.refresh(&mut host_store).await?,
        authority.clone(),
        "Home computer".into(),
        Connectivity::LocalNetwork,
    )
    .await?;
    let card = PairCard::parse(&pair.card().link()?)?;
    let mut client_pair = PairClient::request(
        card.clone(),
        &client_key,
        &mut client_store,
        "My phone".into(),
    )
    .await?;
    let request = pair.pending().context("No pending approval")?;
    assert_eq!(request.node, public(&client_key));
    assert_eq!(request.code, client_pair.code);
    assert!(
        pair.approve(
            "other-request",
            PairGrant {
                invitation: "never-released".into(),
                route: BridgeRoute {
                    ticket: "unused".into(),
                    host_node: host.public_key()
                },
                session_ticket: "unused".into()
            }
        )
        .is_err()
    );
    // A link is consumed when it produces a bound request, even before approval.
    assert!(
        PairClient::request(card, &key(), &mut client_store, "Replay".into())
            .await
            .is_err()
    );
    let bridge = AuthorityBridge::bind(
        host.session_identity()?,
        authority.refresh(&mut host_store).await?,
        public(&client_key),
        authority.clone(),
    )
    .await?;
    let host_endpoint = SessionEndpoint::bind(
        host.session_identity()?,
        authority.refresh(&mut host_store).await?,
        public(&client_key),
    )
    .await?;
    let invitation =
        process.command(json!({"op":"invite","node_public_key":public(&client_key)}))?;
    let complete = pair.approve(
        &request.id,
        PairGrant {
            invitation: invitation["invite"].as_str().unwrap().into(),
            route: BridgeRoute {
                ticket: bridge.ticket()?,
                host_node: host.public_key(),
            },
            session_ticket: host_endpoint.ticket()?,
        },
    )?;
    let grant = client_pair.grant().await?;
    let bridge_client = BridgeAuthority::new(grant.route)?;
    let client = bridge_client
        .enroll(client_key, &grant.invitation, &mut client_store)
        .await?;
    let client_endpoint = SessionEndpoint::bind(
        client.session_identity()?,
        bridge_client.refresh(&mut client_store).await?,
        host.public_key(),
    )
    .await?;
    client_endpoint
        .round_trip(&grant.session_ticket, "Phone verifies computer")
        .await?;
    let phone_ticket = client_endpoint.ticket()?;
    let finish = client_pair.finish(phone_ticket);
    let owner = async {
        let joined = complete.await?;
        host_endpoint
            .round_trip(&joined.ticket, "Computer verifies phone")
            .await?;
        joined
            .confirm
            .send(true)
            .map_err(|_| anyhow::anyhow!("Phone disconnected"))?;
        Ok::<_, anyhow::Error>(())
    };
    let (a, b) = tokio::join!(finish, owner);
    a?;
    b?;
    client_pair.close().await;
    client_endpoint.close().await;
    host_endpoint.close().await;
    bridge.close().await;
    pair.close().await;
    process.command(json!({"op":"stop"}))?;
    process.child.wait()?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; real list policy and zero-name denial"]
async fn authorized_file_pages_bind_versions_and_release_no_names_after_denial() -> Result<()> {
    use connect_core::session::sharing::{ReadRequest, Share, ShareConfig};
    use std::sync::Arc;
    let (mut process, info) = AuthorityProcess::start()?;
    let authority = LocalAuthority::new(info["url"].as_str().unwrap())?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let dir = tempfile::tempdir()?;
    let folder = dir.path().join("files");
    std::fs::create_dir(&folder)?;
    for i in 0..35 {
        std::fs::write(
            folder.join(format!("Family note {i:02}.txt")),
            format!("Note {i}"),
        )?;
    }
    std::fs::write(folder.join("too-large.bin"), vec![0; 65537])?;
    std::fs::create_dir(folder.join("subfolder"))?;
    let outside = dir.path().join("outside.txt");
    std::fs::write(&outside, b"private")?;
    std::fs::hard_link(&outside, folder.join("hard-link.txt"))?;
    let mut host_store = TrustStore::create(&dir.path().join("host.json"), pin.clone())?;
    let host_key = key();
    let executor = key();
    let invite =
        process.command(json!({"op":"edge_invite","node_public_key":public(&host_key)}))?;
    let (host, _) = authority
        .enroll_host(
            host_key,
            &executor,
            invite["invite"].as_str().unwrap(),
            &mut host_store,
        )
        .await?;
    let mut client_store = TrustStore::create(&dir.path().join("client.json"), pin.clone())?;
    let client_key = key();
    let invite = process.command(json!({"op":"invite","node_public_key":public(&client_key)}))?;
    let client = authority
        .enroll(
            client_key,
            invite["invite"].as_str().unwrap(),
            &mut client_store,
        )
        .await?;
    // A read-only policy cannot release a directory listing.
    let policy=process.command(json!({"op":"read_policy","host_node":host.public_key(),"peer_node":client.public_key(),"collection":"family"}))?;
    let config = ShareConfig {
        directory: folder.clone(),
        collection_id: "family".into(),
        policy_id: "connect-read".into(),
        attestation_id: policy["attestation_id"].as_str().unwrap().into(),
    };
    let share = Arc::new(Share::open(
        config,
        authority.clone(),
        pin.clone(),
        &dir.path().join("sharing"),
    )?);
    let mut host_endpoint = SessionEndpoint::bind_with_share(
        host.session_identity()?,
        authority.refresh(&mut host_store).await?,
        client.public_key(),
        Some(share.clone()),
    )
    .await?;
    let client_endpoint = SessionEndpoint::bind(
        client.session_identity()?,
        authority.refresh(&mut client_store).await?,
        host.public_key(),
    )
    .await?;
    assert!(
        client_endpoint
            .list_files(&host_endpoint.ticket()?, None)
            .await
            .is_err()
    );
    assert_eq!(share.released_names(), 0);
    host_endpoint.close().await;
    drop(share);
    let policy=process.command(json!({"op":"list_policy","host_node":host.public_key(),"peer_node":client.public_key(),"collection":"family"}))?;
    let share = Arc::new(Share::open(
        ShareConfig {
            directory: folder.clone(),
            collection_id: "family".into(),
            policy_id: "connect-read".into(),
            attestation_id: policy["attestation_id"].as_str().unwrap().into(),
        },
        authority.clone(),
        pin,
        &dir.path().join("sharing-list"),
    )?);
    host_endpoint = SessionEndpoint::bind_with_share(
        host.session_identity()?,
        authority.refresh(&mut host_store).await?,
        client.public_key(),
        Some(share.clone()),
    )
    .await?;
    let ticket = host_endpoint.ticket()?;
    let first = client_endpoint.list_files(&ticket, None).await?;
    assert_eq!(first.files.len(), 32);
    let second = client_endpoint.list_files(&ticket, first.next).await?;
    assert_eq!(second.files.len(), 3);
    assert!(second.next.is_none());
    assert_eq!(share.released_names(), 35);
    assert_eq!(share.released_bytes(), 0);
    let file = &first.files[0];
    let request = || ReadRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        collection_id: first.collection_id.clone(),
        file_name: file.name.clone(),
        expected_sha256: Some(file.sha256.clone()),
    };
    let report = client_endpoint.read_file(&ticket, request()).await?;
    assert_eq!(report.sha256, file.sha256);
    let before = share.released_bytes();
    std::fs::write(folder.join(&file.name), b"changed after listing")?;
    assert!(client_endpoint.read_file(&ticket, request()).await.is_err());
    assert_eq!(share.released_bytes(), before);
    process.command(json!({"op":"deny_list","peer_node":client.public_key()}))?;
    assert!(client_endpoint.list_files(&ticket, None).await.is_err());
    assert_eq!(share.released_names(), 35);
    process.command(json!({"op":"stop"}))?;
    process.child.wait()?;
    assert!(client_endpoint.list_files(&ticket, None).await.is_err());
    assert_eq!(share.released_names(), 35);
    client_endpoint.close().await;
    host_endpoint.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; remote sharing host enrollment, list/read and revocation through a verified bridge"]
async fn remote_sharing_host_uses_bridge_for_governed_files_without_local_authority() -> Result<()>
{
    use connect_core::{
        authority::AuthorityAccess,
        session::{
            bridge::{AuthorityBridge, BridgeAuthority, BridgeRoute},
            sharing::{ReadRequest, Share, ShareConfig},
        },
    };
    use std::sync::Arc;
    let (mut process, info) = AuthorityProcess::start()?;
    let local = LocalAuthority::new(info["url"].as_str().unwrap())?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let dir = tempfile::tempdir()?;
    let mut owner_store = TrustStore::create(&dir.path().join("owner-trust.json"), pin.clone())?;
    let owner_key = key();
    let invite = process.command(json!({"op":"invite","node_public_key":public(&owner_key)}))?;
    let owner = local
        .enroll(
            owner_key,
            invite["invite"].as_str().unwrap(),
            &mut owner_store,
        )
        .await?;
    let sharing_key = key();
    let bridge = AuthorityBridge::bind(
        owner.session_identity()?,
        local.refresh(&mut owner_store).await?,
        public(&sharing_key),
        local.clone(),
    )
    .await?;
    let remote = BridgeAuthority::new(BridgeRoute {
        host_node: owner.public_key(),
        ticket: bridge.ticket()?,
    })?;
    let mut host_store = TrustStore::create(&dir.path().join("host-trust.json"), pin.clone())?;
    let executor = key();
    let invite =
        process.command(json!({"op":"edge_invite","node_public_key":public(&sharing_key)}))?;
    let (mut host, edge) = remote
        .enroll_host(
            sharing_key,
            &executor,
            invite["invite"].as_str().unwrap(),
            &mut host_store,
        )
        .await?;
    assert_eq!(edge["executor_key"]["public_key"], public(&executor));
    let previous_certificate = host.certificate()["cert_id"].clone();
    remote.renew(&mut host, &mut host_store).await?;
    assert_ne!(previous_certificate, host.certificate()["cert_id"]);
    let mut reader_store = TrustStore::create(&dir.path().join("reader-trust.json"), pin.clone())?;
    let reader_key = key();
    let invite = process.command(json!({"op":"invite","node_public_key":public(&reader_key)}))?;
    let reader = local
        .enroll(
            reader_key,
            invite["invite"].as_str().unwrap(),
            &mut reader_store,
        )
        .await?;
    let folder = dir.path().join("shared");
    std::fs::create_dir(&folder)?;
    std::fs::write(folder.join("note.txt"), b"Shared from a remote device")?;
    std::fs::create_dir(folder.join("Photos"))?;
    std::fs::write(folder.join("Photos/image.txt"), b"Nested remote file")?;
    let policy = process.command(json!({"op":"list_policy","host_node":host.public_key(),"peer_node":reader.public_key(),"collection":"family"}))?;
    let share = Arc::new(Share::open(
        ShareConfig {
            directory: folder,
            collection_id: "family".into(),
            policy_id: "connect-read".into(),
            attestation_id: policy["attestation_id"].as_str().unwrap().into(),
        },
        AuthorityAccess::Remote(remote.clone()),
        pin,
        &dir.path().join("sharing"),
    )?);
    let host_endpoint = SessionEndpoint::bind_with_share(
        host.session_identity()?,
        remote.refresh(&mut host_store).await?,
        reader.public_key(),
        Some(share.clone()),
    )
    .await?;
    let reader_endpoint = SessionEndpoint::bind(
        reader.session_identity()?,
        local.refresh(&mut reader_store).await?,
        host.public_key(),
    )
    .await?;
    let ticket = host_endpoint.ticket()?;
    let page = reader_endpoint.list_files(&ticket, None).await?;
    assert_eq!(page.files.len(), 1);
    assert_eq!(page.files[0].name, "note.txt");
    let report = reader_endpoint
        .read_file(
            &ticket,
            ReadRequest {
                request_id: uuid::Uuid::new_v4().to_string(),
                collection_id: "family".into(),
                file_name: "note.txt".into(),
                expected_sha256: Some(page.files[0].sha256.clone()),
            },
        )
        .await?;
    assert_eq!(report.text.as_deref(), Some("Shared from a remote device"));
    let nested = reader_endpoint
        .browse_from(&host.public_key(), &ticket, None, vec!["Photos".into()])
        .await?;
    assert_eq!(nested.files[0].name, "image.txt");
    let file = &nested.files[0];
    let mut downloaded = tempfile::tempfile()?;
    let result = reader_endpoint
        .download_window_from(
            &host.public_key(),
            &ticket,
            connect_core::session::sharing::download::Request {
                request_id: uuid::Uuid::new_v4().to_string(),
                collection_id: "family".into(),
                file_name: file.name.clone(),
                directory: nested.directory,
                version: file.version.clone(),
                size: file.bytes,
                token: None,
                offset: 0,
                length: 65536,
            },
            &mut downloaded,
        )
        .await?;
    assert!(result.done);
    assert_eq!(result.bytes, 18);
    let names = share.released_names();
    let bytes = share.released_bytes();
    process.command(
        json!({"op":"deny_list","host_node":host.public_key(),"peer_node":reader.public_key()}),
    )?;
    assert!(reader_endpoint.list_files(&ticket, None).await.is_err());
    assert_eq!(share.released_names(), names);
    assert_eq!(share.released_bytes(), bytes);
    bridge.suspend();
    assert!(reader_endpoint.list_files(&ticket, None).await.is_err());
    assert_eq!(share.released_names(), names);
    host_endpoint.close().await;
    reader_endpoint.close().await;
    bridge.close().await;
    Ok(())
}
fn key() -> SigningKey {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).unwrap();
    SigningKey::from_bytes(&bytes)
}
fn public(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}

#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; real edge enrollment, live read policy, receipts and zero-byte denial"]
async fn protected_read_binds_snapshot_and_peer_and_refuses_policy_revocation_and_outage()
-> Result<()> {
    use connect_core::session::sharing::{ReadRequest, Share, ShareConfig};
    use std::sync::Arc;
    let (mut process, info) = AuthorityProcess::start()?;
    let authority = LocalAuthority::new(info["url"].as_str().unwrap())?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("collection");
    std::fs::create_dir(&root)?;
    std::fs::write(root.join("sample.txt"), b"A protected Genesis Mesh read.")?;
    let mut host_store = TrustStore::create(&dir.path().join("host.json"), pin.clone())?;
    let host_key = key();
    let executor = key();
    let invitation =
        process.command(json!({"op":"edge_invite","node_public_key":public(&host_key)}))?;
    let (host, edge) = authority
        .enroll_host(
            host_key,
            &executor,
            invitation["invite"].as_str().unwrap(),
            &mut host_store,
        )
        .await?;
    assert_eq!(edge["node_sovereign_id"], "connect-host");
    let mut client_store = TrustStore::create(&dir.path().join("client.json"), pin.clone())?;
    let client_key = key();
    let invitation =
        process.command(json!({"op":"invite","node_public_key":public(&client_key)}))?;
    let mut client = authority
        .enroll(
            client_key,
            invitation["invite"].as_str().unwrap(),
            &mut client_store,
        )
        .await?;
    let policy=process.command(json!({"op":"read_policy","host_node":host.public_key(),"peer_node":client.public_key(),"collection":"allowed"}))?;
    let share = Arc::new(Share::open(
        ShareConfig {
            collection_id: "allowed".into(),
            directory: root.clone(),
            attestation_id: policy["attestation_id"].as_str().unwrap().into(),
            policy_id: "connect-read".into(),
        },
        authority.clone(),
        pin,
        &dir.path().join("sharing"),
    )?);
    let host_endpoint = SessionEndpoint::bind_with_share(
        host.session_identity()?,
        authority.refresh(&mut host_store).await?,
        client.public_key(),
        Some(share.clone()),
    )
    .await?;
    let client_endpoint = SessionEndpoint::bind(
        client.session_identity()?,
        authority.refresh(&mut client_store).await?,
        host.public_key(),
    )
    .await?;
    let request = |collection: &str, name: &str, digest: Option<String>| ReadRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        collection_id: collection.into(),
        file_name: name.into(),
        expected_sha256: digest,
    };
    let ticket = host_endpoint.ticket()?;
    for (collection, name) in [
        ("other", "sample.txt"),
        ("allowed", "../sample.txt"),
        ("allowed", "sample.txt:ads"),
    ] {
        assert!(
            client_endpoint
                .read_file(&ticket, request(collection, name, None))
                .await
                .is_err()
        );
        assert_eq!(share.released_bytes(), 0);
    }
    let receipts = dir.path().join("sharing/receipts");
    let unavailable = dir.path().join("sharing/receipts-unavailable");
    std::fs::rename(&receipts, &unavailable)?;
    std::fs::write(&receipts, b"Receipt storage unavailable")?;
    let refused = client_endpoint
        .read_file(&ticket, request("allowed", "sample.txt", None))
        .await;
    std::fs::remove_file(&receipts)?;
    std::fs::rename(&unavailable, &receipts)?;
    assert!(refused.is_err());
    assert_eq!(share.released_bytes(), 0);
    let report = client_endpoint
        .read_file(&ticket, request("allowed", "sample.txt", None))
        .await?;
    assert_eq!(
        report.text.as_deref(),
        Some("A protected Genesis Mesh read.")
    );
    assert_eq!(report.bytes, 30);
    let receipt: Value = serde_json::from_slice(&std::fs::read(
        dir.path()
            .join("sharing/receipts")
            .join(format!("{}.json", report.receipt_id)),
    )?)?;
    assert_eq!(receipt["receipt"]["phase"], "client_verified");
    assert!(receipt["receipt"]["client_ack"]["proof"]["signature"].is_string());
    std::fs::write(root.join("buffer.bin"), vec![255; 64 * 1024])?;
    let binary = client_endpoint
        .read_file(&ticket, request("allowed", "buffer.bin", None))
        .await?;
    assert_eq!(binary.bytes, 64 * 1024);
    assert!(binary.text.is_none());
    let before = share.released_bytes();
    let marker = dir.path().join("read-decision-waiting");
    process.command(json!({"op":"pause_reads","marker":marker}))?;
    {
        let reading = client_endpoint.read_file(&ticket, request("allowed", "sample.txt", None));
        tokio::pin!(reading);
        tokio::select! {
            result = &mut reading => anyhow::bail!("Read finished before interruption: {}", result.is_ok()),
            result = tokio::time::timeout(Duration::from_secs(3), async {
                while !marker.exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }) => result.context("Read did not reach authorization")?,
        }
        host_endpoint.suspend();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut reading)
                .await?
                .is_err()
        );
    }
    process.command(json!({"op":"resume_reads"}))?;
    assert_eq!(share.released_bytes(), before);
    host_endpoint.refresh(
        host.session_identity()?,
        authority.refresh(&mut host_store).await?,
    )?;
    let recovered = client_endpoint
        .read_file(&ticket, request("allowed", "sample.txt", None))
        .await?;
    assert_eq!(recovered.bytes, 30);
    let before = share.released_bytes();
    std::fs::write(root.join("sample.txt"), b"changed file")?;
    assert!(
        client_endpoint
            .read_file(
                &ticket,
                request("allowed", "sample.txt", Some(report.sha256))
            )
            .await
            .is_err()
    );
    assert_eq!(share.released_bytes(), before);
    process.command(json!({"op":"deny_reads","peer_node":client.public_key()}))?;
    assert!(
        client_endpoint
            .read_file(&ticket, request("allowed", "sample.txt", None))
            .await
            .is_err()
    );
    assert_eq!(share.released_bytes(), before);
    process.command(
        json!({"op":"allow_reads","peer_node":client.public_key(),"collection":"allowed"}),
    )?;
    assert!(
        client_endpoint
            .read_file(&ticket, request("allowed", "sample.txt", None))
            .await
            .is_ok()
    );
    // Revoke exactly the certificate used by the existing session endpoint.
    // A separately renewed, unrevoked credential is not whole-device recovery.
    let revoked = client.certificate()["cert_id"].clone();
    authority.renew(&mut client, &mut client_store).await?;
    process.command(json!({"op":"revoke","cert_id":revoked}))?;
    let before = share.released_bytes();
    assert!(
        client_endpoint
            .read_file(&ticket, request("allowed", "sample.txt", None))
            .await
            .is_err()
    );
    assert_eq!(share.released_bytes(), before);
    client_endpoint.refresh(
        client.session_identity()?,
        authority.refresh(&mut client_store).await?,
    )?;
    assert!(
        client_endpoint
            .read_file(&ticket, request("allowed", "sample.txt", None))
            .await
            .is_ok()
    );
    let before = share.released_bytes();
    process
        .command(json!({"op":"revoke_attestation","attestation_id":policy["attestation_id"]}))?;
    assert!(
        client_endpoint
            .read_file(&ticket, request("allowed", "sample.txt", None))
            .await
            .is_err()
    );
    assert_eq!(share.released_bytes(), before);
    process.command(json!({"op":"stop"}))?;
    process.child.wait()?;
    assert!(
        client_endpoint
            .read_file(&ticket, request("allowed", "sample.txt", None))
            .await
            .is_err()
    );
    assert_eq!(share.released_bytes(), before);
    client_endpoint.close().await;
    host_endpoint.close().await;
    println!(
        "Protected read: live policy and receipts, zero-byte pre-release denials, revoked peer certificate, authorization interruption and explicit fresh-read recovery passed."
    );
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; Windows edge-host vault and explicit sharing lifecycle"]
async fn windows_sharing_host_persists_its_role_but_reopens_with_sharing_disabled() -> Result<()> {
    use connect_core::{device::DeviceController, session::sharing::ShareConfig};
    let (mut process, info) = AuthorityProcess::start()?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let dir = tempfile::tempdir()?;
    let profile = dir.path().join("device");
    let mut host = DeviceController::prepare(&profile, info["url"].as_str().unwrap().into(), pin)?;
    let node = host.status()?.node_public_key;
    let invitation = process.command(json!({"op":"edge_invite","node_public_key":node}))?;
    host.enroll_host(invitation["invite"].as_str().unwrap())
        .await?;
    let certificate = host.status()?.certificate_id;
    assert!(host.status()?.sharing_host);
    drop(host);
    let mut host = DeviceController::open(&profile)?;
    assert!(host.status()?.sharing_host);
    assert_eq!(host.status()?.certificate_id, certificate);
    assert_eq!(host.status()?.node_public_key, node);
    let peer = public(&key());
    let policy = process.command(
        json!({"op":"read_policy","host_node":node,"peer_node":peer,"collection":"allowed"}),
    )?;
    let collection = dir.path().join("collection");
    std::fs::create_dir(&collection)?;
    host.configure_sharing(Some(ShareConfig {
        collection_id: "allowed".into(),
        directory: collection,
        attestation_id: policy["attestation_id"].as_str().unwrap().into(),
        policy_id: "connect-read".into(),
    }))?;
    assert!(host.status()?.sharing_enabled);
    let displayed = host.status()?.sharing_config.unwrap();
    assert_eq!(displayed.collection_id, "allowed");
    assert_eq!(displayed.policy_id, "connect-read");
    assert_eq!(
        displayed.attestation_id,
        policy["attestation_id"].as_str().unwrap()
    );
    assert_eq!(
        host.status()?.root_public_key,
        info["pin"]["root_public_key"].as_str().unwrap()
    );
    assert!(host.status()?.trust_checkpoint.observed_at.is_some());
    host.start(&peer).await?;
    assert!(host.status()?.ready);
    assert!(host.configure_sharing(None).is_err());
    host.stop().await;
    drop(host);
    let mut host = DeviceController::open(&profile)?;
    assert!(host.status()?.sharing_host);
    assert!(!host.status()?.sharing_enabled);
    assert!(host.status()?.sharing_config.is_none());
    assert!(!host.is_running());
    // Only an explicitly selected consumer share opts into durable restoration.
    host.enable_managed_connectivity()?;
    host.save_managed_share(Some(displayed))?;
    drop(host);
    let mut host = DeviceController::open(&profile)?;
    assert!(!host.status()?.sharing_enabled);
    host.restore_managed_share()?;
    assert!(host.status()?.sharing_enabled);
    host.save_managed_share(None)?;
    drop(host);
    let mut host = DeviceController::open(&profile)?;
    host.restore_managed_share()?;
    assert!(!host.status()?.sharing_enabled);
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; client enrolls through Iroh with no HTTP authority configured"]
async fn remote_device_enrolls_persists_and_connects_without_local_authority() -> Result<()> {
    use connect_core::{device::DeviceController, session::bridge::BridgeRoute};
    let (mut process, info) = AuthorityProcess::start()?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let directory = tempfile::tempdir()?;
    let host_path = directory.path().join("host");
    let client_path = directory.path().join("remote");
    let mut host = DeviceController::prepare(
        &host_path,
        info["url"].as_str().unwrap().into(),
        pin.clone(),
    )?;
    let host_invite =
        process.command(json!({"op":"invite","node_public_key":host.status()?.node_public_key}))?;
    host.enroll(host_invite["invite"].as_str().unwrap()).await?;
    let mut client = DeviceController::prepare_remote(&client_path, pin.clone())?;
    let client_key = client.status()?.node_public_key;
    assert!(client.status()?.authority.is_none());
    assert!(!client.status()?.authority_configured);
    assert!(client.enroll("no-connection-yet").await.is_err());
    assert!(!client.status()?.enrollment_pending);
    drop(client);
    let mut client = DeviceController::open(&client_path)?;
    assert_eq!(client.status()?.node_public_key, client_key);
    // The host can select a device key before that device has a certificate.
    host.start(&client_key).await?;
    let host_key = host.status()?.node_public_key;
    let route = BridgeRoute {
        ticket: host.status()?.bridge_ticket.unwrap(),
        host_node: host_key.clone(),
    };
    let wrong_key = key();
    let wrong_invite =
        process.command(json!({"op":"invite","node_public_key":public(&wrong_key)}))?;
    client.use_bridge(route.clone()).await?;
    assert!(
        client
            .enroll(wrong_invite["invite"].as_str().unwrap())
            .await
            .is_err()
    );
    assert!(client.status()?.enrollment_pending);
    assert!(client.status()?.certificate_id.is_none());
    let invite = process.command(json!({"op":"invite","node_public_key":client_key}))?;
    client.enroll(invite["invite"].as_str().unwrap()).await?;
    assert!(!client.status()?.enrollment_pending);
    let certificate = client.status()?.certificate_id;
    assert!(certificate.is_some());
    assert!(client.status()?.authority.is_none());
    drop(client);
    let mut client = DeviceController::open(&client_path)?;
    assert_eq!(client.status()?.certificate_id, certificate);
    assert_eq!(client.status()?.node_public_key, client_key);
    assert!(client.status()?.authority_via_bridge);
    assert!(!client.status()?.local_authority_available);
    assert!(client.use_local_authority().is_err());
    client.start(&host_key).await?;
    assert!(
        client
            .send(
                &host.status()?.ticket.unwrap(),
                "remote enrollment complete"
            )
            .await?
            .genesis_mesh_authenticated
    );
    host.stop().await;
    assert!(client.refresh().await.is_err());
    assert!(!client.status()?.ready);
    client.stop().await;
    println!(
        "Remote device: no-local-authority preparation, invite binding, enrollment over Iroh, durable restart, authenticated message, and host loss passed."
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; real single-use invitation and renewal over the enrollment/control channels"]
async fn real_remote_invite_cannot_be_reused_and_enrolled_device_can_renew() -> Result<()> {
    use connect_core::session::bridge::{AuthorityBridge, BridgeAuthority, BridgeRoute};
    let (mut process, info) = AuthorityProcess::start()?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let directory = tempfile::tempdir()?;
    let local = LocalAuthority::new(info["url"].as_str().unwrap())?;
    let mut host_store = TrustStore::create(&directory.path().join("host.json"), pin.clone())?;
    let host_key = key();
    let host_invite =
        process.command(json!({"op":"invite","node_public_key":public(&host_key)}))?;
    let host = local
        .enroll(
            host_key,
            host_invite["invite"].as_str().unwrap(),
            &mut host_store,
        )
        .await?;
    let client_key = key();
    let client_invite =
        process.command(json!({"op":"invite","node_public_key":public(&client_key)}))?;
    let bridge = AuthorityBridge::bind(
        host.session_identity()?,
        local.refresh(&mut host_store).await?,
        public(&client_key),
        local,
    )
    .await?;
    let remote = BridgeAuthority::new(BridgeRoute {
        ticket: bridge.ticket()?,
        host_node: host.public_key(),
    })?;
    let mut client_store = TrustStore::create(&directory.path().join("client.json"), pin)?;
    let invite = client_invite["invite"].as_str().unwrap();
    let mut client = remote
        .enroll(client_key.clone(), invite, &mut client_store)
        .await?;
    assert_eq!(client.certificate()["roles"], json!(["role:client"]));
    assert!(
        remote
            .enroll(client_key, invite, &mut client_store)
            .await
            .is_err()
    );
    let original = client.certificate()["cert_id"].clone();
    remote.renew(&mut client, &mut client_store).await?;
    assert_ne!(client.certificate()["cert_id"], original);
    assert_eq!(bridge.forwarded_renewals(), 1);
    bridge.close().await;
    println!(
        "Remote enrollment: real single-use invite, authority-assigned roles and subsequent authenticated renewal passed."
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; exercises real renewal through Iroh without a client HTTP authority adapter"]
async fn real_authority_renewal_through_iroh_bridge_and_outage_refusal() -> Result<()> {
    use connect_core::session::bridge::{AuthorityBridge, BridgeAuthority, BridgeRoute};
    let (mut process, info) = AuthorityProcess::start()?;
    let local = LocalAuthority::new(info["url"].as_str().unwrap())?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let dir = tempfile::tempdir()?;
    let mut client_store = TrustStore::create(&dir.path().join("client.json"), pin.clone())?;
    let mut host_store = TrustStore::create(&dir.path().join("host.json"), pin.clone())?;
    let mut nodes = Vec::new();
    for store in [&mut client_store, &mut host_store] {
        let key = key();
        let invite = process.command(json!({"op":"invite","node_public_key":public(&key)}))?;
        nodes.push(
            local
                .enroll(key, invite["invite"].as_str().unwrap(), store)
                .await?,
        );
    }
    let host = nodes.pop().unwrap();
    let mut client = nodes.pop().unwrap();
    let bridge = AuthorityBridge::bind(
        host.session_identity()?,
        local.refresh(&mut host_store).await?,
        client.public_key(),
        local.clone(),
    )
    .await?;
    let route = BridgeRoute {
        ticket: bridge.ticket()?,
        host_node: host.public_key(),
    };
    let remote = BridgeAuthority::new(route.clone())?;
    let old = client.certificate().clone();
    remote.renew(&mut client, &mut client_store).await?;
    assert_ne!(client.certificate()["cert_id"], old["cert_id"]);
    assert_eq!(bridge.forwarded_renewals(), 1);
    let host_endpoint = SessionEndpoint::bind(
        host.session_identity()?,
        local.refresh(&mut host_store).await?,
        client.public_key(),
    )
    .await?;
    let client_endpoint = SessionEndpoint::bind(
        client.session_identity()?,
        remote.refresh(&mut client_store).await?,
        host.public_key(),
    )
    .await?;
    assert!(
        client_endpoint
            .round_trip(&host_endpoint.ticket()?, "renewed through desktop")
            .await?
            .genesis_mesh_authenticated
    );
    // Recreate the remote adapter and checkpoint; no local HTTP origin is supplied.
    drop(client_store);
    let mut client_store = TrustStore::open(&dir.path().join("client.json"), &pin)?;
    let remote = BridgeAuthority::new(route)?;
    remote.refresh(&mut client_store).await?;
    process.command(json!({"op":"revoke","cert_id":client.certificate()["cert_id"]}))?;
    bridge.refresh(
        host.session_identity()?,
        local.refresh(&mut host_store).await?,
    )?;
    let saved = client.certificate().clone();
    assert!(remote.renew(&mut client, &mut client_store).await.is_err());
    assert_eq!(client.certificate(), &saved);
    assert_eq!(bridge.forwarded_renewals(), 1);
    process.command(json!({"op":"stop"}))?;
    process.child.wait()?;
    assert!(remote.refresh(&mut client_store).await.is_err());
    client_endpoint.close().await;
    host_endpoint.close().await;
    bridge.close().await;
    println!(
        "Real NA bridge: Iroh-only trust refresh and signed renewal, authenticated echo, restart, revoked renewal and outage refusal passed."
    );
    Ok(())
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON and an unlocked native credential store; three durable device profiles"]
async fn multiple_saved_devices_preserve_connections_routes_and_isolate_forgetting() -> Result<()> {
    use connect_core::{
        device::{DeviceController, PairedDevice},
        session::bridge::BridgeRoute,
    };
    let (mut process, info) = AuthorityProcess::start()?;
    let dir = tempfile::tempdir()?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let url = info["url"].as_str().unwrap();
    let paths = [
        dir.path().join("owner"),
        dir.path().join("first"),
        dir.path().join("second"),
    ];
    let mut nodes = Vec::new();
    for path in &paths {
        let mut device = DeviceController::prepare(path, url.into(), pin.clone())?;
        let invite = process
            .command(json!({"op":"invite","node_public_key":device.status()?.node_public_key}))?;
        device.enroll(invite["invite"].as_str().unwrap()).await?;
        nodes.push(device);
    }
    let mut second = nodes.pop().unwrap();
    let mut first = nodes.pop().unwrap();
    let mut host = nodes.pop().unwrap();
    let host_node = host.status()?.node_public_key;
    let first_node = first.status()?.node_public_key;
    let second_node = second.status()?.node_public_key;
    host.start(&first_node).await?;
    first.start(&host_node).await?;
    let host_ticket = host.status()?.ticket.unwrap();
    let route = BridgeRoute {
        host_node: host_node.clone(),
        ticket: host.status()?.bridge_ticket.unwrap(),
    };
    first.send(&host_ticket, "verify first approval").await?;
    host.remember_pairing(PairedDevice {
        name: "First device".into(),
        node: first_node.clone(),
        ticket: first.status()?.ticket.unwrap(),
    })?;
    first.remember_pairing(PairedDevice {
        name: "Home".into(),
        node: host_node.clone(),
        ticket: host_ticket.clone(),
    })?;
    first.stop().await;
    first.use_bridge(route.clone()).await?;
    first.reconnect_saved().await?;
    host.start(&second_node).await?;
    second.start(&host_node).await?;
    second.send(&host_ticket, "verify second approval").await?;
    host.remember_pairing(PairedDevice {
        name: "Second device".into(),
        node: second_node.clone(),
        ticket: second.status()?.ticket.unwrap(),
    })?;
    second.remember_pairing(PairedDevice {
        name: "Home".into(),
        node: host_node.clone(),
        ticket: host_ticket.clone(),
    })?;
    // Adding and selecting another device must preserve the first device's
    // transport ticket and access to the same verified authority bridge.
    first.refresh().await?;
    first
        .send(&host_ticket, "first after adding second")
        .await?;
    second.stop().await;
    second.use_bridge(route).await?;
    second.reconnect_saved().await?;
    second.refresh().await?;
    assert_eq!(host.status()?.devices.len(), 2);
    host.stop().await;
    drop(host);
    let mut host = DeviceController::open(&paths[0])?;
    assert_eq!(host.status()?.devices.len(), 2);
    assert_eq!(host.status()?.node_public_key, host_node);
    host.reconnect_saved().await?;
    let new_ticket = host.status()?.ticket.unwrap();
    first.send(&new_ticket, "after registry restart").await?;
    host.forget_device(&first_node).await?;
    let remaining_ticket = host.status()?.ticket.unwrap();
    assert_eq!(host.status()?.devices.len(), 1);
    assert_eq!(host.status()?.devices[0].node, second_node);
    assert!(
        first
            .send(&remaining_ticket, "forgotten node")
            .await
            .is_err()
    );
    second.send(&remaining_ticket, "second retained").await?;
    host.stop().await;
    first.stop().await;
    second.stop().await;
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; uses disposable Windows DPAPI profiles and a real isolated authority"]
async fn durable_devices_enroll_reopen_refresh_revoke_and_fail_closed_on_outage() -> Result<()> {
    use connect_core::device::DeviceController;
    let (mut process, info) = AuthorityProcess::start()?;
    let directory = tempfile::tempdir()?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let url = info["url"].as_str().unwrap().to_owned();
    let client_path = directory.path().join("client");
    let mut client = DeviceController::prepare(&client_path, url.clone(), pin.clone())?;
    let mut server =
        DeviceController::prepare(&directory.path().join("server"), url.clone(), pin.clone())?;
    assert!(DeviceController::prepare(&client_path, url, pin).is_err());
    assert!(
        DeviceController::open(&client_path).is_err(),
        "one writer per profile"
    );
    let client_key = client.status()?.node_public_key;
    let server_key = server.status()?.node_public_key;
    assert!(client.start(&server_key).await.is_err());
    for controller in [&mut client, &mut server] {
        let invite = process.command(
            json!({"op": "invite", "node_public_key": controller.status()?.node_public_key}),
        )?;
        controller
            .enroll(invite["invite"].as_str().unwrap())
            .await?;
        assert!(!controller.status()?.enrollment_pending);
    }
    let certificate = client.status()?.certificate_id;
    drop(client);
    let mut client = DeviceController::open(&client_path)?;
    assert_eq!(client.status()?.node_public_key, client_key);
    assert_eq!(client.status()?.certificate_id, certificate);
    assert!(client.status()?.ticket.is_none());
    assert!(!client.status()?.ready);
    server.start(&client_key).await?;
    let bridge_ticket = server
        .status()?
        .bridge_ticket
        .context("Missing host bridge ticket")?;
    client
        .use_bridge(connect_core::session::bridge::BridgeRoute {
            ticket: bridge_ticket,
            host_node: server_key.clone(),
        })
        .await?;
    let renewed = client.status()?.certificate_id;
    assert_ne!(renewed, certificate);
    assert!(client.status()?.authority_via_bridge);
    drop(client);
    let mut client = DeviceController::open(&client_path)?;
    assert!(client.status()?.authority_via_bridge);
    client.start(&server_key).await?;
    assert!(
        client.status()?.bridge_ticket.is_none(),
        "bridges are not chained"
    );
    assert!(
        client.use_local_authority().is_err(),
        "stop before changing authority"
    );
    let ticket = server.status()?.ticket.unwrap();
    assert!(
        client
            .send(&ticket, "durable identity")
            .await?
            .genesis_mesh_authenticated
    );
    server.refresh().await?;
    // Addresses can grow as Iroh discovers interfaces; the transport ID stays stable.
    let before: Value = serde_json::from_str(&ticket)?;
    let after: Value = serde_json::from_str(&server.status()?.ticket.unwrap())?;
    let before: iroh::EndpointAddr = serde_json::from_value(before["endpoint"].clone())?;
    let after: iroh::EndpointAddr = serde_json::from_value(after["endpoint"].clone())?;
    assert_eq!(before.id, after.id);
    assert!(
        client
            .send(&ticket, "after refresh")
            .await?
            .genesis_mesh_authenticated
    );
    process.command(json!({"op": "revoke", "cert_id": renewed}))?;
    server.refresh().await?;
    assert!(client.send(&ticket, "revoked").await.is_err());
    assert!(client.refresh().await.is_err());
    assert!(!client.status()?.ready);
    process.command(json!({"op": "stop"}))?;
    process.child.wait()?;
    assert!(server.refresh().await.is_err());
    assert!(!server.status()?.ready);
    assert!(
        server
            .send(&client.status()?.ticket.unwrap(), "offline")
            .await
            .is_err()
    );
    client.stop().await;
    server.stop().await;
    client.use_local_authority()?;
    assert!(!client.status()?.authority_via_bridge);
    println!(
        "Windows devices: protected identity restart, enrollment, trust refresh, QUIC echo, revocation and outage suspension passed."
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON with genesis-mesh installed; starts an isolated loopback authority"]
async fn real_authority_enrollment_renewal_reconnect_revocation_and_restart() -> Result<()> {
    let (mut process, info) = AuthorityProcess::start()?;
    let authority = LocalAuthority::new(info["url"].as_str().context("Missing authority URL")?)?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let directory = tempfile::tempdir()?;
    let client_path = directory.path().join("client.json");
    let server_path = directory.path().join("server.json");
    let mut client_store = TrustStore::create(&client_path, pin.clone())?;
    let mut server_store = TrustStore::create(&server_path, pin.clone())?;
    let client_key = key();
    let server_key = key();
    let client_invite =
        process.command(json!({"op": "invite", "node_public_key": public(&client_key)}))?;
    let server_invite =
        process.command(json!({"op": "invite", "node_public_key": public(&server_key)}))?;
    let mut client = authority
        .enroll(
            client_key.clone(),
            client_invite["invite"].as_str().unwrap(),
            &mut client_store,
        )
        .await?;
    let server = authority
        .enroll(
            server_key,
            server_invite["invite"].as_str().unwrap(),
            &mut server_store,
        )
        .await?;
    ensure!(
        client.certificate()["roles"] == json!(["role:client"]),
        "Wrong assigned role"
    );
    assert!(
        authority
            .enroll(
                client_key,
                client_invite["invite"].as_str().unwrap(),
                &mut client_store
            )
            .await
            .is_err(),
        "single-use invite must be refused"
    );
    let original = client.certificate()["cert_id"].clone();
    authority.renew(&mut client, &mut client_store).await?;
    assert_ne!(client.certificate()["cert_id"], original);

    // Reopen the on-disk watermark before the next refresh.
    drop(client_store);
    let mut client_store = TrustStore::open(&client_path, &pin)?;
    let client_endpoint = SessionEndpoint::bind(
        client.session_identity()?,
        authority.refresh(&mut client_store).await?,
        server.public_key(),
    )
    .await?;
    let server_endpoint = SessionEndpoint::bind(
        server.session_identity()?,
        authority.refresh(&mut server_store).await?,
        client.public_key(),
    )
    .await?;
    let report = client_endpoint
        .round_trip(&server_endpoint.ticket()?, "real authority hello")
        .await?;
    assert!(report.genesis_mesh_authenticated);
    assert_eq!(server_endpoint.received_messages(), 1);
    server_endpoint.close().await;

    process.command(json!({"op": "revoke", "cert_id": client.certificate()["cert_id"]}))?;
    let unchanged = client.certificate().clone();
    assert!(
        authority
            .renew(&mut client, &mut client_store)
            .await
            .is_err()
    );
    assert_eq!(client.certificate(), &unchanged);
    // The client still holds its earlier snapshot; the fresh server must refuse it.
    let server_endpoint = SessionEndpoint::bind(
        server.session_identity()?,
        authority.refresh(&mut server_store).await?,
        client.public_key(),
    )
    .await?;
    assert!(
        client_endpoint
            .round_trip(&server_endpoint.ticket()?, "must be denied")
            .await
            .is_err()
    );
    assert_eq!(server_endpoint.received_messages(), 0);
    client_endpoint.close().await;
    server_endpoint.close().await;
    drop(server_store);
    let mut server_store = TrustStore::open(&server_path, &pin)?;
    authority.refresh(&mut server_store).await?;

    process.command(json!({"op": "stop"}))?;
    process.child.wait()?;
    assert!(authority.refresh(&mut server_store).await.is_err());
    println!(
        "Real NA: enrollment, invite reuse refusal, renewal, persisted trust restart, authenticated QUIC, revocation refusal, authority outage passed."
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; disk-backed windows, full-size gates, version and denial/outage enforcement"]
async fn large_downloads_keep_full_size_policy_and_verify_windows() -> Result<()> {
    use connect_core::session::sharing::{
        Share, ShareConfig,
        download::{MIN_WINDOW_BYTES, Request},
    };
    use std::sync::Arc;
    let (mut process, info) = AuthorityProcess::start()?;
    let authority = LocalAuthority::new(info["url"].as_str().unwrap())?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let dir = tempfile::tempdir()?;
    let folder = dir.path().join("files");
    std::fs::create_dir(&folder)?;
    let content: Vec<u8> = (0..2 * 1024 * 1024 + 19).map(|i| (i % 251) as u8).collect();
    std::fs::write(folder.join("video.bin"), &content)?;
    let mut host_store = TrustStore::create(&dir.path().join("host.json"), pin.clone())?;
    let host_key = key();
    let executor = key();
    let invite =
        process.command(json!({"op":"edge_invite","node_public_key":public(&host_key)}))?;
    let (host, _) = authority
        .enroll_host(
            host_key,
            &executor,
            invite["invite"].as_str().unwrap(),
            &mut host_store,
        )
        .await?;
    let mut client_store = TrustStore::create(&dir.path().join("client.json"), pin.clone())?;
    let client_key = key();
    let invite = process.command(json!({"op":"invite","node_public_key":public(&client_key)}))?;
    let client = authority
        .enroll(
            client_key,
            invite["invite"].as_str().unwrap(),
            &mut client_store,
        )
        .await?;

    let policy=process.command(json!({"op":"list_policy","host_node":host.public_key(),"peer_node":client.public_key(),"collection":"family"}))?;
    let share = Arc::new(Share::open(
        ShareConfig {
            directory: folder.clone(),
            collection_id: "family".into(),
            policy_id: "connect-read".into(),
            attestation_id: policy["attestation_id"].as_str().unwrap().into(),
        },
        authority.clone(),
        pin,
        &dir.path().join("sharing"),
    )?);
    let host_endpoint = SessionEndpoint::bind_with_share(
        host.session_identity()?,
        authority.refresh(&mut host_store).await?,
        client.public_key(),
        Some(share.clone()),
    )
    .await?;
    let client_endpoint = SessionEndpoint::bind(
        client.session_identity()?,
        authority.refresh(&mut client_store).await?,
        host.public_key(),
    )
    .await?;
    let ticket = host_endpoint.ticket()?;
    let page = client_endpoint
        .catalog_from(&host.public_key(), &ticket, None)
        .await?;
    assert_eq!(page.files.len(), 1);
    let file = &page.files[0];
    assert_eq!(file.bytes, content.len() as u64);
    let request = |token: Option<String>, offset| Request {
        request_id: uuid::Uuid::new_v4().to_string(),
        collection_id: "family".into(),
        file_name: file.name.clone(),
        directory: Vec::new(),
        version: file.version.clone(),
        size: file.bytes,
        token,
        offset,
        length: MIN_WINDOW_BYTES,
    };
    let mut output = tempfile::tempfile()?;
    // A 64-KiB window does not bypass the policy's full-file size gate.
    assert!(
        client_endpoint
            .download_window_from(&host.public_key(), &ticket, request(None, 0), &mut output)
            .await
            .is_err()
    );
    assert_eq!(share.released_bytes(), 0);
    assert_eq!(output.metadata()?.len(), 0);
    // Denial must remove newly prepared snapshots rather than fill the cache.
    assert_eq!(
        std::fs::read_dir(dir.path().join("sharing/download-snapshots"))?.count(),
        0
    );
    process.command(json!({"op":"allow_reads","peer_node":client.public_key(),"collection":"family","max_size":1073741824}))?;
    let first = client_endpoint
        .download_window_from(&host.public_key(), &ticket, request(None, 0), &mut output)
        .await?;
    assert_eq!(first.bytes, 65536);
    let token = Some(first.token.clone());
    let offset = first.bytes as u64;
    // Wrong tokens and changed versions cannot expose additional bytes.
    let mut invalid = request(Some(uuid::Uuid::new_v4().to_string()), offset);
    assert!(
        client_endpoint
            .download_window_from(&host.public_key(), &ticket, invalid.clone(), &mut output)
            .await
            .is_err()
    );
    invalid = request(token.clone(), offset);
    invalid.version = "0".repeat(64);
    assert!(
        client_endpoint
            .download_window_from(&host.public_key(), &ticket, invalid, &mut output)
            .await
            .is_err()
    );
    assert_eq!(share.released_bytes(), offset);
    // A live policy denial stops the very next window and preserves confirmed offset.
    process.command(json!({"op":"deny_reads","peer_node":client.public_key()}))?;
    assert!(
        client_endpoint
            .download_window_from(
                &host.public_key(),
                &ticket,
                request(token.clone(), offset),
                &mut output
            )
            .await
            .is_err()
    );
    assert_eq!(share.released_bytes(), offset);
    assert_eq!(output.metadata()?.len(), offset);
    process.command(json!({"op":"allow_reads","peer_node":client.public_key(),"collection":"family","max_size":1073741824}))?;
    let mut rest = request(token.clone(), offset);
    rest.length = 4 * 1024 * 1024;
    let last = client_endpoint
        .download_window_from(&host.public_key(), &ticket, rest, &mut output)
        .await?;
    assert!(last.done);
    use std::io::{Read, Seek, SeekFrom};
    output.seek(SeekFrom::Start(0))?;
    let mut received = Vec::new();
    output.read_to_end(&mut received)?;
    assert_eq!(received, content);
    use sha2::{Digest, Sha256};
    let digest: String = Sha256::digest(&received)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(last.sha256, digest);
    // Changed source metadata invalidates a fresh download of an old catalog entry.
    std::fs::write(folder.join("video.bin"), b"changed")?;
    let before = share.released_bytes();
    let mut fresh = tempfile::tempfile()?;
    assert!(
        client_endpoint
            .download_window_from(&host.public_key(), &ticket, request(None, 0), &mut fresh)
            .await
            .is_err()
    );
    assert_eq!(share.released_bytes(), before);
    process.command(json!({"op":"stop"}))?;
    process.child.wait()?;
    output.set_len(offset)?;
    assert!(
        client_endpoint
            .download_window_from(
                &host.public_key(),
                &ticket,
                request(token, offset),
                &mut output
            )
            .await
            .is_err()
    );
    assert_eq!(share.released_bytes(), before);
    client_endpoint.close().await;
    host_endpoint.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; real nested folder permissions and path-bound download tokens"]
async fn nested_browsing_and_downloads_bind_paths_and_preserve_flat_clients() -> Result<()> {
    use connect_core::session::sharing::{
        Share, ShareConfig,
        browse::Kind,
        download::{MIN_WINDOW_BYTES, Request},
    };
    use std::sync::Arc;
    let (mut process, info) = AuthorityProcess::start()?;
    let authority = LocalAuthority::new(info["url"].as_str().unwrap())?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let dir = tempfile::tempdir()?;
    let folder = dir.path().join("files");
    std::fs::create_dir(&folder)?;
    let content: Vec<u8> = (0..2 * 1024 * 1024 + 19).map(|i| (i % 251) as u8).collect();
    std::fs::write(folder.join("video.bin"), &content)?;
    let mut host_store = TrustStore::create(&dir.path().join("host.json"), pin.clone())?;
    let host_key = key();
    let executor = key();
    let invite =
        process.command(json!({"op":"edge_invite","node_public_key":public(&host_key)}))?;
    let (host, _) = authority
        .enroll_host(
            host_key,
            &executor,
            invite["invite"].as_str().unwrap(),
            &mut host_store,
        )
        .await?;
    let mut client_store = TrustStore::create(&dir.path().join("client.json"), pin.clone())?;
    let client_key = key();
    let invite = process.command(json!({"op":"invite","node_public_key":public(&client_key)}))?;
    let client = authority
        .enroll(
            client_key,
            invite["invite"].as_str().unwrap(),
            &mut client_store,
        )
        .await?;

    std::fs::create_dir_all(folder.join("Photos/Été 2026"))?;
    std::fs::create_dir(folder.join("Other"))?;
    let nested = vec!["Photos".to_owned(), "Été 2026".to_owned()];
    let data = vec![31u8; 131075];
    std::fs::write(folder.join("Photos/Été 2026/picture.jpg"), &data)?;
    std::fs::write(folder.join("Other/picture.jpg"), vec![99u8; data.len()])?;
    let policy=process.command(json!({"op":"list_policy","host_node":host.public_key(),"peer_node":client.public_key(),"collection":"family","max_size":1073741824}))?;
    let share = Arc::new(Share::open(
        ShareConfig {
            directory: folder,
            collection_id: "family".into(),
            policy_id: "connect-read".into(),
            attestation_id: policy["attestation_id"].as_str().unwrap().into(),
        },
        authority.clone(),
        pin,
        &dir.path().join("sharing"),
    )?);
    let server = SessionEndpoint::bind_with_share(
        host.session_identity()?,
        authority.refresh(&mut host_store).await?,
        client.public_key(),
        Some(share.clone()),
    )
    .await?;
    let reader = SessionEndpoint::bind(
        client.session_identity()?,
        authority.refresh(&mut client_store).await?,
        host.public_key(),
    )
    .await?;
    let ticket = server.ticket()?;
    // Existing catalog clients retain their flat v1 response format.
    assert_eq!(
        reader
            .catalog_from(&host.public_key(), &ticket, None)
            .await?
            .files
            .len(),
        1
    );
    let root = reader
        .browse_from(&host.public_key(), &ticket, None, Vec::new())
        .await?;
    assert_eq!(root.files.len(), 3);
    assert_eq!(
        root.files.iter().filter(|e| e.kind == Kind::Folder).count(),
        2
    );
    let page = reader
        .browse_from(&host.public_key(), &ticket, None, nested.clone())
        .await?;
    assert_eq!(page.directory, nested);
    assert_eq!(page.files.len(), 1);
    let file = &page.files[0];
    let other = reader
        .browse_from(&host.public_key(), &ticket, None, vec!["Other".into()])
        .await?;
    let before = share.released_names();
    for bad in [
        vec!["..".into()],
        vec!["/Photos".into()],
        vec!["Photos/Été 2026".into()],
    ] {
        assert!(
            reader
                .browse_from(&host.public_key(), &ticket, None, bad)
                .await
                .is_err()
        );
        assert_eq!(share.released_names(), before);
    }
    let request = |token, offset| Request {
        request_id: uuid::Uuid::new_v4().to_string(),
        collection_id: "family".into(),
        file_name: file.name.clone(),
        directory: nested.clone(),
        version: file.version.clone(),
        size: file.bytes,
        token,
        offset,
        length: MIN_WINDOW_BYTES,
    };
    let mut output = tempfile::tempfile()?;
    let first = reader
        .download_window_from(&host.public_key(), &ticket, request(None, 0), &mut output)
        .await?;
    let offset = first.bytes as u64;
    let mut wrong = request(Some(first.token.clone()), offset);
    wrong.directory = vec!["Other".into()];
    wrong.version = other.files[0].version.clone();
    assert!(
        reader
            .download_window_from(&host.public_key(), &ticket, wrong, &mut output)
            .await
            .is_err()
    );
    assert_eq!(share.released_bytes(), offset);
    assert_eq!(output.metadata()?.len(), offset);
    let mut rest = request(Some(first.token), offset);
    rest.length = MIN_WINDOW_BYTES * 4;
    let last = reader
        .download_window_from(&host.public_key(), &ticket, rest, &mut output)
        .await?;
    assert!(last.done);
    use std::io::{Read, Seek, SeekFrom};
    output.seek(SeekFrom::Start(0))?;
    let mut received = Vec::new();
    output.read_to_end(&mut received)?;
    assert_eq!(received, data);
    let before_names = share.released_names();
    let before_bytes = share.released_bytes();
    process.command(json!({"op":"deny_list","peer_node":client.public_key()}))?;
    assert!(
        reader
            .browse_from(&host.public_key(), &ticket, None, nested.clone())
            .await
            .is_err()
    );
    let mut fresh = tempfile::tempfile()?;
    assert!(
        reader
            .download_window_from(&host.public_key(), &ticket, request(None, 0), &mut fresh)
            .await
            .is_err()
    );
    assert_eq!(share.released_names(), before_names);
    assert_eq!(share.released_bytes(), before_bytes);
    reader.close().await;
    server.close().await;
    process.command(json!({"op":"stop"}))?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires CONNECT_NA_PYTHON; guided pairing on the local network, its saved ports and the network's setting"]
async fn guided_pairing_works_on_the_local_network_and_survives_a_computer_restart() -> Result<()> {
    use connect_core::{
        Connectivity,
        device::{DeviceController, PairedDevice},
        session::{
            bridge::BridgeRoute,
            pairing::{PairCard, PairGrant},
        },
    };
    let (mut process, info) = AuthorityProcess::start()?;
    let pin: TrustPin = serde_json::from_value(info["pin"].clone())?;
    let dir = tempfile::tempdir()?;
    let mut computer = DeviceController::prepare(
        &dir.path().join("computer"),
        info["url"].as_str().unwrap().into(),
        pin,
    )?;
    computer.enable_managed_connectivity()?;
    let computer_node = computer.status()?.node_public_key;
    let invitation = process.command(json!({"op":"invite","node_public_key":computer_node}))?;
    computer
        .enroll(invitation["invite"].as_str().unwrap())
        .await?;
    computer
        .set_network_connectivity(Connectivity::LocalNetwork)
        .await?;
    let status = computer.status()?.connectivity;
    assert!(status.network_computer);
    assert_eq!(status.effective, Connectivity::LocalNetwork);
    assert!(
        computer
            .set_own_connectivity(Some(Connectivity::LocalNetwork))
            .await
            .is_err(),
        "The network computer's choice is the network's setting"
    );

    let pair = computer.create_pairing("Home computer".into()).await?;
    let card = PairCard::parse(&pair.card().link()?)?;
    assert_eq!(card.connectivity(), Connectivity::LocalNetwork);
    let mut phone = DeviceController::prepare_remote(&dir.path().join("phone"), card.pin.clone())?;
    let mut joining = phone
        .request_pairing(card.clone(), "My phone".into())
        .await?;
    let request = pair.pending().context("No pending approval")?;
    let invitation =
        process.command(json!({"op":"invite","node_public_key":request.node.clone()}))?;
    computer.start(&request.node).await?;
    let host = computer.status()?;
    let completion = pair.approve(
        &request.id,
        PairGrant {
            invitation: invitation["invite"].as_str().unwrap().into(),
            route: BridgeRoute {
                host_node: host.node_public_key.clone(),
                ticket: host.bridge_ticket.context("Missing authority connection")?,
            },
            session_ticket: host.ticket.context("Missing device connection")?,
        },
    )?;
    let grant = joining.grant().await?;
    phone.use_bridge(grant.route).await?;
    phone.enroll(&grant.invitation).await?;
    phone.start(&card.host_node).await?;
    phone
        .send(&grant.session_ticket, "Phone verifies computer")
        .await?;
    let phone_ticket = phone.status()?.ticket.context("Missing phone connection")?;
    phone.remember_pairing(PairedDevice {
        name: card.host_name.clone(),
        node: card.host_node.clone(),
        ticket: grant.session_ticket,
    })?;
    let finish = joining.finish(phone_ticket);
    let owner = async {
        let joined = completion.await?;
        computer
            .send(&joined.ticket, "Computer verifies phone")
            .await?;
        computer.remember_pairing(PairedDevice {
            name: request.name.clone(),
            node: request.node.clone(),
            ticket: joined.ticket,
        })?;
        joined
            .confirm
            .send(true)
            .map_err(|_| anyhow::anyhow!("Phone disconnected"))?;
        Ok::<_, anyhow::Error>(())
    };
    let (a, b) = tokio::join!(finish, owner);
    a?;
    b?;
    joining.close().await;
    pair.close().await;

    let status = phone.status()?.connectivity;
    assert!(!status.network_computer);
    assert_eq!(status.network, Connectivity::LocalNetwork);
    assert_eq!(status.effective, Connectivity::LocalNetwork);
    phone.refresh().await?;
    assert_eq!(
        phone.status()?.connectivity.network,
        Connectivity::LocalNetwork,
        "The network computer's authenticated answer keeps the setting"
    );
    phone
        .set_own_connectivity(Some(Connectivity::PublicRelays))
        .await?;
    assert_eq!(
        phone.status()?.connectivity.effective,
        Connectivity::LocalNetwork,
        "A looser device choice never widens the network's setting"
    );
    phone.set_own_connectivity(None).await?;

    // Restarting the network computer reuses its ports, so the phone's saved
    // addresses keep working without relays or a new pairing.
    let port = computer.session()?.port();
    assert!(port.is_some());
    computer.stop().await;
    computer.start(&request.node).await?;
    assert_eq!(computer.session()?.port(), port);
    phone.refresh().await?;
    let saved = phone
        .paired_device()
        .context("Missing saved computer")?
        .ticket
        .clone();
    phone
        .send(&saved, "Phone reaches the restarted computer")
        .await?;

    phone.stop().await;
    computer.stop().await;
    process.command(json!({"op":"stop"}))?;
    process.child.wait()?;
    Ok(())
}
