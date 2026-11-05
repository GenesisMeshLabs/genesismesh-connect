//! Disposable real-core adapter acceptance; never uses the user's network.
#![cfg(debug_assertions)]
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use connect_core::{
    access_workflow::{AccessContext, AccessJournal, Authorization, Stage},
    owner::OwnerRuntime,
    session::sharing::SpaceKind,
};
use std::path::{Path, PathBuf};

fn start(path: &Path) -> Result<OwnerRuntime> {
    let python =
        PathBuf::from(std::env::var_os("CONNECT_NA_PYTHON").context("Set CONNECT_NA_PYTHON")?);
    OwnerRuntime::start_python(
        &python,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/connect/authority/main.py"),
        path,
    )
}
fn node(seed: u8) -> String {
    STANDARD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

#[test]
#[ignore = "Requires matching CONNECT_NA_PYTHON and disposable native secret store"]
fn real_authority_commit_lost_reply_restart_readback_and_stale_denial() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let owner_path = dir.path().join("owner");
    let mut owner = start(&owner_path)?;
    let info = owner.create("Access workflow acceptance")?;
    owner.capabilities()?.require_access_update(&info.pin)?;
    let host = node(2);
    let phone = node(3);
    let stranger = node(4);
    let context = AccessContext {
        pin: info.pin,
        actor: host.clone(),
        audience: host.clone(),
    };
    let collection = uuid::Uuid::new_v4().to_string();
    owner.space_share(
        &host,
        &collection,
        "Family photos",
        &[phone],
        None,
        SpaceKind::Folder,
    )?;
    let before = owner.access_get(&host, &collection)?;
    let mut after = before.clone();
    after.max_bytes = 8192;
    let journal_path = dir.path().join("workflows.json");
    let mut journal = AccessJournal::open(&journal_path)?;
    let review = journal.prepare(
        context.clone(),
        collection.clone(),
        "Family photos".into(),
        before.clone(),
        after,
        Utc::now(),
    )?;
    assert_eq!(
        owner.access_get(&host, &collection)?.version,
        1,
        "Review did not mutate the authority"
    );
    journal.submit(
        &review.intent.id,
        &review.digest,
        &context,
        owner.access_get(&host, &collection)?,
        Utc::now(),
    )?;
    // The core commits, but the application loses the reply before recording it.
    owner.access_update(&host, &collection, &review.intent.after)?;
    drop(owner);
    drop(journal);
    let mut owner = start(&owner_path)?;
    let reopened = owner.open()?;
    assert_eq!(reopened.pin, context.pin);
    let mut journal = AccessJournal::open(&journal_path)?;
    assert_eq!(
        journal.get(&review.intent.id, &context)?.stage,
        Stage::Unknown
    );
    let observed = owner.access_get(&host, &collection)?;
    let record = journal.observe(&review.intent.id, observed.clone())?;
    assert_eq!(record.stage, Stage::StateObserved);
    assert_eq!(
        record.authorization,
        Authorization::Unknown,
        "Readback is not a signed authorization receipt"
    );
    assert!(
        journal
            .submit(
                &review.intent.id,
                &review.digest,
                &context,
                observed.clone(),
                Utc::now()
            )
            .is_err()
    );
    assert_eq!(
        owner.access_get(&host, &collection)?.version,
        2,
        "No repeat mutation on recovery"
    );
    let review = journal.prepare(
        context.clone(),
        collection.clone(),
        "Family photos".into(),
        observed.clone(),
        observed.clone(),
        Utc::now(),
    )?;
    let mut concurrent = observed;
    concurrent.max_bytes = 2048;
    let result = owner.access_update(&host, &collection, &concurrent)?;
    assert!(
        journal
            .submit(
                &review.intent.id,
                &review.digest,
                &context,
                result.settings.clone(),
                Utc::now()
            )
            .is_err()
    );
    assert!(
        owner
            .access_update(&stranger, &collection, &result.settings)
            .is_err()
    );
    assert_eq!(
        owner.access_get(&host, &collection)?.version,
        3,
        "Denial has no extra policy version"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires matching CONNECT_NA_PYTHON and disposable native secret store"]
async fn remote_resource_discovery_uses_real_authority_and_authenticated_host_scope() -> Result<()>
{
    use connect_core::{
        authority::{LocalAuthority, TrustStore},
        operations::OperationId,
        session::{
            SessionEndpoint,
            bridge::{AuthorityBridge, BridgeAuthority, BridgeRoute},
        },
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let dir = tempfile::tempdir()?;
    let mut owner = start(&dir.path().join("owner"))?;
    let info = owner.create("Remote readiness")?;
    let local = LocalAuthority::new(&info.url)?;
    let server_key = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
    let client_key = ed25519_dalek::SigningKey::from_bytes(&[13; 32]);
    let mut server_store =
        TrustStore::create(&dir.path().join("server-trust.json"), info.pin.clone())?;
    let mut client_store =
        TrustStore::create(&dir.path().join("client-trust.json"), info.pin.clone())?;
    let invite = owner.invite(&node(12), false)?;
    let server = local.enroll(server_key, &invite, &mut server_store).await?;
    let invite = owner.invite(&node(13), false)?;
    let client = local.enroll(client_key, &invite, &mut client_store).await?;
    let client_endpoint = SessionEndpoint::bind(
        client.session_identity()?,
        local.refresh(&mut client_store).await?,
        server.public_key(),
    )
    .await?;
    let collection = uuid::Uuid::new_v4().to_string();
    owner.space_share(
        &client.public_key(),
        &collection,
        "Phone photos",
        &[server.public_key()],
        None,
        SpaceKind::Folder,
    )?;
    let other_collection = uuid::Uuid::new_v4().to_string();
    owner.space_share(
        &server.public_key(),
        &other_collection,
        "Computer files",
        &[client.public_key()],
        None,
        SpaceKind::Folder,
    )?;
    let bridge = AuthorityBridge::bind(
        server.session_identity()?,
        local.refresh(&mut server_store).await?,
        client.public_key(),
        local,
    )
    .await?;
    bridge.publish_spaces(owner.space_list()?);
    bridge.publish_members(vec![connect_core::device::PairedDevice {
        name: "Phone".into(),
        node: client.public_key(),
        ticket: client_endpoint.ticket()?,
    }]);
    let (handle, mut requests) = tokio::sync::mpsc::channel::<connect_core::owner::OwnerRequest>(8);
    bridge.serve_owner(handle);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let runtime = std::thread::spawn(move || {
        while let Some(request) = requests.blocking_recv() {
            observed.fetch_add(1, Ordering::SeqCst);
            let _ = request.reply.send(owner.answer(request.call));
        }
    });
    // Deliberately same-host loopback, independent of LAN/VPN routing.
    let mut ticket: serde_json::Value = serde_json::from_str(&bridge.ticket()?)?;
    let socket = ticket["endpoint"]["addrs"]
        .as_array()
        .context("No bridge addresses")?
        .iter()
        .filter_map(|a| a["Ip"].as_str()?.parse::<std::net::SocketAddr>().ok())
        .find(|a| a.is_ipv4())
        .context("No IPv4 bridge socket")?;
    ticket["endpoint"]["addrs"] = serde_json::json!([{"Ip":format!("127.0.0.1:{}",socket.port())}]);
    let remote = BridgeAuthority::new(BridgeRoute {
        host_node: server.public_key(),
        ticket: ticket.to_string(),
    })?;
    let trust = remote.refresh(&mut client_store).await?;
    let capabilities = remote
        .resource_capabilities(
            client.session_identity()?,
            trust.clone(),
            &info.pin,
            collection.clone(),
        )
        .await?;
    capabilities.require(
        &info.pin,
        &client.public_key(),
        &collection,
        OperationId::UpdateAccess,
    )?;
    assert_eq!(capabilities.policy_version, 1);
    assert!(
        remote
            .resource_capabilities(
                client.session_identity()?,
                trust.clone(),
                &info.pin,
                other_collection
            )
            .await
            .is_err(),
        "Being a recipient does not make it the host"
    );
    let mut wrong = info.pin.clone();
    wrong.network_name = "Other".into();
    assert!(
        remote
            .resource_capabilities(
                client.session_identity()?,
                trust.clone(),
                &wrong,
                collection.clone()
            )
            .await
            .is_err()
    );
    let settings: connect_core::owner::AccessPolicy = serde_json::from_value(
        remote
            .access_policy(
                client.session_identity()?,
                trust.clone(),
                collection.clone(),
                None,
            )
            .await?,
    )?;
    assert_eq!(settings.version, 1, "Discovery changed no policy");
    let mut changed = settings;
    changed.max_bytes = 8192;
    remote
        .access_policy(
            client.session_identity()?,
            trust.clone(),
            collection.clone(),
            Some(changed),
        )
        .await?;
    assert_eq!(
        remote
            .resource_capabilities(
                client.session_identity()?,
                trust.clone(),
                &info.pin,
                collection.clone()
            )
            .await?
            .policy_version,
        2
    );
    let before = calls.load(Ordering::SeqCst);
    bridge.publish_members(vec![]);
    assert!(
        remote
            .resource_capabilities(client.session_identity()?, trust, &info.pin, collection)
            .await
            .is_err()
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        before,
        "Unsaved caller never reaches owner runtime"
    );
    client_endpoint.close().await;
    bridge.close().await;
    drop(bridge);
    runtime
        .join()
        .map_err(|_| anyhow::anyhow!("Owner test thread failed"))?;
    Ok(())
}
