//! Disposable embedded authority + independent profiles + real governed resources.
//! No device operations, app-boundary qualification, or replacement trust engine.
#![cfg(all(target_os = "linux", feature = "pairing-completion-recovery"))]
#[path = "support/foreground_pairing.rs"]
mod pairing_support;
#[path = "support/foreground_resources.rs"]
mod resource_support;
#[path = "support/embedded_owner.rs"]
mod support;
use anyhow::{Context, Result};
use connect_core::{
    owner::foreground::ForegroundNetwork,
    session::sharing::{SpaceKind, download::MIN_WINDOW_BYTES},
};
use pairing_support::ticket;
use resource_support::*;
use std::sync::Arc;

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn recovered_pair_shares_nested_files_both_ways_with_fresh_core_decisions() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut network = Network::new(root, true).await?;
    let (folder, expected) = content(root, "owner-files")?;
    let local = network
        .host_folder(&folder, "From the authority host")
        .await?;
    let (host, address) = network.host_ticket().await?;
    let before = support::core_calls(root, DECISION);
    let file = entry(&network.member, &host, &address, &local.collection_id).await?;
    receive(
        &network.member,
        &host,
        &address,
        &local.collection_id,
        &file,
        &expected,
    )
    .await?;
    assert!(
        support::core_calls(root, DECISION) >= before + 6,
        "Browse and each download window must reach the actual core"
    );
    let (folder, expected) = content(root, "member-files")?;
    let remote = network
        .member
        .share_space(
            None,
            folder,
            "From the joined device".into(),
            vec![host.clone()],
            SpaceKind::Folder,
        )
        .await?;
    let member = network.member.status()?;
    assert!(member.authority.is_none() && member.authority_via_bridge && member.sharing_host);
    let address = ticket(member.ticket.context("Missing member session")?)?;
    let before = support::core_calls(root, DECISION);
    {
        let owner = network.host.lock().await;
        let file = entry(
            &owner.device,
            &member.node_public_key,
            &address,
            &remote.collection_id,
        )
        .await?;
        receive(
            &owner.device,
            &member.node_public_key,
            &address,
            &remote.collection_id,
            &file,
            &expected,
        )
        .await?;
    }
    assert!(
        support::core_calls(root, DECISION) >= before + 6,
        "Remote-host decisions must use the authority bridge"
    );
    network.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn narrowing_full_file_policy_stops_next_window_without_extending_staging() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let network = Network::new(root, false).await?;
    let (folder, expected) = content(root, "owner-files")?;
    let config = network
        .host_folder(&folder, "Policy-controlled folder")
        .await?;
    let (host, address) = network.host_ticket().await?;
    let file = entry(&network.member, &host, &address, &config.collection_id).await?;
    let mut output = tempfile::tempfile()?;
    let first = network
        .member
        .session()?
        .download_window_from(
            &host,
            &address,
            download(&config.collection_id, &file, None, 0),
            &mut output,
        )
        .await?;
    assert!(!first.done);
    assert_eq!(first.bytes, MIN_WINDOW_BYTES as usize);
    let mut policy = {
        network
            .host
            .lock()
            .await
            .runtime
            .access_get(&host, &config.collection_id)?
    };
    policy.max_bytes = MIN_WINDOW_BYTES as u64;
    {
        let mut owner = network.host.lock().await;
        owner
            .runtime
            .access_update(&host, &config.collection_id, &policy)?;
        publish(&mut owner)?;
    }
    let before = support::core_calls(root, DECISION);
    let next = download(
        &config.collection_id,
        &file,
        Some(first.token.clone()),
        first.bytes as u64,
    );
    assert!(
        network
            .member
            .session()?
            .download_window_from(&host, &address, next.clone(), &mut output)
            .await
            .is_err(),
        "A window-sized allowance cannot authorize the larger file"
    );
    assert!(
        support::core_calls(root, DECISION) > before,
        "The running share must ask core again"
    );
    assert_eq!(output.metadata()?.len(), first.bytes as u64);
    assert_eq!(bytes(&mut output)?, &expected[..first.bytes]);
    // An explicit new policy version can permit continuing the same exact snapshot.
    {
        let mut owner = network.host.lock().await;
        let mut allowed = owner.runtime.access_get(&host, &config.collection_id)?;
        allowed.max_bytes = file.bytes;
        owner
            .runtime
            .access_update(&host, &config.collection_id, &allowed)?;
        publish(&mut owner)?;
    }
    let mut rest = next;
    rest.length = MIN_WINDOW_BYTES * 4;
    let last = network
        .member
        .session()?
        .download_window_from(&host, &address, rest, &mut output)
        .await?;
    assert!(last.done);
    assert_eq!(last.sha256, digest(&expected));
    assert_eq!(bytes(&mut output)?, expected);
    network.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn authenticated_member_without_resource_permission_gets_no_names_or_file_output()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let network = Network::new(root, false).await?;
    let mut outsider = {
        let mut host = network.host.lock().await;
        pair(&mut host, &root.join("outsider"), false).await?
    };
    let (folder, _) = content(root, "owner-files")?;
    let config = network.host_folder(&folder, "Chosen devices only").await?;
    let (host, address) = network.host_ticket().await?;
    let report = outsider
        .session()?
        .round_trip_to(Some(&host), &address, "Authenticated is not authorized")
        .await?;
    assert!(report.genesis_mesh_authenticated);
    let file = entry(&network.member, &host, &address, &config.collection_id).await?;
    assert!(
        outsider
            .session()?
            .browse_from(
                &host,
                &address,
                None,
                vec![],
                Some(config.collection_id.clone())
            )
            .await
            .is_err()
    );
    let mut output = tempfile::tempfile()?;
    assert!(
        outsider
            .session()?
            .download_window_from(
                &host,
                &address,
                download(&config.collection_id, &file, None, 0),
                &mut output
            )
            .await
            .is_err()
    );
    assert_eq!(output.metadata()?.len(), 0);
    outsider.stop().await;
    network.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn core_revocation_stops_resource_access_before_cached_endpoint_trust_is_refreshed()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let network = Network::new(root, false).await?;
    let (folder, _) = content(root, "owner-files")?;
    let config = network.host_folder(&folder, "Revocable folder").await?;
    let (host, address) = network.host_ticket().await?;
    let file = entry(&network.member, &host, &address, &config.collection_id).await?;
    let mut output = tempfile::tempfile()?;
    let first = network
        .member
        .session()?
        .download_window_from(
            &host,
            &address,
            download(&config.collection_id, &file, None, 0),
            &mut output,
        )
        .await?;
    let member = network.member.status()?;
    assert!(
        network
            .host
            .lock()
            .await
            .runtime
            .remove_device(&member.node_public_key)?
            .revoked
            > 0
    );
    // Cached transport still proves possession. The protected operation must
    // independently fetch core trust and refuse this now-revoked member.
    assert!(
        network
            .member
            .session()?
            .round_trip_to(Some(&host), &address, "Cached diagnostic session")
            .await?
            .genesis_mesh_authenticated
    );
    assert!(
        network
            .member
            .session()?
            .browse_from(
                &host,
                &address,
                None,
                vec![],
                Some(config.collection_id.clone())
            )
            .await
            .is_err()
    );
    assert!(
        network
            .member
            .session()?
            .download_window_from(
                &host,
                &address,
                download(
                    &config.collection_id,
                    &file,
                    Some(first.token),
                    first.bytes as u64
                ),
                &mut output
            )
            .await
            .is_err()
    );
    assert_eq!(output.metadata()?.len(), first.bytes as u64);
    assert_eq!(
        network.member.status()?.certificate_id,
        member.certificate_id
    );
    assert_eq!(support::calls(root, "invite"), 2);
    network.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn normal_authority_shutdown_refuses_next_resource_request_while_cached_transport_stays_live()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let network = Network::new(root, false).await?;
    let (folder, expected) = content(root, "owner-files")?;
    let config = network
        .host_folder(&folder, "Live authority required")
        .await?;
    let (host, address) = network.host_ticket().await?;
    let file = entry(&network.member, &host, &address, &config.collection_id).await?;
    let mut output = tempfile::tempfile()?;
    let first = network
        .member
        .session()?
        .download_window_from(
            &host,
            &address,
            download(&config.collection_id, &file, None, 0),
            &mut output,
        )
        .await?;
    // Normal shutdown of this fixture's live embedded core; neither an induced
    // startup failure nor a replacement authority or poisoned native session.
    let Network {
        host: state,
        worker,
        mut member,
    } = network;
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    let owner = Arc::try_unwrap(state)
        .map_err(|_| anyhow::anyhow!("Fixture host is still borrowed"))?
        .into_inner();
    let ForegroundNetwork {
        runtime,
        mut device,
        ..
    } = owner;
    drop(runtime);
    let after_close = support::core_calls(root, DECISION);
    assert!(
        member
            .session()?
            .round_trip_to(
                Some(&host),
                &address,
                "Cached transport after normal authority close"
            )
            .await?
            .genesis_mesh_authenticated
    );
    assert!(
        member
            .session()?
            .browse_from(
                &host,
                &address,
                None,
                vec![],
                Some(config.collection_id.clone())
            )
            .await
            .is_err()
    );
    assert!(
        member
            .session()?
            .download_window_from(
                &host,
                &address,
                download(
                    &config.collection_id,
                    &file,
                    Some(first.token),
                    first.bytes as u64
                ),
                &mut output
            )
            .await
            .is_err()
    );
    assert_eq!(output.metadata()?.len(), first.bytes as u64);
    assert_eq!(bytes(&mut output)?, &expected[..first.bytes]);
    assert_eq!(support::core_calls(root, DECISION), after_close);
    assert_eq!(support::calls(root, "invite"), 2);
    member.stop().await;
    device.stop().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn joined_device_shares_real_tcp_service_and_native_policy_change_closes_live_stream()
-> Result<()> {
    use connect_core::{owner::AccessPolicy, session::sharing::service::Target};
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut network = Network::new(root, false).await?;
    let (host, _) = network.host_ticket().await?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let echo = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut bytes = [0; 128];
                while let Ok(n) = stream.read(&mut bytes).await {
                    if n == 0 || stream.write_all(&bytes[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let directory = root.join("service-state");
    std::fs::create_dir(&directory)?;
    let service = network
        .member
        .share_service(
            directory,
            "My local service".into(),
            vec![host],
            SpaceKind::Tcp,
            Target {
                port,
                max_bytes: 65536,
                max_seconds: 60,
            },
        )
        .await?;
    let status = network.member.status()?;
    assert!(status.authority.is_none() && status.authority_via_bridge);
    let address = ticket(status.ticket.context("Missing member service endpoint")?)?;
    let session = network.host.lock().await.device.session()?;
    async fn tcp_pair() -> Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let application = TcpStream::connect(listener.local_addr()?).await?;
        let (adapter, _) = listener.accept().await?;
        Ok((application, adapter))
    }
    // Kind and collection are checked before any connection reaches the target.
    let (_, adapter) = tcp_pair().await?;
    assert!(
        session
            .forward_service(
                &status.node_public_key,
                &address,
                &service.collection_id,
                SpaceKind::Web,
                adapter
            )
            .await
            .is_err()
    );
    let (_, adapter) = tcp_pair().await?;
    assert!(
        session
            .forward_service(
                &status.node_public_key,
                &address,
                &uuid::Uuid::new_v4().to_string(),
                SpaceKind::Tcp,
                adapter
            )
            .await
            .is_err()
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    let (mut application, adapter) = tcp_pair().await?;
    let peer = status.node_public_key.clone();
    let destination = address.clone();
    let collection = service.collection_id.clone();
    let endpoint = session.clone();
    let before = support::core_calls(root, DECISION);
    let forwarding = tokio::spawn(async move {
        endpoint
            .forward_service(&peer, &destination, &collection, SpaceKind::Tcp, adapter)
            .await
    });
    application.write_all(b"hello service").await?;
    let mut reply = [0; 13];
    timeout(Duration::from_secs(15), application.read_exact(&mut reply)).await??;
    assert_eq!(&reply, b"hello service");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    assert!(support::core_calls(root, DECISION) > before);
    // Change only the authority policy through the actual member->bridge->native
    // adapter. The target and active connection remain unchanged.
    let mut policy: AccessPolicy = serde_json::from_value(
        network
            .member
            .access_policy(service.collection_id.clone(), None)
            .await?,
    )?;
    let stale = policy.clone();
    policy.max_bytes = 1;
    let changed = network
        .member
        .access_policy(service.collection_id.clone(), Some(policy))
        .await?;
    assert_eq!(changed["settings"]["max_bytes"], 1);
    assert!(
        network
            .member
            .access_policy(service.collection_id.clone(), Some(stale))
            .await
            .is_err(),
        "An old review cannot overwrite a newer policy version"
    );
    assert!(
        timeout(Duration::from_secs(15), forwarding)
            .await??
            .is_err(),
        "A new authority refusal must close the live stream"
    );
    let (_, adapter) = tcp_pair().await?;
    assert!(
        session
            .forward_service(
                &status.node_public_key,
                &address,
                &service.collection_id,
                SpaceKind::Tcp,
                adapter
            )
            .await
            .is_err()
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "Refused connections must never reach the local service"
    );
    echo.abort();
    assert!(echo.await.unwrap_err().is_cancelled());
    network.close().await;
    Ok(())
}
