//! Actual managed core, native host and authenticated QUIC Requests dispatch.
//! All authorities, keys and profiles are disposable; no Android startup test.
#![cfg(debug_assertions)]
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use connect_core::{
    Connectivity,
    authority::{EnrolledDevice, LocalAuthority, TrustStore},
    device::{DeviceController, PairedDevice},
    owner::{OwnerRequest, OwnerRuntime},
    owner_control::*,
    session::{
        SessionEndpoint,
        bridge::{BridgeAuthority, BridgeRoute},
        pairing::{PairCard, PairClient},
    },
};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Mutex;

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(k: &SigningKey) -> String {
    STANDARD.encode(k.verifying_key().to_bytes())
}
fn loopback(mut value: Value) -> Result<Value> {
    let socket = value["endpoint"]["addrs"]
        .as_array()
        .context("Missing addresses")?
        .iter()
        .filter_map(|a| a["Ip"].as_str()?.parse::<std::net::SocketAddr>().ok())
        .find(|a| a.is_ipv4())
        .context("Missing IPv4 socket")?;
    value["endpoint"]["addrs"] = json!([{"Ip":format!("127.0.0.1:{}",socket.port())}]);
    Ok(value)
}
fn ticket(text: String) -> Result<String> {
    Ok(serde_json::to_string(&loopback(serde_json::from_str(
        &text,
    )?)?)?)
}
fn enrollment(
    scope: &ControlScope,
    member: &EnrolledDevice,
    admin: &SigningKey,
) -> Result<EnrollmentRequest> {
    let now = Utc::now();
    EnrollmentRequest::sign(
        EnrollmentIntent {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            scope: scope.clone(),
            controller_node: member.public_key(),
            administrative_key: public(admin),
            permissions: [
                Permission::ListPairing,
                Permission::ApprovePairing,
                Permission::RejectPairing,
            ]
            .into_iter()
            .collect(),
            created_at: now,
            expires_at: now + Duration::seconds(120),
            grant_expires_at: now + Duration::minutes(10),
        },
        admin,
    )
}
fn command(grant: &Grant, admin: &SigningKey, action: OwnerAction) -> Result<OwnerCommand> {
    let now = Utc::now();
    OwnerCommand::sign(
        CommandIntent {
            version: 1,
            grant_id: grant.enrollment.intent.id.clone(),
            nonce: uuid::Uuid::new_v4().to_string(),
            scope: grant.enrollment.intent.scope.clone(),
            controller_node: grant.enrollment.intent.controller_node.clone(),
            action,
            created_at: now,
            expires_at: now + Duration::seconds(120),
        },
        admin,
    )
}
async fn exchange(
    remote: &BridgeAuthority,
    member: &EnrolledDevice,
    authority: &LocalAuthority,
    trust: &mut TrustStore,
    request: ControlExchange,
) -> Result<ControlReply> {
    remote
        .owner_control(
            member.session_identity()?,
            authority.refresh(trust).await?,
            &ControlEnvelope {
                version: 1,
                request,
            },
        )
        .await
        .context("Authenticated Requests exchange")
}
async fn result(
    remote: &BridgeAuthority,
    member: &EnrolledDevice,
    authority: &LocalAuthority,
    trust: &mut TrustStore,
    cmd: &OwnerCommand,
) -> Result<ControlReply> {
    exchange(
        remote,
        member,
        authority,
        trust,
        ControlExchange::Result {
            nonce: cmd.intent.nonce.clone(),
            digest: cmd.digest()?,
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Requires pinned CONNECT_NA_PYTHON and isolated native credential store"]
async fn real_quic_requests_require_local_enrollment_and_never_replay_pairing() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut owner = if let Some(binary) = std::env::var_os("CONNECT_OWNER_BINARY") {
        OwnerRuntime::start(std::path::Path::new(&binary), &dir.path().join("authority"))?
    } else {
        let python = std::env::var_os("CONNECT_NA_PYTHON").context("Set CONNECT_NA_PYTHON")?;
        OwnerRuntime::start_python(
            std::path::Path::new(&python),
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../apps/connect/authority/main.py"),
            &dir.path().join("authority"),
        )?
    };
    let info = owner.create("Requests acceptance")?;
    owner.pairing_ready(&info.pin)?;
    let authority = LocalAuthority::new(&info.url)?;
    let mut host =
        DeviceController::prepare(&dir.path().join("host"), info.url.clone(), info.pin.clone())?;
    host.enable_managed_connectivity()?;
    host.set_network_connectivity(Connectivity::LocalNetwork)
        .await?;
    let host_node = host.status()?.node_public_key;
    host.enroll_host(&owner.invite(&host_node, true)?).await?;
    let scope = ControlScope {
        pin: info.pin.clone(),
        host_node: host_node.clone(),
    };
    let mut trust = TrustStore::create(&dir.path().join("member-trust.json"), info.pin.clone())?;
    let (member, _) = authority
        .enroll_host(
            key(71),
            &key(72),
            &owner.invite(&public(&key(71)), true)?,
            &mut trust,
        )
        .await?;
    host.start(&member.public_key()).await?;
    let member_session = SessionEndpoint::bind(
        member.session_identity()?,
        authority.refresh(&mut trust).await?,
        host_node.clone(),
    )
    .await?;
    host.remember_pairing(PairedDevice {
        name: "Controller".into(),
        node: member.public_key(),
        ticket: ticket(member_session.ticket()?)?,
    })?;
    let route = BridgeRoute {
        host_node: host_node.clone(),
        ticket: ticket(host.status()?.bridge_ticket.context("No bridge")?)?,
    };
    let remote = BridgeAuthority::new(route)?;
    let (sender, mut requests) = tokio::sync::mpsc::channel::<OwnerRequest>(8);
    host.serve_owner(sender);
    let state = Arc::new(Mutex::new((owner, host)));
    let worker_state = state.clone();
    let drop_reply = Arc::new(AtomicBool::new(false));
    let worker_drop = drop_reply.clone();
    let worker = tokio::spawn(async move {
        while let Some(message) = requests.recv().await {
            let mut state = worker_state.lock().await;
            let (owner, host) = &mut *state;
            let reply = match message.call {
                connect_core::owner::OwnerCall::Control {
                    node,
                    certificate,
                    request,
                } => {
                    host.answer_owner_control(owner, &node, &certificate, request)
                        .await
                }
                call => owner.answer(call),
            };
            if !worker_drop.swap(false, Ordering::SeqCst) {
                let _ = message.reply.send(reply);
            }
        }
    });
    let admin = key(73);
    let request = enrollment(&scope, &member, &admin)?;
    // No remote request, even a signed one, initializes the registry.
    assert!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Enroll {
                request: request.clone()
            }
        )
        .await
        .is_err()
    );
    assert!(!dir.path().join("host/owner-control.json").exists());
    assert!(
        !dir.path()
            .join("host/owner-control.owner-control-lock")
            .exists()
    );
    state.lock().await.1.enable_owner_requests()?;
    assert!(matches!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Enroll {
                request: request.clone()
            }
        )
        .await?,
        ControlReply::Enrollment(EnrollmentState::Pending { .. })
    ));
    let unapproved = Grant {
        enrollment: request.clone(),
        approval_digest: request.digest()?,
        approved_at: Utc::now(),
        revoked_at: None,
    };
    let denied = command(&unapproved, &admin, OwnerAction::ListPairing)?;
    assert!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Execute { command: denied }
        )
        .await
        .is_err()
    );
    {
        let mut state = state.lock().await;
        let mut control = state.1.open_owner_requests()?;
        assert!(
            control
                .approve_locally(&mut state.1, &request.intent.id, "changed digest")
                .await
                .is_err()
        );
        control.decline_locally(&request.intent.id, &request.digest()?)?;
    }
    assert!(matches!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::EnrollmentStatus {
                id: request.intent.id
            }
        )
        .await?,
        ControlReply::Enrollment(EnrollmentState::Declined)
    ));
    let request = enrollment(&scope, &member, &admin)?;
    exchange(
        &remote,
        &member,
        &authority,
        &mut trust,
        ControlExchange::Enroll {
            request: request.clone(),
        },
    )
    .await?;
    let grant = {
        let mut state = state.lock().await;
        let mut control = state.1.open_owner_requests()?;
        control
            .approve_locally(&mut state.1, &request.intent.id, &request.digest()?)
            .await?
    };
    assert!(matches!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::EnrollmentStatus {
                id: request.intent.id
            }
        )
        .await?,
        ControlReply::Enrollment(EnrollmentState::Active { .. })
    ));
    // Lose the real dispatch reply. Readback survives registry close/reopen;
    // resubmitting the exact signed execution remains refused.
    let list = command(&grant, &admin, OwnerAction::ListPairing)?;
    drop_reply.store(true, Ordering::SeqCst);
    assert!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Execute {
                command: list.clone()
            }
        )
        .await
        .is_err()
    );
    assert!(matches!(
        result(&remote, &member, &authority, &mut trust, &list).await?,
        ControlReply::Result(ControlResult::PairingList { request: None })
    ));
    assert!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Execute { command: list }
        )
        .await
        .is_err()
    );
    // An expired command is refused, not assigned a fresh validity window.
    let mut expired = command(&grant, &admin, OwnerAction::ListPairing)?.intent;
    expired.created_at = Utc::now() - Duration::seconds(120);
    expired.expires_at = Utc::now() - Duration::seconds(1);
    let expired = OwnerCommand::sign(expired, &admin)?;
    assert!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Execute { command: expired }
        )
        .await
        .is_err()
    );
    let candidate = key(74);
    let mut candidate_trust =
        TrustStore::create(&dir.path().join("candidate-trust.json"), info.pin.clone())?;
    let pair = state.lock().await.1.create_pairing("Home".into()).await?;
    let card: PairCard = serde_json::from_value(loopback(serde_json::to_value(pair.card())?)?)?;
    let mut candidate_pair =
        PairClient::request(card, &candidate, &mut candidate_trust, "Candidate".into()).await?;
    let target = PairingTarget::from_pending(&pair.pending().context("No pending candidate")?);
    let mut changed = target.clone();
    changed.name = "A different device".into();
    let stale = command(&grant, &admin, OwnerAction::RejectPairing(changed))?;
    assert!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Execute {
                command: stale.clone()
            }
        )
        .await
        .is_err()
    );
    assert!(
        pair.pending().is_some(),
        "A stale approval/rejection cannot consume the real target"
    );
    assert!(matches!(
        result(&remote, &member, &authority, &mut trust, &stale).await?,
        ControlReply::Result(ControlResult::Unconfirmed)
    ));
    let reject = command(&grant, &admin, OwnerAction::RejectPairing(target))?;
    assert!(matches!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Execute {
                command: reject.clone()
            }
        )
        .await?,
        ControlReply::Result(ControlResult::Rejected { .. })
    ));
    assert!(candidate_pair.grant().await.is_err());
    assert!(matches!(
        result(&remote, &member, &authority, &mut trust, &reject).await?,
        ControlReply::Result(ControlResult::Rejected { .. })
    ));
    assert!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Execute { command: reject }
        )
        .await
        .is_err()
    );
    candidate_pair.close().await;
    // A fresh ceremony can actually enroll, prove and persist the exact candidate.
    let pair = state.lock().await.1.create_pairing("Home".into()).await?;
    let card = serde_json::from_value(loopback(serde_json::to_value(pair.card())?)?)?;
    let mut candidate_pair =
        PairClient::request(card, &candidate, &mut candidate_trust, "Candidate".into()).await?;
    let target = PairingTarget::from_pending(&pair.pending().context("No pending candidate")?);
    let approve = command(&grant, &admin, OwnerAction::ApprovePairing(target))?;
    let client = async {
        let issued = candidate_pair.grant().await?;
        let bridge = BridgeAuthority::new(BridgeRoute {
            host_node: issued.route.host_node,
            ticket: ticket(issued.route.ticket)?,
        })?;
        let (joined, _) = bridge
            .enroll_host(
                candidate,
                &key(75),
                &issued.invitation,
                &mut candidate_trust,
            )
            .await?;
        let session = SessionEndpoint::bind(
            joined.session_identity()?,
            bridge.refresh(&mut candidate_trust).await?,
            host_node.clone(),
        )
        .await?;
        session
            .round_trip(&ticket(issued.session_ticket)?, "Candidate verifies host")
            .await?;
        candidate_pair.finish(ticket(session.ticket()?)?).await?;
        candidate_pair.close().await;
        bridge.close().await;
        session.close().await;
        Ok::<_, anyhow::Error>(())
    };
    let (reply, client) = tokio::join!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Execute {
                command: approve.clone()
            }
        ),
        client
    );
    client?;
    // Preparing the candidate refreshes the host's peer set. The existing
    // bridge deliberately fences old connections on that change, so a lost
    // execution reply is legitimate. Only durable result readback establishes
    // completion; we never resend the approval.
    if let Ok(reply) = reply {
        assert!(
            matches!(reply,ControlReply::Result(ControlResult::Approved{node}) if node == public(&key(74)))
        );
    }
    assert!(matches!(
        result(&remote, &member, &authority, &mut trust, &approve).await?,
        ControlReply::Result(ControlResult::Approved { .. })
    ));
    assert!(
        state
            .lock()
            .await
            .1
            .status()?
            .devices
            .iter()
            .any(|d| d.node == public(&key(74)))
    );
    assert!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Execute {
                command: approve.clone()
            }
        )
        .await
        .is_err()
    );
    // Local revocation bars both new operations and saved-result disclosure.
    state
        .lock()
        .await
        .1
        .open_owner_requests()?
        .revoke_locally(&grant.enrollment.intent.id)?;
    assert!(
        result(&remote, &member, &authority, &mut trust, &approve)
            .await
            .is_err()
    );
    let revoked = command(&grant, &admin, OwnerAction::ListPairing)?;
    assert!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::Execute { command: revoked }
        )
        .await
        .is_err()
    );
    // Even an existing authenticated bridge session cannot override fresh core CRL.
    state.lock().await.0.remove_device(&member.public_key())?;
    assert!(
        exchange(
            &remote,
            &member,
            &authority,
            &mut trust,
            ControlExchange::EnrollmentStatus {
                id: grant.enrollment.intent.id
            }
        )
        .await
        .is_err()
    );
    worker.abort();
    let _ = worker.await;
    state.lock().await.1.stop().await;
    member_session.close().await;
    remote.close().await;
    Ok(())
}
