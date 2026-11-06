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
/// Independent signed HTTP administrator for the timing regression. Only the
/// disposable fixture's recovery export is read; seeds stay in zeroized memory.
struct IndependentAdmin {
    key: SigningKey,
    key_id: String,
    audience: String,
    url: String,
}
fn independent_http() -> Result<reqwest::Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()?)
}
impl IndependentAdmin {
    async fn from_fixture(owner: &mut OwnerRuntime, url: String) -> Result<Self> {
        let genesis: Value = independent_http()?
            .get(format!("{url}/sovereign.json"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let audience = genesis["network_authority"]["public_key"]
            .as_str()
            .context("Missing fixture authority public key")?
            .to_owned();
        let backup = owner.backup()?;
        let encoded = backup
            .keys
            .iter()
            .find(|(name, _)| name.ends_with("/operator.key"))
            .context("Missing fixture operator")?
            .1;
        let raw = zeroize::Zeroizing::new(STANDARD.decode(encoded)?);
        let text = std::str::from_utf8(&raw)?;
        let key_id = text
            .lines()
            .find_map(|line| line.strip_prefix("# Key ID: "))
            .context("Missing fixture operator key ID")?
            .to_owned();
        let seed = zeroize::Zeroizing::new(
            text.lines()
                .filter(|line| !line.starts_with('#'))
                .map(str::trim)
                .collect::<String>(),
        );
        let key = genesis_mesh_sdk::load_signing_key(&seed)?;
        Ok(Self {
            key,
            key_id,
            audience,
            url,
        })
    }
    async fn revoke(&self, certificate: &Value) -> Result<()> {
        let body = json!({"cert_id":certificate["cert_id"],"reason":"key_compromise"});
        let request = genesis_mesh_sdk::AdminRequest {
            method: "POST",
            path: "/admin/revoke",
            query: &[],
            audience: &self.audience,
            body: &body,
        };
        let headers = genesis_mesh_sdk::build_admin_headers(&request, &self.key_id, &self.key)?;
        let reply = independent_http()?
            .post(format!("{}/admin/revoke", self.url))
            .header("X-Admin-Key-Id", headers.key_id)
            .header("X-Admin-Timestamp", headers.timestamp)
            .header("X-Admin-Nonce", headers.nonce)
            .header("X-Admin-Signature", headers.signature)
            .json(&body)
            .send()
            .await?;
        assert!(
            reply.status().is_success(),
            "Independent fixture admin revocation failed"
        );
        let result: Value = reply.json().await?;
        assert!(
            result["edge_node"]["revoked_cert_ids"]
                .as_array()
                .is_some_and(|ids| ids.contains(&certificate["cert_id"])),
            "Core did not revoke candidate"
        );
        Ok(())
    }
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
    requests_scenario(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Requires pinned CONNECT_NA_PYTHON and isolated native credential store"]
async fn candidate_revoked_during_wait_is_not_remembered_or_confirmed_and_cannot_replay()
-> Result<()> {
    requests_scenario(true).await
}

async fn requests_scenario(revoke_candidate: bool) -> Result<()> {
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
    let independent_admin = if revoke_candidate {
        Some(IndependentAdmin::from_fixture(&mut owner, info.url.clone()).await?)
    } else {
        None
    };
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
        if let Some(admin) = &independent_admin {
            // The native adapter is already waiting for Joined while holding
            // its host lock. The independent core route needs no such lock.
            assert!(
                state.try_lock().is_err(),
                "Revocation must occur during the enrollment wait"
            );
            admin.revoke(joined.certificate()).await?;
            let current = authority.refresh(&mut candidate_trust).await?;
            assert!(
                VerifiedController::from_session(
                    &scope,
                    &current,
                    joined.certificate(),
                    &joined.public_key(),
                    Utc::now()
                )
                .is_err(),
                "Fresh core trust must refuse the revoked candidate"
            );
        }
        // Both endpoints retain pre-revocation session trust. This still
        // authenticates, so the later commit refresh is the essential guard.
        session
            .round_trip(&ticket(issued.session_ticket)?, "Candidate verifies host")
            .await?;
        let finish = candidate_pair.finish(ticket(session.ticket()?)?).await;
        if revoke_candidate {
            assert!(
                finish.is_err(),
                "Revoked candidate received success confirmation"
            );
        } else {
            finish?;
        }
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
            !revoke_candidate
                && matches!(reply,ControlReply::Result(ControlResult::Approved{node}) if node == public(&key(74)))
        );
    }
    let ControlReply::Result(readback) =
        result(&remote, &member, &authority, &mut trust, &approve).await?
    else {
        anyhow::bail!("Expected durable pairing result")
    };
    assert_eq!(
        readback,
        if revoke_candidate {
            ControlResult::Unconfirmed
        } else {
            ControlResult::Approved {
                node: public(&key(74)),
            }
        }
    );
    assert_eq!(
        state
            .lock()
            .await
            .1
            .status()?
            .devices
            .iter()
            .any(|d| d.node == public(&key(74))),
        !revoke_candidate,
        "Revoked candidates must not enter the durable device list"
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
