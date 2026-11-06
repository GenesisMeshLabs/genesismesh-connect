//! Actual managed core, native host and authenticated QUIC Requests dispatch.
//! All authorities, keys and profiles are disposable; no Android startup test.
#![cfg(debug_assertions)]
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use connect_core::{
    Connectivity,
    authority::{EnrolledDevice, LocalAuthority, TrustStore},
    device::{DeviceController, EnrollmentAvailability, PairedDevice},
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

fn start_fixture_owner(directory: &std::path::Path) -> Result<OwnerRuntime> {
    if let Some(binary) = std::env::var_os("CONNECT_OWNER_BINARY") {
        OwnerRuntime::start(std::path::Path::new(&binary), &directory.join("authority"))
    } else {
        let python = std::env::var_os("CONNECT_NA_PYTHON").context("Set CONNECT_NA_PYTHON")?;
        OwnerRuntime::start_python(
            std::path::Path::new(&python),
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../apps/connect/authority/main.py"),
            &directory.join("authority"),
        )
    }
}

/// Test fixture consent only; never installed as a production presence provider.
struct EnrollmentFixturePresence;
impl LocalAdminPresence for EnrollmentFixturePresence {
    fn available(&self) -> bool {
        true
    }
    fn confirm(&mut self, _: &LocalAdminReview) -> Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Requires pinned core and private disposable native credential service"]
async fn native_client_enrollment_resumes_same_id_after_lost_reply_and_needs_explicit_host_approval()
-> Result<()> {
    use std::sync::atomic::AtomicUsize;
    let dir = tempfile::tempdir()?;
    let mut owner = start_fixture_owner(dir.path())?;
    let info = owner.create("Durable client enrollment")?;
    let mut host =
        DeviceController::prepare(&dir.path().join("host"), info.url.clone(), info.pin.clone())?;
    host.enable_managed_connectivity()?;
    host.set_network_connectivity(Connectivity::LocalNetwork)
        .await?;
    let host_node = host.status()?.node_public_key;
    host.enroll_host(&owner.invite(&host_node, true)?).await?;
    let profile = dir.path().join("client");
    let mut client = DeviceController::prepare(&profile, info.url.clone(), info.pin.clone())?;
    assert_eq!(
        client.owner_enrollment_overview()?.availability,
        EnrollmentAvailability::Unjoined
    );
    let client_node = client.status()?.node_public_key;
    client
        .enroll_host(&owner.invite(&client_node, true)?)
        .await?;
    host.start(&client_node).await?;
    client
        .use_bridge(BridgeRoute {
            host_node: host_node.clone(),
            ticket: ticket(host.status()?.bridge_ticket.context("Missing bridge")?)?,
        })
        .await?;
    client.enable_managed_connectivity()?;
    client.start(&host_node).await?;
    host.send(
        &ticket(client.status()?.ticket.context("Missing client session")?)?,
        "Identify enrollment fixture client",
    )
    .await?;
    host.remember_pairing(PairedDevice {
        name: "Enrollment client".into(),
        node: client_node.clone(),
        ticket: ticket(client.status()?.ticket.context("Missing client session")?)?,
    })?;
    client.remember_pairing(PairedDevice {
        name: "Home hub".into(),
        node: host_node.clone(),
        ticket: ticket(host.status()?.ticket.context("Missing host session")?)?,
    })?;
    assert_eq!(
        host.owner_enrollment_overview()?.availability,
        EnrollmentAvailability::NetworkComputer
    );
    host.enable_owner_requests()?;
    let independent = IndependentAdmin::from_fixture(&mut owner, info.url).await?;
    let (sender, mut messages) = tokio::sync::mpsc::channel::<OwnerRequest>(8);
    host.serve_owner(sender);
    let state = Arc::new(Mutex::new((owner, host)));
    let server = state.clone();
    let sends = Arc::new(AtomicUsize::new(0));
    let calls = sends.clone();
    let commands = Arc::new(AtomicUsize::new(0));
    let executions = commands.clone();
    let drop_enroll = Arc::new(AtomicBool::new(true));
    let lose_enroll = drop_enroll.clone();
    let drop_check = Arc::new(AtomicBool::new(false));
    let lose_check = drop_check.clone();
    let worker = tokio::spawn(async move {
        while let Some(message) = messages.recv().await {
            let mut state = server.lock().await;
            let (owner, host) = &mut *state;
            let mut discard = false;
            let response = match message.call {
                connect_core::owner::OwnerCall::Control {
                    node,
                    certificate,
                    request,
                } => {
                    match &request.request {
                        ControlExchange::Enroll { .. } => {
                            calls.fetch_add(1, Ordering::SeqCst);
                            discard = lose_enroll.swap(false, Ordering::SeqCst);
                        }
                        ControlExchange::EnrollmentStatus { .. } => {
                            discard = lose_check.swap(false, Ordering::SeqCst);
                        }
                        ControlExchange::Execute { .. } => {
                            executions.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                    host.answer_owner_control(owner, &node, &certificate, request)
                        .await
                }
                call => owner.answer(call),
            };
            if !discard {
                let _ = message.reply.send(response);
            }
        }
    });
    let absent = client.owner_enrollment_overview()?;
    assert_eq!(absent.availability, EnrollmentAvailability::Member);
    assert_eq!(absent.host, "Home hub");
    assert!(absent.entry.is_none());
    assert!(!absent.can_check);
    assert!(client.check_owner_enrollment_overview().await.is_err());
    for file in [
        "owner-enrollment.json",
        "owner-enrollment.owner-enrollment-lock",
        "administrative-key.json",
        "administrative-key.administrative-key-lock",
    ] {
        assert!(!profile.join(file).exists(), "Inspection created {file}");
    }
    let request = client
        .prepare_owner_enrollment([Permission::ListPairing].into_iter().collect(), 600)
        .await?;
    let id = request.intent.id.clone();
    let digest = request.digest()?;
    let key_before = std::fs::read(profile.join("administrative-key.json"))?;
    assert_eq!(
        client
            .retain_owner_enrollment(request.clone(), &digest)
            .await?
            .status,
        ClientEnrollmentStatus::Reviewed
    );
    let reviewed = client.owner_enrollment_overview()?;
    assert!(!reviewed.can_check);
    assert_eq!(
        reviewed.entry.context("Missing reviewed display")?.status,
        ClientEnrollmentStatus::Reviewed
    );
    assert!(
        state
            .lock()
            .await
            .1
            .open_owner_requests()?
            .pending_locally()
            .is_empty(),
        "Retaining must not submit or grant anything"
    );
    assert_eq!(
        client.submit_owner_enrollment(&digest).await?.status,
        ClientEnrollmentStatus::Uncertain
    );
    assert_eq!(sends.load(Ordering::SeqCst), 1);
    assert!(client.submit_owner_enrollment(&digest).await.is_err());
    drop(client);
    let mut client = DeviceController::open(&profile)?;
    let saved = client.saved_owner_enrollment()?;
    assert_eq!(saved.request.intent.id, id);
    assert_eq!(saved.reviewed_digest, digest);
    assert_eq!(saved.status, ClientEnrollmentStatus::Uncertain);
    assert!(
        client
            .prepare_owner_enrollment([Permission::ApprovePairing].into_iter().collect(), 600)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(profile.join("administrative-key.json"))?,
        key_before
    );
    assert_eq!(
        client.check_owner_enrollment().await?.status,
        ClientEnrollmentStatus::Pending
    );
    drop_check.store(true, Ordering::SeqCst);
    let uncertain = client.check_owner_enrollment().await?;
    assert_eq!(uncertain.status, ClientEnrollmentStatus::Uncertain);
    assert_eq!(
        uncertain.last_observed,
        Some(ClientEnrollmentStatus::Pending)
    );
    assert_eq!(
        client.check_owner_enrollment().await?.status,
        ClientEnrollmentStatus::Pending
    );
    let certificate = {
        let mut server = state.lock().await;
        let (owner, host) = &mut *server;
        let pending = host.open_owner_requests()?.pending_locally();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request.intent.id, id);
        assert_eq!(
            serde_json::to_value(&pending[0].request)?,
            serde_json::to_value(&request)?
        );
        let certificate = pending[0].certificate.clone();
        let mut book = LocalAdministration::default();
        let input = LocalAdminInput {
            action: LocalAdminAction::Approve,
            enrollment_id: Some(id.clone()),
        };
        let review = book.review(owner, host, input.clone()).await?;
        assert_eq!(
            book.commit(owner, host, review.reference, &mut UnavailableAdminPresence)
                .await?
                .kind,
            LocalAdminOutcomeKind::Refused
        );
        assert!(host.open_owner_requests()?.grants_locally().is_empty());
        let review = book.review(owner, host, input).await?;
        assert_eq!(
            book.commit(
                owner,
                host,
                review.reference,
                &mut EnrollmentFixturePresence
            )
            .await?
            .kind,
            LocalAdminOutcomeKind::Confirmed
        );
        certificate
    };
    let active = client.check_owner_enrollment().await?;
    assert_eq!(active.status, ClientEnrollmentStatus::Active);
    assert_eq!(active.request.intent.id, id);
    assert_eq!(active.reviewed_digest, digest);
    let display = client.check_owner_enrollment_overview().await?;
    assert!(display.can_check);
    assert_eq!(display.host, "Home hub");
    let encoded = serde_json::to_string(&display)?;
    for private in [
        "signature",
        "administrative_key",
        "root_public_key",
        "approval_digest",
        "grant",
        &request.intent.administrative_key,
        &request.intent.scope.pin.root_public_key,
    ] {
        assert!(
            !encoded.contains(private),
            "Read-only projection exposed native proof/key material"
        );
    }
    let display = display.entry.context("Missing active display")?;
    assert_eq!(display.status, ClientEnrollmentStatus::Active);
    assert_eq!(display.request_id, id);
    assert_eq!(display.permissions, vec![Permission::ListPairing]);
    assert_eq!(display.access_ends, request.intent.grant_expires_at);
    let history = client
        .owner_enrollment_overview()?
        .entry
        .context("Missing historical display")?;
    assert_eq!(history.status, ClientEnrollmentStatus::Uncertain);
    assert_eq!(history.last_observed, Some(ClientEnrollmentStatus::Active));
    {
        let mut server = state.lock().await;
        let (owner, host) = &mut *server;
        let mut book = LocalAdministration::default();
        let review = book
            .review(
                owner,
                host,
                LocalAdminInput {
                    action: LocalAdminAction::Revoke,
                    enrollment_id: Some(id.clone()),
                },
            )
            .await?;
        assert_eq!(
            book.commit(
                owner,
                host,
                review.reference,
                &mut EnrollmentFixturePresence
            )
            .await?
            .kind,
            LocalAdminOutcomeKind::Confirmed
        );
    }
    assert_eq!(
        client.check_owner_enrollment().await?.status,
        ClientEnrollmentStatus::Revoked
    );
    // Missing native credentials block resume without deleting/replacing work.
    let key_path = profile.join("administrative-key.json");
    std::fs::remove_file(&key_path)?;
    let journal_before = std::fs::read(profile.join("owner-enrollment.json"))?;
    let attention = client.owner_enrollment_overview()?;
    assert!(attention.attention);
    assert!(attention.entry.is_none());
    assert!(!attention.can_check);
    assert!(client.check_owner_enrollment().await.is_err());
    assert!(
        client
            .prepare_owner_enrollment([Permission::ListPairing].into_iter().collect(), 600)
            .await
            .is_err()
    );
    assert!(!key_path.exists());
    assert_eq!(
        std::fs::read(profile.join("owner-enrollment.json"))?,
        journal_before
    );
    std::fs::write(&key_path, &key_before)?; // Restore only this disposable fixture's existing native reference.
    independent.revoke(&certificate).await?;
    assert!(
        client.check_owner_enrollment().await.is_err(),
        "Current core membership is still mandatory"
    );
    assert_eq!(std::fs::read(&key_path)?, key_before);
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "No enrollment replay or replacement"
    );
    assert_eq!(
        commands.load(Ordering::SeqCst),
        0,
        "Enrollment never dispatches pairing commands"
    );
    client.stop().await;
    worker.abort();
    let _ = worker.await;
    let state = Arc::try_unwrap(state)
        .ok()
        .context("Fixture host still referenced")?
        .into_inner();
    let (owner, mut host) = state;
    host.stop().await;
    drop(owner);
    Ok(())
}
async fn requests_scenario(revoke_candidate: bool) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut owner = start_fixture_owner(dir.path())?;
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
