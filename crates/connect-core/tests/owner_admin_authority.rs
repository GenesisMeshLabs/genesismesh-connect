//! Native local administration with genuine core membership and a test-only
//! presence adapter. This does not qualify physical user presence or installed UX.
#![cfg(debug_assertions)]
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use connect_core::{
    Connectivity,
    authority::{LocalAuthority, TrustStore},
    device::{DeviceController, PairedDevice},
    owner::OwnerRuntime,
    owner_control::*,
    session::SessionEndpoint,
};
use ed25519_dalek::SigningKey;

struct FixturePresence {
    accept: bool,
    calls: usize,
}
struct ChangingPresence {
    path: std::path::PathBuf,
    scope: ControlScope,
}
impl LocalAdminPresence for ChangingPresence {
    fn available(&self) -> bool {
        true
    }
    fn confirm(&mut self, review: &LocalAdminReview) -> Result<()> {
        let reference = &review.reference;
        ControlStore::open(&self.path, &self.scope)?.decline_locally(
            reference
                .enrollment_id
                .as_deref()
                .context("Missing fixture enrollment")?,
            reference
                .enrollment_digest
                .as_deref()
                .context("Missing fixture digest")?,
            Utc::now(),
        )
    }
}
impl LocalAdminPresence for FixturePresence {
    fn available(&self) -> bool {
        true
    }
    fn confirm(&mut self, review: &LocalAdminReview) -> Result<()> {
        ensure!(
            !review.reference.review_digest.is_empty(),
            "Missing exact review binding"
        );
        self.calls += 1;
        ensure!(self.accept, "Authentication was canceled");
        Ok(())
    }
}
fn input(action: LocalAdminAction, id: Option<&str>) -> LocalAdminInput {
    LocalAdminInput {
        action,
        enrollment_id: id.map(Into::into),
    }
}
fn public(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}
fn enrollment(scope: ControlScope, node: String, key: &SigningKey) -> Result<EnrollmentRequest> {
    let now = Utc::now();
    EnrollmentRequest::sign(
        EnrollmentIntent {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            scope,
            controller_node: node,
            administrative_key: public(key),
            permissions: [Permission::ListPairing, Permission::ApprovePairing]
                .into_iter()
                .collect(),
            created_at: now,
            expires_at: now + Duration::seconds(120),
            grant_expires_at: now + Duration::minutes(10),
        },
        key,
    )
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Requires pinned real authority and isolated native credential store; fixture presence only"]
async fn local_host_reviews_are_exact_scoped_single_use_and_recover_by_readback() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let owner_path = dir.path().join("owner");
    let mut owner = if let Some(binary) = std::env::var_os("CONNECT_OWNER_BINARY") {
        OwnerRuntime::start(std::path::Path::new(&binary), &owner_path)?
    } else {
        let python = std::env::var_os("CONNECT_NA_PYTHON").context("Set CONNECT_NA_PYTHON")?;
        OwnerRuntime::start_python(
            std::path::Path::new(&python),
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../apps/connect/authority/main.py"),
            &owner_path,
        )?
    };
    let info = owner.create("Local host administration")?;
    let authority = LocalAuthority::new(&info.url)?;
    let mut host =
        DeviceController::prepare(&dir.path().join("host"), info.url.clone(), info.pin.clone())?;
    host.enable_managed_connectivity()?;
    host.set_network_connectivity(Connectivity::LocalNetwork)
        .await?;
    let host_node = host.status()?.node_public_key;
    host.enroll_host(&owner.invite(&host_node, true)?).await?;
    let member_key = SigningKey::from_bytes(&[81; 32]);
    let executor = SigningKey::from_bytes(&[82; 32]);
    let admin_key = SigningKey::from_bytes(&[83; 32]);
    let mut member_trust =
        TrustStore::create(&dir.path().join("member-trust.json"), info.pin.clone())?;
    let (member, _) = authority
        .enroll_host(
            member_key.clone(),
            &executor,
            &owner.invite(&public(&member_key), true)?,
            &mut member_trust,
        )
        .await?;
    host.start(&member.public_key()).await?;
    let peer = SessionEndpoint::bind(
        member.session_identity()?,
        authority.refresh(&mut member_trust).await?,
        host_node.clone(),
    )
    .await?;
    host.session()?
        .round_trip(&peer.ticket()?, "Identify the actual member")
        .await?;
    host.remember_pairing(PairedDevice {
        name: "Owner’s phone".into(),
        node: member.public_key(),
        ticket: peer.ticket()?,
    })?;
    let scope = ControlScope {
        pin: info.pin,
        host_node,
    };
    let mut book = LocalAdministration::default();
    let mut presence = FixturePresence {
        accept: true,
        calls: 0,
    };
    let view = book.view(&mut owner, &mut host).await?;
    assert!(!view.enabled);
    assert!(
        !dir.path().join("host/owner-control.json").exists(),
        "Inspection must not opt in"
    );
    let enable = book
        .review(&mut owner, &mut host, input(LocalAdminAction::Enable, None))
        .await?;
    let blocked = book
        .commit(
            &mut owner,
            &mut host,
            enable.reference.clone(),
            &mut UnavailableAdminPresence,
        )
        .await?;
    assert_eq!(blocked.kind, LocalAdminOutcomeKind::Refused);
    assert!(!book.view(&mut owner, &mut host).await?.enabled);
    assert!(
        book.commit(
            &mut owner,
            &mut host,
            enable.reference.clone(),
            &mut presence
        )
        .await
        .is_err()
    );
    assert_eq!(
        presence.calls, 0,
        "A consumed gated review cannot be replayed with another provider"
    );
    let enable = book
        .review(&mut owner, &mut host, input(LocalAdminAction::Enable, None))
        .await?;
    let mut forged = enable.reference.clone();
    forged.review_digest = "tampered".into();
    assert!(
        book.commit(&mut owner, &mut host, forged, &mut presence)
            .await
            .is_err()
    );
    assert_eq!(
        book.commit(
            &mut owner,
            &mut host,
            enable.reference.clone(),
            &mut presence
        )
        .await?
        .kind,
        LocalAdminOutcomeKind::Confirmed
    );
    assert!(book.view(&mut owner, &mut host).await?.enabled);
    assert_eq!(
        LocalAdministration::default()
            .check(&mut owner, &mut host, enable.reference)
            .await?
            .kind,
        LocalAdminOutcomeKind::Confirmed
    );
    // A valid core member without a saved device identity cannot be approved
    // merely because it supplied a display label or administrative signature.
    let unknown_key = SigningKey::from_bytes(&[84; 32]);
    let mut unknown_trust =
        TrustStore::create(&dir.path().join("unknown-trust.json"), scope.pin.clone())?;
    let (unknown, _) = authority
        .enroll_host(
            unknown_key.clone(),
            &SigningKey::from_bytes(&[85; 32]),
            &owner.invite(&public(&unknown_key), true)?,
            &mut unknown_trust,
        )
        .await?;
    let unknown_request = enrollment(
        scope.clone(),
        unknown.public_key(),
        &SigningKey::from_bytes(&[86; 32]),
    )?;
    host.open_owner_requests()?
        .answer(
            &mut owner,
            &mut host,
            &unknown.public_key(),
            unknown.certificate(),
            ControlEnvelope {
                version: 1,
                request: ControlExchange::Enroll {
                    request: unknown_request.clone(),
                },
            },
        )
        .await?;
    let view = book.view(&mut owner, &mut host).await?;
    assert!(
        !view
            .pending
            .iter()
            .find(|v| v.id == unknown_request.intent.id)
            .context("Missing unknown request")?
            .known_device
    );
    assert!(
        book.review(
            &mut owner,
            &mut host,
            input(LocalAdminAction::Approve, Some(&unknown_request.intent.id))
        )
        .await
        .is_err()
    );
    let decline = book
        .review(
            &mut owner,
            &mut host,
            input(LocalAdminAction::Decline, Some(&unknown_request.intent.id)),
        )
        .await?;
    book.commit(&mut owner, &mut host, decline.reference, &mut presence)
        .await?;
    let request = enrollment(scope.clone(), member.public_key(), &admin_key)?;
    host.open_owner_requests()?
        .answer(
            &mut owner,
            &mut host,
            &member.public_key(),
            member.certificate(),
            ControlEnvelope {
                version: 1,
                request: ControlExchange::Enroll {
                    request: request.clone(),
                },
            },
        )
        .await?;
    let review = book
        .review(
            &mut owner,
            &mut host,
            input(LocalAdminAction::Approve, Some(&request.intent.id)),
        )
        .await?;
    let shown = review
        .device
        .as_ref()
        .context("Missing requesting device")?;
    assert_eq!(shown.device_name, "Owner’s phone");
    assert!(shown.known_device);
    assert_eq!(
        shown.permissions,
        vec![Permission::ListPairing, Permission::ApprovePairing]
    );
    assert_eq!(shown.enrollment_digest, request.digest()?);
    assert_eq!(shown.access_ends, request.intent.grant_expires_at);
    let mut canceled = FixturePresence {
        accept: false,
        calls: 0,
    };
    assert_eq!(
        book.commit(&mut owner, &mut host, review.reference, &mut canceled)
            .await?
            .kind,
        LocalAdminOutcomeKind::Refused
    );
    assert_eq!(book.view(&mut owner, &mut host).await?.pending.len(), 1);
    // A separate local actor changes the exact pending intent's decision after
    // review. Commit must refuse before invoking native presence.
    let stale = book
        .review(
            &mut owner,
            &mut host,
            input(LocalAdminAction::Approve, Some(&request.intent.id)),
        )
        .await?;
    host.open_owner_requests()?
        .decline_locally(&request.intent.id, &request.digest()?)?;
    let calls = presence.calls;
    assert_eq!(
        book.commit(&mut owner, &mut host, stale.reference, &mut presence)
            .await?
            .kind,
        LocalAdminOutcomeKind::Refused
    );
    assert_eq!(presence.calls, calls);
    // A new request can be declined; discard the reply and reconstruct only by
    // scoped readback after losing all native in-memory reviews.
    let during = enrollment(scope.clone(), member.public_key(), &admin_key)?;
    host.open_owner_requests()?
        .answer(
            &mut owner,
            &mut host,
            &member.public_key(),
            member.certificate(),
            ControlEnvelope {
                version: 1,
                request: ControlExchange::Enroll {
                    request: during.clone(),
                },
            },
        )
        .await?;
    let review = book
        .review(
            &mut owner,
            &mut host,
            input(LocalAdminAction::Approve, Some(&during.intent.id)),
        )
        .await?;
    let mut changing = ChangingPresence {
        path: dir.path().join("host/owner-control.json"),
        scope: scope.clone(),
    };
    assert_eq!(
        book.commit(&mut owner, &mut host, review.reference, &mut changing)
            .await?
            .kind,
        LocalAdminOutcomeKind::Refused
    );
    let declined_by_other = LocalAdminReference {
        review_id: uuid::Uuid::new_v4().to_string(),
        review_digest: "readback-only".into(),
        scope: book.view(&mut owner, &mut host).await?.scope,
        action: LocalAdminAction::Decline,
        enrollment_id: Some(during.intent.id.clone()),
        enrollment_digest: Some(during.digest()?),
    };
    assert_eq!(
        LocalAdministration::default()
            .check(&mut owner, &mut host, declined_by_other)
            .await?
            .observed,
        Some(LocalAdminDecision::Declined)
    );
    let declined = enrollment(scope.clone(), member.public_key(), &admin_key)?;
    host.open_owner_requests()?
        .answer(
            &mut owner,
            &mut host,
            &member.public_key(),
            member.certificate(),
            ControlEnvelope {
                version: 1,
                request: ControlExchange::Enroll {
                    request: declined.clone(),
                },
            },
        )
        .await?;
    let review = book
        .review(
            &mut owner,
            &mut host,
            input(LocalAdminAction::Decline, Some(&declined.intent.id)),
        )
        .await?;
    let saved = review.reference.clone();
    book.commit(&mut owner, &mut host, review.reference, &mut presence)
        .await?;
    book = LocalAdministration::default();
    let checked = book.check(&mut owner, &mut host, saved.clone()).await?;
    assert_eq!(checked.kind, LocalAdminOutcomeKind::Confirmed);
    assert_eq!(checked.observed, Some(LocalAdminDecision::Declined));
    assert!(
        book.commit(&mut owner, &mut host, saved.clone(), &mut presence)
            .await
            .is_err()
    );
    let mut foreign = saved;
    foreign.scope = "another-host".into();
    assert!(book.check(&mut owner, &mut host, foreign).await.is_err());
    let approved = enrollment(scope.clone(), member.public_key(), &admin_key)?;
    host.open_owner_requests()?
        .answer(
            &mut owner,
            &mut host,
            &member.public_key(),
            member.certificate(),
            ControlEnvelope {
                version: 1,
                request: ControlExchange::Enroll {
                    request: approved.clone(),
                },
            },
        )
        .await?;
    let review = book
        .review(
            &mut owner,
            &mut host,
            input(LocalAdminAction::Approve, Some(&approved.intent.id)),
        )
        .await?;
    let approved_reference = review.reference.clone();
    assert_eq!(
        book.commit(&mut owner, &mut host, review.reference, &mut presence)
            .await?
            .observed,
        Some(LocalAdminDecision::Approved)
    );
    book = LocalAdministration::default();
    assert_eq!(
        book.check(&mut owner, &mut host, approved_reference)
            .await?
            .kind,
        LocalAdminOutcomeKind::Confirmed
    );
    let revoke = book
        .review(
            &mut owner,
            &mut host,
            input(LocalAdminAction::Revoke, Some(&approved.intent.id)),
        )
        .await?;
    let revoked_reference = revoke.reference.clone();
    book.commit(&mut owner, &mut host, revoke.reference, &mut presence)
        .await?;
    book = LocalAdministration::default();
    assert_eq!(
        book.check(&mut owner, &mut host, revoked_reference)
            .await?
            .observed,
        Some(LocalAdminDecision::Revoked)
    );
    // Core revocation between review and commit is a refused approval, even
    // though the device remains in this host's saved-name list.
    let revoked_member = enrollment(scope, member.public_key(), &admin_key)?;
    host.open_owner_requests()?
        .answer(
            &mut owner,
            &mut host,
            &member.public_key(),
            member.certificate(),
            ControlEnvelope {
                version: 1,
                request: ControlExchange::Enroll {
                    request: revoked_member.clone(),
                },
            },
        )
        .await?;
    let review = book
        .review(
            &mut owner,
            &mut host,
            input(LocalAdminAction::Approve, Some(&revoked_member.intent.id)),
        )
        .await?;
    owner.remove_device(&member.public_key())?;
    let calls = presence.calls;
    assert_eq!(
        book.commit(&mut owner, &mut host, review.reference, &mut presence)
            .await?
            .kind,
        LocalAdminOutcomeKind::Refused
    );
    assert_eq!(presence.calls, calls);
    let state = dir.path().join("host/owner-control.json");
    let preserved = dir.path().join("preserved-control.json");
    std::fs::rename(&state, &preserved)?;
    assert!(
        book.view(&mut owner, &mut host).await.is_err(),
        "Missing initialized state cannot look disabled"
    );
    assert!(
        host.enable_owner_requests().is_err(),
        "Missing initialized state must not be reset"
    );
    std::fs::rename(preserved, state)?;
    peer.close().await;
    host.stop().await;
    Ok(())
}

#[test]
fn local_ipc_shapes_refuse_arbitrary_actions_and_presence_overrides() {
    assert!(
        serde_json::from_value::<LocalAdminInput>(
            serde_json::json!({"action":"approve","enrollment_id":"x","presence":true})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<LocalAdminInput>(
            serde_json::json!({"action":"sign_anything","enrollment_id":null})
        )
        .is_err()
    );
    assert!(!UnavailableAdminPresence.available());
}
