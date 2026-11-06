#[allow(dead_code)]
mod support;
use anyhow::Result;
use chrono::Duration;
use connect_core::{authority::TrustPin, owner_control::*};
use ed25519_dalek::SigningKey;
use serde_json::json;
use support::{Fixture, key, public, signed};

fn scope(f: &Fixture) -> ControlScope {
    ControlScope {
        pin: TrustPin {
            network_name: "connect-spike".into(),
            root_public_key: public(&f.root),
        },
        host_node: public(&f.server),
    }
}
fn peer(f: &Fixture) -> Result<VerifiedController> {
    VerifiedController::from_session(
        &scope(f),
        &f.trust()?,
        &f.client_cert,
        &public(&f.client),
        f.now,
    )
}
fn enrollment(
    f: &Fixture,
    admin: &SigningKey,
    permissions: &[Permission],
) -> Result<EnrollmentRequest> {
    EnrollmentRequest::sign(
        EnrollmentIntent {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            scope: scope(f),
            controller_node: public(&f.client),
            administrative_key: public(admin),
            permissions: permissions.iter().copied().collect(),
            created_at: f.now,
            expires_at: f.now + Duration::seconds(120),
            grant_expires_at: f.now + Duration::hours(1),
        },
        admin,
    )
}
fn command(f: &Fixture, admin: &SigningKey, id: &str, action: OwnerAction) -> Result<OwnerCommand> {
    OwnerCommand::sign(
        CommandIntent {
            version: 1,
            grant_id: id.into(),
            nonce: uuid::Uuid::new_v4().to_string(),
            scope: scope(f),
            controller_node: public(&f.client),
            action,
            created_at: f.now,
            expires_at: f.now + Duration::seconds(120),
        },
        admin,
    )
}
fn target() -> PairingTarget {
    PairingTarget {
        request_id: uuid::Uuid::new_v4().to_string(),
        node: public(&key()),
        name: "My iPhone".into(),
        comparison_code: "012345".into(),
    }
}

#[test]
fn enrollment_queue_is_bound_idempotent_and_survives_restart() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("control.json");
    let mut store = ControlStore::create(&path, scope(&f), f.now)?;
    let request = enrollment(&f, &admin, &[Permission::ListPairing])?;
    let digest = request.digest()?;
    let submit = |store: &mut ControlStore| {
        store.request_enrollment(request.clone(), f.client_cert.clone(), &peer(&f)?, f.now)
    };
    assert!(matches!(
        submit(&mut store)?,
        EnrollmentState::Pending { .. }
    ));
    assert!(matches!(
        submit(&mut store)?,
        EnrollmentState::Pending { .. }
    ));
    assert_eq!(store.pending_enrollments(f.now).len(), 1);
    assert!(store.grants().is_empty(), "submission is not approval");
    let mut changed = request.intent.clone();
    changed.grant_expires_at += Duration::minutes(1);
    assert!(
        store
            .request_enrollment(
                EnrollmentRequest::sign(changed, &admin)?,
                f.client_cert.clone(),
                &peer(&f)?,
                f.now
            )
            .is_err()
    );
    let mut altered_certificate = f.client_cert.clone();
    altered_certificate["cert_id"] = json!("another-certificate");
    assert!(
        store
            .request_enrollment(request.clone(), altered_certificate, &peer(&f)?, f.now)
            .is_err()
    );
    assert!(matches!(
        store.enrollment_state(&public(&f.server), &request.intent.id, f.now),
        EnrollmentState::Missing
    ));
    drop(store);
    let mut store = ControlStore::open(&path, &scope(&f))?;
    assert_eq!(store.pending_enrollments(f.now).len(), 1);
    store.enroll_locally(request.clone(), &digest, &peer(&f)?, f.now)?;
    assert!(store.pending_enrollments(f.now).is_empty());
    assert!(matches!(
        submit(&mut store)?,
        EnrollmentState::Active { .. }
    ));
    store.revoke_locally(&request.intent.id, f.now)?;
    assert!(matches!(submit(&mut store)?, EnrollmentState::Revoked));
    Ok(())
}

#[test]
fn declined_enrollment_does_not_reappear_or_grant_access() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let dir = tempfile::tempdir()?;
    let mut store = ControlStore::create(&dir.path().join("c.json"), scope(&f), f.now)?;
    let request = enrollment(&f, &admin, &[Permission::ListPairing])?;
    store.request_enrollment(request.clone(), f.client_cert.clone(), &peer(&f)?, f.now)?;
    assert!(
        store
            .decline_locally(&request.intent.id, "changed", f.now)
            .is_err()
    );
    store.decline_locally(&request.intent.id, &request.digest()?, f.now)?;
    assert!(store.pending_enrollments(f.now).is_empty());
    assert!(matches!(
        store.request_enrollment(request.clone(), f.client_cert.clone(), &peer(&f)?, f.now)?,
        EnrollmentState::Declined
    ));
    assert!(
        store
            .enroll_locally(request.clone(), &request.digest()?, &peer(&f)?, f.now)
            .is_err()
    );
    assert!(matches!(
        store.enrollment_state(
            &public(&f.client),
            &request.intent.id,
            f.now + Duration::minutes(3)
        ),
        EnrollmentState::Expired
    ));
    Ok(())
}

#[test]
fn enrollment_queue_is_bounded_without_evicting_waiting_requests() -> Result<()> {
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let mut store = ControlStore::create(&dir.path().join("c.json"), scope(&f), f.now)?;
    let first = enrollment(&f, &key(), &[Permission::ListPairing])?;
    store.request_enrollment(first.clone(), f.client_cert.clone(), &peer(&f)?, f.now)?;
    let second = enrollment(&f, &key(), &[Permission::ListPairing])?;
    assert!(
        store
            .request_enrollment(second, f.client_cert.clone(), &peer(&f)?, f.now)
            .is_err()
    );
    assert_eq!(
        store.pending_enrollments(f.now)[0].request.digest()?,
        first.digest()?
    );
    let mut huge = f.client_cert.clone();
    huge["padding"] = json!("x".repeat(65_536));
    assert!(
        store
            .request_enrollment(first, huge, &peer(&f)?, f.now)
            .is_err()
    );
    Ok(())
}

#[test]
fn results_are_exact_private_durable_and_never_replay_permission() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("c.json");
    let mut store = ControlStore::create(&path, scope(&f), f.now)?;
    let grant = enroll(&mut store, &f, &admin, &[Permission::ApprovePairing])?;
    let target = target();
    let cmd = command(
        &f,
        &admin,
        &grant.enrollment.intent.id,
        OwnerAction::ApprovePairing(target.clone()),
    )?;
    let reserved = store.reserve(&cmd, &peer(&f)?, f.now)?;
    store.record_result(
        reserved.nonce(),
        reserved.digest(),
        ControlResult::Started,
        f.now,
    )?;
    assert!(
        store
            .record_result(
                reserved.nonce(),
                reserved.digest(),
                ControlResult::Approved {
                    node: public(&f.client)
                },
                f.now
            )
            .is_err()
    );
    assert!(
        store
            .record_result(
                reserved.nonce(),
                reserved.digest(),
                ControlResult::Rejected {
                    node: target.node.clone()
                },
                f.now
            )
            .is_err()
    );
    let result = ControlResult::Approved { node: target.node };
    store.record_result(reserved.nonce(), reserved.digest(), result.clone(), f.now)?;
    assert_eq!(
        store.checked_result(&peer(&f)?, reserved.nonce(), reserved.digest(), f.now)?,
        result
    );
    assert!(
        store
            .checked_result(&peer(&f)?, reserved.nonce(), "wrong", f.now)
            .is_err()
    );
    assert!(
        store
            .record_result(
                reserved.nonce(),
                reserved.digest(),
                ControlResult::Started,
                f.now
            )
            .is_err()
    );
    assert_eq!(
        store.result_for(&public(&f.server), reserved.nonce(), reserved.digest()),
        ControlResult::Unconfirmed
    );
    assert_eq!(
        store.result_for(&public(&f.client), reserved.nonce(), "wrong"),
        ControlResult::Unconfirmed
    );
    drop(store);
    let mut store = ControlStore::open(&path, &scope(&f))?;
    assert_eq!(
        store.result_for(&public(&f.client), reserved.nonce(), reserved.digest()),
        result
    );
    assert!(store.reserve(&cmd, &peer(&f)?, f.now).is_err());
    store.revoke_locally(&grant.enrollment.intent.id, f.now)?;
    assert!(
        store
            .checked_result(&peer(&f)?, reserved.nonce(), reserved.digest(), f.now)
            .is_err()
    );
    drop(store);
    let mut saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    saved["used"][0]["result"]["node"] = json!(public(&f.client));
    std::fs::write(&path, serde_json::to_vec(&saved)?)?;
    assert!(
        ControlStore::open(&path, &scope(&f)).is_err(),
        "invalid persisted results are refused"
    );
    Ok(())
}
fn enroll(
    store: &mut ControlStore,
    f: &Fixture,
    admin: &SigningKey,
    permissions: &[Permission],
) -> Result<Grant> {
    let request = enrollment(f, admin, permissions)?;
    let digest = request.digest()?;
    store.enroll_locally(request, &digest, &peer(f)?, f.now)
}

#[test]
fn membership_and_key_possession_require_explicit_exact_local_enrollment() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("owner-control.json");
    let mut store = ControlStore::create(&path, scope(&f), f.now)?;
    let request = enrollment(&f, &admin, &[Permission::ListPairing])?;
    let cmd = command(&f, &admin, &request.intent.id, OwnerAction::ListPairing)?;
    assert!(
        store.reserve(&cmd, &peer(&f)?, f.now).is_err(),
        "membership and admin signature are not owner approval"
    );
    assert!(
        store
            .enroll_locally(request.clone(), "changed-review", &peer(&f)?, f.now)
            .is_err()
    );
    assert!(store.grants().is_empty());
    let digest = request.digest()?;
    store.enroll_locally(request.clone(), &digest, &peer(&f)?, f.now)?;
    assert!(
        store
            .enroll_locally(request, &digest, &peer(&f)?, f.now)
            .is_err()
    );
    let reserved = store.reserve(&cmd, &peer(&f)?, f.now)?;
    assert_eq!(reserved.action(), &OwnerAction::ListPairing);
    assert_eq!(
        store.observation(reserved.nonce()),
        Some(Observation::Unconfirmed)
    );
    assert!(store.reserve(&cmd, &peer(&f)?, f.now).is_err());
    drop(store);
    let mut reopened = ControlStore::open(&path, &scope(&f))?;
    assert_eq!(
        reopened.observation(&cmd.intent.nonce),
        Some(Observation::Unconfirmed)
    );
    assert!(
        reopened.reserve(&cmd, &peer(&f)?, f.now).is_err(),
        "a lost reply cannot replay after restart"
    );
    reopened.observe_reply(reserved, f.now)?;
    assert_eq!(
        reopened.observation(&cmd.intent.nonce),
        Some(Observation::ReplyObserved)
    );
    assert!(
        reopened.reserve(&cmd, &peer(&f)?, f.now).is_err(),
        "a reply is not retry permission"
    );
    Ok(())
}

#[test]
fn local_review_binds_requested_scope_key_expiry_and_exact_permissions() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let dir = tempfile::tempdir()?;
    let mut store = ControlStore::create(&dir.path().join("control.json"), scope(&f), f.now)?;
    let original = enrollment(&f, &admin, &[Permission::ListPairing])?;
    let digest = original.digest()?;
    let mut changed = original.intent.clone();
    changed.permissions.insert(Permission::ApprovePairing);
    assert!(
        store
            .enroll_locally(
                EnrollmentRequest::sign(changed, &admin)?,
                &digest,
                &peer(&f)?,
                f.now
            )
            .is_err()
    );
    let mut changed = original.intent.clone();
    changed.grant_expires_at += Duration::hours(1);
    assert!(
        store
            .enroll_locally(
                EnrollmentRequest::sign(changed, &admin)?,
                &digest,
                &peer(&f)?,
                f.now
            )
            .is_err()
    );
    let mut changed = original.intent.clone();
    changed.administrative_key = public(&key());
    assert!(EnrollmentRequest::sign(changed, &admin).is_err());
    let mut changed = original.intent.clone();
    changed.administrative_key = public(&f.client);
    assert!(
        EnrollmentRequest::sign(changed, &f.client).is_err(),
        "node keys are not reused as admin keys"
    );
    let mut changed = original.intent.clone();
    changed.grant_expires_at = f.now + Duration::days(31);
    assert!(EnrollmentRequest::sign(changed, &admin).is_err());
    assert!(store.grants().is_empty());
    Ok(())
}

#[test]
fn command_signature_binds_every_target_and_context_field() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let dir = tempfile::tempdir()?;
    let mut store = ControlStore::create(&dir.path().join("control.json"), scope(&f), f.now)?;
    let grant = enroll(
        &mut store,
        &f,
        &admin,
        &[Permission::ApprovePairing, Permission::RejectPairing],
    )?;
    let t = target();
    let cmd = command(
        &f,
        &admin,
        &grant.enrollment.intent.id,
        OwnerAction::ApprovePairing(t.clone()),
    )?;
    type Mutation = Box<dyn Fn(&mut CommandIntent)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|i| i.nonce = uuid::Uuid::new_v4().to_string()),
        Box::new(|i| i.grant_id = uuid::Uuid::new_v4().to_string()),
        Box::new(|i| i.scope.pin.root_public_key = public(&key())),
        Box::new(|i| i.scope.pin.network_name = "Other home".into()),
        Box::new(|i| i.scope.host_node = public(&key())),
        Box::new(|i| i.controller_node = public(&key())),
        Box::new(|i| i.expires_at -= Duration::seconds(1)),
        Box::new(|i| i.created_at -= Duration::seconds(1)),
        Box::new(|i| {
            if let OwnerAction::ApprovePairing(t) = &mut i.action {
                t.node = public(&key())
            }
        }),
        Box::new(|i| {
            if let OwnerAction::ApprovePairing(t) = &mut i.action {
                t.name = "Different phone".into()
            }
        }),
        Box::new(|i| {
            if let OwnerAction::ApprovePairing(t) = &mut i.action {
                t.request_id = uuid::Uuid::new_v4().to_string()
            }
        }),
        Box::new(|i| {
            if let OwnerAction::ApprovePairing(t) = &mut i.action {
                t.comparison_code = "999999".into()
            }
        }),
        Box::new(move |i| i.action = OwnerAction::RejectPairing(t.clone())),
    ];
    for mutate in mutations {
        let mut changed = cmd.clone();
        mutate(&mut changed.intent);
        assert!(store.reserve(&changed, &peer(&f)?, f.now).is_err());
    }
    assert!(
        store.observation(&cmd.intent.nonce).is_none(),
        "refusals did not consume the valid request"
    );
    let reserved = store.reserve(&cmd, &peer(&f)?, f.now)?;
    assert_eq!(reserved.digest(), cmd.digest()?);
    Ok(())
}

#[test]
fn permission_expiry_revocation_and_wrong_signer_fail_closed() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("control.json");
    let mut store = ControlStore::create(&path, scope(&f), f.now)?;
    let grant = enroll(&mut store, &f, &admin, &[Permission::ListPairing])?;
    let id = &grant.enrollment.intent.id;
    assert!(
        store
            .reserve(
                &command(&f, &admin, id, OwnerAction::ApprovePairing(target()))?,
                &peer(&f)?,
                f.now
            )
            .is_err()
    );
    assert!(
        store
            .reserve(
                &command(&f, &key(), id, OwnerAction::ListPairing)?,
                &peer(&f)?,
                f.now
            )
            .is_err()
    );
    let mut expired = command(&f, &admin, id, OwnerAction::ListPairing)?.intent;
    expired.created_at -= Duration::minutes(3);
    expired.expires_at -= Duration::minutes(3);
    assert!(
        store
            .reserve(&OwnerCommand::sign(expired, &admin)?, &peer(&f)?, f.now)
            .is_err()
    );
    let mut future = command(&f, &admin, id, OwnerAction::ListPairing)?.intent;
    future.created_at += Duration::seconds(1);
    future.expires_at += Duration::seconds(1);
    assert!(
        store
            .reserve(&OwnerCommand::sign(future, &admin)?, &peer(&f)?, f.now)
            .is_err()
    );
    store.revoke_locally(id, f.now)?;
    drop(store);
    let mut store = ControlStore::open(&path, &scope(&f))?;
    assert!(
        store
            .reserve(
                &command(&f, &admin, id, OwnerAction::ListPairing)?,
                &peer(&f)?,
                f.now
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn membership_checks_reject_revocation_wrong_peer_root_and_staleness() -> Result<()> {
    let mut f = Fixture::new();
    let s = scope(&f);
    let trust = f.trust()?;
    assert!(
        VerifiedController::from_session(&s, &trust, &f.client_cert, &public(&f.server), f.now)
            .is_err()
    );
    let mut other = s.clone();
    other.pin.root_public_key = public(&key());
    assert!(
        VerifiedController::from_session(&other, &trust, &f.client_cert, &public(&f.client), f.now)
            .is_err()
    );
    let admin = key();
    let dir = tempfile::tempdir()?;
    let mut store = ControlStore::create(&dir.path().join("c.json"), s.clone(), f.now)?;
    let grant = enroll(&mut store, &f, &admin, &[Permission::ListPairing])?;
    let cmd = command(
        &f,
        &admin,
        &grant.enrollment.intent.id,
        OwnerAction::ListPairing,
    )?;
    assert!(
        store
            .reserve(&cmd, &peer(&f)?, f.now + Duration::seconds(5))
            .is_err()
    );
    let server =
        VerifiedController::from_session(&s, &trust, &f.server_cert, &public(&f.server), f.now)?;
    assert!(store.reserve(&cmd, &server, f.now).is_err());
    f.crl["revoked_certificates"] = json!([{"certificate_id":"client-cert"}]);
    f.crl = signed(f.crl, &[&f.authority]);
    assert!(
        peer(&f).is_err(),
        "current signed revocation overrides an existing grant"
    );
    Ok(())
}

#[test]
fn strict_envelopes_refuse_generic_admin_dispatch_and_unexpected_fields() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let request = enrollment(&f, &admin, &[Permission::ListPairing])?;
    let encoded = serde_json::to_vec(&request)?;
    EnrollmentRequest::parse(&encoded)?;
    let cmd = command(&f, &admin, &request.intent.id, OwnerAction::ListPairing)?;
    OwnerCommand::parse(&serde_json::to_vec(&cmd)?)?;
    let mut value = serde_json::to_value(&cmd)?;
    value["intent"]["url"] = json!("/admin/root");
    assert!(OwnerCommand::parse(&serde_json::to_vec(&value)?).is_err());
    let mut value = serde_json::to_value(&cmd)?;
    value["intent"]["action"] = json!({"operation":"replace_root"});
    assert!(OwnerCommand::parse(&serde_json::to_vec(&value)?).is_err());
    let mut value = serde_json::to_value(&cmd)?;
    value["intent"]["action"] = json!({"operation":"list_pairing","target":{"shell":"x"}});
    assert!(OwnerCommand::parse(&serde_json::to_vec(&value)?).is_err());
    assert!(OwnerCommand::parse(b"{\"intent\":{},\"intent\":{}}").is_err());
    assert!(EnrollmentRequest::parse(&vec![b' '; 16385]).is_err());
    Ok(())
}

#[test]
fn a_reserved_approval_still_requires_the_exact_current_pairing_request() -> Result<()> {
    use connect_core::session::pairing::PairRequest;
    let t = target();
    let action = OwnerAction::ApprovePairing(t.clone());
    let pending = PairRequest {
        id: t.request_id.clone(),
        node: t.node.clone(),
        name: t.name.clone(),
        code: t.comparison_code.clone(),
    };
    action.require_pending(&pending)?;
    let mut changed = pending.clone();
    changed.code = "999999".into();
    assert!(action.require_pending(&changed).is_err());
    let mut changed = pending.clone();
    changed.id = uuid::Uuid::new_v4().to_string();
    assert!(action.require_pending(&changed).is_err());
    let mut changed = pending.clone();
    changed.node = public(&key());
    assert!(action.require_pending(&changed).is_err());
    let mut changed = pending.clone();
    changed.name = "Renamed".into();
    assert!(action.require_pending(&changed).is_err());
    assert!(OwnerAction::ListPairing.require_pending(&pending).is_err());
    Ok(())
}

#[test]
fn expired_enrollment_and_expired_grant_do_not_gain_scope() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let dir = tempfile::tempdir()?;
    let mut store = ControlStore::create(&dir.path().join("control.json"), scope(&f), f.now)?;
    let mut intent = enrollment(&f, &admin, &[Permission::ListPairing])?.intent;
    intent.grant_expires_at = f.now + Duration::seconds(121);
    let request = EnrollmentRequest::sign(intent, &admin)?;
    let late = f.now + Duration::seconds(120);
    let late_peer = VerifiedController::from_session(
        &scope(&f),
        &f.trust()?,
        &f.client_cert,
        &public(&f.client),
        late,
    )?;
    assert!(
        store
            .enroll_locally(request.clone(), &request.digest()?, &late_peer, late)
            .is_err()
    );
    let grant = store.enroll_locally(request.clone(), &request.digest()?, &peer(&f)?, f.now)?;
    let earlier = command(
        &f,
        &admin,
        &grant.enrollment.intent.id,
        OwnerAction::ListPairing,
    )?;
    let reserved = store.reserve(&earlier, &peer(&f)?, f.now)?;
    store.record_result(
        reserved.nonce(),
        reserved.digest(),
        ControlResult::PairingList { request: None },
        f.now,
    )?;
    let expiry = grant.enrollment.intent.grant_expires_at;
    // Trust and membership remain valid at this short grant's exact expiry.
    let late_peer = VerifiedController::from_session(
        &scope(&f),
        &f.trust()?,
        &f.client_cert,
        &public(&f.client),
        expiry,
    )?;
    assert!(
        store
            .checked_result(&late_peer, reserved.nonce(), reserved.digest(), expiry)
            .is_err(),
        "A retained result must not outlive its administrator grant"
    );
    let mut intent = command(
        &f,
        &admin,
        &grant.enrollment.intent.id,
        OwnerAction::ListPairing,
    )?
    .intent;
    intent.created_at = expiry;
    intent.expires_at = expiry + Duration::seconds(120);
    let cmd = OwnerCommand::sign(intent, &admin)?;
    assert!(store.reserve(&cmd, &late_peer, expiry).is_err());
    Ok(())
}

#[test]
fn corruption_loss_foreign_scope_and_concurrent_writers_are_preserved_and_refused() -> Result<()> {
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("control.json");
    let store = ControlStore::create(&path, scope(&f), f.now)?;
    assert!(ControlStore::open(&path, &scope(&f)).is_err());
    drop(store);
    let mut other = scope(&f);
    other.host_node = public(&key());
    assert!(ControlStore::open(&path, &other).is_err());
    let bytes = b"{broken";
    std::fs::write(&path, bytes)?;
    assert!(ControlStore::open(&path, &scope(&f)).is_err());
    assert_eq!(std::fs::read(&path)?, bytes);
    std::fs::remove_file(&path)?;
    assert!(ControlStore::open(&path, &scope(&f)).is_err());
    assert!(
        ControlStore::create(&path, scope(&f), f.now).is_err(),
        "missing initialized registry is never silently reset"
    );
    Ok(())
}

#[test]
fn clock_rollback_cannot_reenable_expired_pruned_nonces() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("c.json");
    let mut store = ControlStore::create(&path, scope(&f), f.now)?;
    let grant = enroll(&mut store, &f, &admin, &[Permission::ListPairing])?;
    let cmd = command(
        &f,
        &admin,
        &grant.enrollment.intent.id,
        OwnerAction::ListPairing,
    )?;
    store.reserve(&cmd, &peer(&f)?, f.now)?;
    let now = f.now + Duration::seconds(121);
    let mut fresh = cmd.intent.clone();
    fresh.nonce = uuid::Uuid::new_v4().to_string();
    fresh.created_at = now;
    fresh.expires_at = now + Duration::seconds(120);
    let fresh = OwnerCommand::sign(fresh, &admin)?;
    let fresh_peer = VerifiedController::from_session(
        &scope(&f),
        &f.trust()?,
        &f.client_cert,
        &public(&f.client),
        now,
    )?;
    store.reserve(&fresh, &fresh_peer, now)?;
    assert_eq!(store.observation(&cmd.intent.nonce), None);
    drop(store);
    let mut reopened = ControlStore::open(&path, &scope(&f))?;
    assert!(
        reopened.reserve(&cmd, &peer(&f)?, f.now).is_err(),
        "high-water timestamp survives restart"
    );
    Ok(())
}

#[test]
fn failed_durable_write_never_returns_dispatch_permission() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("c.json");
    let mut store = ControlStore::create(&path, scope(&f), f.now)?;
    let grant = enroll(&mut store, &f, &admin, &[Permission::ListPairing])?;
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;
    let cmd = command(
        &f,
        &admin,
        &grant.enrollment.intent.id,
        OwnerAction::ListPairing,
    )?;
    assert!(store.reserve(&cmd, &peer(&f)?, f.now).is_err());
    std::fs::remove_dir(&path)?;
    assert!(
        store
            .reserve(
                &command(
                    &f,
                    &admin,
                    &grant.enrollment.intent.id,
                    OwnerAction::ListPairing
                )?,
                &peer(&f)?,
                f.now
            )
            .is_err(),
        "persistence failure poisons in-memory authorization"
    );
    Ok(())
}

#[test]
fn bounded_replay_window_never_evicts_an_unexpired_reservation() -> Result<()> {
    let f = Fixture::new();
    let admin = key();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("c.json");
    let mut store = ControlStore::create(&path, scope(&f), f.now)?;
    let grant = enroll(&mut store, &f, &admin, &[Permission::ListPairing])?;
    let verified = peer(&f)?;
    let first = command(
        &f,
        &admin,
        &grant.enrollment.intent.id,
        OwnerAction::ListPairing,
    )?;
    store.reserve(&first, &verified, f.now)?;
    for _ in 1..256 {
        store.reserve(
            &command(
                &f,
                &admin,
                &grant.enrollment.intent.id,
                OwnerAction::ListPairing,
            )?,
            &verified,
            f.now,
        )?;
    }
    let refused = command(
        &f,
        &admin,
        &grant.enrollment.intent.id,
        OwnerAction::ListPairing,
    )?;
    let before = std::fs::read(&path)?;
    assert!(
        store
            .reserve(&refused, &verified, f.now)
            .err()
            .expect("capacity refusal")
            .to_string()
            .contains("Too many active")
    );
    assert_eq!(
        std::fs::read(&path)?,
        before,
        "capacity refusal did not discard replay protection"
    );
    assert_eq!(
        store.observation(&first.intent.nonce),
        Some(Observation::Unconfirmed)
    );
    drop(store);
    let mut store = ControlStore::open(&path, &scope(&f))?;
    assert!(store.reserve(&first, &verified, f.now).is_err());
    Ok(())
}

#[test]
fn oversized_storage_and_duplicate_json_are_preserved() -> Result<()> {
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("c.json");
    drop(ControlStore::create(&path, scope(&f), f.now)?);
    let bytes = vec![b' '; 4 * 1024 * 1024 + 1];
    std::fs::write(&path, &bytes)?;
    assert!(ControlStore::open(&path, &scope(&f)).is_err());
    assert_eq!(std::fs::metadata(&path)?.len(), bytes.len() as u64);
    let bytes = b"{\"version\":1,\"version\":1}";
    std::fs::write(&path, bytes)?;
    assert!(ControlStore::open(&path, &scope(&f)).is_err());
    assert_eq!(std::fs::read(&path)?, bytes);
    Ok(())
}

#[cfg(unix)]
#[test]
fn links_in_state_lock_and_ancestors_are_refused() -> Result<()> {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let real = dir.path().join("real");
    std::fs::create_dir(&real)?;
    let link = dir.path().join("alias");
    symlink(&real, &link)?;
    assert!(ControlStore::create(&link.join("c.json"), scope(&f), f.now).is_err());
    let path = real.join("c.json");
    let original = real.join("unrelated.json");
    std::fs::write(&original, b"unchanged")?;
    symlink(&original, &path)?;
    assert!(ControlStore::open(&path, &scope(&f)).is_err());
    assert_eq!(std::fs::read(&original)?, b"unchanged");
    std::fs::remove_file(&path)?;
    symlink(&original, path.with_extension("owner-control-lock"))?;
    assert!(ControlStore::create(&path, scope(&f), f.now).is_err());
    Ok(())
}
