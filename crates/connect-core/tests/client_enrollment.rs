use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use connect_core::{authority::TrustPin, owner_control::*};
use ed25519_dalek::SigningKey;

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(n: u8) -> String {
    STANDARD.encode(key(n).verifying_key().to_bytes())
}
fn fixture() -> Result<(EnrollmentBinding, EnrollmentRequest)> {
    let binding = EnrollmentBinding {
        scope: ControlScope {
            pin: TrustPin {
                network_name: "client enrollment".into(),
                root_public_key: public(1),
            },
            host_node: public(2),
        },
        controller_node: public(3),
        administrative_key: public(4),
    };
    let now = Utc::now();
    let request = EnrollmentRequest::sign(
        EnrollmentIntent {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            scope: binding.scope.clone(),
            controller_node: binding.controller_node.clone(),
            administrative_key: binding.administrative_key.clone(),
            permissions: [Permission::ListPairing].into_iter().collect(),
            created_at: now,
            expires_at: now + Duration::seconds(120),
            grant_expires_at: now + Duration::hours(1),
        },
        &key(4),
    )?;
    Ok((binding, request))
}
fn grant(request: &EnrollmentRequest) -> Result<Grant> {
    Ok(Grant {
        enrollment: request.clone(),
        approval_digest: request.digest()?,
        approved_at: request.intent.created_at,
        revoked_at: None,
    })
}
fn reply(state: EnrollmentState) -> ControlReply {
    ControlReply::Enrollment(state)
}

#[test]
fn exact_review_is_saved_before_one_send_and_restart_only_checks_the_same_id() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("client.json");
    let (binding, request) = fixture()?;
    let now = request.intent.created_at;
    let digest = request.digest()?;
    assert!(
        ClientEnrollment::create(&path, binding.clone(), request.clone(), "changed", now).is_err()
    );
    assert!(!path.exists());
    let mut workflow =
        ClientEnrollment::create(&path, binding.clone(), request.clone(), &digest, now)?;
    assert_eq!(workflow.view().status, ClientEnrollmentStatus::Reviewed);
    assert!(
        ClientEnrollment::open(&path, &binding, now).is_err(),
        "Native lock must be exclusive"
    );
    assert!(workflow.status_query(now).is_err());
    assert!(workflow.reserve_submission("changed", now).is_err());
    let submission = workflow.reserve_submission(&digest, now)?;
    let ControlExchange::Enroll { request: sent } = &submission.envelope().request else {
        panic!("Expected exactly the retained enrollment")
    };
    assert_eq!(serde_json::to_value(sent)?, serde_json::to_value(&request)?);
    drop(workflow); // Reservation completed; transport/reply may or may not have happened.
    let mut workflow = ClientEnrollment::open(&path, &binding, now)?;
    assert_eq!(workflow.view().status, ClientEnrollmentStatus::Uncertain);
    assert_eq!(workflow.view().request.intent.id, request.intent.id);
    assert!(workflow.reserve_submission(&digest, now).is_err());
    let check = workflow.status_query(now)?;
    assert!(
        matches!(&check.envelope().request,ControlExchange::EnrollmentStatus{id} if id==&request.intent.id)
    );
    assert!(
        workflow
            .record_reply(
                submission,
                reply(EnrollmentState::Pending {
                    request: request.clone()
                }),
                now
            )
            .is_err(),
        "Old instance permit must not settle a new session"
    );
    assert_eq!(
        workflow
            .record_reply(check, reply(EnrollmentState::Pending { request }), now)?
            .status,
        ClientEnrollmentStatus::Pending
    );
    drop(workflow);
    let workflow = ClientEnrollment::open(&path, &binding, now)?;
    assert_eq!(workflow.view().status, ClientEnrollmentStatus::Uncertain);
    assert_eq!(
        workflow.view().last_observed,
        Some(ClientEnrollmentStatus::Pending)
    );
    Ok(())
}

#[test]
fn all_authenticated_host_states_remain_distinct_from_uncertainty() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (binding, request) = fixture()?;
    let now = request.intent.created_at;
    for (n, (state, expected)) in [
        (
            EnrollmentState::Pending {
                request: request.clone(),
            },
            ClientEnrollmentStatus::Pending,
        ),
        (
            EnrollmentState::Active {
                grant: grant(&request)?,
            },
            ClientEnrollmentStatus::Active,
        ),
        (EnrollmentState::Declined, ClientEnrollmentStatus::Declined),
        (EnrollmentState::Expired, ClientEnrollmentStatus::Expired),
        (EnrollmentState::Revoked, ClientEnrollmentStatus::Revoked),
        (EnrollmentState::Missing, ClientEnrollmentStatus::Missing),
    ]
    .into_iter()
    .enumerate()
    {
        let path = dir.path().join(format!("client-{n}.json"));
        let mut workflow = ClientEnrollment::create(
            &path,
            binding.clone(),
            request.clone(),
            &request.digest()?,
            now,
        )?;
        let call = workflow.reserve_submission(&request.digest()?, now)?;
        let view = workflow.record_reply(call, reply(state), now)?;
        assert_eq!(view.status, expected);
        assert_eq!(view.last_observed, Some(expected));
        assert_eq!(view.observed_at, Some(now));
        let _unanswered = workflow.status_query(now)?;
        assert_eq!(workflow.view().status, ClientEnrollmentStatus::Uncertain);
        assert_eq!(workflow.view().last_observed, Some(expected));
        drop(workflow);
        assert_eq!(
            ClientEnrollment::open(&path, &binding, now)?.view().status,
            ClientEnrollmentStatus::Uncertain
        );
    }
    Ok(())
}

#[test]
fn altered_requests_grants_times_and_pairing_results_are_refused_without_losing_saved_work()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("client.json");
    let (binding, request) = fixture()?;
    let now = request.intent.created_at;
    let mut workflow = ClientEnrollment::create(
        &path,
        binding.clone(),
        request.clone(),
        &request.digest()?,
        now,
    )?;
    let _lost = workflow.reserve_submission(&request.digest()?, now)?;
    let mut changed = Vec::new();
    for change in 0..8 {
        let mut intent = request.intent.clone();
        match change {
            0 => intent.id = uuid::Uuid::new_v4().to_string(),
            1 => {
                intent.permissions.insert(Permission::ApprovePairing);
            }
            2 => intent.grant_expires_at += Duration::seconds(1),
            3 => intent.expires_at -= Duration::seconds(1),
            4 => intent.scope.host_node = public(5),
            5 => intent.scope.pin.network_name = "different".into(),
            6 => intent.controller_node = public(6),
            _ => intent.administrative_key = public(7),
        }
        let signing_key = key(if change == 7 { 7 } else { 4 });
        let actual = EnrollmentRequest::sign(intent, &signing_key)?;
        changed.push(reply(EnrollmentState::Pending {
            request: actual.clone(),
        }));
        changed.push(reply(EnrollmentState::Active {
            grant: grant(&actual)?,
        }));
    }
    let valid = grant(&request)?;
    let mut bad = valid.clone();
    bad.approval_digest = "changed".into();
    changed.push(reply(EnrollmentState::Active { grant: bad }));
    let mut bad = valid.clone();
    bad.revoked_at = Some(now);
    changed.push(reply(EnrollmentState::Active { grant: bad }));
    let mut bad = valid.clone();
    bad.approved_at = now - Duration::seconds(1);
    changed.push(reply(EnrollmentState::Active { grant: bad }));
    let mut bad = valid;
    bad.approved_at = now + Duration::seconds(1);
    changed.push(reply(EnrollmentState::Active { grant: bad }));
    changed.push(ControlReply::Result(ControlResult::PairingList {
        request: None,
    }));
    for value in changed {
        let check = workflow.status_query(now)?;
        assert!(workflow.record_reply(check, value, now).is_err());
        assert_eq!(workflow.view().status, ClientEnrollmentStatus::Uncertain);
        assert_eq!(workflow.view().reviewed_digest, request.digest()?);
        assert_eq!(
            serde_json::to_value(workflow.view().request)?,
            serde_json::to_value(&request)?
        );
        assert!(
            workflow
                .reserve_submission(&request.digest()?, now)
                .is_err()
        );
    }
    let expired_at = request.intent.grant_expires_at;
    let check = workflow.status_query(expired_at)?;
    assert!(
        workflow
            .record_reply(
                check,
                reply(EnrollmentState::Active {
                    grant: grant(&request)?
                }),
                expired_at
            )
            .is_err()
    );
    drop(workflow);
    ClientEnrollment::open(&path, &binding, expired_at)?;
    Ok(())
}

#[test]
fn superseded_checks_cannot_replace_newer_observations() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("client.json");
    let (binding, request) = fixture()?;
    let now = request.intent.created_at;
    let mut workflow =
        ClientEnrollment::create(&path, binding, request.clone(), &request.digest()?, now)?;
    let old = workflow.reserve_submission(&request.digest()?, now)?;
    let current = workflow.status_query(now)?;
    workflow.record_reply(current, reply(EnrollmentState::Revoked), now)?;
    assert!(
        workflow
            .record_reply(
                old,
                reply(EnrollmentState::Active {
                    grant: grant(&request)?
                }),
                now
            )
            .is_err()
    );
    assert_eq!(workflow.view().status, ClientEnrollmentStatus::Revoked);
    Ok(())
}

#[test]
fn foreign_context_missing_corrupt_oversized_and_backwards_state_are_preserved() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("client.json");
    let (binding, request) = fixture()?;
    let now = request.intent.created_at;
    assert!(ClientEnrollment::open(&path, &binding, now).is_err());
    assert!(!path.with_extension("owner-enrollment-lock").exists());
    drop(ClientEnrollment::create(
        &path,
        binding.clone(),
        request.clone(),
        &request.digest()?,
        now,
    )?);
    let original = std::fs::read(&path)?;
    for change in 0..4 {
        let mut foreign = binding.clone();
        match change {
            0 => foreign.scope.pin.root_public_key = public(8),
            1 => foreign.scope.host_node = public(8),
            2 => foreign.controller_node = public(8),
            _ => foreign.administrative_key = public(8),
        }
        assert!(ClientEnrollment::open(&path, &foreign, now).is_err());
        assert_eq!(std::fs::read(&path)?, original);
    }
    assert!(ClientEnrollment::open(&path, &binding, now - Duration::seconds(1)).is_err());
    for corrupt in [b"{broken".to_vec(), vec![b' '; 64 * 1024 + 1]] {
        std::fs::write(&path, &corrupt)?;
        assert!(ClientEnrollment::open(&path, &binding, now).is_err());
        assert!(
            ClientEnrollment::create(
                &path,
                binding.clone(),
                request.clone(),
                &request.digest()?,
                now
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&path)?, corrupt);
    }
    std::fs::remove_file(&path)?;
    assert!(
        ClientEnrollment::create(&path, binding, request.clone(), &request.digest()?, now).is_err()
    );
    assert!(!path.exists());
    Ok(())
}

#[test]
fn failed_persistence_never_returns_a_submission_or_allows_an_in_memory_retry() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("client.json");
    let (binding, request) = fixture()?;
    let now = request.intent.created_at;
    let mut workflow = ClientEnrollment::create(
        &path,
        binding.clone(),
        request.clone(),
        &request.digest()?,
        now,
    )?;
    let original = std::fs::read(&path)?;
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;
    assert!(
        workflow
            .reserve_submission(&request.digest()?, now)
            .is_err()
    );
    assert_eq!(workflow.view().status, ClientEnrollmentStatus::Uncertain);
    std::fs::remove_dir(&path)?;
    std::fs::write(&path, original)?;
    assert!(
        workflow
            .reserve_submission(&request.digest()?, now)
            .is_err()
    );
    drop(workflow);
    let mut workflow = ClientEnrollment::open(&path, &binding, now)?;
    assert_eq!(workflow.view().status, ClientEnrollmentStatus::Reviewed);
    // Nothing was returned to the transport before the failed reservation.
    workflow.reserve_submission(&request.digest()?, now)?;
    Ok(())
}
