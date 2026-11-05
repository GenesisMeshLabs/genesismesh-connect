use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use connect_core::{
    access_workflow::{AccessContext, AccessIntent, AccessJournal, Authorization, Stage},
    authority::TrustPin,
    owner::AccessPolicy,
};

fn context() -> AccessContext {
    AccessContext {
        pin: TrustPin {
            root_public_key: STANDARD.encode([1; 32]),
            network_name: "Home".into(),
        },
        actor: STANDARD.encode([2; 32]),
        audience: STANDARD.encode([3; 32]),
    }
}
fn policy() -> AccessPolicy {
    AccessPolicy {
        version: 1,
        recipients: vec![STANDARD.encode([4; 32])],
        expires_at: None,
        max_bytes: 4096,
        max_seconds: 300,
        extra_gates: vec![],
    }
}

#[test]
fn exact_scope_expiry_identity_version_and_replay_are_checked_before_dispatch() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let mut journal = AccessJournal::open(&path)?;
    let now = Utc::now();
    let before = policy();
    let mut after = before.clone();
    after.max_bytes = 2048;
    let record = journal.prepare(
        context(),
        uuid::Uuid::new_v4().to_string(),
        "Photos".into(),
        before.clone(),
        after,
        now,
    )?;
    assert_eq!(record.authorization, Authorization::NotEvaluated);
    let mut wrong = context();
    wrong.actor = STANDARD.encode([9; 32]);
    assert!(
        journal
            .submit(
                &record.intent.id,
                &record.digest,
                &wrong,
                before.clone(),
                now
            )
            .is_err()
    );
    wrong = context();
    wrong.pin.root_public_key = STANDARD.encode([9; 32]);
    assert!(journal.get(&record.intent.id, &wrong).is_err());
    wrong = context();
    wrong.audience = STANDARD.encode([9; 32]);
    assert!(journal.get(&record.intent.id, &wrong).is_err());
    assert!(
        journal
            .submit(
                &record.intent.id,
                "changed digest",
                &context(),
                before.clone(),
                now
            )
            .is_err()
    );
    assert!(
        journal
            .submit(
                &record.intent.id,
                &record.digest,
                &context(),
                before.clone(),
                now + Duration::minutes(5)
            )
            .is_err()
    );
    assert!(
        journal
            .submit(
                &record.intent.id,
                &record.digest,
                &context(),
                before.clone(),
                now - Duration::seconds(1)
            )
            .is_err()
    );
    let mut changed = before.clone();
    changed.max_bytes = 999;
    assert!(
        journal
            .submit(&record.intent.id, &record.digest, &context(), changed, now)
            .is_err()
    );
    changed = before.clone();
    changed.version += 1;
    assert!(
        journal
            .submit(&record.intent.id, &record.digest, &context(), changed, now)
            .is_err()
    );
    assert_eq!(
        journal
            .submit(
                &record.intent.id,
                &record.digest,
                &context(),
                before.clone(),
                now
            )?
            .stage,
        Stage::Submitted
    );
    assert!(
        journal
            .submit(&record.intent.id, &record.digest, &context(), before, now)
            .is_err()
    );
    assert!(journal.cancel(&record.intent.id, &context()).is_err());
    Ok(())
}

#[test]
fn crash_keeps_same_intent_and_unknown_state_never_retries_or_claims_a_receipt() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let before = policy();
    let mut journal = AccessJournal::open(&path)?;
    let record = journal.prepare(
        context(),
        uuid::Uuid::new_v4().to_string(),
        "Documents".into(),
        before.clone(),
        before.clone(),
        Utc::now(),
    )?;
    journal.submit(
        &record.intent.id,
        &record.digest,
        &context(),
        before.clone(),
        Utc::now(),
    )?;
    drop(journal);
    let mut journal = AccessJournal::open(&path)?;
    let recovered = journal.get(&record.intent.id, &context())?;
    assert_eq!(recovered.stage, Stage::Unknown);
    assert_eq!(recovered.digest, record.digest);
    assert_eq!(
        journal.observe(&record.intent.id, before.clone())?.stage,
        Stage::Unknown
    );
    assert!(
        journal
            .prepare(
                context(),
                record.intent.collection.clone(),
                "Documents".into(),
                before.clone(),
                before.clone(),
                Utc::now()
            )
            .is_err()
    );
    let mut observed = before.clone();
    observed.version += 1;
    let result = journal.observe(&record.intent.id, observed.clone())?;
    assert_eq!(result.stage, Stage::StateObserved);
    assert_eq!(result.authorization, Authorization::Unknown);
    observed.version += 1;
    assert_eq!(
        journal.observe(&record.intent.id, observed)?.stage,
        Stage::Conflict
    );
    Ok(())
}

#[test]
fn schema_tampering_arbitrary_payloads_and_invalid_limits_are_refused() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let mut journal = AccessJournal::open(&path)?;
    let now = Utc::now();
    let before = policy();
    for invalid in [0, (1 << 53)] {
        let mut after = before.clone();
        after.max_bytes = invalid;
        assert!(
            journal
                .prepare(
                    context(),
                    uuid::Uuid::new_v4().to_string(),
                    "Photos".into(),
                    before.clone(),
                    after,
                    now
                )
                .is_err()
        );
    }
    let record = journal.prepare(
        context(),
        uuid::Uuid::new_v4().to_string(),
        "Photos".into(),
        before.clone(),
        before,
        now,
    )?;
    let mut value = serde_json::to_value(&record.intent)?;
    value["command"] = serde_json::json!("arbitrary");
    assert!(serde_json::from_value::<AccessIntent>(value).is_err());
    drop(journal);
    let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    value["records"][0]["intent"]["after"]["max_bytes"] = serde_json::json!(1000);
    std::fs::write(&path, serde_json::to_vec(&value)?)?;
    assert!(AccessJournal::open(&path).is_err());
    assert_eq!(std::fs::read(&path)?, serde_json::to_vec(&value)?);
    std::fs::write(&path, br#"{"schema":1,"schema":1,"records":[]}"#)?;
    assert!(AccessJournal::open(&path).is_err());
    Ok(())
}

#[test]
fn single_writer_cancel_and_persistence_failure_do_not_dispatch() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let mut journal = AccessJournal::open(&path)?;
    assert!(AccessJournal::open(&path).is_err());
    let record = journal.prepare(
        context(),
        uuid::Uuid::new_v4().to_string(),
        "Photos".into(),
        policy(),
        policy(),
        Utc::now(),
    )?;
    journal.cancel(&record.intent.id, &context())?;
    assert!(
        journal
            .submit(
                &record.intent.id,
                &record.digest,
                &context(),
                policy(),
                Utc::now()
            )
            .is_err()
    );
    // Rename failure simulates full/unavailable persistence. No caller receives
    // permission to dispatch and this handle stays unusable.
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;
    assert!(
        journal
            .prepare(
                context(),
                uuid::Uuid::new_v4().to_string(),
                "Photos".into(),
                policy(),
                policy(),
                Utc::now()
            )
            .is_err()
    );
    assert!(
        journal
            .prepare(
                context(),
                uuid::Uuid::new_v4().to_string(),
                "Photos".into(),
                policy(),
                policy(),
                Utc::now()
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn missing_history_after_initialization_does_not_silently_reset_pending_work() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let journal = AccessJournal::open(&path)?;
    assert!(path.is_file());
    drop(journal);
    std::fs::remove_file(&path)?;
    assert!(AccessJournal::open(&path).is_err());
    assert!(!path.exists());
    Ok(())
}

#[test]
fn settled_history_is_archived_before_active_compaction_and_unknown_dispatch_stays() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let mut journal = AccessJournal::open(&path)?;
    let context = context();
    let pending_collection = uuid::Uuid::new_v4().to_string();
    let pending = journal.prepare(
        context.clone(),
        pending_collection,
        "Waiting".into(),
        policy(),
        policy(),
        Utc::now(),
    )?;
    journal.submit(
        &pending.intent.id,
        &pending.digest,
        &context,
        policy(),
        Utc::now(),
    )?;
    journal.uncertain(&pending.intent.id)?;
    let collection = uuid::Uuid::new_v4().to_string();
    let mut before = policy();
    for _ in 0..130 {
        let review = journal.prepare(
            context.clone(),
            collection.clone(),
            "Photos".into(),
            before.clone(),
            before.clone(),
            Utc::now(),
        )?;
        journal.submit(
            &review.intent.id,
            &review.digest,
            &context,
            before.clone(),
            Utc::now(),
        )?;
        before.version += 1;
        journal.observe(&review.intent.id, before.clone())?;
    }
    assert_eq!(
        journal.get(&pending.intent.id, &context)?.stage,
        Stage::Unknown
    );
    let archives =
        std::fs::read_dir(path.with_extension("archive"))?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(archives.len(), 1);
    let archived: serde_json::Value = serde_json::from_slice(&std::fs::read(archives[0].path())?)?;
    assert_eq!(archived["records"].as_array().unwrap().len(), 64);
    let old_id = archived["records"][0]["intent"]["id"].as_str().unwrap();
    let local = journal.history_record(
        &connect_core::access_workflow::history::HistoryScope {
            pin: context.pin.clone(),
            actor: context.actor.clone(),
        },
        old_id,
    )?;
    assert!(local.archived);
    assert!(!local.signed);
    assert!(
        !archived["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["intent"]["id"] == pending.intent.id)
    );
    drop(journal);
    assert_eq!(
        AccessJournal::open(&path)?
            .get(&pending.intent.id, &context)?
            .stage,
        Stage::Unknown
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn private_permissions_and_link_substitution_are_checked() -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let mut journal = AccessJournal::open(&path)?;
    journal.prepare(
        context(),
        uuid::Uuid::new_v4().to_string(),
        "Photos".into(),
        policy(),
        policy(),
        Utc::now(),
    )?;
    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o777,
        0o600
    );
    drop(journal);
    let link = dir.path().join("linked.json");
    symlink(&path, &link)?;
    assert!(AccessJournal::open(&link).is_err());
    Ok(())
}
