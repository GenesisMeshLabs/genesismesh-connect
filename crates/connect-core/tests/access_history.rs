use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use connect_core::{
    access_workflow::{
        AccessContext, AccessJournal, Authorization, Stage,
        history::{HistoryContext, HistoryFilter, HistoryQuery, HistoryScope, RecoveryHint},
    },
    authority::TrustPin,
    owner::AccessPolicy,
};
use std::collections::BTreeSet;

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
fn scope() -> HistoryScope {
    let c = context();
    HistoryScope {
        pin: c.pin,
        actor: c.actor,
    }
}
fn view(owned: &[String]) -> HistoryContext {
    HistoryContext {
        scope: scope(),
        audience: Some(context().audience),
        owned: owned.iter().cloned().collect(),
        disconnected: false,
    }
}
fn policy(version: u64) -> AccessPolicy {
    AccessPolicy {
        version,
        recipients: vec![STANDARD.encode([4; 32])],
        expires_at: None,
        max_bytes: 4096,
        max_seconds: 300,
        extra_gates: vec![],
    }
}
fn query(filter: HistoryFilter, limit: u8) -> HistoryQuery {
    HistoryQuery {
        filter,
        limit,
        cursor: None,
    }
}

#[test]
fn local_history_is_scoped_paginated_and_new_entries_do_not_repeat_prior_pages() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut journal = AccessJournal::open(&dir.path().join("journal.json"))?;
    let collection = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    for n in 0..5 {
        journal.prepare(
            context(),
            collection.clone(),
            format!("Review {n}"),
            policy(1),
            policy(1),
            now + Duration::seconds(n),
        )?;
    }
    let mut other = context();
    other.actor = STANDARD.encode([8; 32]);
    journal.prepare(
        other,
        collection.clone(),
        "Other actor".into(),
        policy(1),
        policy(1),
        now,
    )?;
    other = context();
    other.pin.root_public_key = STANDARD.encode([9; 32]);
    journal.prepare(
        other,
        collection.clone(),
        "Other root".into(),
        policy(1),
        policy(1),
        now,
    )?;
    let mut request = query(HistoryFilter::All, 2);
    let first = journal.history_page(&view(&[collection.clone()]), &request)?;
    assert_eq!(
        first
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        ["Review 4", "Review 3"]
    );
    journal.prepare(
        context(),
        collection.clone(),
        "Newer".into(),
        policy(1),
        policy(1),
        now + Duration::seconds(10),
    )?;
    request.cursor = first.next;
    let second = journal.history_page(&view(&[collection.clone()]), &request)?;
    assert_eq!(
        second
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        ["Review 2", "Review 1"]
    );
    request.cursor = second.next;
    let third = journal.history_page(&view(&[collection]), &request)?;
    assert_eq!(third.entries.len(), 1);
    assert!(third.next.is_none());
    request.filter = HistoryFilter::NeedsAttention;
    assert!(journal.history_page(&view(&[]), &request).is_err());
    request.filter = HistoryFilter::All;
    let mut wrong = view(&[]);
    wrong.scope.pin.network_name = "Other".into();
    assert!(journal.history_page(&wrong, &request).is_err());
    assert!(
        journal
            .history_page(&view(&[]), &query(HistoryFilter::All, 0))
            .is_err()
    );
    Ok(())
}

#[test]
fn unresolved_recovery_uses_current_host_resource_and_connection_but_never_replays() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let mut journal = AccessJournal::open(&path)?;
    let collection = uuid::Uuid::new_v4().to_string();
    let record = journal.prepare(
        context(),
        collection.clone(),
        "Taxes".into(),
        policy(1),
        policy(1),
        Utc::now(),
    )?;
    journal.submit(
        &record.intent.id,
        &record.digest,
        &context(),
        policy(1),
        Utc::now(),
    )?;
    drop(journal);
    let journal = AccessJournal::open(&path)?;
    let mut state = view(&[collection]);
    let page = journal.history_page(&state, &query(HistoryFilter::NeedsAttention, 20))?;
    assert_eq!(page.attention_count, 1);
    assert_eq!(page.entries[0].stage, Stage::Unknown);
    assert_eq!(page.entries[0].recovery, RecoveryHint::CheckStatus);
    assert_eq!(
        journal.history_summary(&state, &record.intent.id)?.recovery,
        RecoveryHint::CheckStatus
    );
    state.disconnected = true;
    assert_eq!(
        journal
            .history_page(&state, &HistoryQuery::default())?
            .entries[0]
            .recovery,
        RecoveryHint::Disconnected
    );
    state.owned.clear();
    assert_eq!(
        journal
            .history_page(&state, &HistoryQuery::default())?
            .entries[0]
            .recovery,
        RecoveryHint::ItemStopped
    );
    state.audience = Some(STANDARD.encode([9; 32]));
    assert_eq!(
        journal
            .history_page(&state, &HistoryQuery::default())?
            .entries[0]
            .recovery,
        RecoveryHint::PreviousHost
    );
    let local = journal.history_record(&scope(), &record.intent.id)?;
    assert!(!local.signed);
    assert_eq!(local.record.authorization, Authorization::Unknown);
    assert_eq!(local.evidence_class, "unsigned_local_workflow_metadata");
    let mut wrong = scope();
    wrong.actor = STANDARD.encode([8; 32]);
    assert!(journal.history_record(&wrong, &record.intent.id).is_err());
    Ok(())
}

#[test]
fn an_old_conflict_is_not_attention_after_a_newer_checked_change() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut journal = AccessJournal::open(&dir.path().join("journal.json"))?;
    let collection = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let first = journal.prepare(
        context(),
        collection.clone(),
        "Photos".into(),
        policy(1),
        policy(1),
        now,
    )?;
    journal.submit(&first.intent.id, &first.digest, &context(), policy(1), now)?;
    journal.observe(&first.intent.id, policy(3))?;
    assert_eq!(
        journal
            .history_page(&view(&[collection.clone()]), &HistoryQuery::default())?
            .attention_count,
        1
    );
    let second = journal.prepare(
        context(),
        collection.clone(),
        "Photos".into(),
        policy(3),
        policy(3),
        now + Duration::seconds(1),
    )?;
    journal.submit(
        &second.intent.id,
        &second.digest,
        &context(),
        policy(3),
        now + Duration::seconds(1),
    )?;
    journal.core_accepted(&second.intent.id)?;
    journal.observe(&second.intent.id, policy(4))?;
    let page = journal.history_page(&view(&[collection]), &HistoryQuery::default())?;
    assert_eq!(page.attention_count, 0);
    assert_eq!(page.entries.len(), 2);
    assert!(page.entries.iter().all(|e| !e.needs_attention));
    Ok(())
}

#[test]
fn archive_crash_copies_deduplicate_and_bad_archives_report_partial_without_resetting() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let mut journal = AccessJournal::open(&path)?;
    let collection = uuid::Uuid::new_v4().to_string();
    let record = journal.prepare(
        context(),
        collection.clone(),
        "Photos".into(),
        policy(1),
        policy(1),
        Utc::now(),
    )?;
    journal.submit(
        &record.intent.id,
        &record.digest,
        &context(),
        policy(1),
        Utc::now(),
    )?;
    journal.core_accepted(&record.intent.id)?;
    journal.observe(&record.intent.id, policy(2))?;
    let archive = path.with_extension("archive");
    std::fs::create_dir(&archive)?;
    let copied = archive.join(format!("{}.json", uuid::Uuid::new_v4()));
    std::fs::copy(&path, &copied)?;
    let page = journal.history_page(&view(&[collection.clone()]), &HistoryQuery::default())?;
    assert_eq!(page.entries.len(), 1);
    assert!(!page.entries[0].archived);
    assert!(!page.incomplete);
    let broken = archive.join(format!("{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&broken, b"broken")?;
    let page = journal.history_page(&view(&[collection]), &HistoryQuery::default())?;
    assert_eq!(page.entries.len(), 1);
    assert!(page.incomplete);
    assert_eq!(std::fs::read(&broken)?, b"broken");
    let export = journal.history_record(&scope(), &record.intent.id)?;
    let value: serde_json::Value = serde_json::from_str(&export.document()?)?;
    assert_eq!(value["signed"], false);
    assert_eq!(value["record"]["digest"], record.digest);
    assert_eq!(
        value["record"]["intent"]["collection"],
        record.intent.collection
    );
    Ok(())
}

#[test]
fn archive_entry_limit_is_explicit_and_never_hides_current_unresolved_state() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let mut journal = AccessJournal::open(&path)?;
    let collection = uuid::Uuid::new_v4().to_string();
    let record = journal.prepare(
        context(),
        collection.clone(),
        "Waiting".into(),
        policy(1),
        policy(1),
        Utc::now(),
    )?;
    journal.submit(
        &record.intent.id,
        &record.digest,
        &context(),
        policy(1),
        Utc::now(),
    )?;
    journal.uncertain(&record.intent.id)?;
    let archive = path.with_extension("archive");
    std::fs::create_dir(&archive)?;
    for _ in 0..260 {
        std::fs::write(
            archive.join(format!("{}.json", uuid::Uuid::new_v4())),
            br#"{"schema":1,"records":[]}"#,
        )?;
    }
    let page = journal.history_page(&view(&[collection]), &HistoryQuery::default())?;
    assert!(page.incomplete);
    assert_eq!(page.attention_count, 1);
    assert_eq!(page.entries[0].id, record.intent.id);
    assert!(serde_json::from_str::<HistoryQuery>(r#"{"path":"outside"}"#).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_archives_are_not_followed() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("journal.json");
    let journal = AccessJournal::open(&path)?;
    let archive = path.with_extension("archive");
    std::fs::create_dir(&archive)?;
    let outside = dir.path().join("outside.json");
    std::fs::write(&outside, br#"{"schema":1,"records":[]}"#)?;
    std::os::unix::fs::symlink(
        &outside,
        archive.join(format!("{}.json", uuid::Uuid::new_v4())),
    )?;
    let page = journal.history_page(
        &HistoryContext {
            scope: scope(),
            audience: None,
            owned: BTreeSet::new(),
            disconnected: true,
        },
        &HistoryQuery::default(),
    )?;
    assert!(page.incomplete);
    assert!(page.entries.is_empty());
    assert!(outside.exists());
    Ok(())
}
