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
