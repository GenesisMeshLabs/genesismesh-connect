//! Disposable real-core renewal/reopen fixtures; no phone or user storage.
#[path = "../../tests/support/embedded_owner.rs"]
mod support;
use super::*;
use crate::owner::foreground::{ForegroundNetwork, SetupChoice};

async fn create(root: &Path) -> Result<ForegroundNetwork> {
    let mut setup = support::begin(root, support::create(), None)?;
    setup.open_authority()?;
    setup.prepare_device()?;
    setup.request_invitation()?;
    setup.enroll_device().await?;
    setup.finish()
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core Python and sealed fixture storage"]
async fn reopened_owner_accepts_real_persisted_renewal_with_same_identity_and_fresh_trust()
-> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let mut network = create(root).await?;
    let before = network.device.status()?;
    // Exactly the existing controller maintenance path: real signed renewal,
    // verifier acceptance and protected persistence, before a process restart.
    let client = network.device.authority.as_ref().unwrap().clone();
    client
        .renew(
            network.device.device.as_mut().unwrap(),
            &mut network.device.trust,
        )
        .await?;
    network.device.vault.save_certificate(
        network
            .device
            .device
            .as_ref()
            .unwrap()
            .certificate()
            .clone(),
    )?;
    let renewed = network.device.status()?;
    assert_ne!(before.certificate_id, renewed.certificate_id);
    assert_eq!(before.node_public_key, renewed.node_public_key);
    let checkpoint = root.join("native/foreground-setup.json");
    let old: serde_json::Value = serde_json::from_slice(&std::fs::read(&checkpoint)?)?;
    assert_eq!(
        old["certificate_id"].as_str(),
        before.certificate_id.as_deref()
    );
    drop(network);
    let mut setup = support::begin(root, SetupChoice::Open, None)?;
    setup.open_authority()?;
    setup.prepare_device()?;
    setup.request_invitation()?; // Ready path must never invite again.
    setup.enroll_device().await?; // Verify current trust, not another enrollment.
    let network = setup.finish()?;
    let after = network.device.status()?;
    assert_eq!(renewed.certificate_id, after.certificate_id);
    assert_eq!(before.node_public_key, after.node_public_key);
    assert_eq!(before.root_public_key, after.root_public_key);
    assert_eq!(before.network, after.network);
    let updated: serde_json::Value = serde_json::from_slice(&std::fs::read(&checkpoint)?)?;
    assert_eq!(old["operation"], updated["operation"]);
    assert_eq!(old["pin"], updated["pin"]);
    assert_eq!(
        updated["certificate_id"].as_str(),
        after.certificate_id.as_deref()
    );
    assert_eq!(support::calls(root, "create"), 1);
    assert_eq!(support::calls(root, "invite"), 1);
    assert_eq!(support::core_calls(root, "/join"), 1);
    assert_eq!(support::core_calls(root, "/renew"), 1);
    Ok(())
}

async fn refuse_changed_credential(kind: &str) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let mut network = create(root).await?;
    let checkpoint = root.join("native/foreground-setup.json");
    let saved = std::fs::read(&checkpoint)?;
    match kind {
        "revoked" => {
            network
                .runtime
                .remove_device(&network.device.status()?.node_public_key)?;
        }
        "tampered" => {
            let mut cert = network.device.vault.certificate().unwrap().clone();
            cert["cert_id"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
            network.device.vault.save_certificate(cert)?;
        }
        "unrelated" => {
            let mut other = DeviceController::prepare(
                &root.join("other"),
                network.info.url.clone(),
                network.info.pin.clone(),
            )?;
            let invitation = network
                .runtime
                .invite(&other.status()?.node_public_key, true)?;
            other.enroll_host(&invitation).await?;
            network
                .device
                .vault
                .save_certificate(other.vault.certificate().unwrap().clone())?;
        }
        _ => unreachable!(),
    }
    drop(network);
    let mut setup = support::begin(root, SetupChoice::Open, None)?;
    setup.open_authority()?;
    if setup.prepare_device().is_ok() {
        assert!(setup.enroll_device().await.is_err());
    }
    assert!(setup.finish().is_err());
    assert_eq!(
        std::fs::read(&checkpoint)?,
        saved,
        "Refusal preserves the last verified checkpoint"
    );
    assert_eq!(support::calls(root, "create"), 1);
    assert_eq!(
        support::core_calls(root, "/join"),
        if kind == "unrelated" { 2 } else { 1 }
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core Python and sealed fixture storage"]
async fn revoked_owner_membership_cannot_reopen_as_a_renewal() -> Result<()> {
    refuse_changed_credential("revoked").await
}
#[tokio::test]
#[ignore = "Requires disposable pinned-core Python and sealed fixture storage"]
async fn tampered_owner_membership_cannot_reopen_as_a_renewal() -> Result<()> {
    refuse_changed_credential("tampered").await
}
#[tokio::test]
#[ignore = "Requires disposable pinned-core Python and sealed fixture storage"]
async fn another_nodes_valid_membership_cannot_reopen_as_a_renewal() -> Result<()> {
    refuse_changed_credential("unrelated").await
}
