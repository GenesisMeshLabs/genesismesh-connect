//! Explicit disposable foreground coordinator fixtures.
#![cfg(target_os = "linux")]
#[path = "support/embedded_owner.rs"]
mod support;
use anyhow::{Context, Result};
use connect_core::{
    device::DeviceController,
    owner::foreground::{ForegroundSetup, NativeSetupConfig, SetupChoice, SetupStage},
};
use serde_json::Value;
use support::{backend, begin, calls, create, sealed_store};
#[tokio::test]
#[ignore = "Requires disposable pinned-core Python and explicit sealed fixture storage"]
async fn create_and_reopen_use_existing_device_enrollment_and_rebind_without_new_issuance()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut setup = begin(root, create(), None)?;
    setup.open_authority()?;
    setup.prepare_device()?;
    setup.request_invitation()?;
    setup.enroll_device().await?;
    let network = setup.finish()?;
    let first = network.device.status()?;
    let first_origin = network.info.url.clone();
    assert!(
        first.connectivity.network_computer && first.sharing_host && first.certificate_id.is_some()
    );
    assert!(
        begin(root, SetupChoice::Open, None).is_err(),
        "Live setup lease is exclusive"
    );
    drop(network);
    // Force a different port instead of relying on random ephemeral-port choice.
    let old_address = first_origin
        .strip_prefix("http://")
        .context("Fixture loopback origin")?;
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(old_address.parse()?)?;
    let _old_port = socket.listen(1)?;
    assert!(begin(root, create(), None).is_err());
    let mut setup = begin(root, SetupChoice::Open, None)?;
    setup.open_authority()?;
    setup.prepare_device()?;
    setup.request_invitation()?;
    setup.enroll_device().await?;
    let network = setup.finish()?;
    let second = network.device.status()?;
    assert_eq!(first.node_public_key, second.node_public_key);
    assert_eq!(first.certificate_id, second.certificate_id);
    assert_eq!(first.root_public_key, second.root_public_key);
    assert_eq!(second.authority.as_deref(), Some(network.info.url.as_str()));
    assert_ne!(
        first_origin, network.info.url,
        "Fixture core binds a fresh loopback listener"
    );
    assert_eq!(calls(root, "create"), 1);
    assert_eq!(calls(root, "invite"), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core Python and explicit sealed fixture storage"]
async fn lost_authority_reply_is_opened_explicitly_and_never_recreated() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut setup = begin(root, create(), Some("create"))?;
    assert!(setup.open_authority().is_err());
    assert!(setup.view().needs_review);
    assert!(setup.open_authority().is_err());
    drop(setup);
    assert!(begin(root, create(), None).is_err());
    let mut setup = begin(root, SetupChoice::Open, None)?;
    setup.open_authority()?;
    setup.prepare_device()?;
    setup.request_invitation()?;
    setup.enroll_device().await?;
    assert_eq!(setup.view().stage, SetupStage::Ready);
    assert_eq!(calls(root, "create"), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core Python and explicit sealed fixture storage"]
async fn uncertain_invitation_is_preserved_and_never_invited_or_enrolled_again() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut setup = begin(root, create(), Some("invite"))?;
    setup.open_authority()?;
    setup.prepare_device()?;
    let before = setup.device_status()?.node_public_key;
    assert!(setup.request_invitation().is_err());
    assert!(setup.request_invitation().is_err());
    assert!(setup.enroll_device().await.is_err());
    drop(setup);
    let mut setup = begin(root, SetupChoice::Open, None)?;
    setup.open_authority()?;
    assert!(setup.prepare_device().is_err());
    assert_eq!(setup.view().stage, SetupStage::InviteReserved);
    assert_eq!(calls(root, "invite"), 1);
    let after = DeviceController::open(&root.join("native/device"))?.status()?;
    assert_eq!(before, after.node_public_key);
    assert!(after.certificate_id.is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core Python and explicit sealed fixture storage"]
async fn interrupted_enrollment_never_replays_but_saved_verified_completion_can_finish()
-> Result<()> {
    sealed_store();
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    std::fs::create_dir(root.join("native"))?;
    let (runtime, invite) = backend(&root.join("backend"), None)?;
    let mut setup = ForegroundSetup::begin(
        runtime,
        NativeSetupConfig::new(root.join("native"))?,
        create(),
    )?;
    setup.open_authority()?;
    setup.prepare_device()?;
    setup.request_invitation()?;
    // SETUP ONLY: create the genuine persisted completion as if the process
    // stopped after DeviceController committed it, before coordinator readback.
    let token = invite
        .lock()
        .unwrap()
        .take()
        .context("Missing fixture invite")?;
    drop(setup); // Release the real trust lock before constructing fixture state.
    let (mut fixture_owner, _) = backend(&root.join("backend"), None)?;
    let info = fixture_owner.open()?;
    let mut device = DeviceController::open(&root.join("native/device"))?;
    device.rebind_owned_authority(info.url, &info.pin)?;
    device.enroll_host(&token).await?;
    let completed = device.status()?;
    drop(device);
    drop(fixture_owner);
    let mut resumed = begin(root, SetupChoice::Open, None)?;
    resumed.open_authority()?;
    resumed.prepare_device()?;
    assert_eq!(resumed.view().stage, SetupStage::Ready);
    let network = resumed.finish()?;
    assert_eq!(
        completed.certificate_id,
        network.device.status()?.certificate_id
    );
    assert_eq!(calls(root, "invite"), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core Python and explicit sealed fixture storage"]
async fn reserved_but_unsubmitted_enrollment_and_absent_authority_need_review() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut setup = begin(root, create(), None)?;
    setup.open_authority()?;
    setup.prepare_device()?;
    setup.request_invitation()?;
    drop(setup);
    let mut setup = begin(root, SetupChoice::Open, None)?;
    setup.open_authority()?;
    assert!(setup.prepare_device().is_err());
    assert_eq!(setup.view().stage, SetupStage::EnrollmentReserved);
    assert_eq!(calls(root, "invite"), 1);
    drop(setup);
    let absent = tempfile::tempdir()?;
    let setup = begin(absent.path(), create(), None)?;
    drop(setup); // Reserved before any authority action.
    let mut setup = begin(absent.path(), SetupChoice::Open, None)?;
    assert!(setup.open_authority().is_err());
    assert_eq!(calls(absent.path(), "create"), 0);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core Python and explicit sealed fixture storage"]
async fn interrupted_device_preparation_opens_its_saved_key_but_never_replaces_a_missing_one()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut setup = begin(root, create(), None)?;
    setup.open_authority()?;
    setup.prepare_device()?;
    let node = setup.device_status()?.node_public_key;
    drop(setup);
    let path = root.join("native/foreground-setup.json");
    // SETUP ONLY: model the earlier durable reservation, before node readback.
    let mut value: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    value["stage"] = serde_json::json!("device_preparing");
    value["node"] = Value::Null;
    std::fs::write(&path, serde_json::to_vec(&value)?)?;
    let mut setup = begin(root, SetupChoice::Open, None)?;
    setup.open_authority()?;
    setup.prepare_device()?;
    assert_eq!(node, setup.device_status()?.node_public_key);
    setup.request_invitation()?;
    setup.enroll_device().await?;
    assert_eq!(calls(root, "create"), 1);
    assert_eq!(calls(root, "invite"), 1);
    drop(setup);

    let missing = tempfile::tempdir()?;
    let root = missing.path();
    let mut setup = begin(root, create(), None)?;
    setup.open_authority()?;
    drop(setup);
    let path = root.join("native/foreground-setup.json");
    let mut value: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    value["stage"] = serde_json::json!("device_preparing");
    std::fs::write(&path, serde_json::to_vec(&value)?)?;
    let mut setup = begin(root, SetupChoice::Open, None)?;
    setup.open_authority()?;
    assert!(setup.prepare_device().is_err());
    assert!(!root.join("native/device").exists());
    assert_eq!(calls(root, "invite"), 0);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core Python and explicit sealed fixture storage"]
async fn cancelled_enrollment_keeps_the_existing_pending_fence_and_is_never_replayed() -> Result<()>
{
    use std::{future::Future, task::Poll};
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut setup = begin(root, create(), None)?;
    setup.open_authority()?;
    setup.prepare_device()?;
    setup.request_invitation()?;
    let node = setup.device_status()?.node_public_key;
    {
        let mut future = Box::pin(setup.enroll_device());
        std::future::poll_fn(|context| {
            assert!(matches!(future.as_mut().poll(context), Poll::Pending));
            Poll::Ready(())
        })
        .await;
    }
    assert!(setup.view().needs_review);
    assert!(setup.device_status()?.enrollment_pending);
    assert!(setup.request_invitation().is_err());
    drop(setup);
    let mut setup = begin(root, SetupChoice::Open, None)?;
    setup.open_authority()?;
    assert!(setup.prepare_device().is_err());
    drop(setup);
    let saved = DeviceController::open(&root.join("native/device"))?.status()?;
    assert_eq!(node, saved.node_public_key);
    assert!(saved.enrollment_pending);
    assert_eq!(calls(root, "invite"), 1);
    Ok(())
}
