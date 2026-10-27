//! Bundled owner runtime, real core initialization and signed routes.
#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
mod desktop {
    use anyhow::{Context, Result};
    use connect_core::{device::DeviceController, owner::OwnerRuntime};
    use std::path::PathBuf;

    fn binary() -> Result<PathBuf> {
        std::env::var_os("CONNECT_OWNER_BINARY")
            .map(PathBuf::from)
            .context("Set CONNECT_OWNER_BINARY to the packaged authority")
    }

    #[tokio::test]
    #[ignore = "Requires the packaged, standalone owner runtime"]
    async fn create_enroll_reopen_and_rebind_preserve_the_same_network() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let owner_path = directory.path().join("network-owner");
        let profile = directory.path().join("device");
        let mut owner = OwnerRuntime::start(&binary()?, &owner_path)?;
        let info = owner.create("My home")?;
        let mut device = DeviceController::prepare(&profile, info.url.clone(), info.pin.clone())?;
        let node = device.status()?.node_public_key;
        let invite = owner
            .invite(&node, true)
            .context("Invite the first sharing device")?;
        device.enroll_host(&invite).await?;
        assert!(device.status()?.sharing_host);
        assert!(device.status()?.certificate_id.is_some());
        let subject = device
            .status()?
            .sharing_subject
            .context("Missing sharing subject")?;
        assert!(subject.starts_with("connect-device-"));
        assert_eq!(device.status()?.root_public_key, info.pin.root_public_key);
        let mut other = DeviceController::prepare(
            &directory.path().join("other-device"),
            info.url.clone(),
            info.pin.clone(),
        )?;
        let other_node = other.status()?.node_public_key;
        let other_invite = owner
            .invite(&other_node, true)
            .context("Invite the second sharing device")?;
        other.enroll_host(&other_invite).await?;
        assert_ne!(
            other.status()?.sharing_subject.as_deref(),
            Some(subject.as_str())
        );
        let collection = uuid::Uuid::new_v4().to_string();
        let permission = owner
            .share_for_subject(&node, &other_node, &collection, &subject)
            .context("Issue folder permission for the enrolled subject")?;
        let folder = directory.path().join("shared");
        std::fs::create_dir(&folder)?;
        std::fs::write(folder.join("Note.txt"), b"Real packaged owner sharing")?;
        device.configure_sharing(Some(connect_core::session::sharing::ShareConfig {
            collection_id: collection,
            directory: folder,
            policy_id: permission["policy_id"]
                .as_str()
                .context("Missing policy")?
                .into(),
            attestation_id: permission["attestation_id"]
                .as_str()
                .context("Missing attestation")?
                .into(),
        }))?;
        device.start(&other_node).await?;
        other.start(&node).await?;
        let page = other
            .session()?
            .list_files(
                &device.status()?.ticket.context("Missing file endpoint")?,
                None,
            )
            .await?;
        assert_eq!(page.files.len(), 1);
        assert_eq!(page.files[0].name, "Note.txt");
        device.stop().await;
        other.stop().await;
        drop(other);
        assert!(owner.create("Replace this network").is_err());
        assert!(owner.invite("invalid", false).is_err());
        let certificate = device.status()?.certificate_id;
        drop(device);
        drop(owner);
        let mut owner = OwnerRuntime::start(&binary()?, &owner_path)?;
        let restored = owner.open()?;
        assert_eq!(restored.pin, info.pin);
        let mut device = DeviceController::open(&profile)?;
        device.rebind_owned_authority(restored.url.clone(), &restored.pin)?;
        device.refresh().await?;
        assert_eq!(device.status()?.certificate_id, certificate);
        assert_eq!(device.status()?.node_public_key, node);
        let mut wrong = restored.pin.clone();
        wrong.network_name = "Other network".into();
        assert!(device.rebind_owned_authority(restored.url, &wrong).is_err());
        assert_eq!(device.status()?.network, info.pin.network_name);
        drop(device);
        drop(owner);
        Ok(())
    }
}
