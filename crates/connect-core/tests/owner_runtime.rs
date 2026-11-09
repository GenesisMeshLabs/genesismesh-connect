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

    #[test]
    #[ignore = "Requires the packaged, standalone owner runtime"]
    fn packaged_resource_readiness_checks_real_ownership_and_bundled_release() -> Result<()> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use connect_core::{operations::OperationId, session::sharing::SpaceKind};
        let directory = tempfile::tempdir()?;
        let mut owner = OwnerRuntime::start(&binary()?, &directory.path().join("owner"))?;
        let info = owner.create("Packaged readiness")?;
        let node = |seed| {
            STANDARD.encode(
                ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .to_bytes(),
            )
        };
        let host = node(21);
        let phone = node(22);
        let collection = uuid::Uuid::new_v4().to_string();
        owner.space_share(
            &host,
            &collection,
            "Photos",
            &[phone.clone()],
            None,
            SpaceKind::Folder,
        )?;
        let capabilities = owner.resource_capabilities(&host, &collection)?;
        assert_eq!(
            capabilities.operations,
            connect_core::operations::resource_operation_ids()
        );
        capabilities.require(&info.pin, &host, &collection, OperationId::UpdateAccess)?;
        assert!(owner.resource_capabilities(&phone, &collection).is_err());
        assert_eq!(owner.access_get(&host, &collection)?.version, 1);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "Requires the packaged, standalone owner runtime"]
    async fn create_enroll_reopen_and_rebind_preserve_the_same_network() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let owner_path = directory.path().join("network-owner");
        let profile = directory.path().join("device");
        let mut owner = OwnerRuntime::start(&binary()?, &owner_path)?;
        let info = owner.create("My home")?;
        owner.capabilities()?.require_access_update(&info.pin)?;
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
            ..Default::default()
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

    /// A device removed after the recovery file was saved, and seen removed by
    /// another device, puts the restored network behind what that device has
    /// seen. Today devices refuse it as a rollback: safe, but they cannot use
    /// the restored network. See docs/restore-proposal.md.
    #[tokio::test]
    #[ignore = "Requires the packaged, standalone owner runtime"]
    async fn devices_that_saw_a_later_removal_refuse_a_network_restored_from_an_older_file()
    -> Result<()> {
        use connect_core::recovery;
        let directory = tempfile::tempdir()?;
        let first = directory.path().join("first");
        let mut owner = OwnerRuntime::start(&binary()?, &first.join("network-owner"))?;
        let info = owner.create("Older file")?;
        let mut computer =
            DeviceController::prepare(&first.join("device"), info.url.clone(), info.pin.clone())?;
        computer.enable_managed_connectivity()?;
        let invite = owner.invite(&computer.status()?.node_public_key, true)?;
        computer.enroll_host(&invite).await?;
        let mut phone = DeviceController::prepare(
            &directory.path().join("phone"),
            info.url.clone(),
            info.pin.clone(),
        )?;
        // Devices join as the app pairs them, with host invitations.
        phone.enable_managed_connectivity()?;
        let invite = owner.invite(&phone.status()?.node_public_key, true)?;
        phone.enroll_host(&invite).await?;
        let mut tablet = DeviceController::prepare(
            &directory.path().join("tablet"),
            info.url.clone(),
            info.pin.clone(),
        )?;
        let tablet_node = tablet.status()?.node_public_key;
        tablet.enable_managed_connectivity()?;
        let invite = owner.invite(&tablet_node, true)?;
        tablet.enroll_host(&invite).await?;
        phone.refresh().await?;
        let before = phone.status()?.trust_checkpoint.crl_sequence;

        let file = directory.path().join("Older.gmrecovery");
        let key = recovery::create(
            &mut owner,
            info.pin.clone(),
            computer.recovery_identity()?,
            &file,
        )?;
        // After the file: the tablet is removed, and the phone sees it.
        let removal = owner.remove_device(&tablet_node)?;
        phone.refresh().await?;
        let seen = phone.status()?.trust_checkpoint.crl_sequence;
        let tablet_on_old = tablet.refresh().await;
        eprintln!(
            "Removal revoked {} certificate(s). Removed tablet refresh against the old network: {}.",
            removal.revoked,
            tablet_on_old
                .as_ref()
                .map_or_else(|e| format!("refused: {e:#}"), |()| "accepted".into()),
        );
        drop(computer);
        drop(owner);

        let second = directory.path().join("second");
        let start = |dir: &std::path::Path| OwnerRuntime::start(&binary()?, dir);
        let mut restored = recovery::restore(
            &file,
            &key,
            &second.join("network-owner"),
            &second.join("device"),
            start,
        )?;
        restored.device.refresh().await?;
        let restored_sequence = restored.device.status()?.trust_checkpoint.crl_sequence;
        phone.rebind_owned_authority(restored.info.url.clone(), &restored.info.pin)?;
        let phone_after = phone.refresh().await;
        tablet.rebind_owned_authority(restored.info.url.clone(), &restored.info.pin)?;
        let tablet_after = tablet.refresh().await;
        eprintln!(
            "CRL sequence: before the file {before:?}, seen by the phone after the removal {seen:?},              restored network {restored_sequence:?}. Phone refresh against the restored network: {}.              Removed tablet refresh against it: {}.",
            phone_after
                .as_ref()
                .map_or_else(|e| format!("refused: {e:#}"), |()| "accepted".into()),
            tablet_after
                .as_ref()
                .map_or_else(|e| format!("refused: {e:#}"), |()| "accepted".into()),
        );
        assert_eq!(removal.revoked, 1);
        assert_eq!(
            (before, seen, restored_sequence),
            (Some(0), Some(1), Some(0))
        );
        for refused in [phone_after, tablet_after] {
            assert!(
                format!("{:#}", refused.expect_err("A rollback is refused"))
                    .contains("CRL rollback")
            );
        }
        drop(phone);
        drop(tablet);
        drop(restored);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "Requires the packaged, standalone owner runtime"]
    async fn a_recovery_file_brings_the_same_network_computer_back_elsewhere() -> Result<()> {
        use connect_core::recovery;
        let directory = tempfile::tempdir()?;
        let first = directory.path().join("first");
        let mut owner = OwnerRuntime::start(&binary()?, &first.join("network-owner"))?;
        let info = owner.create("Moving home")?;
        let mut computer =
            DeviceController::prepare(&first.join("device"), info.url.clone(), info.pin.clone())?;
        computer.enable_managed_connectivity()?;
        let node = computer.status()?.node_public_key;
        let invite = owner.invite(&node, true)?;
        computer.enroll_host(&invite).await?;
        let certificate = computer.status()?.certificate_id;
        let mut phone = DeviceController::prepare(
            &directory.path().join("phone"),
            info.url.clone(),
            info.pin.clone(),
        )?;
        let phone_node = phone.status()?.node_public_key;
        let invite = owner.invite(&phone_node, false)?;
        phone.enroll(&invite).await?;
        assert!(
            phone.recovery_identity().is_err(),
            "Only the network computer writes recovery files"
        );

        let file = directory.path().join("Home.gmrecovery");
        let key = recovery::create(
            &mut owner,
            info.pin.clone(),
            computer.recovery_identity()?,
            &file,
        )?;
        let bytes = std::fs::read(&file)?;
        assert!(!bytes.windows(node.len()).any(|w| w == node.as_bytes()));
        drop(computer);
        drop(owner);

        let second = directory.path().join("second");
        let start = |dir: &std::path::Path| OwnerRuntime::start(&binary()?, dir);
        assert!(
            recovery::restore(
                &file,
                &recovery::new_key()?,
                &second.join("network-owner"),
                &second.join("device"),
                start
            )
            .is_err()
        );
        let mut changed = bytes.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        std::fs::write(directory.path().join("changed.gmrecovery"), &changed)?;
        assert!(
            recovery::restore(
                &directory.path().join("changed.gmrecovery"),
                &key,
                &second.join("network-owner"),
                &second.join("device"),
                start
            )
            .is_err()
        );
        assert!(
            !second.join("network-owner").exists() && !second.join("device").exists(),
            "A refused restore leaves nothing behind"
        );
        // A failure after the identity was staged removes it again, with any
        // staging directories beside it.
        let failing = |_: &std::path::Path| -> Result<OwnerRuntime> {
            anyhow::bail!("The authority could not start")
        };
        assert!(
            recovery::restore(
                &file,
                &key,
                &second.join("network-owner"),
                &second.join("device"),
                failing
            )
            .is_err()
        );
        assert!(
            std::fs::read_dir(&second)?.next().is_none(),
            "A failed restore leaves no identity, network or staging behind"
        );

        let mut restored = recovery::restore(
            &file,
            &key,
            &second.join("network-owner"),
            &second.join("device"),
            start,
        )?;
        assert_eq!(restored.info.pin, info.pin);
        // The screen says the network is back as it was then.
        let saved = chrono::DateTime::parse_from_rfc3339(&restored.saved_at)?;
        assert!(
            saved <= chrono::Utc::now(),
            "Saved when the file was written"
        );
        let status = restored.device.status()?;
        assert_eq!(status.node_public_key, node, "The same computer identity");
        assert_eq!(status.certificate_id, certificate);
        assert!(status.connectivity.network_computer);
        restored.device.refresh().await?;
        let newcomer = DeviceController::prepare(
            &directory.path().join("newcomer"),
            restored.info.url.clone(),
            restored.info.pin.clone(),
        )?;
        let newcomer_node = newcomer.status()?.node_public_key;
        assert!(!restored.owner.invite(&newcomer_node, false)?.is_empty());
        // Devices enrolled before the move stay valid on the restored network.
        phone.rebind_owned_authority(restored.info.url.clone(), &restored.info.pin)?;
        phone.refresh().await?;
        assert!(
            recovery::restore(
                &file,
                &key,
                &second.join("network-owner"),
                &second.join("device"),
                start
            )
            .is_err(),
            "A restore never replaces an existing network"
        );
        drop(phone);
        drop(restored);
        Ok(())
    }
}
