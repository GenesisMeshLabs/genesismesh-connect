use super::{DeviceController, vault::Vault};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

impl DeviceController {
    pub(super) fn require_connected(&self) -> Result<()> {
        ensure!(
            !self.vault.disconnected(),
            "This device is disconnected. Tap Reconnect in Settings."
        );
        ensure!(
            !Self::leaving(&self.state_directory),
            "Finish leaving this network before connecting again."
        );
        Ok(())
    }

    /// Pause this device persistently. Existing peers, keys and folders stay.
    pub async fn disconnect(&mut self) -> Result<()> {
        self.vault.set_disconnected(true)?;
        self.stop().await;
        if let Some(pairing) = self.pairing.take() {
            pairing.close().await;
        }
        if let Some(client) = &self.bridge_client {
            client.close().await;
        }
        self.sharing = None;
        self.problem = None;
        Ok(())
    }

    pub async fn reconnect(&mut self) -> Result<()> {
        ensure!(
            !Self::leaving(&self.state_directory),
            "Finish leaving this network first."
        );
        if !self.vault.disconnected() {
            return Ok(());
        }
        self.rebuild_bridge_client().await?;
        self.restore_managed_share()?;
        self.vault.set_disconnected(false)?;
        self.reconnect_saved().await
    }

    /// Persist intent before erasing anything. It cannot reopen as a member
    /// after a crash, even when the credential store needs unlocking to finish.
    pub async fn begin_leave(&mut self) -> Result<()> {
        ensure!(
            !self.network_computer(),
            "This is the network computer. Disconnect it instead; its network must be preserved."
        );
        self.disconnect().await?;
        let marker = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.state_directory.with_extension("leaving"))?;
        marker.sync_all()?;
        #[cfg(unix)]
        fs::File::open(
            self.state_directory
                .parent()
                .context("Missing application directory")?,
        )?
        .sync_all()?;
        Ok(())
    }

    pub fn leaving(path: &Path) -> bool {
        path.with_extension("leaving").exists()
    }

    /// Only the private profile is erased. Shared directories are references
    /// in its vault and are never traversed. Retrying is safe after key deletion.
    pub fn finish_leave(path: &Path) -> Result<()> {
        ensure!(Self::leaving(path), "No request to leave this network");
        if !path.try_exists()? {
            fs::remove_file(path.with_extension("leaving"))?;
            return Ok(());
        }
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Invalid device directory"
        );
        let parent = path
            .parent()
            .context("Missing application directory")?
            .canonicalize()?;
        let resolved = path.canonicalize()?;
        ensure!(
            resolved.parent() == Some(parent.as_path()),
            "Device directory is outside the application directory"
        );
        Vault::erase(&path.join("device.bin"))?;
        // The sibling marker survives an interrupted profile-directory removal.
        fs::remove_dir_all(path)?;
        fs::remove_file(path.with_extension("leaving"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn interrupted_cleanup_keeps_exports_and_can_finish_after_profile_removal() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let profile = parent.path().join("device");
        let exported = parent.path().join("saved-photo.jpg");
        fs::write(&exported, b"keep me")?;
        fs::create_dir(&profile)?;
        fs::write(profile.join("trust.json"), b"old trust")?;
        assert!(DeviceController::finish_leave(&profile).is_err());
        assert!(profile.join("trust.json").exists());
        fs::write(profile.with_extension("leaving"), b"")?;
        assert!(DeviceController::open(&profile).is_err());
        DeviceController::finish_leave(&profile)?;
        assert!(!profile.exists());
        assert_eq!(fs::read(&exported)?, b"keep me");
        // Interrupted between profile removal and removing the sibling marker.
        fs::write(profile.with_extension("leaving"), b"")?;
        DeviceController::finish_leave(&profile)?;
        assert!(!DeviceController::leaving(&profile));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_never_follows_a_profile_or_content_symlink() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("photo"), b"keep")?;
        let profile = parent.path().join("device");
        std::os::unix::fs::symlink(outside.path(), &profile)?;
        fs::write(profile.with_extension("leaving"), b"")?;
        assert!(DeviceController::finish_leave(&profile).is_err());
        fs::remove_file(&profile)?;
        fs::create_dir(&profile)?;
        std::os::unix::fs::symlink(outside.path(), profile.join("link"))?;
        DeviceController::finish_leave(&profile)?;
        assert_eq!(fs::read(outside.path().join("photo"))?, b"keep");
        Ok(())
    }

    #[tokio::test]
    #[ignore = "Uses a disposable identity in the native credential store"]
    async fn disconnect_persists_blocks_implicit_reconnect_and_leave_allows_fresh_join()
    -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("device");
        let pin = crate::authority::TrustPin {
            root_public_key: base64::engine::general_purpose::STANDARD.encode([7; 32]),
            network_name: "lifecycle-test".into(),
        };
        let mut device = DeviceController::prepare_remote(&path, pin.clone())?;
        let identity = device.status()?.node_public_key;
        device.disconnect().await?;
        drop(device);
        let mut device = DeviceController::open(&path)?;
        assert!(device.status()?.disconnected);
        assert!(!device.needs_maintenance());
        device.reconnect_saved().await?;
        assert!(!device.is_running());
        assert!(
            device
                .start(&identity)
                .await
                .unwrap_err()
                .to_string()
                .contains("disconnected")
        );
        assert!(device.refresh().await.is_err());
        assert!(
            device
                .enroll("unused-invite")
                .await
                .unwrap_err()
                .to_string()
                .contains("disconnected")
        );
        assert!(
            device
                .share_space(
                    None,
                    dir.path().join("photos"),
                    "Photos".into(),
                    vec![],
                    crate::session::sharing::SpaceKind::Folder
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("disconnected")
        );
        device.reconnect().await?;
        assert!(!device.status()?.disconnected);
        assert_eq!(device.status()?.node_public_key, identity);
        device.begin_leave().await?;
        assert!(device.reconnect().await.is_err());
        drop(device);
        DeviceController::finish_leave(&path)?;
        let mut joined = DeviceController::prepare_remote(&path, pin)?;
        assert_ne!(joined.status()?.node_public_key, identity);
        joined.begin_leave().await?;
        drop(joined);
        DeviceController::finish_leave(&path)?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "Uses a disposable identity in the native credential store"]
    async fn network_computer_cannot_leave() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("device");
        let pin = crate::authority::TrustPin {
            root_public_key: base64::engine::general_purpose::STANDARD.encode([7; 32]),
            network_name: "owner-lifecycle-test".into(),
        };
        let mut owner = DeviceController::prepare(&path, "http://127.0.0.1:9443".into(), pin)?;
        owner.enable_managed_connectivity()?;
        assert!(owner.begin_leave().await.is_err());
        assert!(!DeviceController::leaving(&path));
        assert!(!owner.status()?.disconnected);
        owner.discard()?;
        Ok(())
    }
}
