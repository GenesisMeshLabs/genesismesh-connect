use super::{DeviceController, vault::Vault};
use crate::session::bridge::Unreached;
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, time::Duration};
use tokio::time::Instant;

/// How long a starting device keeps asking for its network computer: as long as
/// a running device waits for its host, two minutes, since a phone that runs the
/// network was unreachable for 42 to 88 seconds while it restarted. Each attempt
/// is itself bounded by the bridge deadline.
const REACH_FOR: Duration = crate::session::ASK_AGAIN_FOR;

/// Decides, after each failed attempt, whether to ask the network computer
/// again: only when it could not be reached, after 1, 2, 4 and then 8 seconds,
/// and never with a wait that would pass the budget.
struct Reaching {
    started: Instant,
    wait: Duration,
    budget: Duration,
}

impl Reaching {
    fn new(budget: Duration, now: Instant) -> Self {
        Self {
            started: now,
            wait: Duration::from_secs(1),
            budget,
        }
    }

    /// The wait before asking again, or the error to report.
    fn after(&mut self, error: anyhow::Error, now: Instant) -> Result<Duration> {
        if !error.is::<Unreached>() {
            return Err(error);
        }
        if now.duration_since(self.started) + self.wait >= self.budget {
            return Err(error.context(
                "Your network computer could not be reached. Keep Connect open on the device \
                 that runs your network, then try again.",
            ));
        }
        let wait = self.wait;
        self.wait = (wait * 2).min(Duration::from_secs(8));
        Ok(wait)
    }
}

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

    /// Start the saved connection and check trust, for a device that has just
    /// started, such as an agent or a command. While the network computer cannot
    /// be reached, as when the phone that runs it restarts, it is asked again for
    /// up to two minutes. Only reaching it is repeated: the failed step fetched
    /// trust, which changes nothing. Any answer, a refusal above all, is final.
    /// An app that refreshes on a timer does not need this.
    pub async fn connect_when_reachable(&mut self) -> Result<()> {
        let mut reaching = Reaching::new(REACH_FOR, Instant::now());
        loop {
            let outcome = match self.reconnect_saved().await {
                Ok(()) => self.refresh().await,
                failed => failed,
            };
            match outcome {
                Ok(()) => return Ok(()),
                Err(error) => tokio::time::sleep(reaching.after(error, Instant::now())?).await,
            }
        }
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
        let admin_path = path.join(super::admin_vault::FILE);
        match fs::symlink_metadata(&admin_path) {
            Ok(_) => {
                let vault = Vault::open(&path.join("device.bin"))?;
                use base64::{Engine as _, engine::general_purpose::STANDARD};
                super::AdministrativeKey::erase_for_device(
                    &admin_path,
                    vault.pin(),
                    &STANDARD.encode(vault.key().verifying_key().to_bytes()),
                )?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
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

    fn unreached() -> anyhow::Error {
        anyhow::anyhow!("deadline has elapsed").context(Unreached)
    }

    #[test]
    fn only_an_unreached_network_computer_is_asked_again_within_two_minutes() {
        let start = Instant::now();
        let mut reaching = Reaching::new(REACH_FOR, start);
        let mut at = start;
        let mut waits = Vec::new();
        // Each attempt that cannot connect takes the bridge deadline, 15 s.
        let last = loop {
            at += Duration::from_secs(15);
            match reaching.after(unreached(), at) {
                Ok(wait) => {
                    waits.push(wait.as_secs());
                    at += wait;
                }
                Err(error) => break error,
            }
        };
        assert_eq!(waits, [1, 2, 4, 8, 8]);
        assert!(at.duration_since(start) < REACH_FOR + Duration::from_secs(15));
        assert!(last.is::<Unreached>());
        assert!(last.to_string().contains("Keep Connect open"));
        assert!(format!("{last:#}").contains("did not answer in time"));

        // A quick failure, as with no route, is asked again more often.
        let mut reaching = Reaching::new(REACH_FOR, start);
        let mut at = start;
        let mut waits = Vec::new();
        while let Ok(wait) = reaching.after(unreached(), at) {
            waits.push(wait.as_secs());
            at += wait;
        }
        let mut expected = vec![1, 2, 4];
        expected.extend([8; 14]);
        assert_eq!(waits, expected);

        // Any answer is final at once: a refusal, a document that fails
        // verification, or this device being disconnected.
        for answer in [
            "Your network computer refused or could not answer this request",
            "Trust history does not verify against the pinned root",
            "This device is disconnected. Tap Reconnect in Settings.",
        ] {
            let mut reaching = Reaching::new(REACH_FOR, start);
            let error = reaching
                .after(anyhow::anyhow!(answer), start)
                .expect_err(answer);
            assert_eq!(error.to_string(), answer);
        }
        // The plain timeout text without the mark, as from a renewal that was
        // sent, is not asked again: that request may have changed something.
        let mut reaching = Reaching::new(REACH_FOR, start);
        assert!(
            reaching
                .after(
                    anyhow::anyhow!("deadline has elapsed")
                        .context("Your network computer did not answer in time"),
                    start
                )
                .is_err()
        );
    }

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
