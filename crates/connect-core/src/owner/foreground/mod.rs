//! Native-only foreground setup. Progress is not authorization or permission to retry.
mod journal;
use super::{OwnerInfo, OwnerRuntime};
use crate::{
    authority::{LocalAuthority, TrustPin},
    device::{DeviceController, DeviceStatus},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Constructed by native code only; no path or authority origin is frontend input.
pub struct NativeSetupConfig {
    directory: PathBuf,
}
impl NativeSetupConfig {
    pub fn new(directory: PathBuf) -> Result<Self> {
        journal::check(&directory)?;
        ensure!(
            directory.is_dir(),
            "Use existing native application storage"
        );
        Ok(Self { directory })
    }
    fn profile(&self) -> PathBuf {
        self.directory.join("device")
    }
}
pub enum SetupChoice {
    Create { name: String },
    Open,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetupStage {
    AuthorityReserved,
    AuthorityReady,
    DevicePreparing,
    DeviceReady,
    InviteReserved,
    EnrollmentReserved,
    Ready,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    schema: u8,
    operation: String,
    name: String,
    stage: SetupStage,
    pin: Option<TrustPin>,
    node: Option<String>,
    certificate_id: Option<String>,
}
fn public_key(value: &str) -> Result<()> {
    let bytes = STANDARD.decode(value)?;
    ensure!(
        bytes.len() == 32 && STANDARD.encode(bytes) == value,
        "Invalid setup public identity"
    );
    Ok(())
}
fn uuid(value: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(value)?.to_string() == value,
        "Invalid setup identifier"
    );
    Ok(())
}
impl Saved {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == 1
                && (1..=80).contains(&self.name.chars().count())
                && self.name.trim() == self.name
                && !self.name.chars().any(char::is_control),
            "Invalid setup name/version"
        );
        uuid(&self.operation)?;
        ensure!(
            self.pin.is_some() == (self.stage != SetupStage::AuthorityReserved),
            "Invalid saved authority stage"
        );
        if let Some(pin) = &self.pin {
            public_key(&pin.root_public_key)?;
            ensure!(pin.network_name == self.name, "Setup network changed");
        }
        let has_node = matches!(
            self.stage,
            SetupStage::DeviceReady
                | SetupStage::InviteReserved
                | SetupStage::EnrollmentReserved
                | SetupStage::Ready
        );
        ensure!(
            self.node.is_some() == has_node,
            "Invalid saved device stage"
        );
        if let Some(node) = &self.node {
            public_key(node)?;
        }
        ensure!(
            self.certificate_id.is_some() == (self.stage == SetupStage::Ready),
            "Invalid saved enrollment stage"
        );
        if let Some(id) = &self.certificate_id {
            uuid(id)?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct SetupView {
    pub operation: String,
    pub network: String,
    pub stage: SetupStage,
    pub needs_review: bool,
}

/// After a Create that failed before its authority existed, for example when
/// the root key's authentication was declined: when the native backend holds
/// no custody or state either, remove the setup record so the person can simply
/// try again. Returns whether it was removed; anything further along is kept.
pub fn abandon_unstarted_create(
    mut runtime: OwnerRuntime,
    config: &NativeSetupConfig,
) -> Result<bool> {
    let status = runtime.embedded_status()?;
    if status.configured || status.running || config.profile().exists() {
        return Ok(false);
    }
    journal::Journal::abandon_unstarted(&config.directory)?;
    Ok(true)
}

pub struct ForegroundSetup {
    config: NativeSetupConfig,
    journal: journal::Journal,
    runtime: OwnerRuntime,
    info: Option<OwnerInfo>,
    device: Option<DeviceController>,
    invitation: Option<Zeroizing<String>>,
    fresh_creation: bool,
    usable: bool,
    membership_verified: bool,
}
/// Retain this lease alongside the runtime/device; another setup must not overlap.
pub struct ForegroundLease {
    _journal: journal::Journal,
}
pub struct ForegroundNetwork {
    pub runtime: OwnerRuntime,
    pub info: OwnerInfo,
    pub device: DeviceController,
    pub lease: ForegroundLease,
}
impl ForegroundSetup {
    pub fn begin(
        mut runtime: OwnerRuntime,
        config: NativeSetupConfig,
        choice: SetupChoice,
    ) -> Result<Self> {
        journal::check(&config.profile())?;
        let fresh = match choice {
            SetupChoice::Create { name } => {
                ensure!(
                    !config.profile().exists(),
                    "Existing device identity must be preserved"
                );
                let status = runtime.embedded_status()?;
                ensure!(
                    !status.configured && !status.running,
                    "Open the existing protected authority"
                );
                let saved = Saved {
                    schema: 1,
                    operation: uuid::Uuid::new_v4().to_string(),
                    name,
                    stage: SetupStage::AuthorityReserved,
                    pin: None,
                    node: None,
                    certificate_id: None,
                };
                saved.validate()?;
                Some(saved)
            }
            SetupChoice::Open => None,
        };
        let fresh_creation = fresh.is_some();
        let journal = journal::Journal::acquire(&config.directory, fresh)?;
        Ok(Self {
            config,
            journal,
            runtime,
            info: None,
            device: None,
            invitation: None,
            fresh_creation,
            usable: true,
            membership_verified: false,
        })
    }
    pub fn view(&self) -> SetupView {
        SetupView {
            operation: self.journal.saved.operation.clone(),
            network: self.journal.saved.name.clone(),
            stage: self.journal.saved.stage,
            needs_review: !self.usable
                || matches!(
                    self.journal.saved.stage,
                    SetupStage::InviteReserved | SetupStage::EnrollmentReserved
                ),
        }
    }
    /// Existing controller projection only; no extra profile open or native operation.
    pub fn device_status(&self) -> Result<DeviceStatus> {
        self.device
            .as_ref()
            .context("Device is not prepared")?
            .status()
    }
    fn enter(&mut self) -> Result<()> {
        ensure!(
            self.usable,
            "Setup is unconfirmed; use a fresh explicit Open for inspection, never repeat the write"
        );
        self.usable = false;
        self.journal.check_current()?;
        Ok(())
    }
    /// Blocking native work: invoke on a worker, never the UI/async runtime thread.
    pub fn open_authority(&mut self) -> Result<()> {
        self.enter()?;
        ensure!(
            self.info.is_none(),
            "Authority was already opened in this setup session"
        );
        let status = self.runtime.embedded_status()?;
        let fresh = std::mem::take(&mut self.fresh_creation);
        let info = if fresh {
            ensure!(
                !status.configured && !status.running,
                "Authority setup changed; preserve it for review"
            );
            self.runtime.create(&self.journal.saved.name)?
        } else {
            ensure!(
                status.configured,
                "Saved authority outcome is unavailable; creation will not be replayed"
            );
            self.runtime.open()?
        };
        ensure!(
            info.managed && info.pin.network_name == self.journal.saved.name,
            "Native authority scope changed"
        );
        LocalAuthority::new(&info.url)?;
        public_key(&info.pin.root_public_key)?;
        let capabilities = self.runtime.capabilities()?;
        ensure!(
            capabilities.transport == "local_android_embedded",
            "Use the fixed native embedded backend"
        );
        capabilities.require_access_update(&info.pin)?;
        self.runtime.pairing_ready(&info.pin)?;
        if let Some(pin) = &self.journal.saved.pin {
            ensure!(pin == &info.pin, "Saved authority identity changed");
        } else {
            self.journal.saved.pin = Some(info.pin.clone());
            self.journal.saved.stage = SetupStage::AuthorityReady;
            self.journal.commit()?;
        }
        self.info = Some(info);
        self.usable = true;
        Ok(())
    }
    /// Save a node identity before inviting it; interrupted preparation never creates a second key.
    pub fn prepare_device(&mut self) -> Result<()> {
        self.enter()?;
        ensure!(
            self.device.is_none(),
            "Device was already opened in this setup session"
        );
        let info = self
            .info
            .clone()
            .context("Open the native authority first")?;
        let profile = self.config.profile();
        journal::check(&profile)?;
        let creating = self.journal.saved.stage == SetupStage::AuthorityReady;
        let mut device = if creating {
            ensure!(
                !profile.exists(),
                "Unexpected device profile; preserve it for review"
            );
            self.journal.saved.stage = SetupStage::DevicePreparing;
            self.journal.commit()?;
            DeviceController::prepare(&profile, info.url.clone(), info.pin.clone())?
        } else {
            ensure!(
                profile.is_dir(),
                "Interrupted device setup needs review; no new identity will be made"
            );
            DeviceController::open(&profile)?
        };
        let status = device.status()?;
        ensure!(
            status.root_public_key == info.pin.root_public_key
                && status.network == info.pin.network_name
                && status.authority.is_some()
                && !status.authority_via_bridge
                && !status.disconnected,
            "Saved device belongs to another setup"
        );
        if let Some(node) = &self.journal.saved.node {
            ensure!(
                node == &status.node_public_key,
                "Saved device identity changed"
            );
        } else {
            ensure!(
                self.journal.saved.stage == SetupStage::DevicePreparing
                    && status.certificate_id.is_none()
                    && !status.enrollment_pending,
                "Unexpected prepared device credential"
            );
            self.journal.saved.node = Some(status.node_public_key.clone());
            self.journal.saved.stage = SetupStage::DeviceReady;
            self.journal.commit()?;
        }
        match self.journal.saved.stage {
            SetupStage::DeviceReady => ensure!(
                status.certificate_id.is_none() && !status.enrollment_pending,
                "Uncertain device enrollment must not be repeated"
            ),
            SetupStage::EnrollmentReserved => self.record_enrolled(&status)?,
            SetupStage::Ready => {
                Self::require_enrolled(&status)?;
                // A verified renewal changes certificate ID, not the pinned
                // network/member identity checked above. Fresh signed trust is
                // required in enroll_device before updating this checkpoint.
            }
            _ => anyhow::bail!("Interrupted invitation needs review; it will not be repeated"),
        }
        device.rebind_owned_authority(info.url.clone(), &info.pin)?;
        device.enable_managed_connectivity()?;
        self.device = Some(device);
        self.usable = true;
        Ok(())
    }
    fn require_enrolled(status: &DeviceStatus) -> Result<()> {
        ensure!(
            status.sharing_host
                && status.certificate_id.is_some()
                && !status.enrollment_pending
                && status
                    .certificate_expires_at
                    .as_deref()
                    .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                    .is_some_and(|t| t > chrono::Utc::now()),
            "Saved host enrollment needs review or credential maintenance"
        );
        Ok(())
    }
    fn record_enrolled(&mut self, status: &DeviceStatus) -> Result<()> {
        Self::require_enrolled(status)?;
        self.journal.saved.certificate_id = status.certificate_id.clone();
        self.journal.saved.stage = SetupStage::Ready;
        self.journal.commit()
    }
    /// Blocking native invitation. A lost response leaves the reservation, never another invitation.
    pub fn request_invitation(&mut self) -> Result<()> {
        self.enter()?;
        if self.journal.saved.stage == SetupStage::Ready {
            self.usable = true;
            return Ok(());
        }
        ensure!(
            self.device.is_some() && self.journal.saved.stage == SetupStage::DeviceReady,
            "Prepare the exact device before inviting it"
        );
        self.journal.saved.stage = SetupStage::InviteReserved;
        self.journal.commit()?;
        let invitation = Zeroizing::new(
            self.runtime.invite(
                self.journal
                    .saved
                    .node
                    .as_deref()
                    .context("Missing prepared node")?,
                true,
            )?,
        );
        self.journal.saved.stage = SetupStage::EnrollmentReserved;
        self.journal.commit()?;
        self.invitation = Some(invitation);
        self.usable = true;
        Ok(())
    }
    /// Existing enrollment path only. Cancellation leaves both progress and device pending markers.
    pub async fn enroll_device(&mut self) -> Result<()> {
        self.enter()?;
        if self.journal.saved.stage == SetupStage::Ready {
            let device = self
                .device
                .as_mut()
                .context("Prepare the saved device first")?;
            device.verify_owned_membership().await?;
            let status = device.status()?;
            Self::require_enrolled(&status)?;
            if status.certificate_id != self.journal.saved.certificate_id {
                self.record_enrolled(&status)?;
            }
            self.membership_verified = true;
            self.usable = true;
            return Ok(());
        }
        ensure!(
            self.journal.saved.stage == SetupStage::EnrollmentReserved,
            "No reserved enrollment"
        );
        let invitation = self
            .invitation
            .take()
            .context("Interrupted enrollment needs review; it cannot be replayed")?;
        let device = self
            .device
            .as_mut()
            .context("Missing exact prepared device")?;
        device.enroll_host(&invitation).await?;
        let status = device.status()?;
        self.record_enrolled(&status)?;
        self.membership_verified = true;
        self.usable = true;
        Ok(())
    }
    pub fn finish(self) -> Result<ForegroundNetwork> {
        ensure!(
            self.usable
                && self.membership_verified
                && self.journal.saved.stage == SetupStage::Ready,
            "Foreground setup is not complete"
        );
        Ok(ForegroundNetwork {
            runtime: self.runtime,
            info: self.info.context("Missing opened authority")?,
            device: self.device.context("Missing enrolled device")?,
            lease: ForegroundLease {
                _journal: self.journal,
            },
        })
    }
}
