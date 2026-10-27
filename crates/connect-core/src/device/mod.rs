//! Durable desktop identity and explicit lifecycle; private keys never cross UI IPC.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) mod owner_store;
#[cfg(target_os = "linux")]
mod sealed_store;
#[cfg(target_os = "linux")]
pub use sealed_store::{MASTER_KEY_CREDENTIAL, use_sealed_store};
mod vault;
pub(crate) use vault::validate_peer;

/// A compiled native adapter is available. Opening a locked/missing OS store
/// can still fail; callers must preserve the existing identity in that case.
pub const fn secure_storage_supported() -> bool {
    cfg!(any(
        windows,
        target_os = "macos",
        target_os = "linux",
        target_os = "android",
        target_os = "ios"
    ))
}

use crate::session::sharing::{Share, ShareConfig, Shares};
use crate::{
    Connectivity,
    authority::{EnrolledDevice, LocalAuthority, TrustPin, TrustStore},
    session::{
        SessionEndpoint, SessionReport,
        bridge::{AuthorityBridge, BridgeAuthority, BridgeRoute, NetworkSettings, SpaceView},
    },
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};
use vault::Vault;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairedDevice {
    pub name: String,
    pub node: String,
    pub ticket: String,
}

#[derive(Serialize)]
pub struct DeviceStatus {
    pub network: String,
    pub root_public_key: String,
    pub trust_checkpoint: crate::authority::TrustCheckpointStatus,
    pub authority: Option<String>,
    pub local_authority_available: bool,
    pub authority_configured: bool,
    pub node_public_key: String,
    pub certificate_id: Option<String>,
    pub certificate_expires_at: Option<String>,
    pub peer_node: Option<String>,
    pub ticket: Option<String>,
    pub received_messages: u64,
    pub ready: bool,
    pub enrollment_pending: bool,
    pub problem: Option<String>,
    pub authority_via_bridge: bool,
    pub bridge_host_node: Option<String>,
    pub bridge_ticket: Option<String>,
    pub sharing_host: bool,
    pub sharing_subject: Option<String>,
    pub sharing_enabled: bool,
    /// The first shared folder, for profiles from before Spaces.
    pub sharing_config: Option<ShareConfig>,
    /// The Spaces this device shares, as saved: a folder that could not be
    /// opened (an unplugged disk, say) stays shared and listed.
    pub shares: Vec<ShareConfig>,
    /// The Spaces this device hosts or that name it, as last listed.
    pub spaces: Vec<SpaceView>,
    pub paired_device: Option<PairedDevice>,
    pub devices: Vec<PairedDevice>,
    /// The network's other devices, from the network computer.
    pub members: Vec<PairedDevice>,
    pub connectivity: ConnectivityStatus,
}

/// How this device reaches the others, and who decided it.
#[derive(Serialize)]
pub struct ConnectivityStatus {
    /// The network computer's setting (on that computer, the owner's own).
    pub network: Connectivity,
    /// This device's stricter choice, if any.
    pub own: Option<Connectivity>,
    /// What this device actually uses.
    pub effective: Connectivity,
    /// Whether this device holds the network's setting.
    pub network_computer: bool,
    /// Guided profiles follow the setting; advanced profiles keep local mode.
    pub guided: bool,
}

/// What a device made of the network computer's list of Spaces.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AppliedSpaces {
    /// This device's Spaces the computer lists but this device no longer
    /// shares: the computer is asked again to forget them.
    pub stale: Vec<String>,
    /// Spaces this device shares that the computer stopped: they stop here.
    pub ended: Vec<String>,
}

fn connectivity_of(vault: &Vault) -> Connectivity {
    if vault.consumer_mode() {
        Connectivity::effective(vault.network_connectivity(), vault.own_connectivity())
    } else {
        Connectivity::LocalNetwork
    }
}

/// Guided profiles reach their network computer under the current setting;
/// advanced profiles keep reaching it the way its ticket was created.
fn bridge_client(route: BridgeRoute, vault: &Vault) -> Result<BridgeAuthority> {
    let client = BridgeAuthority::new(route)?;
    Ok(if vault.consumer_mode() {
        client.with_connectivity(connectivity_of(vault))
    } else {
        client
    })
}

pub struct DeviceController {
    vault: Vault,
    authority: Option<LocalAuthority>,
    trust: TrustStore,
    device: Option<EnrolledDevice>,
    endpoint: Option<Arc<SessionEndpoint>>,
    bridge_client: Option<BridgeAuthority>,
    bridge_host: Option<AuthorityBridge>,
    problem: Option<String>,
    state_directory: std::path::PathBuf,
    sharing: Option<Arc<Shares>>,
    pairing: Option<Arc<crate::session::pairing::PairHost>>,
    /// On the network computer: its owner runtime, for devices' Space requests,
    /// and the registry devices list from.
    owner: Option<crate::owner::OwnerHandle>,
    spaces: Option<Vec<crate::owner::Space>>,
    /// When this device last asked its network computer for its settings.
    settings_checked: Option<std::time::Instant>,
}

impl DeviceController {
    /// A restarted owner sidecar may bind a new loopback port. Only the locally
    /// owned authority with the exact existing pin may replace that origin.
    pub fn rebind_owned_authority(&mut self, authority: String, pin: &TrustPin) -> Result<()> {
        ensure!(
            self.vault.pin() == pin,
            "The local network identity changed; existing trust was preserved"
        );
        ensure!(
            self.bridge_client.is_none() && self.endpoint.is_none(),
            "Stop before changing the local authority origin"
        );
        let client = LocalAuthority::new(&authority)?;
        self.vault.save_authority(authority)?;
        self.authority = Some(client);
        Ok(())
    }
    /// Atomically install the initial profile. The caller chooses its private
    /// application data parent, not a peer-supplied filesystem path.
    pub fn prepare(path: &Path, authority: String, pin: TrustPin) -> Result<Self> {
        LocalAuthority::new(&authority)?;
        Self::prepare_profile(path, Some(authority), pin)
    }

    /// Save a durable node key before the desktop can select it for enrollment.
    /// The operator's bridge route is configured afterward, without a local NA.
    pub fn prepare_remote(path: &Path, pin: TrustPin) -> Result<Self> {
        Self::prepare_profile(path, None, pin)
    }

    fn prepare_profile(path: &Path, authority: Option<String>, pin: TrustPin) -> Result<Self> {
        ensure!(!path.exists(), "This device is already prepared");
        let parent = path.parent().context("Missing application directory")?;
        std::fs::create_dir_all(parent)?;
        let stage = tempfile::tempdir_in(parent)?;
        {
            let _trust = TrustStore::create(&stage.path().join("trust.json"), pin.clone())?;
            let _vault = Vault::create(&stage.path().join("device.bin"), authority, pin)?;
        }
        std::fs::rename(stage.path(), path)?;
        Self::open(path)
    }

    /// The network computer's own identity and verified trust history, for an
    /// encrypted recovery file. Paired devices trust this identity, so a
    /// restore keeps it instead of creating a new one.
    pub fn recovery_identity(&self) -> Result<crate::recovery::DeviceIdentity> {
        ensure!(
            self.network_computer(),
            "Create recovery files on your network computer"
        );
        Ok(crate::recovery::DeviceIdentity {
            vault: self.vault.export()?,
            trust: std::fs::read(self.state_directory.join("trust.json"))?,
        })
    }

    /// Restore the network computer's identity from a recovery file, for the
    /// restored authority at `authority`. Never replaces an existing profile.
    pub fn restore_identity(
        path: &Path,
        identity: &crate::recovery::DeviceIdentity,
        authority: String,
        pin: TrustPin,
    ) -> Result<Self> {
        LocalAuthority::new(&authority)?;
        ensure!(!path.exists(), "This device is already prepared");
        let parent = path.parent().context("Missing application directory")?;
        std::fs::create_dir_all(parent)?;
        let stage = tempfile::tempdir_in(parent)?;
        std::fs::write(stage.path().join("trust.json"), &identity.trust)?;
        TrustStore::open(&stage.path().join("trust.json"), &pin)?;
        Vault::restore(
            &stage.path().join("device.bin"),
            &identity.vault,
            authority,
            &pin,
        )?;
        std::fs::rename(stage.path(), path)?;
        Self::open(path)
    }

    /// Remove a profile this process just created, after a failed restore,
    /// including its secret in a native credential store.
    pub fn discard(self) -> Result<()> {
        let path = self.state_directory.clone();
        let Self { vault, .. } = self;
        vault.discard()?;
        std::fs::remove_dir_all(path)?;
        Ok(())
    }

    pub fn open(path: &Path) -> Result<Self> {
        let vault = Vault::open(&path.join("device.bin"))?;
        let trust = TrustStore::open(&path.join("trust.json"), vault.pin())?;
        let authority = vault.authority().map(LocalAuthority::new).transpose()?;
        let device = vault
            .certificate()
            .map(|cert| EnrolledDevice::restore(vault.key(), cert.clone()))
            .transpose()?;
        let bridge_client = vault
            .bridge_route()
            .cloned()
            .map(|route| bridge_client(route, &vault))
            .transpose()?;
        ensure!(
            device.is_none() || authority.is_some() || bridge_client.is_some(),
            "Enrolled device has no authority connection"
        );
        Ok(Self {
            vault,
            authority,
            trust,
            device,
            endpoint: None,
            bridge_client,
            bridge_host: None,
            problem: None,
            state_directory: path.to_owned(),
            sharing: None,
            pairing: None,
            owner: None,
            spaces: None,
            settings_checked: None,
        })
    }

    pub fn status(&self) -> Result<DeviceStatus> {
        Ok(DeviceStatus {
            network: self.vault.pin().network_name.clone(),
            root_public_key: self.vault.pin().root_public_key.clone(),
            trust_checkpoint: self.trust.status(),
            authority: self.vault.authority().map(str::to_owned),
            local_authority_available: self.authority.is_some(),
            authority_configured: self.authority.is_some() || self.bridge_client.is_some(),
            node_public_key: STANDARD.encode(self.vault.key().verifying_key().to_bytes()),
            certificate_id: self
                .vault
                .certificate()
                .and_then(|c| c["cert_id"].as_str())
                .map(str::to_owned),
            certificate_expires_at: self
                .vault
                .certificate()
                .and_then(|c| c["expires_at"].as_str())
                .map(str::to_owned),
            peer_node: self.vault.peer().map(str::to_owned),
            ticket: self.endpoint.as_ref().map(|e| e.ticket()).transpose()?,
            received_messages: self.endpoint.as_ref().map_or(0, |e| e.received_messages()),
            ready: self.endpoint.as_ref().is_some_and(|e| e.ready()),
            enrollment_pending: self.vault.pending(),
            problem: self.problem.clone(),
            authority_via_bridge: self.bridge_client.is_some(),
            bridge_host_node: self
                .vault
                .bridge_route()
                .map(|route| route.host_node.clone()),
            bridge_ticket: self
                .bridge_host
                .as_ref()
                .map(|host| host.ticket())
                .transpose()?,
            sharing_host: self.vault.edge().is_some(),
            sharing_subject: self
                .vault
                .edge()
                .and_then(|e| e["node_sovereign_id"].as_str())
                .map(str::to_owned),
            sharing_enabled: self.sharing.is_some(),
            sharing_config: self.shares().into_iter().next(),
            shares: self.vault.saved_shares().to_vec(),
            spaces: self.vault.spaces().to_vec(),
            paired_device: self.vault.paired().cloned(),
            devices: self.vault.peers().to_vec(),
            members: self.vault.members().to_vec(),
            connectivity: ConnectivityStatus {
                network: self.vault.network_connectivity(),
                own: self.vault.own_connectivity(),
                effective: self.connectivity(),
                network_computer: self.network_computer(),
                guided: self.vault.consumer_mode(),
            },
        })
    }

    /// Advanced profiles keep their local-network sessions; guided profiles
    /// follow the network computer's setting, or this device's stricter one.
    fn connectivity(&self) -> Connectivity {
        connectivity_of(&self.vault)
    }

    /// The guided network computer: it runs the authority this network uses.
    fn network_computer(&self) -> bool {
        self.vault.consumer_mode() && self.authority.is_some() && self.bridge_client.is_none()
    }

    /// Change how every device reaches this network. Running connections close
    /// and reopen; devices learn the new setting from their next trust refresh.
    pub async fn set_network_connectivity(&mut self, connectivity: Connectivity) -> Result<()> {
        ensure!(
            self.network_computer(),
            "Change the connection setting on your network computer"
        );
        if self.vault.network_connectivity() == connectivity {
            return Ok(());
        }
        self.stop().await;
        if let Some(pairing) = self.pairing.take() {
            pairing.close().await;
        }
        self.vault.save_network_connectivity(connectivity)?;
        self.reconnect_saved().await
    }

    /// Make this device stricter than its network, or follow the network again.
    pub async fn set_own_connectivity(&mut self, own: Option<Connectivity>) -> Result<()> {
        ensure!(
            self.vault.consumer_mode() && !self.network_computer(),
            "Your network computer sets the connection for every device"
        );
        if self.vault.own_connectivity() == own {
            return Ok(());
        }
        self.stop().await;
        self.vault.save_own_connectivity(own)?;
        self.rebuild_bridge_client().await?;
        self.reopen_sharing()?;
        self.reconnect_saved().await
    }

    /// Replace the authority client after its route or setting changed,
    /// closing the old endpoint first.
    async fn rebuild_bridge_client(&mut self) -> Result<()> {
        if let Some(old) = self.bridge_client.take() {
            old.close().await;
        }
        self.bridge_client = self
            .vault
            .bridge_route()
            .cloned()
            .map(|route| bridge_client(route, &self.vault))
            .transpose()?;
        Ok(())
    }

    /// A sharing host asks for decisions through the authority client, so it
    /// reopens with the current one. Sessions must be stopped.
    fn reopen_sharing(&mut self) -> Result<()> {
        if self.sharing.is_some() {
            self.configure_shares(self.shares())?;
        }
        Ok(())
    }
    /// The Spaces this device is sharing now, with their current grants.
    fn shares(&self) -> Vec<ShareConfig> {
        self.sharing
            .as_ref()
            .map(|shares| shares.iter().map(|share| share.config()).collect())
            .unwrap_or_default()
    }

    /// Accept the network computer's authenticated answer: fresh addresses for
    /// the same endpoints, and its connection setting, in one write. An answer
    /// naming another endpoint is ignored as a whole. Returns whether this
    /// device's connections must reopen: a different effective setting, or a
    /// new authority route for a sharing host.
    async fn accept_settings(&mut self, settings: NetworkSettings) -> Result<bool> {
        let before = self.connectivity();
        let Ok(route_changed) = self.vault.apply_network_answer(
            settings.authority_ticket,
            settings.session_ticket,
            settings.connectivity,
        ) else {
            return Ok(false);
        };
        let changed = self.connectivity() != before;
        if route_changed || changed {
            self.rebuild_bridge_client().await?;
        }
        Ok(changed || (route_changed && self.sharing.is_some()))
    }

    pub async fn enroll(&mut self, invite: &str) -> Result<()> {
        ensure!(self.device.is_none(), "This device is already enrolled");
        ensure!(
            self.bridge_client.is_some() || self.authority.is_some(),
            "Configure the desktop authority connection first"
        );
        self.vault.mark_enrollment()?;
        let device = match &self.bridge_client {
            Some(client) => {
                client
                    .enroll(self.vault.key(), invite, &mut self.trust)
                    .await?
            }
            None => {
                self.authority
                    .as_ref()
                    .context("Missing local authority")?
                    .enroll(self.vault.key(), invite, &mut self.trust)
                    .await?
            }
        };
        self.vault.save_certificate(device.certificate().clone())?;
        self.device = Some(device);
        self.problem = None;
        Ok(())
    }
    pub async fn enroll_host(&mut self, invite: &str) -> Result<()> {
        ensure!(
            self.device.is_none(),
            "Choose sharing host enrollment before enrolling this profile"
        );
        let executor = self.vault.executor()?;
        self.vault.mark_enrollment()?;
        let (device, edge) = match &self.bridge_client {
            Some(client) => {
                client
                    .enroll_host(self.vault.key(), &executor, invite, &mut self.trust)
                    .await?
            }
            None => {
                self.authority
                    .as_ref()
                    .context("Configure the authority connection first")?
                    .enroll_host(self.vault.key(), &executor, invite, &mut self.trust)
                    .await?
            }
        };
        self.vault.save_host(device.certificate().clone(), edge)?;
        self.device = Some(device);
        self.problem = None;
        Ok(())
    }
    /// Share exactly one folder, or none.
    pub fn configure_sharing(&mut self, config: Option<ShareConfig>) -> Result<()> {
        self.configure_shares(config.into_iter().collect())
    }
    /// Share exactly these Spaces. Each keeps its own evidence and download
    /// snapshots under its collection.
    pub fn configure_shares(&mut self, configs: Vec<ShareConfig>) -> Result<()> {
        ensure!(
            self.endpoint.is_none(),
            "Stop the session before changing sharing"
        );
        // Files arriving in an inbox keep their staging while the shares
        // reopen; each share's trust checkpoint is released first.
        let _arriving = self.sharing.as_ref().map(|shares| shares.staging());
        self.sharing = None;
        if configs.is_empty() {
            return Ok(());
        }
        ensure!(
            self.vault.edge().is_some(),
            "Enroll this profile with a sharing invitation before sharing"
        );
        let authority = match &self.bridge_client {
            Some(client) => crate::authority::AuthorityAccess::Remote(client.clone()),
            None => self
                .authority
                .as_ref()
                .context("Missing local authority")?
                .clone()
                .into(),
        };
        let opened = configs
            .into_iter()
            .map(|config| {
                let state = self
                    .state_directory
                    .join("sharing")
                    .join(&config.collection_id);
                Ok(Arc::new(Share::open(
                    config,
                    authority.clone(),
                    self.vault.pin().clone(),
                    &state,
                )?))
            })
            .collect::<Result<Vec<_>>>()
            .and_then(Shares::new);
        self.sharing = Some(Arc::new(opened?));
        Ok(())
    }
    pub fn save_managed_share(&mut self, config: Option<ShareConfig>) -> Result<()> {
        self.save_managed_shares(config.into_iter().collect())
    }
    pub fn save_managed_shares(&mut self, configs: Vec<ShareConfig>) -> Result<()> {
        ensure!(self.vault.consumer_mode(), "Use guided setup first");
        self.configure_shares(configs.clone())?;
        self.vault.save_shares(configs)
    }
    pub fn restore_managed_share(&mut self) -> Result<()> {
        if self.vault.consumer_mode()
            && self.sharing.is_none()
            && !self.vault.saved_shares().is_empty()
        {
            self.configure_shares(self.vault.saved_shares().to_vec())?;
        }
        Ok(())
    }
    /// Share this Space, or replace the one with its collection, saving it.
    /// Running connections reopen with the new set.
    pub async fn set_space(&mut self, config: ShareConfig) -> Result<()> {
        let mut configs: Vec<_> = self
            .vault
            .saved_shares()
            .iter()
            .filter(|share| share.collection_id != config.collection_id)
            .cloned()
            .collect();
        configs.push(config);
        self.replace_shares(configs).await
    }
    /// Stop sharing one Space on this device.
    pub async fn drop_space(&mut self, collection: &str) -> Result<()> {
        let configs: Vec<_> = self
            .vault
            .saved_shares()
            .iter()
            .filter(|share| share.collection_id != collection)
            .cloned()
            .collect();
        self.replace_shares(configs).await
    }
    /// Save and serve exactly these Spaces. Reopening connections needs the
    /// network computer; when it cannot be reached, the change still holds and
    /// the problem shows until the next refresh reconnects.
    async fn replace_shares(&mut self, configs: Vec<ShareConfig>) -> Result<()> {
        self.stop().await;
        let changed = self.save_managed_shares(configs);
        // A failed start records its problem and is retried by maintenance.
        let _ = self.reconnect_saved().await;
        changed
    }
    /// On the network computer: answer devices' Space requests with this
    /// owner runtime.
    pub fn serve_owner(&mut self, owner: crate::owner::OwnerHandle) {
        if let Some(host) = &self.bridge_host {
            host.serve_owner(owner.clone());
        }
        self.owner = Some(owner);
    }
    /// On the network computer: the Space registry devices list from.
    pub fn publish_spaces(&mut self, spaces: Vec<crate::owner::Space>) {
        if let Some(host) = &self.bridge_host {
            host.publish_spaces(spaces.clone());
        }
        self.spaces = Some(spaces);
    }
    /// Ask the network computer for a Space on `directory`, shared with
    /// `recipients`, then share it. `collection` changes an existing Space.
    pub async fn share_space(
        &mut self,
        collection: Option<String>,
        directory: std::path::PathBuf,
        name: String,
        recipients: Vec<String>,
        kind: crate::session::sharing::SpaceKind,
    ) -> Result<ShareConfig> {
        let client = self
            .bridge_client
            .clone()
            .context("Share folders on your network computer from its own screen")?;
        let identity = self
            .device
            .as_ref()
            .context("Join your network first")?
            .session_identity()?;
        let trust = client.refresh(&mut self.trust).await?;
        let collection = collection.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let view = client
            .share_space(identity, trust, collection, name, recipients, kind)
            .await?;
        let config = Self::space_config(view, directory)?;
        self.set_space(config.clone()).await?;
        Ok(config)
    }
    /// The saved form of one of this device's Spaces.
    pub fn space_config(view: SpaceView, directory: std::path::PathBuf) -> Result<ShareConfig> {
        let grant = view.grant.context("Missing shared folder grant")?;
        Ok(ShareConfig {
            collection_id: view.collection,
            directory,
            attestation_id: grant.attestation_id,
            policy_id: grant.policy_id,
            name: view.name,
            recipients: grant.recipients,
            kind: view.kind,
        })
    }
    /// Stop one of this device's Spaces here, then ask the network computer
    /// to forget it. Returns whether it confirmed; if it could not be reached,
    /// it is asked again at a later refresh, and nothing is served meanwhile.
    pub async fn unshare_space(&mut self, collection: &str) -> Result<bool> {
        ensure!(
            self.vault
                .saved_shares()
                .iter()
                .any(|share| share.collection_id == collection),
            "Only the device sharing a folder can stop sharing it"
        );
        self.drop_space(collection).await?;
        // The network computer's own Spaces are removed by its owner runtime.
        let (Some(client), Some(device)) = (self.bridge_client.clone(), self.device.as_ref())
        else {
            return Ok(false);
        };
        let identity = device.session_identity()?;
        let confirmed = async {
            let trust = client.refresh(&mut self.trust).await?;
            client
                .unshare_space(identity, trust, collection.to_owned())
                .await
        }
        .await;
        Ok(confirmed.is_ok())
    }
    /// Take the network computer's list of Spaces for this device: keep it for
    /// display, and use renewed grants for the Spaces this device shares. The
    /// computer can take a removed device off a Space's devices, never add
    /// one.
    pub fn apply_spaces(&mut self, views: Vec<SpaceView>) -> Result<AppliedSpaces> {
        let own = self.status()?.node_public_key;
        let mut saved = self.vault.saved_shares().to_vec();
        let mut renewed = false;
        let mut stale = Vec::new();
        for view in views.iter().filter(|view| view.host == own) {
            let Some(grant) = &view.grant else { continue };
            let Some(config) = saved
                .iter_mut()
                .find(|share| share.collection_id == view.collection)
            else {
                stale.push(view.collection.clone());
                continue;
            };
            let before = config.recipients.len();
            config
                .recipients
                .retain(|node| grant.recipients.contains(node));
            renewed |= config.recipients.len() != before;
            if config.attestation_id != grant.attestation_id {
                if let Some(share) = self
                    .sharing
                    .as_ref()
                    .and_then(|shares| shares.iter().find(|s| s.collection_id() == view.collection))
                {
                    share.renew(&grant.attestation_id)?;
                }
                config.attestation_id = grant.attestation_id.clone();
                renewed = true;
            }
        }
        // A Space this device shares that the computer no longer lists was
        // stopped there, for example when its last device was removed.
        let ended = saved
            .iter()
            .filter(|share| {
                !share.name.is_empty()
                    && !views
                        .iter()
                        .any(|view| view.host == own && view.collection == share.collection_id)
            })
            .map(|share| share.collection_id.clone())
            .collect();
        if renewed {
            self.vault.save_shares(saved)?;
        }
        self.vault.save_spaces(views)?;
        Ok(AppliedSpaces { stale, ended })
    }
    pub async fn create_pairing(
        &mut self,
        name: String,
    ) -> Result<Arc<crate::session::pairing::PairHost>> {
        ensure!(
            self.vault.consumer_mode() && self.vault.peers().len() < 32,
            "This network computer supports up to 32 saved devices. Existing devices were preserved."
        );
        self.refresh().await?;
        if let Some(previous) = self.pairing.take() {
            previous.close().await;
        }
        let authority = self
            .authority
            .as_ref()
            .context("Add devices from the network computer")?
            .clone();
        let trust = authority.refresh(&mut self.trust).await?;
        let host = crate::session::pairing::PairHost::bind(
            self.device
                .as_ref()
                .context("Finish network setup first")?
                .session_identity()?,
            trust,
            authority,
            name,
            self.connectivity(),
        )
        .await?;
        self.pairing = Some(host.clone());
        Ok(host)
    }
    pub fn pairing(&self) -> Option<Arc<crate::session::pairing::PairHost>> {
        self.pairing.clone()
    }
    pub async fn request_pairing(
        &mut self,
        card: crate::session::pairing::PairCard,
        name: String,
    ) -> Result<crate::session::pairing::PairClient> {
        ensure!(
            self.vault.pin() == &card.pin && self.device.is_none(),
            "This device already belongs to a network. Its identity was preserved."
        );
        self.enable_managed_connectivity()?;
        if self.vault.network_connectivity() != card.connectivity() {
            self.vault.save_network_connectivity(card.connectivity())?;
        }
        crate::session::pairing::PairClient::request(card, &self.vault.key(), &mut self.trust, name)
            .await
    }

    /// Only an already-enrolled device can adopt the bridge. Complete one
    /// mutually authenticated renewal, then atomically persist route + credential.
    pub async fn use_bridge(&mut self, route: BridgeRoute) -> Result<()> {
        ensure!(
            self.sharing.is_none(),
            "Disable sharing before changing the authority connection"
        );
        ensure!(
            self.endpoint.is_none(),
            "Stop the session before changing the authority connection"
        );
        let client = bridge_client(route.clone(), &self.vault)?;
        let Some(device) = self.device.as_mut() else {
            // This is an explicit host pin, not evidence that a host was verified.
            // Enrollment verifies its certificate + connection proof before any invite.
            self.vault.save_route(Some(route))?;
            self.bridge_client = Some(client);
            self.problem = None;
            return Ok(());
        };
        client.renew(device, &mut self.trust).await?;
        if let Err(error) = self
            .vault
            .save_bridge_renewal(device.certificate().clone(), route)
        {
            *device = EnrolledDevice::restore(
                self.vault.key(),
                self.vault
                    .certificate()
                    .context("Missing saved certificate")?
                    .clone(),
            )?;
            return Err(error);
        }
        self.bridge_client = Some(client);
        self.problem = None;
        Ok(())
    }

    pub fn use_local_authority(&mut self) -> Result<()> {
        ensure!(
            self.endpoint.is_none(),
            "Stop the session before changing the authority connection"
        );
        ensure!(
            self.authority.is_some(),
            "This device has no local authority configured"
        );
        self.vault.save_route(None)?;
        self.bridge_client = None;
        self.problem = None;
        Ok(())
    }

    pub async fn start(&mut self, peer: &str) -> Result<()> {
        ensure!(
            STANDARD.decode(peer).is_ok_and(|k| k.len() == 32),
            "Enter the other device's node public key"
        );
        ensure!(
            peer != STANDARD.encode(self.vault.key().verifying_key().to_bytes()),
            "Choose another device"
        );
        self.vault.save_peer(peer.to_owned())?;
        self.sync_peers()?;
        let outcome = self.refresh_inner(true).await;
        self.record_outcome(&outcome);
        let trust = outcome?;
        self.follow_network(trust).await
    }

    /// Call every 30 seconds while running, and immediately after resume. Every
    /// failed check suspends sessions; an unchanged old CRL alone is not freshness.
    pub async fn refresh(&mut self) -> Result<()> {
        if self.device.is_none() {
            return Ok(());
        }
        let outcome = self.refresh_inner(false).await;
        self.record_outcome(&outcome);
        let trust = outcome?;
        self.follow_network(trust).await
    }

    /// Refresh now and ask the network computer for its setting and devices,
    /// even within the interval, for example when the owner opens Devices.
    pub async fn check_network(&mut self) -> Result<()> {
        self.settings_checked = None;
        self.refresh().await
    }

    /// Ask the network computer for its connection setting and current
    /// addresses. An older or unreachable computer leaves everything as it is:
    /// this answer never affects trust, only how this device reaches others.
    async fn follow_network(&mut self, trust: crate::session::TrustSnapshot) -> Result<()> {
        // File operations refresh trust too; one answer per refresh interval.
        if !self.vault.consumer_mode()
            || self
                .settings_checked
                .is_some_and(|at| at.elapsed() < std::time::Duration::from_secs(25))
        {
            return Ok(());
        }
        let (Some(client), Some(device)) = (self.bridge_client.clone(), self.device.as_ref())
        else {
            return Ok(());
        };
        let identity = device.session_identity()?;
        self.settings_checked = Some(std::time::Instant::now());
        if let Ok(settings) = client.settings(identity.clone(), trust.clone()).await
            && self.accept_settings(settings).await?
        {
            let running = self.endpoint.is_some();
            self.stop().await;
            self.reopen_sharing()?;
            if running {
                let outcome = self.refresh_inner(true).await;
                self.record_outcome(&outcome);
                outcome?;
            }
        }
        self.follow_members(identity.clone(), trust.clone()).await?;
        self.follow_spaces(identity, trust).await
    }

    /// Learn the Spaces shared with this device, pick up renewed grants for
    /// its own, and finish stopping any the network computer still lists.
    /// Like the member list, this never affects trust.
    async fn follow_spaces(
        &mut self,
        identity: crate::session::SessionIdentity,
        trust: crate::session::TrustSnapshot,
    ) -> Result<()> {
        let Some(client) = self.bridge_client.clone() else {
            return Ok(());
        };
        let Ok((mut views, inboxes)) = client.listing(identity.clone(), trust.clone()).await else {
            return Ok(());
        };
        // Inboxes the computer did not list just now stay as last listed.
        views.extend(inboxes.unwrap_or_else(|| {
            self.vault
                .spaces()
                .iter()
                .filter(|space| space.kind == crate::session::sharing::SpaceKind::Inbox)
                .cloned()
                .collect()
        }));
        // A profile at its size limit keeps the last list.
        let Ok(applied) = self.apply_spaces(views) else {
            return Ok(());
        };
        for collection in applied.stale {
            let _ = client
                .unshare_space(identity.clone(), trust.clone(), collection)
                .await;
        }
        for collection in applied.ended {
            self.drop_space(&collection).await?;
        }
        Ok(())
    }

    /// Learn the network's other devices from the network computer, telling it
    /// this device's current address. An older or unreachable computer leaves
    /// the saved list as it is; the list never affects trust or permissions.
    async fn follow_members(
        &mut self,
        identity: crate::session::SessionIdentity,
        trust: crate::session::TrustSnapshot,
    ) -> Result<()> {
        let Some(client) = self.bridge_client.clone() else {
            return Ok(());
        };
        let ticket = self.endpoint.as_ref().and_then(|e| e.ticket().ok());
        let Ok(members) = client.members(identity, trust, ticket).await else {
            return Ok(());
        };
        let nodes = |vault: &Vault| -> Vec<String> {
            vault.members().iter().map(|m| m.node.clone()).collect()
        };
        let before = nodes(&self.vault);
        // A profile at its size limit keeps the last list.
        if self.vault.save_members(members).unwrap_or(false) && nodes(&self.vault) != before {
            // Only a change of devices touches running connections; a new
            // address does not.
            self.sync_peers()?;
        }
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.endpoint.is_some()
    }
    pub fn needs_maintenance(&self) -> bool {
        self.endpoint.is_some() || self.pairing.is_some() || self.vault.auto_connect()
    }

    fn record_outcome<T>(&mut self, outcome: &Result<T>) {
        self.problem = outcome.as_ref().err().map(ToString::to_string);
        if outcome.is_err()
            && let Some(endpoint) = &self.endpoint
        {
            endpoint.suspend();
        }
        if outcome.is_err()
            && let Some(host) = &self.bridge_host
        {
            host.suspend();
        }
        if outcome.is_err()
            && let Some(host) = &self.pairing
        {
            host.suspend();
        }
    }

    async fn refresh_inner(&mut self, start: bool) -> Result<crate::session::TrustSnapshot> {
        let device = self.device.as_mut().context("Enroll this device first")?;
        if device.renewal_due() {
            if let Some(endpoint) = &self.endpoint {
                endpoint.suspend();
            }
            if let Some(host) = &self.bridge_host {
                host.suspend();
            }
            match &self.bridge_client {
                Some(client) => client.renew(device, &mut self.trust).await?,
                None => {
                    self.authority
                        .as_ref()
                        .context("Missing local authority")?
                        .renew(device, &mut self.trust)
                        .await?
                }
            }
            // Persist the verified renewal before exposing it to any session.
            if let Err(error) = self.vault.save_certificate(device.certificate().clone()) {
                *device = EnrolledDevice::restore(
                    self.vault.key(),
                    self.vault
                        .certificate()
                        .context("Missing saved certificate")?
                        .clone(),
                )?;
                return Err(error);
            }
        }
        let trust = match &self.bridge_client {
            Some(client) => client.refresh(&mut self.trust).await?,
            None => {
                self.authority
                    .as_ref()
                    .context("Missing local authority")?
                    .refresh(&mut self.trust)
                    .await?
            }
        };
        let snapshot = trust.clone();
        if let Some(host) = &self.pairing {
            host.refresh(device.session_identity()?, trust.clone())?;
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.refresh(device.session_identity()?, trust.clone())?;
            if let Some(host) = &self.bridge_host {
                host.refresh(device.session_identity()?, trust)?;
                // Addresses change with the network; devices pick them up.
                host.publish_session(Some(endpoint.ticket()?))?;
                // And devices report theirs, for the others to find them.
                let reported = host.take_reported();
                if !reported.is_empty() && self.vault.save_peer_addresses(reported).unwrap_or(false)
                {
                    host.publish_members(self.vault.peers().to_vec());
                }
            }
        } else if start {
            let peer = self.vault.peer().context("Choose a peer first")?.to_owned();
            let connectivity = connectivity_of(&self.vault);
            let bridge_host = if self.bridge_client.is_none() {
                Some(
                    AuthorityBridge::bind_with_transport(
                        device.session_identity()?,
                        trust.clone(),
                        peer.clone(),
                        self.authority
                            .as_ref()
                            .context("Missing local authority")?
                            .clone(),
                        if self.vault.consumer_mode() {
                            Some(self.vault.saved_transport(true)?)
                        } else {
                            None
                        },
                        connectivity,
                    )
                    .await?,
                )
            } else {
                None
            };
            if let Some(host) = &bridge_host
                && self.vault.consumer_mode()
            {
                self.vault.save_transport_port(true, host.port())?;
            }
            // Devices asking before this would get no list, never an empty one.
            if let Some(host) = &bridge_host {
                host.publish_members(self.vault.peers().to_vec());
                if let Some(owner) = &self.owner {
                    host.serve_owner(owner.clone());
                }
                if let Some(spaces) = &self.spaces {
                    host.publish_spaces(spaces.clone());
                }
            }
            let endpoint = Arc::new(
                SessionEndpoint::bind_with_transport(
                    device.session_identity()?,
                    trust,
                    peer,
                    self.sharing.clone(),
                    if self.vault.consumer_mode() {
                        Some(self.vault.saved_transport(false)?)
                    } else {
                        None
                    },
                    connectivity,
                )
                .await?,
            );
            if self.vault.consumer_mode() {
                self.vault.save_transport_port(false, endpoint.port())?;
            }
            if let Some(host) = &bridge_host {
                host.publish_session(Some(endpoint.ticket()?))?;
            }
            self.endpoint = Some(endpoint);
            self.bridge_host = bridge_host;
            self.sync_peers()?;
        }
        Ok(snapshot)
    }

    pub fn session(&self) -> Result<Arc<SessionEndpoint>> {
        self.endpoint
            .clone()
            .context("Start an authenticated session first")
    }
    pub fn paired_device(&self) -> Option<&PairedDevice> {
        self.vault.paired()
    }
    pub async fn select_device(&mut self, node: &str) -> Result<()> {
        ensure!(
            self.vault
                .peers()
                .iter()
                .chain(self.vault.members())
                .any(|p| p.node == node),
            "Choose a saved device"
        );
        self.start(node).await
    }
    pub async fn forget_device(&mut self, node: &str) -> Result<()> {
        ensure!(
            !self.vault.members().iter().any(|p| p.node == node),
            "This device belongs to your network. Your network computer decides who belongs."
        );
        ensure!(
            self.vault.peers().iter().any(|p| p.node == node),
            "Choose a saved device"
        );
        ensure!(
            self.vault
                .bridge_route()
                .is_none_or(|r| r.host_node != node),
            "This device provides your authority connection. Configure another authority connection before forgetting it."
        );
        self.stop().await;
        self.vault.forget_pairing(node)?;
        self.reconnect_saved().await
    }
    fn sync_peers(&self) -> Result<()> {
        let Some(selected) = self.vault.peer() else {
            return Ok(());
        };
        // Members connect too; what they may do is still decided per operation.
        let mut allowed: Vec<_> = self
            .vault
            .peers()
            .iter()
            .chain(self.vault.members())
            .map(|p| p.node.clone())
            .collect();
        if !allowed.iter().any(|n| n == selected) {
            allowed.push(selected.to_owned());
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.set_peers(selected.to_owned(), allowed.clone())?;
        }
        if let Some(bridge) = &self.bridge_host {
            bridge.set_peers(selected.to_owned(), allowed)?;
        }
        self.publish_members();
        Ok(())
    }
    /// On the network computer: the saved devices its members learn about.
    fn publish_members(&self) {
        if let Some(bridge) = &self.bridge_host {
            bridge.publish_members(self.vault.peers().to_vec());
        }
    }
    pub fn enable_managed_connectivity(&mut self) -> Result<()> {
        self.vault.enable_consumer()
    }
    pub async fn reconnect_saved(&mut self) -> Result<()> {
        if !self.vault.auto_connect() || self.endpoint.is_some() {
            return Ok(());
        }
        let Some(peer) = self.vault.paired() else {
            return Ok(());
        };
        let node = peer.node.clone();
        self.start(&node).await
    }
    pub fn remember_pairing(&mut self, peer: PairedDevice) -> Result<()> {
        ensure!(
            peer.name.chars().count() <= 64 && !peer.name.trim().is_empty(),
            "Choose a device name"
        );
        ensure!(
            self.vault.peer() == Some(peer.node.as_str()),
            "Pairing does not match the selected identity"
        );
        self.vault.save_pairing(peer)?;
        // On the network computer, the other devices learn about this one.
        self.publish_members();
        Ok(())
    }
    pub async fn send(&self, ticket: &str, message: &str) -> Result<SessionReport> {
        self.session()?.round_trip(ticket, message).await
    }
    pub async fn stop(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close().await;
        }
        if let Some(host) = self.bridge_host.take() {
            host.close().await;
        }
    }
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    use super::*;

    fn authority_ticket(id: iroh::EndpointId, port: u16) -> String {
        serde_json::to_string(&serde_json::json!({
            "version": 1,
            "service": "authority",
            "endpoint": iroh::EndpointAddr::new(id).with_ip_addr(([192, 0, 2, 1], port).into()),
        }))
        .unwrap()
    }
    fn settings(id: iroh::EndpointId, port: u16, connectivity: Connectivity) -> NetworkSettings {
        NetworkSettings {
            connectivity,
            authority_ticket: authority_ticket(id, port),
            session_ticket: None,
        }
    }

    #[tokio::test]
    #[ignore = "Requires a native OS credential store; Linux runner uses an isolated Secret Service"]
    async fn a_device_follows_its_network_computer_and_only_accepts_the_same_endpoint() -> Result<()>
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("device");
        let pin = TrustPin {
            network_name: "disposable-connectivity-test".into(),
            root_public_key: STANDARD.encode([5; 32]),
        };
        let mut device = DeviceController::prepare_remote(&path, pin)?;
        device.enable_managed_connectivity()?;
        let host = iroh::SecretKey::generate().public();
        device
            .use_bridge(BridgeRoute {
                ticket: authority_ticket(host, 7000),
                host_node: STANDARD.encode([9; 32]),
            })
            .await?;
        assert_eq!(
            device.status()?.connectivity.effective,
            Connectivity::PublicRelays
        );
        assert!(
            device
                .accept_settings(settings(host, 7001, Connectivity::LocalNetwork))
                .await?
        );
        let status = device.status()?;
        assert_eq!(status.connectivity.network, Connectivity::LocalNetwork);
        assert_eq!(status.connectivity.effective, Connectivity::LocalNetwork);
        assert!(!status.connectivity.network_computer);
        assert_eq!(
            device.vault.bridge_route().map(|r| r.ticket.clone()),
            Some(authority_ticket(host, 7001)),
            "Fresh addresses for the same endpoint replace the saved ones"
        );
        assert!(
            !device
                .accept_settings(settings(host, 7001, Connectivity::LocalNetwork))
                .await?,
            "An unchanged answer reopens nothing"
        );
        let other = iroh::SecretKey::generate().public();
        assert!(
            !device
                .accept_settings(settings(other, 7002, Connectivity::PublicRelays))
                .await?
        );
        assert_eq!(
            device.status()?.connectivity.network,
            Connectivity::LocalNetwork,
            "An answer naming another endpoint changes nothing"
        );
        assert_eq!(
            device.vault.bridge_route().map(|r| r.ticket.clone()),
            Some(authority_ticket(host, 7001))
        );
        assert!(
            device
                .set_network_connectivity(Connectivity::PublicRelays)
                .await
                .is_err(),
            "Only the network computer sets the network's connection"
        );
        device
            .set_own_connectivity(Some(Connectivity::PublicRelays))
            .await?;
        assert_eq!(
            device.status()?.connectivity.effective,
            Connectivity::LocalNetwork,
            "A looser device choice never widens a private network"
        );
        assert!(
            device
                .accept_settings(settings(host, 7001, Connectivity::PublicRelays))
                .await?
        );
        assert_eq!(
            device.status()?.connectivity.effective,
            Connectivity::PublicRelays
        );
        device
            .set_own_connectivity(Some(Connectivity::LocalNetwork))
            .await?;
        assert_eq!(
            device.status()?.connectivity.effective,
            Connectivity::LocalNetwork,
            "A device may stay stricter than a public network"
        );
        // A valid route with a session address for another endpoint is still
        // refused as a whole: nothing is partly applied.
        let session = |id: iroh::EndpointId| {
            serde_json::to_string(&serde_json::json!({
                "version": 1,
                "endpoint": iroh::EndpointAddr::new(id).with_ip_addr(([192, 0, 2, 2], 7100).into()),
            }))
            .unwrap()
        };
        let computer = iroh::SecretKey::generate().public();
        let host_node = STANDARD.encode([9; 32]);
        device.vault.save_peer(host_node.clone())?;
        device.vault.save_pairing(PairedDevice {
            name: "Home computer".into(),
            node: host_node,
            ticket: session(computer),
        })?;
        let mut mixed = settings(host, 7003, Connectivity::PublicRelays);
        mixed.session_ticket = Some(session(other));
        assert!(!device.accept_settings(mixed).await?);
        assert_eq!(
            device.vault.bridge_route().map(|r| r.ticket.clone()),
            Some(authority_ticket(host, 7001))
        );
        assert_eq!(
            device.status()?.connectivity.network,
            Connectivity::PublicRelays
        );
        assert_eq!(
            device.paired_device().map(|p| p.ticket.clone()),
            Some(session(computer))
        );
        drop(device);
        let reopened = DeviceController::open(&path)?;
        let status = reopened.status()?;
        assert_eq!(status.connectivity.network, Connectivity::PublicRelays);
        assert_eq!(status.connectivity.own, Some(Connectivity::LocalNetwork));
        assert_eq!(status.connectivity.effective, Connectivity::LocalNetwork);
        Ok(())
    }

    #[test]
    #[ignore = "Requires a native OS credential store; Linux runner uses an isolated Secret Service"]
    fn member_lists_skip_known_devices_stay_within_32_and_survive_a_reopen() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("device");
        let pin = TrustPin {
            network_name: "disposable-member-test".into(),
            root_public_key: STANDARD.encode([6; 32]),
        };
        let mut device = DeviceController::prepare_remote(&path, pin)?;
        let own = device.status()?.node_public_key;
        let ticket = |id: iroh::EndpointId, port: u16| {
            serde_json::to_string(&serde_json::json!({
                "version": 1,
                "endpoint": iroh::EndpointAddr::new(id).with_ip_addr(([192, 0, 2, 3], port).into()),
            }))
            .unwrap()
        };
        let node = |byte: u8| STANDARD.encode([byte; 32]);
        let member = |byte: u8| PairedDevice {
            name: format!("Device {byte}"),
            node: node(byte),
            ticket: ticket(iroh::SecretKey::generate().public(), 7000 + u16::from(byte)),
        };
        let computer = PairedDevice {
            name: "Home computer".into(),
            node: node(200),
            ticket: ticket(iroh::SecretKey::generate().public(), 6999),
        };
        device.vault.save_route(Some(BridgeRoute {
            ticket: authority_ticket(iroh::SecretKey::generate().public(), 7500),
            host_node: computer.node.clone(),
        }))?;
        device.vault.save_peer(computer.node.clone())?;
        device.vault.save_pairing(computer.clone())?;

        // Never this device, a paired one, or the same device twice; and the
        // network computer stays selected when the list does not name it.
        let mut list: Vec<_> = (1..=40).map(member).collect();
        list.push(PairedDevice {
            name: "Me".into(),
            node: own.clone(),
            ticket: ticket(iroh::SecretKey::generate().public(), 7600),
        });
        list.push(computer.clone());
        list.push(member(1));
        assert!(device.vault.save_members(list.clone())?);
        let kept = device.vault.members().to_vec();
        assert_eq!(kept.len(), 31, "With the computer, 32 devices in all");
        assert!(
            kept.iter()
                .all(|m| m.node != own && m.node != computer.node)
        );
        assert_eq!(kept.first().map(|m| m.name.as_str()), Some("Device 1"));
        assert_eq!(device.vault.peer(), Some(computer.node.as_str()));
        assert!(
            !device.vault.save_members(list)?,
            "An unchanged list writes nothing"
        );
        // Tickets are kept in one spelling.
        let spaced = kept[0].ticket.replace(',', " , ");
        let mut respelled = kept.clone();
        respelled[0].ticket = spaced;
        assert!(!device.vault.save_members(respelled)?);

        // A selected member that leaves falls back to the network computer;
        // one that stays keeps the selection.
        device.vault.save_peer(node(2))?;
        assert!(device.vault.save_members(kept[1..].to_vec())?);
        assert_eq!(device.vault.peer(), Some(node(2).as_str()));
        assert_eq!(
            device.vault.paired().map(|p| p.name.clone()),
            Some("Device 2".into())
        );
        assert!(device.vault.save_members(kept[2..].to_vec())?);
        assert_eq!(device.vault.peer(), Some(computer.node.as_str()));

        // Pairing with a member moves it out of the member list.
        device.vault.save_peer(node(3))?;
        device.vault.save_pairing(member(3))?;
        assert!(device.vault.members().iter().all(|m| m.node != node(3)));
        assert_eq!(
            device.vault.peers().len() + device.vault.members().len(),
            30
        );

        // A reopened profile keeps its member list.
        let members = device.vault.members().to_vec();
        drop(device);
        let reopened = DeviceController::open(&path)?;
        assert_eq!(reopened.status()?.members, members);
        Ok(())
    }

    #[test]
    #[ignore = "Requires a native OS credential store; Linux runner uses an isolated Secret Service"]
    fn listed_spaces_renew_this_devices_grants_and_name_the_ones_it_stopped() -> Result<()> {
        use crate::session::bridge::SpaceGrant;
        let dir = tempfile::tempdir()?;
        let pin = TrustPin {
            network_name: "disposable-space-test".into(),
            root_public_key: STANDARD.encode([4; 32]),
        };
        let mut device = DeviceController::prepare_remote(&dir.path().join("device"), pin)?;
        let own = device.status()?.node_public_key;
        let phone = STANDARD.encode([5; 32]);
        let (removed, newcomer) = (STANDARD.encode([6; 32]), STANDARD.encode([8; 32]));
        let (kept, stopped, theirs, ended) = (
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        );
        let config = ShareConfig {
            collection_id: kept.clone(),
            directory: dir.path().join("photos"),
            attestation_id: uuid::Uuid::new_v4().to_string(),
            policy_id: format!("connect-{kept}"),
            name: "Photos".into(),
            recipients: vec![phone.clone(), removed.clone()],
            ..Default::default()
        };
        // A Space the computer stopped, and a folder shared before Spaces.
        let gone = ShareConfig {
            collection_id: ended.clone(),
            name: "Only the removed device".into(),
            recipients: vec![removed.clone()],
            ..config.clone()
        };
        let legacy = ShareConfig {
            collection_id: uuid::Uuid::new_v4().to_string(),
            name: String::new(),
            ..config.clone()
        };
        device
            .vault
            .save_shares(vec![config.clone(), gone, legacy])?;
        // The computer took the removed device off; it never adds one.
        let grant = |collection: &str, attestation: String| SpaceGrant {
            policy_id: format!("connect-{collection}"),
            attestation_id: attestation,
            recipients: vec![phone.clone(), newcomer.clone()],
            valid_until: "2027-01-01T00:00:00+00:00".into(),
        };
        let renewed = uuid::Uuid::new_v4().to_string();
        let views = vec![
            SpaceView {
                collection: kept.clone(),
                name: "Photos".into(),
                host: own.clone(),
                kind: Default::default(),
                grant: Some(grant(&kept, renewed.clone())),
            },
            SpaceView {
                collection: stopped.clone(),
                name: "Old folder".into(),
                host: own.clone(),
                kind: Default::default(),
                grant: Some(grant(&stopped, uuid::Uuid::new_v4().to_string())),
            },
            SpaceView {
                collection: theirs.clone(),
                name: "Recipes".into(),
                host: phone.clone(),
                kind: Default::default(),
                grant: None,
            },
        ];
        assert_eq!(
            device.apply_spaces(views.clone())?,
            AppliedSpaces {
                stale: vec![stopped.clone()],
                ended: vec![ended.clone()],
            }
        );
        assert_eq!(
            device.vault.saved_shares()[0].attestation_id,
            renewed,
            "A renewed grant is saved with the Space"
        );
        assert_eq!(
            device.vault.saved_shares()[0].recipients,
            vec![phone.clone()],
            "Only its host adds devices to a Space; the computer takes removed ones off"
        );
        let listed = device.status()?.spaces;
        assert_eq!(listed.len(), 3);
        assert!(
            listed.iter().all(|s| s.grant.is_none()),
            "Grants stay with the shares"
        );
        assert!(
            !device.vault.save_spaces(views)?,
            "An unchanged list writes nothing"
        );
        Ok(())
    }

    #[test]
    #[ignore = "Requires a native OS credential store; Linux runner uses an isolated Secret Service"]
    fn reported_addresses_replace_only_the_same_endpoint() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let pin = TrustPin {
            network_name: "disposable-address-test".into(),
            root_public_key: STANDARD.encode([7; 32]),
        };
        let mut device = DeviceController::prepare_remote(&dir.path().join("device"), pin)?;
        let ticket = |id: iroh::EndpointId, port: u16| {
            crate::session::canonical_ticket(
                &serde_json::json!({
                    "version": 1,
                    "endpoint": iroh::EndpointAddr::new(id).with_ip_addr(([192, 0, 2, 4], port).into()),
                })
                .to_string(),
            )
            .unwrap()
        };
        let (phone_endpoint, other) = (
            iroh::SecretKey::generate().public(),
            iroh::SecretKey::generate().public(),
        );
        let phone = PairedDevice {
            name: "Phone".into(),
            node: STANDARD.encode([8; 32]),
            ticket: ticket(phone_endpoint, 7000),
        };
        device.vault.save_peer(phone.node.clone())?;
        device.vault.save_pairing(phone.clone())?;
        let report =
            |ticket: String| std::collections::BTreeMap::from([(phone.node.clone(), ticket)]);
        assert!(
            !device
                .vault
                .save_peer_addresses(report(ticket(other, 7001)))?
        );
        assert!(
            !device
                .vault
                .save_peer_addresses(report(phone.ticket.clone()))?
        );
        assert!(
            !device
                .vault
                .save_peer_addresses(std::collections::BTreeMap::from([(
                    STANDARD.encode([9; 32]),
                    ticket(phone_endpoint, 7002)
                )]))?,
            "An address for a device that is not saved is ignored"
        );
        assert_eq!(device.vault.peers()[0].ticket, phone.ticket);
        assert!(
            device
                .vault
                .save_peer_addresses(report(ticket(phone_endpoint, 7003)))?
        );
        assert_eq!(device.vault.peers()[0].ticket, ticket(phone_endpoint, 7003));
        assert_eq!(
            device.vault.paired().map(|p| p.ticket.clone()),
            Some(ticket(phone_endpoint, 7003))
        );
        Ok(())
    }
}
