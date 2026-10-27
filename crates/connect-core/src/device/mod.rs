//! Durable desktop identity and explicit lifecycle; private keys never cross UI IPC.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) mod owner_store;
mod vault;

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

use crate::session::sharing::{Share, ShareConfig};
use crate::{
    Connectivity,
    authority::{EnrolledDevice, LocalAuthority, TrustPin, TrustStore},
    session::{
        SessionEndpoint, SessionReport,
        bridge::{AuthorityBridge, BridgeAuthority, BridgeRoute, NetworkSettings},
    },
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};
use vault::Vault;

#[derive(Clone, Deserialize, Serialize)]
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
    pub sharing_config: Option<ShareConfig>,
    pub paired_device: Option<PairedDevice>,
    pub devices: Vec<PairedDevice>,
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
    sharing: Option<Arc<Share>>,
    pairing: Option<Arc<crate::session::pairing::PairHost>>,
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
            sharing_config: self.sharing.as_ref().map(|share| share.config().clone()),
            paired_device: self.vault.paired().cloned(),
            devices: self.vault.peers().to_vec(),
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
        let config = self.sharing.as_ref().map(|share| share.config().clone());
        if config.is_some() {
            self.configure_sharing(config)?;
        }
        Ok(())
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
    pub fn configure_sharing(&mut self, config: Option<ShareConfig>) -> Result<()> {
        ensure!(
            self.endpoint.is_none(),
            "Stop the session before changing sharing"
        );
        if let Some(config) = config {
            ensure!(
                self.vault.edge().is_some(),
                "Enroll this profile with a sharing invitation before sharing"
            );
            self.sharing = None;
            self.sharing = Some(Arc::new(Share::open(
                config,
                match &self.bridge_client {
                    Some(client) => crate::authority::AuthorityAccess::Remote(client.clone()),
                    None => self
                        .authority
                        .as_ref()
                        .context("Missing local authority")?
                        .clone()
                        .into(),
                },
                self.vault.pin().clone(),
                &self.state_directory.join("sharing"),
            )?));
        } else {
            self.sharing = None;
        }
        Ok(())
    }
    pub fn save_managed_share(&mut self, config: Option<ShareConfig>) -> Result<()> {
        ensure!(self.vault.consumer_mode(), "Use guided setup first");
        self.configure_sharing(config.clone())?;
        self.vault.save_share(config)
    }
    pub fn restore_managed_share(&mut self) -> Result<()> {
        if self.vault.consumer_mode()
            && self.sharing.is_none()
            && let Some(config) = self.vault.saved_share().cloned()
        {
            self.configure_sharing(Some(config))?;
        }
        Ok(())
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
        let Ok(settings) = client.settings(identity, trust).await else {
            return Ok(());
        };
        if self.accept_settings(settings).await? {
            let running = self.endpoint.is_some();
            self.stop().await;
            self.reopen_sharing()?;
            if running {
                let outcome = self.refresh_inner(true).await;
                self.record_outcome(&outcome);
                outcome?;
            }
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
            self.vault.peers().iter().any(|p| p.node == node),
            "Choose a saved device"
        );
        self.start(node).await
    }
    pub async fn forget_device(&mut self, node: &str) -> Result<()> {
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
        let mut allowed: Vec<_> = self.vault.peers().iter().map(|p| p.node.clone()).collect();
        if !allowed.iter().any(|n| n == selected) {
            allowed.push(selected.to_owned());
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.set_peers(selected.to_owned(), allowed.clone())?;
        }
        if let Some(bridge) = &self.bridge_host {
            bridge.set_peers(selected.to_owned(), allowed)?;
        }
        Ok(())
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
        self.vault.save_pairing(peer)
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
}
