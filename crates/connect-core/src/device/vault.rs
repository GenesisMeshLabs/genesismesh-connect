use crate::authority::TrustPin;
use crate::session::bridge::BridgeRoute;
#[cfg(windows)]
use anyhow::Context;
use anyhow::{Result, ensure};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(windows)]
use std::io::Write;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_FILE: u64 = 128 * 1024;
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "apple_store.rs"]
mod apple;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    test
))]
#[path = "credential_vault.rs"]
pub(super) mod credential;
#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "native_store.rs"]
mod native;

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    #[zeroize(skip)]
    version: u8,
    #[serde(default)]
    #[zeroize(skip)]
    storage_id: String,
    seed: [u8; 32],
    #[serde(default)]
    executor_seed: Option<[u8; 32]>,
    #[serde(default)]
    #[zeroize(skip)]
    edge: Option<Value>,
    #[zeroize(skip)]
    authority: Option<String>,
    #[zeroize(skip)]
    pin: TrustPin,
    #[zeroize(skip)]
    certificate: Option<Value>,
    #[zeroize(skip)]
    peer: Option<String>,
    #[zeroize(skip)]
    enrollment_pending: bool,
    #[serde(default)]
    #[zeroize(skip)]
    bridge_route: Option<BridgeRoute>,
    #[serde(default)]
    transport_seed: Option<[u8; 32]>,
    #[serde(default)]
    bridge_seed: Option<[u8; 32]>,
    #[serde(default)]
    #[zeroize(skip)]
    paired: Option<super::PairedDevice>,
    #[serde(default)]
    #[zeroize(skip)]
    peers: Vec<super::PairedDevice>,
    /// The network's other devices, as the network computer listed them.
    /// Never a device in `peers`; together at most 32.
    #[serde(default)]
    #[zeroize(skip)]
    members: Vec<super::PairedDevice>,
    #[serde(default)]
    auto_connect: bool,
    #[serde(default)]
    consumer_mode: bool,
    #[serde(default)]
    #[zeroize(skip)]
    saved_share: Option<crate::session::sharing::ShareConfig>,
    /// The network computer's choice; on that computer, the owner's own.
    #[serde(default)]
    #[zeroize(skip)]
    network_connectivity: crate::Connectivity,
    /// This device's stricter choice, if any.
    #[serde(default)]
    #[zeroize(skip)]
    own_connectivity: Option<crate::Connectivity>,
    /// Ports the session and bridge endpoints listened on, reused so saved
    /// addresses stay valid when the app restarts.
    #[serde(default)]
    #[zeroize(skip)]
    session_port: Option<u16>,
    #[serde(default)]
    #[zeroize(skip)]
    bridge_port: Option<u16>,
}

pub(super) struct Vault {
    path: PathBuf,
    record: Record,
}

impl Vault {
    pub fn create(path: &Path, authority: Option<String>, pin: TrustPin) -> Result<Self> {
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut())?;
        let record = Record {
            version: 1,
            storage_id: uuid::Uuid::new_v4().to_string(),
            seed: *seed,
            executor_seed: None,
            edge: None,
            authority,
            pin,
            certificate: None,
            peer: None,
            enrollment_pending: false,
            bridge_route: None,
            transport_seed: None,
            bridge_seed: None,
            paired: None,
            peers: Vec::new(),
            members: Vec::new(),
            auto_connect: false,
            consumer_mode: false,
            saved_share: None,
            network_connectivity: crate::Connectivity::default(),
            own_connectivity: None,
            session_port: None,
            bridge_port: None,
        };
        persist(path, &record, true)?;
        Ok(Self {
            path: path.to_owned(),
            record,
        })
    }
    /// Remove a vault this process just created (a failed restore), including
    /// its secret in a native credential store. Windows keeps it in the file.
    pub fn discard(self) -> Result<()> {
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "linux",
            target_os = "android"
        ))]
        {
            let mut reference = Vec::new();
            File::open(&self.path)?
                .take(256)
                .read_to_end(&mut reference)?;
            credential::forget(&reference, &platform_store()?)?;
        }
        std::fs::remove_file(&self.path)?;
        Ok(())
    }
    /// The whole private record, for an encrypted recovery file only.
    pub fn export(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(serde_json::to_vec(&self.record)?))
    }
    /// Recreate a network computer's identity from a recovery file on this
    /// computer: the same keys, protected by this computer's store, pointed at
    /// the restored authority. A shared folder must be chosen again here.
    pub fn restore(
        path: &Path,
        exported: &[u8],
        authority: String,
        pin: &TrustPin,
    ) -> Result<Self> {
        let mut record: Record = serde_json::from_slice(exported)
            .map_err(|_| anyhow::anyhow!("The recovery file's device identity is damaged"))?;
        ensure!(record.version == 1, "Unsupported device identity version");
        ensure!(
            &record.pin == pin,
            "The recovery file's device belongs to another network"
        );
        migrate_peers(&mut record)?;
        record.storage_id = uuid::Uuid::new_v4().to_string();
        record.authority = Some(authority);
        record.saved_share = None;
        persist(path, &record, true)?;
        Ok(Self {
            path: path.to_owned(),
            record,
        })
    }
    pub fn open(path: &Path) -> Result<Self> {
        let mut sealed = Vec::new();
        File::open(path)?
            .take(MAX_FILE + 1)
            .read_to_end(&mut sealed)?;
        ensure!(sealed.len() as u64 <= MAX_FILE, "Device vault too large");
        let plaintext = unprotect(&sealed)?;
        let mut record: Record = serde_json::from_slice(&plaintext)
            .map_err(|_| anyhow::anyhow!("Device vault is damaged"))?;
        ensure!(record.version == 1, "Unsupported device vault version");
        migrate_peers(&mut record)?;
        Ok(Self {
            path: path.to_owned(),
            record,
        })
    }
    pub fn key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.record.seed)
    }
    pub fn edge(&self) -> Option<&Value> {
        self.record.edge.as_ref()
    }
    pub fn executor(&mut self) -> Result<SigningKey> {
        if self.record.executor_seed.is_none() {
            let mut seed = Zeroizing::new([0; 32]);
            getrandom::fill(seed.as_mut())?;
            self.update(|record| record.executor_seed = Some(*seed))?;
        }
        Ok(SigningKey::from_bytes(
            self.record.executor_seed.as_ref().unwrap(),
        ))
    }
    pub fn save_host(&mut self, certificate: Value, edge: Value) -> Result<()> {
        self.update(|record| {
            record.certificate = Some(certificate);
            record.edge = Some(edge);
            record.enrollment_pending = false;
        })
    }
    pub fn authority(&self) -> Option<&str> {
        self.record.authority.as_deref()
    }
    pub fn save_authority(&mut self, authority: String) -> Result<()> {
        self.update(|record| record.authority = Some(authority))
    }
    pub fn pin(&self) -> &TrustPin {
        &self.record.pin
    }
    pub fn certificate(&self) -> Option<&Value> {
        self.record.certificate.as_ref()
    }
    pub fn peer(&self) -> Option<&str> {
        self.record.peer.as_deref()
    }
    pub fn pending(&self) -> bool {
        self.record.enrollment_pending
    }
    pub fn bridge_route(&self) -> Option<&BridgeRoute> {
        self.record.bridge_route.as_ref()
    }
    pub fn save_route(&mut self, route: Option<BridgeRoute>) -> Result<()> {
        self.update(|record| record.bridge_route = route)
    }
    pub fn save_bridge_renewal(&mut self, certificate: Value, route: BridgeRoute) -> Result<()> {
        self.update(|record| {
            record.certificate = Some(certificate);
            record.bridge_route = Some(route);
        })
    }
    pub fn mark_enrollment(&mut self) -> Result<()> {
        self.update(|record| record.enrollment_pending = true)
    }
    pub fn save_certificate(&mut self, certificate: Value) -> Result<()> {
        self.update(|record| {
            record.certificate = Some(certificate);
            record.enrollment_pending = false;
        })
    }
    pub fn save_peer(&mut self, peer: String) -> Result<()> {
        self.update(|record| record.peer = Some(peer))
    }
    pub fn transport(&mut self, bridge: bool) -> Result<iroh::SecretKey> {
        let seed = if bridge {
            self.record.bridge_seed
        } else {
            self.record.transport_seed
        };
        let seed = match seed {
            Some(seed) => Zeroizing::new(seed),
            None => {
                let mut seed = Zeroizing::new([0; 32]);
                getrandom::fill(seed.as_mut())?;
                self.update(|record| {
                    if bridge {
                        record.bridge_seed = Some(*seed)
                    } else {
                        record.transport_seed = Some(*seed)
                    }
                })?;
                seed
            }
        };
        Ok(iroh::SecretKey::from(*seed))
    }
    /// The saved transport identity and its last port.
    pub fn saved_transport(&mut self, bridge: bool) -> Result<crate::connectivity::Transport> {
        Ok(crate::connectivity::Transport {
            key: self.transport(bridge)?,
            port: if bridge {
                self.record.bridge_port
            } else {
                self.record.session_port
            },
        })
    }
    pub fn save_transport_port(&mut self, bridge: bool, port: Option<u16>) -> Result<()> {
        let saved = if bridge {
            self.record.bridge_port
        } else {
            self.record.session_port
        };
        if port.is_none() || saved == port {
            return Ok(());
        }
        self.update(|record| {
            if bridge {
                record.bridge_port = port
            } else {
                record.session_port = port
            }
        })
    }
    /// The selected device: one paired with this device, or a member.
    pub fn paired(&self) -> Option<&super::PairedDevice> {
        self.record
            .peers
            .iter()
            .chain(&self.record.members)
            .find(|p| Some(p.node.as_str()) == self.peer())
    }
    pub fn peers(&self) -> &[super::PairedDevice] {
        &self.record.peers
    }
    pub fn members(&self) -> &[super::PairedDevice] {
        &self.record.members
    }
    /// Keep the network computer's latest list of the other devices: never
    /// this device or one it paired with itself, and at most 32 devices in
    /// all. A selected member that left the network falls back to the network
    /// computer. Returns whether anything changed.
    pub fn save_members(&mut self, members: Vec<super::PairedDevice>) -> Result<bool> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let own = STANDARD.encode(self.key().verifying_key().to_bytes());
        let mut kept: Vec<super::PairedDevice> = Vec::new();
        for member in members {
            validate_peer(&member)?;
            if member.node == own
                || self.record.peers.iter().any(|p| p.node == member.node)
                || kept.iter().any(|m| m.node == member.node)
            {
                continue;
            }
            if self.record.peers.len() + kept.len() >= 32 {
                break;
            }
            kept.push(member);
        }
        if kept == self.record.members {
            return Ok(false);
        }
        // Only a selected member that left the list changes the selection.
        let left = self.record.peer.as_ref().is_some_and(|peer| {
            self.record.members.iter().any(|m| &m.node == peer)
                && !kept.iter().any(|m| &m.node == peer)
                && !self.record.peers.iter().any(|p| &p.node == peer)
        });
        self.update(|record| {
            record.members = kept;
            if left {
                record.peer = record
                    .bridge_route
                    .as_ref()
                    .map(|route| route.host_node.clone())
                    .or_else(|| record.peers.first().map(|p| p.node.clone()));
            }
        })?;
        Ok(true)
    }
    pub fn forget_pairing(&mut self, node: &str) -> Result<()> {
        ensure!(
            self.record.peers.iter().any(|p| p.node == node),
            "Choose a saved device"
        );
        self.update(|record| {
            record.peers.retain(|p| p.node != node);
            if record.peer.as_deref() == Some(node) {
                record.peer = record.peers.first().map(|p| p.node.clone());
            }
            record.paired = record
                .peers
                .iter()
                .find(|p| Some(&p.node) == record.peer.as_ref())
                .cloned();
            record.auto_connect = !record.peers.is_empty();
        })
    }
    /// Fresh session addresses devices reported for themselves, kept only for
    /// the endpoint each one paired with. Returns whether anything changed.
    pub fn save_peer_addresses(
        &mut self,
        reported: std::collections::BTreeMap<String, String>,
    ) -> Result<bool> {
        let fresh: Vec<(String, String)> = reported
            .into_iter()
            .filter(|(node, ticket)| {
                self.record.peers.iter().any(|p| {
                    &p.node == node
                        && &p.ticket != ticket
                        && crate::session::ticket_endpoint(&p.ticket).ok()
                            == crate::session::ticket_endpoint(ticket).ok()
                })
            })
            .collect();
        if fresh.is_empty() {
            return Ok(false);
        }
        self.update(|record| {
            for (node, ticket) in fresh {
                for peer in record.peers.iter_mut().filter(|p| p.node == node) {
                    peer.ticket = ticket.clone();
                }
                if let Some(paired) = record.paired.as_mut().filter(|p| p.node == node) {
                    paired.ticket = ticket;
                }
            }
        })?;
        Ok(true)
    }
    pub fn saved_share(&self) -> Option<&crate::session::sharing::ShareConfig> {
        self.record.saved_share.as_ref()
    }
    pub fn save_share(
        &mut self,
        config: Option<crate::session::sharing::ShareConfig>,
    ) -> Result<()> {
        self.update(|record| record.saved_share = config)
    }
    pub fn auto_connect(&self) -> bool {
        self.record.auto_connect
    }
    pub fn network_connectivity(&self) -> crate::Connectivity {
        self.record.network_connectivity
    }
    pub fn own_connectivity(&self) -> Option<crate::Connectivity> {
        self.record.own_connectivity
    }
    pub fn save_network_connectivity(&mut self, connectivity: crate::Connectivity) -> Result<()> {
        self.update(|record| record.network_connectivity = connectivity)
    }
    pub fn save_own_connectivity(
        &mut self,
        connectivity: Option<crate::Connectivity>,
    ) -> Result<()> {
        self.update(|record| record.own_connectivity = connectivity)
    }
    /// Apply the network computer's authenticated answer in one write: fresh
    /// addresses for the saved authority route and for the computer's saved
    /// session, and its connection setting. If either address names another
    /// endpoint, the whole answer is refused and nothing changes. Returns
    /// whether the authority route changed.
    pub fn apply_network_answer(
        &mut self,
        authority_ticket: String,
        session_ticket: Option<String>,
        connectivity: crate::Connectivity,
    ) -> Result<bool> {
        let route = self.record.bridge_route.clone();
        if let Some(route) = &route {
            ensure!(
                crate::session::bridge::endpoint_of(&authority_ticket)?
                    == crate::session::bridge::endpoint_of(&route.ticket)?,
                "The authority address names another endpoint"
            );
        }
        let host = route.as_ref().map(|r| r.host_node.clone());
        let saved = host
            .as_ref()
            .and_then(|host| self.record.peers.iter().find(|p| &p.node == host))
            .map(|p| p.ticket.clone());
        if let (Some(ticket), Some(saved)) = (&session_ticket, &saved) {
            ensure!(
                crate::session::ticket_endpoint(ticket)? == crate::session::ticket_endpoint(saved)?,
                "The device address names another endpoint"
            );
        }
        let route_changed = route.as_ref().is_some_and(|r| r.ticket != authority_ticket);
        let session = session_ticket.filter(|ticket| saved.as_ref().is_some_and(|s| s != ticket));
        if !route_changed && session.is_none() && self.record.network_connectivity == connectivity {
            return Ok(false);
        }
        self.update(|record| {
            if route_changed && let Some(route) = record.bridge_route.as_mut() {
                route.ticket = authority_ticket;
            }
            if let (Some(ticket), Some(host)) = (&session, &host) {
                for peer in record.peers.iter_mut().filter(|p| &p.node == host) {
                    peer.ticket = ticket.clone();
                }
                if let Some(paired) = record.paired.as_mut().filter(|p| &p.node == host) {
                    paired.ticket = ticket.clone();
                }
            }
            record.network_connectivity = connectivity;
        })?;
        Ok(route_changed)
    }
    pub fn consumer_mode(&self) -> bool {
        self.record.consumer_mode
    }
    pub fn enable_consumer(&mut self) -> Result<()> {
        self.update(|record| record.consumer_mode = true)
    }
    pub fn save_pairing(&mut self, peer: super::PairedDevice) -> Result<()> {
        validate_peer(&peer)?;
        ensure!(
            self.record.peers.len() < 32 || self.record.peers.iter().any(|p| p.node == peer.node),
            "This network computer supports up to 32 saved devices"
        );
        self.update(|record| {
            record.peer = Some(peer.node.clone());
            record.peers.retain(|p| p.node != peer.node);
            record.members.retain(|m| m.node != peer.node);
            record.peers.push(peer.clone());
            // Paired devices come first within the 32 a session allows.
            record
                .members
                .truncate(32usize.saturating_sub(record.peers.len()));
            record.paired = Some(peer);
            record.auto_connect = true;
        })
    }
    fn update(&mut self, edit: impl FnOnce(&mut Record)) -> Result<()> {
        let mut next = self.record.clone();
        edit(&mut next);
        ensure!(
            serde_json::to_vec(&next)?.len() as u64 <= MAX_FILE - 1024,
            "Saved device information exceeds this profile's storage limit"
        );
        persist(&self.path, &next, false)?;
        self.record = next;
        Ok(())
    }
}

pub(crate) fn validate_peer(peer: &super::PairedDevice) -> Result<()> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    ensure!(
        !peer.name.trim().is_empty()
            && peer.name.chars().count() <= 64
            && !peer.name.chars().any(char::is_control),
        "Choose a device name of up to 64 characters"
    );
    ensure!(
        STANDARD
            .decode(&peer.node)
            .is_ok_and(|k| k.len() == 32 && STANDARD.encode(k) == peer.node),
        "Invalid saved device identity"
    );
    super::super::session::validate_ticket(&peer.ticket)
}

fn migrate_peers(record: &mut Record) -> Result<()> {
    if record.peers.is_empty()
        && let Some(peer) = &record.paired
    {
        record.peers.push(peer.clone());
    }
    ensure!(
        record.peers.len() + record.members.len() <= 32,
        "Too many saved devices"
    );
    let mut nodes = std::collections::BTreeSet::new();
    for peer in record.peers.iter().chain(&record.members) {
        validate_peer(peer)?;
        ensure!(nodes.insert(&peer.node), "Duplicate saved device identity");
    }
    Ok(())
}

#[cfg(windows)]
fn persist(path: &Path, record: &Record, create: bool) -> Result<()> {
    let plaintext = Zeroizing::new(serde_json::to_vec(record)?);
    let sealed = protect(&plaintext)?;
    let mut pending =
        tempfile::NamedTempFile::new_in(path.parent().context("Missing vault directory")?)?;
    pending.write_all(&sealed)?;
    pending.as_file().sync_all()?;
    if create {
        pending.persist_noclobber(path)?;
    } else {
        pending.persist(path)?;
    }
    Ok(())
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
fn persist(path: &Path, record: &Record, create: bool) -> Result<()> {
    credential::persist(path, record, create, &platform_store()?)
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(super) fn platform_store() -> Result<apple::Store> {
    Ok(apple::Store)
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn platform_store() -> Result<native::Store> {
    native::Store::new()
}
#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
)))]
fn persist(_: &Path, _: &Record, _: bool) -> Result<()> {
    anyhow::bail!("This platform does not provide a supported secure identity store")
}
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
fn unprotect(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    credential::open(bytes, &platform_store()?)
}
#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
)))]
fn unprotect(_: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    anyhow::bail!("This platform does not provide a supported secure identity store")
}

#[cfg(windows)]
fn protect(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(crypt(bytes, true)?.to_vec())
}
#[cfg(windows)]
fn unprotect(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    crypt(bytes, false)
}

#[cfg(windows)]
fn crypt(bytes: &[u8], encrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    };
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_FILE,
        "Invalid protected device record"
    );
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let domain = b"GenesisMesh.Connect.Device.v1";
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: domain.len() as u32,
        pbData: domain.as_ptr().cast_mut(),
    };
    struct Output(CRYPT_INTEGER_BLOB);
    impl Drop for Output {
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                // SAFETY: DPAPI allocated cbData writable bytes; release with LocalFree.
                unsafe {
                    std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                    LocalFree(self.0.pbData.cast());
                }
            }
        }
    }
    let mut output = Output(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    });
    // SAFETY: all input slices remain alive for the call, optional pointers are
    // null, and the OS owns the output allocation. No machine-wide scope flag.
    let success = unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        }
    };
    ensure!(
        success != 0,
        "Windows could not protect/unlock the device record: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        !output.0.pbData.is_null() && output.0.cbData as u64 <= MAX_FILE,
        "Invalid DPAPI output"
    );
    // SAFETY: successful DPAPI output is readable until Output is dropped.
    Ok(Zeroizing::new(
        unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) }.to_vec(),
    ))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn windows_vault_roundtrip_no_plaintext_and_tamper_refusal() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("device.bin");
        let pin = TrustPin {
            root_public_key: "public-root".into(),
            network_name: "private-network-marker".into(),
        };
        let mut vault = Vault::create(&path, Some("http://127.0.0.1:9443".into()), pin)?;
        let public = vault.key().verifying_key();
        assert!(!vault.consumer_mode());
        assert!(!vault.auto_connect());
        vault.enable_consumer()?;
        let session_key = vault.transport(false)?.public();
        let bridge_key = vault.transport(true)?.public();
        assert_ne!(session_key, bridge_key);
        assert_ne!(session_key.as_bytes(), public.as_bytes());
        vault.mark_enrollment()?;
        let bytes = std::fs::read(&path)?;
        assert!(
            !bytes
                .windows(22)
                .any(|part| part == b"private-network-marker")
        );
        assert!(!bytes.windows(32).any(|part| part == vault.record.seed));
        drop(vault);
        let mut reopened = Vault::open(&path)?;
        assert_eq!(reopened.key().verifying_key(), public);
        assert_eq!(reopened.transport(false)?.public(), session_key);
        assert_eq!(reopened.transport(true)?.public(), bridge_key);
        assert!(reopened.consumer_mode());
        assert!(reopened.pending());
        drop(reopened);
        let mut damaged = bytes;
        let middle = damaged.len() / 2;
        damaged[middle] ^= 128;
        std::fs::write(&path, damaged)?;
        assert!(Vault::open(&path).is_err());
        Ok(())
    }
}

#[cfg(all(
    test,
    any(
        target_os = "linux",
        target_os = "macos",
        target_os = "android",
        target_os = "ios"
    )
))]
mod native_tests {
    use super::*;
    #[test]
    #[ignore = "Requires a native OS credential store; Linux runner uses an isolated Secret Service"]
    fn native_store_persists_private_identity_and_missing_credential_never_resets_it() -> Result<()>
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("device.bin");
        let pin = TrustPin {
            network_name: "disposable-native-store-test".into(),
            root_public_key: "test-public-root".into(),
        };
        let mut vault = Vault::create(&path, None, pin)?;
        let id = vault.record.storage_id.clone();
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Ok(store) = platform_store() {
                    let _ = credential::Store::delete(&store, &self.0);
                }
            }
        }
        let _cleanup = Cleanup(id.clone());
        let public = vault.key().verifying_key();
        let transport = vault.transport(false)?.public();
        vault.enable_consumer()?;
        let reference = std::fs::read(&path)?;
        assert!(!reference.windows(32).any(|s| s == vault.record.seed));
        drop(vault);
        let mut reopened = Vault::open(&path)?;
        assert_eq!(public, reopened.key().verifying_key());
        assert_eq!(transport, reopened.transport(false)?.public());
        assert!(reopened.consumer_mode());
        drop(reopened);
        credential::Store::delete(&platform_store()?, &id)?;
        assert!(Vault::open(&path).is_err());
        assert_eq!(std::fs::read(&path)?, reference);
        Ok(())
    }
}
