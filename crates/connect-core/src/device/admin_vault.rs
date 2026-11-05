//! Separate administrative credential. No private key export, cached signing
//! key, remote enrollment or generic signing API. Recovery does not include it.
use crate::{
    authority::TrustPin,
    owner_control::{
        CommandIntent, ControlScope, EnrollmentIntent, EnrollmentRequest, OwnerCommand,
    },
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use genesis_mesh_sdk::parse_strict_json;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PURPOSE: &str = "org.genesismesh.connect.administrative-key.v1";
const MAX_BYTES: u64 = 16 * 1024;
pub(super) const FILE: &str = "administrative-key.json";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeBinding {
    pub scope: ControlScope,
    pub controller_node: String,
}
impl AdministrativeBinding {
    fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        // Reuse the exact canonical key checks from the control protocol.
        super::super::owner_control::public_key(&self.controller_node)
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    purpose: String,
    id: String,
    binding: AdministrativeBinding,
    public_key: String,
    protected: Vec<u8>,
}
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Secret {
    #[zeroize(skip)]
    version: u8,
    purpose: String,
    id: String,
    #[zeroize(skip)]
    binding: AdministrativeBinding,
    seed: [u8; 32],
}
trait Backend {
    fn seal(&self, id: &str, bytes: &[u8]) -> Result<Vec<u8>>;
    fn open(&self, id: &str, protected: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn delete(&self, id: &str, protected: &[u8]) -> Result<()>;
}
struct Native;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
impl Backend for Native {
    fn seal(&self, id: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        use super::vault::credential::Store;
        let store = super::vault::platform_store()?;
        ensure!(
            store.get(id)?.is_none(),
            "Administrative credential already exists"
        );
        store.set(id, bytes)?;
        Ok([store.prefix(), id.as_bytes()].concat())
    }
    fn open(&self, id: &str, protected: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        use super::vault::credential::Store;
        let store = super::vault::platform_store()?;
        ensure!(
            protected == [store.prefix(), id.as_bytes()].concat(),
            "Administrative storage provider or account changed"
        );
        store.get(id)
    }
    fn delete(&self, id: &str, protected: &[u8]) -> Result<()> {
        use super::vault::credential::Store;
        let store = super::vault::platform_store()?;
        ensure!(
            protected == [store.prefix(), id.as_bytes()].concat(),
            "Administrative storage provider or account changed"
        );
        store.delete(id)
    }
}
#[cfg(windows)]
impl Backend for Native {
    fn seal(&self, _id: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(super::vault::crypt_admin(bytes, true)?.to_vec())
    }
    fn open(&self, _id: &str, protected: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(Some(super::vault::crypt_admin(protected, false)?))
    }
    fn delete(&self, _id: &str, _protected: &[u8]) -> Result<()> {
        Ok(())
    }
}
#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
)))]
impl Backend for Native {
    fn seal(&self, _id: &str, _bytes: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("Protected administrative storage is unavailable on this platform")
    }
    fn open(&self, _id: &str, _protected: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        anyhow::bail!("Protected administrative storage is unavailable on this platform")
    }
    fn delete(&self, _id: &str, _protected: &[u8]) -> Result<()> {
        anyhow::bail!("Protected administrative storage is unavailable on this platform")
    }
}

/// Public metadata only. Every signature opens the native credential again.
/// Opening this handle does not establish administrator scope at the host.
pub struct AdministrativeKey {
    path: PathBuf,
    envelope: Envelope,
}
impl AdministrativeKey {
    pub fn create(path: &Path, binding: AdministrativeBinding) -> Result<Self> {
        Self::create_with(path, binding, &Native)
    }
    pub fn open(path: &Path, binding: &AdministrativeBinding) -> Result<Self> {
        Self::open_with(path, binding, &Native)
    }
    pub fn public_key(&self) -> &str {
        &self.envelope.public_key
    }
    pub fn binding(&self) -> &AdministrativeBinding {
        &self.envelope.binding
    }
    pub fn sign_enrollment(&self, intent: EnrollmentIntent) -> Result<EnrollmentRequest> {
        self.enrollment_with(intent, &Native)
    }
    pub fn sign_command(&self, intent: CommandIntent) -> Result<OwnerCommand> {
        self.command_with(intent, &Native)
    }

    fn create_with(
        path: &Path,
        binding: AdministrativeBinding,
        backend: &impl Backend,
    ) -> Result<Self> {
        binding.validate()?;
        let (_lock, initialized) = lock(path)?;
        ensure!(
            !path.exists() && !initialized,
            "Administrative key already exists or needs recovery; it has not been replaced"
        );
        let id = uuid::Uuid::new_v4().to_string();
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut())?;
        let public_key = STANDARD.encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        ensure!(
            public_key != binding.controller_node
                && public_key != binding.scope.host_node
                && public_key != binding.scope.pin.root_public_key,
            "Administrative key must be separate"
        );
        let secret = Secret {
            version: 1,
            purpose: PURPOSE.into(),
            id: id.clone(),
            binding: binding.clone(),
            seed: *seed,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&secret)?);
        let protected = backend.seal(&id, &plaintext)?;
        let envelope = Envelope {
            version: 1,
            purpose: PURPOSE.into(),
            id,
            binding,
            public_key,
            protected,
        };
        let written = (|| -> Result<()> {
            let bytes = serde_json::to_vec(&envelope)?;
            ensure!(
                bytes.len() as u64 <= MAX_BYTES,
                "Administrative key reference is too large"
            );
            let mut pending = tempfile::NamedTempFile::new_in(
                path.parent()
                    .context("Missing administrative key directory")?,
            )?;
            pending.write_all(&bytes)?;
            pending.as_file().sync_all()?;
            pending.persist_noclobber(path)?;
            #[cfg(unix)]
            File::open(
                path.parent()
                    .context("Missing administrative key directory")?,
            )?
            .sync_all()?;
            Ok(())
        })();
        if written.is_err() && !path.exists() {
            let _ = backend.delete(&envelope.id, &envelope.protected);
        }
        written?;
        Ok(Self {
            path: path.into(),
            envelope,
        })
    }
    fn open_with(
        path: &Path,
        binding: &AdministrativeBinding,
        backend: &impl Backend,
    ) -> Result<Self> {
        binding.validate()?;
        let (_lock, _) = lock(path)?;
        let envelope = read(path)?;
        ensure!(
            &envelope.binding == binding,
            "Administrative key belongs to a different network, host or device"
        );
        let _secret=secret(&envelope,backend)?.context("Saved administrative key is missing. Existing identity and permissions were preserved; it has not been replaced.")?;
        Ok(Self {
            path: path.into(),
            envelope,
        })
    }
    fn current(&self, backend: &impl Backend) -> Result<Secret> {
        let current = read(&self.path)?;
        ensure!(
            current.id == self.envelope.id
                && current.binding == self.envelope.binding
                && current.public_key == self.envelope.public_key
                && current.protected == self.envelope.protected,
            "Administrative key reference changed; reopen and review this device"
        );
        secret(&current,backend)?.context("Saved administrative key is missing. Existing identity and permissions were preserved; it has not been replaced.")
    }
    fn enrollment_with(
        &self,
        intent: EnrollmentIntent,
        backend: &impl Backend,
    ) -> Result<EnrollmentRequest> {
        let (_lock, _) = lock(&self.path)?;
        ensure!(
            intent.scope == self.envelope.binding.scope
                && intent.controller_node == self.envelope.binding.controller_node
                && intent.administrative_key == self.envelope.public_key,
            "Enrollment does not match this device's administrative key"
        );
        let secret = self.current(backend)?;
        EnrollmentRequest::sign(intent, &SigningKey::from_bytes(&secret.seed))
    }
    fn command_with(&self, intent: CommandIntent, backend: &impl Backend) -> Result<OwnerCommand> {
        let (_lock, _) = lock(&self.path)?;
        ensure!(
            intent.scope == self.envelope.binding.scope
                && intent.controller_node == self.envelope.binding.controller_node,
            "Owner request does not match this device's administrative key"
        );
        let secret = self.current(backend)?;
        OwnerCommand::sign(intent, &SigningKey::from_bytes(&secret.seed))
    }
    /// Leave-network cleanup only. Host changes may leave an older host binding,
    /// but a foreign root/member credential is never deleted through this path.
    pub(super) fn erase_for_device(path: &Path, pin: &TrustPin, node: &str) -> Result<()> {
        Self::erase_with(path, pin, node, &Native)
    }
    fn erase_with(path: &Path, pin: &TrustPin, node: &str, backend: &impl Backend) -> Result<()> {
        let (_lock, _) = lock(path)?;
        if !path.try_exists()? {
            return Ok(());
        }
        let envelope = read(path)?;
        ensure!(
            &envelope.binding.scope.pin == pin && envelope.binding.controller_node == node,
            "Foreign administrative key was preserved"
        );
        if secret(&envelope, backend)?.is_some() {
            backend.delete(&envelope.id, &envelope.protected)?;
        }
        std::fs::remove_file(path)?;
        #[cfg(unix)]
        File::open(
            path.parent()
                .context("Missing administrative key directory")?,
        )?
        .sync_all()?;
        Ok(())
    }
}
fn read(path: &Path) -> Result<Envelope> {
    check_path(path)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "Administrative key reference is too large"
    );
    let value = parse_strict_json(std::str::from_utf8(&bytes)?).map_err(|_| {
        anyhow::anyhow!("Administrative key reference needs attention; it was preserved")
    })?;
    let envelope: Envelope = serde_json::from_value(value).map_err(|_| {
        anyhow::anyhow!("Administrative key reference needs attention; it was preserved")
    })?;
    ensure!(
        envelope.version == 1
            && envelope.purpose == PURPOSE
            && uuid::Uuid::parse_str(&envelope.id)?.to_string() == envelope.id
            && !envelope.protected.is_empty(),
        "Invalid administrative key reference"
    );
    envelope.binding.validate()?;
    Ok(envelope)
}
fn secret(envelope: &Envelope, backend: &impl Backend) -> Result<Option<Secret>> {
    let Some(bytes) = backend.open(&envelope.id, &envelope.protected)? else {
        return Ok(None);
    };
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "Protected administrative key is too large"
    );
    let record: Secret = serde_json::from_slice(&bytes).map_err(|_| {
        anyhow::anyhow!("Protected administrative key needs attention; it was preserved")
    })?;
    ensure!(
        record.version == 1
            && record.purpose == PURPOSE
            && record.id == envelope.id
            && record.binding == envelope.binding
            && STANDARD.encode(
                SigningKey::from_bytes(&record.seed)
                    .verifying_key()
                    .to_bytes()
            ) == envelope.public_key,
        "Administrative key was substituted; existing credentials were preserved"
    );
    Ok(Some(record))
}
fn check_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.parent().is_some_and(Path::is_dir),
        "Use an absolute existing administrative key directory"
    );
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                ensure!(
                    !meta.file_type().is_symlink(),
                    "Administrative key paths must not contain links"
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    ensure!(
                        meta.file_attributes() & 0x400 == 0,
                        "Administrative key paths must not contain reparse points"
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && ancestor == path => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn lock(path: &Path) -> Result<(File, bool)> {
    check_path(path)?;
    let lock_path = path.with_extension("administrative-key-lock");
    check_path(&lock_path)?;
    let initialized = lock_path.exists();
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(lock_path)?;
    fs2::FileExt::try_lock_exclusive(&file)
        .context("Another administrative key operation is running")?;
    Ok((file, initialized))
}

#[cfg(test)]
#[path = "admin_vault_tests.rs"]
mod tests;
