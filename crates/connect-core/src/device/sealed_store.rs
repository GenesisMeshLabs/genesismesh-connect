//! A headless server's credential store: records encrypted under one master
//! key that systemd hands only to the Connect service, sealed to the machine's
//! TPM where it has one (`systemd-creds`, `LoadCredentialEncrypted=`). The key
//! never reaches disk unencrypted; records are never stored in the clear.
//!
//! Used only when the service is started that way: `CONNECT_SEALED_STORE`
//! names the record directory and `$CREDENTIALS_DIRECTORY` holds
//! `connect-master-key`. There is no fallback to plaintext.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, ensure};
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const CREDENTIAL: &str = "connect-master-key";
const INFO: &[u8] = b"genesismesh-connect/sealed-store/v1";
const NONCE: usize = 12;
const MAX_RECORD: u64 = 256 * 1024;

pub(in crate::device) struct Store {
    directory: PathBuf,
    cipher: Aes256Gcm,
}

impl Store {
    /// The sealed store when the service was started with one, otherwise
    /// `None` and the desktop credential store is used.
    pub fn configured() -> Result<Option<Self>> {
        let Some(directory) = std::env::var_os("CONNECT_SEALED_STORE") else {
            return Ok(None);
        };
        let credentials = std::env::var_os("CREDENTIALS_DIRECTORY")
            .context("The sealed store needs the service's master key credential")?;
        let key = Zeroizing::new(
            std::fs::read(Path::new(&credentials).join(CREDENTIAL))
                .context("The service's master key credential is unavailable")?,
        );
        Ok(Some(Self::open(PathBuf::from(directory), &key)?))
    }

    pub fn open(directory: PathBuf, key: &[u8]) -> Result<Self> {
        ensure!(
            key.len() == 32,
            "The master key credential must be 32 bytes"
        );
        ensure!(
            directory.is_absolute(),
            "The sealed store directory must be absolute"
        );
        std::fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut derived = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(None, key)
            .expand(INFO, derived.as_mut())
            .map_err(|_| anyhow::anyhow!("Master key derivation failed"))?;
        let cipher = Aes256Gcm::new_from_slice(derived.as_ref())
            .map_err(|_| anyhow::anyhow!("Master key derivation failed"))?;
        Ok(Self { directory, cipher })
    }

    /// Record names are the stores' UUID accounts, so no name is a path.
    fn path(&self, id: &str) -> Result<PathBuf> {
        ensure!(
            uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id),
            "Invalid sealed record name"
        );
        Ok(self.directory.join(format!("{id}.sealed")))
    }
}

impl super::vault::credential::Store for Store {
    fn prefix(&self) -> &'static [u8] {
        b"GenesisMesh.Connect.SealedStore.v1\0"
    }
    fn get(&self, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let path = self.path(id)?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("The sealed record could not be read"),
        };
        ensure!(
            bytes.len() > NONCE && bytes.len() as u64 <= MAX_RECORD,
            "The sealed record is damaged"
        );
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&bytes[..NONCE]),
                Payload {
                    msg: &bytes[NONCE..],
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "The sealed record does not open with this machine's master key, or was changed"
                )
            })?;
        Ok(Some(Zeroizing::new(plaintext)))
    }
    fn set(&self, id: &str, secret: &[u8]) -> Result<()> {
        let path = self.path(id)?;
        let mut nonce = [0; NONCE];
        getrandom::fill(&mut nonce)?;
        let sealed = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("The sealed record could not be encrypted"))?;
        let mut pending = tempfile::NamedTempFile::new_in(&self.directory)?;
        pending.write_all(&nonce)?;
        pending.write_all(&sealed)?;
        pending.as_file().sync_all()?;
        pending.persist(path)?;
        Ok(())
    }
    fn delete(&self, id: &str) -> Result<()> {
        match std::fs::remove_file(self.path(id)?) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(error).context("Could not remove the sealed record")
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::vault::credential::Store as _;
    use super::*;

    #[test]
    fn records_open_only_with_their_key_and_name() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = Store::open(directory.path().join("sealed"), &[7; 32])?;
        let id = uuid::Uuid::new_v4().to_string();
        assert!(store.get(&id)?.is_none());
        store.set(&id, b"node seed")?;
        assert_eq!(
            store.get(&id)?.as_deref().map(Vec::as_slice),
            Some(&b"node seed"[..])
        );
        let on_disk = std::fs::read(store.path(&id)?)?;
        assert!(!on_disk.windows(9).any(|w| w == b"node seed"));
        // Another machine's key, a renamed record or a changed byte all refuse.
        let other = Store::open(directory.path().join("sealed"), &[8; 32])?;
        assert!(other.get(&id).is_err());
        let renamed = uuid::Uuid::new_v4().to_string();
        std::fs::copy(store.path(&id)?, store.path(&renamed)?)?;
        assert!(store.get(&renamed).is_err());
        let mut changed = on_disk.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        std::fs::write(store.path(&id)?, changed)?;
        assert!(store.get(&id).is_err());
        store.delete(&id)?;
        store.delete(&id)?;
        assert!(store.get(&id)?.is_none());
        for name in ["../escape", "a/b", "", "not-a-uuid"] {
            assert!(store.set(name, b"x").is_err(), "{name}");
        }
        assert!(Store::open(directory.path().join("short"), &[1; 16]).is_err());
        Ok(())
    }
}
