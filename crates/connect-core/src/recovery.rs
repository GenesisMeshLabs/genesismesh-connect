//! Encrypted recovery files: everything needed to bring a network computer
//! back on another computer, locked with a recovery key the owner keeps apart
//! from the file. Other devices are not in it; they keep their own identities.
//!
//! The recovery key is 160 random bits that Connect generates, never a
//! password a person chooses, so HKDF-SHA256 is enough to derive the
//! AES-256-GCM key. The header is authenticated along with the contents.
use crate::{
    authority::TrustPin,
    device::DeviceController,
    owner::{OwnerInfo, OwnerRuntime},
};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"GenesisMesh.Connect.Recovery\0";
const VERSION: u8 = 1;
const SALT: usize = 16;
const NONCE: usize = 12;
const KEY_BYTES: usize = 20;
const INFO: &[u8] = b"genesismesh-connect/recovery/v1";
/// Larger networks belong on a server with its own database backups.
const MAX_FILE: u64 = 512 * 1024 * 1024;

/// The network computer's own identity: its private device record and its
/// verified trust history.
pub struct DeviceIdentity {
    pub vault: Zeroizing<Vec<u8>>,
    pub trust: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Contents {
    version: u8,
    created_at: String,
    pin: TrustPin,
    owner: OwnerPart,
    device: DevicePart,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerPart {
    root: String,
    config: String,
    keys: BTreeMap<String, String>,
    files: BTreeMap<String, String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DevicePart {
    vault: String,
    trust: String,
}
impl Drop for Contents {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        for value in self.owner.keys.values_mut() {
            value.zeroize();
        }
        self.device.vault.zeroize();
    }
}

/// A fresh recovery key, shown to the owner once: 32 letters and digits in
/// groups of four.
pub fn new_key() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0; KEY_BYTES]);
    getrandom::fill(bytes.as_mut())?;
    let text = Zeroizing::new(data_encoding::BASE32_NOPAD.encode(bytes.as_ref()));
    Ok(Zeroizing::new(
        text.as_bytes()
            .chunks(4)
            .map(|group| std::str::from_utf8(group).expect("base32 is ASCII"))
            .collect::<Vec<_>>()
            .join("-"),
    ))
}

/// Accepts the key as written down: any case, with or without separators.
fn parse_key(text: &str) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let compact = Zeroizing::new(
        text.chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect::<String>(),
    );
    let decoded = Zeroizing::new(
        data_encoding::BASE32_NOPAD
            .decode(compact.as_bytes())
            .ok()
            .filter(|bytes| bytes.len() == KEY_BYTES)
            .context("Check the recovery key: it has 32 letters and digits")?,
    );
    let mut key = Zeroizing::new([0; KEY_BYTES]);
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn cipher(key: &[u8; KEY_BYTES], salt: &[u8]) -> Result<Aes256Gcm> {
    let mut derived = Zeroizing::new([0; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), key)
        .expand(INFO, derived.as_mut())
        .map_err(|_| anyhow::anyhow!("Recovery key derivation failed"))?;
    Aes256Gcm::new_from_slice(derived.as_ref())
        .map_err(|_| anyhow::anyhow!("Recovery key derivation failed"))
}

fn header(salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    [MAGIC, &[VERSION], salt, nonce].concat()
}

fn seal(contents: &Contents, key: &str) -> Result<Vec<u8>> {
    let key = parse_key(key)?;
    let mut salt = [0; SALT];
    let mut nonce = [0; NONCE];
    getrandom::fill(&mut salt)?;
    getrandom::fill(&mut nonce)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(contents)?);
    let header = header(&salt, &nonce);
    let sealed = cipher(&key, &salt)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| anyhow::anyhow!("The recovery file could not be encrypted"))?;
    Ok([header, sealed].concat())
}

fn open(bytes: &[u8], key: &str) -> Result<Contents> {
    let key = parse_key(key)?;
    let length = MAGIC.len() + 1 + SALT + NONCE;
    ensure!(
        bytes.len() > length && bytes.starts_with(MAGIC),
        "This is not a Genesis Mesh Connect recovery file"
    );
    ensure!(
        bytes[MAGIC.len()] == VERSION,
        "This recovery file needs a newer version of Connect"
    );
    let salt = &bytes[MAGIC.len() + 1..MAGIC.len() + 1 + SALT];
    let nonce = &bytes[MAGIC.len() + 1 + SALT..length];
    let plaintext = Zeroizing::new(
        cipher(&key, salt)?
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &bytes[length..],
                    aad: &bytes[..length],
                },
            )
            .map_err(|_| {
                anyhow::anyhow!("The recovery key does not open this file, or the file was changed")
            })?,
    );
    let contents: Contents = serde_json::from_slice(&plaintext)
        .map_err(|_| anyhow::anyhow!("The recovery file's contents are damaged"))?;
    ensure!(contents.version == VERSION, "Unsupported recovery contents");
    Ok(contents)
}

/// A relative path inside a recovery file; nothing may escape its directory.
fn inside(name: &str) -> Result<&Path> {
    let path = Path::new(name);
    // No drive letters or backslashes either, whichever platform wrote it.
    ensure!(
        !name.is_empty()
            && name.len() <= 512
            && !name.contains([':', '\\'])
            && path.components().all(|c| matches!(c, Component::Normal(_))),
        "The recovery file names an invalid location"
    );
    Ok(path)
}

fn files_under(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                let name = entry
                    .path()
                    .strip_prefix(root)?
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                inside(&name)?;
                files.insert(name, STANDARD.encode(std::fs::read(entry.path())?));
            } else {
                anyhow::bail!("Network files must be ordinary files");
            }
        }
    }
    Ok(files)
}

/// Write an encrypted recovery file for this network computer and return the
/// recovery key that opens it. The file is written whole or not at all.
pub fn create(
    owner: &mut OwnerRuntime,
    pin: TrustPin,
    device: DeviceIdentity,
    output: &Path,
) -> Result<Zeroizing<String>> {
    let backup = owner.backup()?;
    let files = files_under(&backup.staging);
    std::fs::remove_dir_all(&backup.staging).ok();
    let contents = Contents {
        version: VERSION,
        created_at: chrono::Utc::now().to_rfc3339(),
        pin,
        owner: OwnerPart {
            root: backup.root.clone(),
            config: backup.config.clone(),
            keys: backup.keys.clone(),
            files: files?,
        },
        device: DevicePart {
            vault: STANDARD.encode(device.vault.as_slice()),
            trust: STANDARD.encode(&device.trust),
        },
    };
    let key = new_key()?;
    let sealed = seal(&contents, &key)?;
    let directory = output
        .parent()
        .context("Choose where to save the recovery file")?;
    let mut pending = tempfile::NamedTempFile::new_in(directory)?;
    pending.write_all(&sealed)?;
    pending.as_file().sync_all()?;
    pending.persist(output)?;
    Ok(key)
}

/// A network brought back from a recovery file.
pub struct Restored {
    pub owner: OwnerRuntime,
    pub info: OwnerInfo,
    pub device: DeviceController,
}

/// Bring a network back on this computer: the authority into `owner_dir`
/// (started with `start`), the network computer's identity into `profile`.
/// Refuses to replace anything that already exists.
pub fn restore(
    file: &Path,
    key: &str,
    owner_dir: &Path,
    profile: &Path,
    start: impl FnOnce(&Path) -> Result<OwnerRuntime>,
) -> Result<Restored> {
    ensure!(
        !owner_dir.join("owner.json").exists() && !profile.exists(),
        "This computer already has a network. It has been preserved."
    );
    let mut bytes = Vec::new();
    std::fs::File::open(file)?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_FILE,
        "This recovery file is too large"
    );
    let contents = open(&bytes, key)?;
    // The identity first: if the authority cannot be restored, the identity is
    // removed again and nothing is left half-installed.
    let identity = DeviceIdentity {
        vault: Zeroizing::new(STANDARD.decode(&contents.device.vault)?),
        trust: STANDARD.decode(&contents.device.trust)?,
    };
    let mut device = DeviceController::restore_identity(
        profile,
        &identity,
        "http://127.0.0.1:1".into(),
        contents.pin.clone(),
    )?;
    let parent = owner_dir
        .parent()
        .context("Missing application directory")?;
    std::fs::create_dir_all(parent)?;
    let staging: PathBuf = tempfile::Builder::new()
        .prefix(".restore-")
        .tempdir_in(parent)?
        .keep();
    let installed = (|| {
        for (name, data) in &contents.owner.files {
            let target = staging.join(inside(name)?);
            std::fs::create_dir_all(target.parent().context("Invalid recovery location")?)?;
            std::fs::write(target, STANDARD.decode(data)?)?;
        }
        let mut owner = start(owner_dir)?;
        let info = owner.restore(
            &staging,
            &contents.owner.root,
            &contents.owner.config,
            &contents.owner.keys,
        )?;
        Ok::<_, anyhow::Error>((owner, info))
    })();
    std::fs::remove_dir_all(&staging).ok();
    let (owner, info) = match installed.and_then(|(owner, info)| {
        ensure!(
            info.pin == contents.pin,
            "The restored network does not match its recovery file"
        );
        Ok((owner, info))
    }) {
        Ok(installed) => installed,
        Err(error) => {
            drop(device);
            std::fs::remove_dir_all(profile).ok();
            return Err(error);
        }
    };
    device.rebind_owned_authority(info.url.clone(), &info.pin)?;
    Ok(Restored {
        owner,
        info,
        device,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contents() -> Contents {
        Contents {
            version: VERSION,
            created_at: "2026-10-27T00:00:00Z".into(),
            pin: TrustPin {
                network_name: "Home".into(),
                root_public_key: STANDARD.encode([4; 32]),
            },
            owner: OwnerPart {
                root: "C:/owner".into(),
                config: "genesis-mesh.toml".into(),
                keys: BTreeMap::from([("network/keys/na.key".into(), "c2VjcmV0".into())]),
                files: BTreeMap::from([("network/na.db".into(), "ZGI=".into())]),
            },
            device: DevicePart {
                vault: "dmF1bHQ=".into(),
                trust: "e30=".into(),
            },
        }
    }

    #[test]
    fn only_the_recovery_key_opens_an_unchanged_file() -> Result<()> {
        let key = new_key()?;
        assert_eq!(key.len(), 39, "32 characters in eight groups of four");
        let sealed = seal(&contents(), &key)?;
        assert!(
            !sealed.windows(8).any(|w| w == b"c2VjcmV0"),
            "Owner keys are never stored in the clear"
        );
        let opened = open(&sealed, &key.to_lowercase().replace('-', " "))?;
        assert_eq!(opened.owner.keys, contents().owner.keys);
        assert_eq!(opened.pin, contents().pin);
        assert!(open(&sealed, &new_key()?).is_err(), "Another key");
        for index in [
            0,
            MAGIC.len(),
            MAGIC.len() + 1,
            MAGIC.len() + 1 + SALT,
            sealed.len() - 1,
        ] {
            let mut changed = sealed.clone();
            changed[index] ^= 1;
            assert!(open(&changed, &key).is_err(), "Changed byte {index}");
        }
        assert!(open(&sealed[..sealed.len() - 1], &key).is_err());
        Ok(())
    }

    #[test]
    fn a_written_down_key_must_have_all_its_characters() {
        assert!(parse_key("ABCD-EFGH").is_err());
        assert!(parse_key("not base32 at all !!").is_err());
        let key = new_key().unwrap();
        assert!(parse_key(&key).is_ok());
        assert!(parse_key(&format!("  {}  ", key.replace('-', ""))).is_ok());
    }

    #[test]
    fn names_in_a_recovery_file_cannot_escape_its_directory() {
        for name in [
            "../outside",
            "/etc/passwd",
            "C:/Windows",
            "a\\..\\b",
            "a/../../b",
            "",
            "./a",
        ] {
            assert!(inside(name).is_err(), "{name}");
        }
        assert!(inside("network/na.db").is_ok());
    }
}
