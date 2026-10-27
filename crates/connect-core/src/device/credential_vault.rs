//! Shared commit rules for native credential stores. Only an opaque account
//! reference is persisted in the app container. Windows keeps its DPAPI format.
use super::{MAX_FILE, Record};
use anyhow::{Context, Result, ensure};
use std::{
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub(in crate::device) trait Store {
    fn prefix(&self) -> &'static [u8];
    fn get(&self, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn set(&self, id: &str, secret: &[u8]) -> Result<()>;
    fn delete(&self, id: &str) -> Result<()>;
}
fn reference(id: &str, store: &impl Store) -> Vec<u8> {
    [store.prefix(), id.as_bytes()].concat()
}
fn account(bytes: &[u8], store: &impl Store) -> Result<String> {
    let id = std::str::from_utf8(
        bytes
            .strip_prefix(store.prefix())
            .context("Identity reference belongs to another storage provider")?,
    )?;
    ensure!(
        uuid::Uuid::parse_str(id)?.to_string() == id,
        "Invalid identity storage account"
    );
    Ok(id.to_owned())
}
pub(super) fn open(reference: &[u8], store: &impl Store) -> Result<Zeroizing<Vec<u8>>> {
    let id = account(reference, store)?;
    let bytes=store.get(&id)?.context("The saved device identity is unavailable. Unlock its system credential store; the identity has not been replaced.")?;
    ensure!(
        bytes.len() as u64 <= MAX_FILE,
        "Secure identity record is too large"
    );
    let record: Record =
        serde_json::from_slice(&bytes).context("Saved device identity needs attention")?;
    ensure!(
        record.storage_id == id && record.version == 1,
        "Identity storage reference mismatch"
    );
    Ok(bytes)
}
pub(super) fn persist(
    path: &Path,
    record: &Record,
    create: bool,
    store: &impl Store,
) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(&record.storage_id)?.to_string() == record.storage_id,
        "Invalid identity storage account"
    );
    let plaintext = Zeroizing::new(serde_json::to_vec(record)?);
    ensure!(
        plaintext.len() as u64 <= MAX_FILE,
        "Secure identity record is too large"
    );
    if create {
        ensure!(
            !path.exists(),
            "This device already has an identity reference"
        );
        ensure!(
            store.get(&record.storage_id)?.is_none(),
            "This secure identity account already exists"
        );
    } else {
        let mut existing = Vec::new();
        std::fs::File::open(path)?
            .take(256)
            .read_to_end(&mut existing)?;
        ensure!(
            existing == reference(&record.storage_id, store),
            "Saved identity reference changed"
        );
        let previous = open(&existing, store)?;
        let prior: Record = serde_json::from_slice(&previous)?;
        ensure!(
            prior.seed == record.seed && prior.pin == record.pin,
            "The saved device identity changed; existing credentials were preserved"
        );
    }
    store.set(&record.storage_id, &plaintext)?;
    if !create {
        return Ok(());
    } // Store update is the commit; reference stays unchanged.
    let committed = (|| -> Result<()> {
        let mut pending =
            tempfile::NamedTempFile::new_in(path.parent().context("Missing identity directory")?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            pending
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        pending.write_all(&reference(&record.storage_id, store))?;
        pending.as_file().sync_all()?;
        pending.persist_noclobber(path)?;
        Ok(())
    })();
    if committed.is_err() {
        let _ = store.delete(&record.storage_id);
    }
    committed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        collections::HashMap,
    };
    struct TestStore {
        secrets: RefCell<HashMap<String, Vec<u8>>>,
        unavailable: Cell<bool>,
    }
    impl Store for TestStore {
        fn prefix(&self) -> &'static [u8] {
            b"test-only-native-reference\0"
        }
        fn get(&self, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            ensure!(!self.unavailable.get(), "Test store unavailable");
            Ok(self.secrets.borrow().get(id).cloned().map(Zeroizing::new))
        }
        fn set(&self, id: &str, secret: &[u8]) -> Result<()> {
            ensure!(!self.unavailable.get(), "Test store unavailable");
            self.secrets.borrow_mut().insert(id.into(), secret.into());
            Ok(())
        }
        fn delete(&self, id: &str) -> Result<()> {
            self.secrets.borrow_mut().remove(id);
            Ok(())
        }
    }
    fn record() -> Record {
        Record {
            version: 1,
            storage_id: uuid::Uuid::new_v4().to_string(),
            seed: [42; 32],
            executor_seed: None,
            edge: None,
            authority: None,
            pin: crate::authority::TrustPin {
                root_public_key: "test-root".into(),
                network_name: "test-network".into(),
            },
            certificate: None,
            peer: None,
            enrollment_pending: false,
            bridge_route: None,
            transport_seed: None,
            bridge_seed: None,
            paired: None,
            peers: Vec::new(),
            auto_connect: false,
            consumer_mode: false,
            saved_share: None,
        }
    }
    #[test]
    fn legacy_pair_migration_and_multiple_devices_preserve_keys_and_selection() -> Result<()> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use serde_json::json;
        let peer = |seed: u8| {
            super::super::super::PairedDevice {
            name: format!("Device {seed}"),
            node: STANDARD.encode([seed; 32]),
            ticket: json!({"version":1,"endpoint":{"id":iroh::SecretKey::from([seed;32]).public().to_string(),"addrs":[{"Ip":"127.0.0.1:1234"}]}}).to_string(),
        }
        };
        let first = peer(1);
        let second = peer(2);
        let mut original = record();
        original.peer = Some(first.node.clone());
        original.paired = Some(first.clone());
        let mut json = serde_json::to_value(&original)?;
        json.as_object_mut().unwrap().remove("peers");
        let mut migrated: Record = serde_json::from_value(json)?;
        super::super::migrate_peers(&mut migrated)?;
        assert_eq!(migrated.peers.len(), 1);
        assert_eq!(migrated.seed, original.seed);
        assert_eq!(migrated.pin, original.pin);
        assert_eq!(migrated.peer, original.peer);
        migrated.peers.push(second);
        super::super::migrate_peers(&mut migrated)?;
        assert_eq!(migrated.peers.len(), 2);
        migrated.peers.push(first);
        assert!(super::super::migrate_peers(&mut migrated).is_err());
        Ok(())
    }

    #[test]
    fn reference_commit_preserves_identity_and_refuses_unavailable_or_substituted_credentials()
    -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("device.bin");
        let store = TestStore {
            secrets: RefCell::new(HashMap::new()),
            unavailable: Cell::new(false),
        };
        let mut record = record();
        persist(&path, &record, true, &store)?;
        let bytes = std::fs::read(&path)?;
        assert!(!bytes.windows(32).any(|v| v == record.seed));
        assert_eq!(
            open(&bytes, &store)?.as_slice(),
            serde_json::to_vec(&record)?
        );
        record.consumer_mode = true;
        persist(&path, &record, false, &store)?;
        assert_eq!(std::fs::read(&path)?, bytes);
        let mut changed = record.clone();
        changed.seed = [7; 32];
        assert!(persist(&path, &changed, false, &store).is_err());
        assert_eq!(
            open(&bytes, &store)?.as_slice(),
            serde_json::to_vec(&record)?
        );
        store.unavailable.set(true);
        assert!(open(&bytes, &store).is_err());
        assert!(persist(&path, &record, false, &store).is_err());
        assert_eq!(std::fs::read(&path)?, bytes);
        store.unavailable.set(false);
        store.secrets.borrow_mut().remove(&record.storage_id);
        assert!(open(&bytes, &store).is_err());
        assert!(persist(&path, &record, false, &store).is_err());
        Ok(())
    }
    #[test]
    fn failed_reference_commit_removes_only_new_credential() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = TestStore {
            secrets: RefCell::new(HashMap::new()),
            unavailable: Cell::new(false),
        };
        let record = record();
        assert!(
            persist(
                &dir.path().join("missing/device.bin"),
                &record,
                true,
                &store
            )
            .is_err()
        );
        assert!(store.secrets.borrow().is_empty());
        assert!(open(b"another-platform-reference", &store).is_err());
        Ok(())
    }
}
