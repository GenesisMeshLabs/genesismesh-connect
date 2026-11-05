use super::*;
use crate::owner_control::{OwnerAction, Permission};
use chrono::{Duration, Utc};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};

#[derive(Default)]
struct TestBackend {
    values: RefCell<HashMap<String, Vec<u8>>>,
    locked: Cell<bool>,
    reads: Cell<usize>,
    writes: Cell<usize>,
    oversize: Cell<bool>,
    provider_changed: Cell<bool>,
}
impl Backend for TestBackend {
    fn seal(&self, id: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        ensure!(!self.locked.get(), "Test credential store locked");
        self.writes.set(self.writes.get() + 1);
        self.values.borrow_mut().insert(id.into(), bytes.into());
        if self.oversize.get() {
            return Ok(vec![7; MAX_BYTES as usize + 1]);
        }
        Ok([b"test-administrative\0".as_slice(), id.as_bytes()].concat())
    }
    fn open(&self, id: &str, protected: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.reads.set(self.reads.get() + 1);
        ensure!(!self.locked.get(), "Test credential store locked");
        ensure!(
            !self.provider_changed.get()
                && protected == [b"test-administrative\0".as_slice(), id.as_bytes()].concat(),
            "Test provider changed"
        );
        Ok(self.values.borrow().get(id).cloned().map(Zeroizing::new))
    }
    fn delete(&self, id: &str, _protected: &[u8]) -> Result<()> {
        ensure!(!self.locked.get(), "Test credential store locked");
        self.values.borrow_mut().remove(id);
        Ok(())
    }
}
fn public(seed: u8) -> String {
    STANDARD.encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
fn binding() -> AdministrativeBinding {
    AdministrativeBinding {
        scope: ControlScope {
            pin: TrustPin {
                network_name: "Admin custody fixture".into(),
                root_public_key: public(1),
            },
            host_node: public(2),
        },
        controller_node: public(3),
    }
}
fn enrollment(key: &AdministrativeKey) -> EnrollmentIntent {
    let now = Utc::now();
    EnrollmentIntent {
        version: 1,
        id: uuid::Uuid::new_v4().to_string(),
        scope: key.binding().scope.clone(),
        controller_node: key.binding().controller_node.clone(),
        administrative_key: key.public_key().into(),
        permissions: [Permission::ListPairing].into_iter().collect(),
        created_at: now,
        expires_at: now + Duration::seconds(120),
        grant_expires_at: now + Duration::minutes(10),
    }
}
fn command(key: &AdministrativeKey) -> CommandIntent {
    let now = Utc::now();
    CommandIntent {
        version: 1,
        grant_id: uuid::Uuid::new_v4().to_string(),
        nonce: uuid::Uuid::new_v4().to_string(),
        scope: key.binding().scope.clone(),
        controller_node: key.binding().controller_node.clone(),
        action: OwnerAction::ListPairing,
        created_at: now,
        expires_at: now + Duration::seconds(120),
    }
}

#[test]
fn separate_native_key_survives_reopen_without_a_plaintext_profile_seed() -> Result<()> {
    let backend = TestBackend::default();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    let key = AdministrativeKey::create_with(&path, binding(), &backend)?;
    let public = key.public_key().to_owned();
    assert_ne!(public, binding().controller_node);
    let secret = secret(&key.envelope, &backend)?.context("Fixture credential missing")?;
    let reference = std::fs::read(&path)?;
    assert!(!reference.windows(32).any(|b| b == secret.seed));
    assert!(!String::from_utf8(reference.clone())?.contains(&STANDARD.encode(secret.seed)));
    assert!(!String::from_utf8(reference.clone())?.contains("\"seed\""));
    let signed = key.enrollment_with(enrollment(&key), &backend)?;
    signed.digest()?;
    drop(key);
    let key = AdministrativeKey::open_with(&path, &binding(), &backend)?;
    assert_eq!(key.public_key(), public);
    assert_eq!(std::fs::read(&path)?, reference);
    assert_eq!(backend.writes.get(), 1);
    let signed = key.command_with(command(&key), &backend)?;
    let payload = genesis_mesh_sdk::canonical_json(
        &serde_json::json!({"domain":"genesismesh-connect/owner-command/v1","intent":signed.intent}),
    )?;
    assert!(genesis_mesh_sdk::verify_canonical(
        &payload,
        &signed.signature,
        &[public]
    ));
    Ok(())
}

#[test]
fn signing_reopens_the_store_and_never_falls_back_to_a_cached_or_new_key() -> Result<()> {
    let backend = TestBackend::default();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    let key = AdministrativeKey::create_with(&path, binding(), &backend)?;
    key.command_with(command(&key), &backend)?;
    let reads = backend.reads.get();
    key.command_with(command(&key), &backend)?;
    assert_eq!(backend.reads.get(), reads + 1);
    let reference = std::fs::read(&path)?;
    backend.locked.set(true);
    assert!(key.command_with(command(&key), &backend).is_err());
    assert!(key.enrollment_with(enrollment(&key), &backend).is_err());
    assert!(AdministrativeKey::open_with(&path, &binding(), &backend).is_err());
    backend.locked.set(false);
    key.command_with(command(&key), &backend)?;
    backend.values.borrow_mut().clear();
    assert!(key.command_with(command(&key), &backend).is_err());
    assert!(AdministrativeKey::create_with(&path, binding(), &backend).is_err());
    assert_eq!(backend.writes.get(), 1);
    assert_eq!(std::fs::read(&path)?, reference);
    Ok(())
}

#[test]
fn missing_initialized_reference_or_locked_first_creation_never_regenerates() -> Result<()> {
    let backend = TestBackend::default();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    let key = AdministrativeKey::create_with(&path, binding(), &backend)?;
    std::fs::remove_file(&path)?;
    assert!(key.command_with(command(&key), &backend).is_err());
    assert!(AdministrativeKey::create_with(&path, binding(), &backend).is_err());
    assert_eq!(backend.values.borrow().len(), 1);
    assert_eq!(backend.writes.get(), 1);
    let other = dir.path().join("locked-first.json");
    backend.locked.set(true);
    assert!(AdministrativeKey::create_with(&other, binding(), &backend).is_err());
    backend.locked.set(false);
    assert!(AdministrativeKey::create_with(&other, binding(), &backend).is_err());
    assert!(!other.exists());
    assert_eq!(backend.writes.get(), 1);
    Ok(())
}

#[test]
fn changed_context_signer_or_provider_is_refused_without_modifying_credentials() -> Result<()> {
    let backend = TestBackend::default();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    let key = AdministrativeKey::create_with(&path, binding(), &backend)?;
    let mut other = binding();
    other.scope.host_node = public(4);
    assert!(AdministrativeKey::open_with(&path, &other, &backend).is_err());
    let mut e = enrollment(&key);
    e.administrative_key = public(4);
    assert!(key.enrollment_with(e, &backend).is_err());
    let mut c = command(&key);
    c.controller_node = public(4);
    assert!(key.command_with(c, &backend).is_err());
    let mut c = command(&key);
    c.scope.pin.root_public_key = public(4);
    assert!(key.command_with(c, &backend).is_err());
    backend.provider_changed.set(true);
    assert!(key.command_with(command(&key), &backend).is_err());
    assert_eq!(backend.writes.get(), 1);
    assert_eq!(backend.values.borrow().len(), 1);
    Ok(())
}

#[test]
fn protected_record_purpose_account_context_and_key_substitution_are_refused() -> Result<()> {
    let backend = TestBackend::default();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    let key = AdministrativeKey::create_with(&path, binding(), &backend)?;
    let original = backend.values.borrow()[&key.envelope.id].clone();
    for (field, value) in [
        ("purpose", serde_json::json!("device-identity")),
        ("id", serde_json::json!(uuid::Uuid::new_v4().to_string())),
        ("version", serde_json::json!(2)),
        ("seed", serde_json::to_value([9u8; 32])?),
    ] {
        let mut changed: serde_json::Value = serde_json::from_slice(&original)?;
        changed[field] = value;
        backend
            .values
            .borrow_mut()
            .insert(key.envelope.id.clone(), serde_json::to_vec(&changed)?);
        assert!(key.command_with(command(&key), &backend).is_err());
    }
    let mut changed: serde_json::Value = serde_json::from_slice(&original)?;
    changed["binding"]["controller_node"] = serde_json::json!(public(9));
    backend
        .values
        .borrow_mut()
        .insert(key.envelope.id.clone(), serde_json::to_vec(&changed)?);
    assert!(
        AdministrativeKey::erase_with(
            &path,
            &binding().scope.pin,
            &binding().controller_node,
            &backend
        )
        .is_err()
    );
    assert!(path.exists());
    backend
        .values
        .borrow_mut()
        .insert(key.envelope.id.clone(), original);
    key.command_with(command(&key), &backend)?;
    Ok(())
}

#[test]
fn substituted_reference_is_not_used_by_an_existing_signer_handle() -> Result<()> {
    let backend = TestBackend::default();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    let key = AdministrativeKey::create_with(&path, binding(), &backend)?;
    let second_path = dir.path().join("other-key.json");
    let second = AdministrativeKey::create_with(&second_path, binding(), &backend)?;
    assert_ne!(key.public_key(), second.public_key());
    std::fs::copy(&second_path, &path)?;
    assert!(key.command_with(command(&key), &backend).is_err());
    assert_eq!(backend.values.borrow().len(), 2);
    Ok(())
}

#[test]
fn failed_reference_commit_cleans_its_unpublished_key_and_refuses_automatic_retry() -> Result<()> {
    let backend = TestBackend::default();
    backend.oversize.set(true);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    assert!(AdministrativeKey::create_with(&path, binding(), &backend).is_err());
    assert!(!path.exists());
    assert!(backend.values.borrow().is_empty());
    backend.oversize.set(false);
    assert!(AdministrativeKey::create_with(&path, binding(), &backend).is_err());
    assert_eq!(backend.writes.get(), 1);
    Ok(())
}

#[test]
fn erase_preserves_locked_foreign_credentials_and_retries_after_secret_deletion() -> Result<()> {
    let backend = TestBackend::default();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    let key = AdministrativeKey::create_with(&path, binding(), &backend)?;
    backend.locked.set(true);
    assert!(
        AdministrativeKey::erase_with(
            &path,
            &binding().scope.pin,
            &binding().controller_node,
            &backend
        )
        .is_err()
    );
    backend.locked.set(false);
    assert!(
        AdministrativeKey::erase_with(&path, &binding().scope.pin, &public(9), &backend).is_err()
    );
    assert!(path.exists());
    assert_eq!(backend.values.borrow().len(), 1);
    backend.values.borrow_mut().remove(&key.envelope.id);
    AdministrativeKey::erase_with(
        &path,
        &binding().scope.pin,
        &binding().controller_node,
        &backend,
    )?;
    AdministrativeKey::erase_with(
        &path,
        &binding().scope.pin,
        &binding().controller_node,
        &backend,
    )?;
    assert!(!path.exists());
    assert!(backend.values.borrow().is_empty());
    assert!(AdministrativeKey::create_with(&path, binding(), &backend).is_err());
    Ok(())
}

#[test]
fn reference_lock_corruption_and_oversize_do_not_contact_or_replace_the_store() -> Result<()> {
    let backend = TestBackend::default();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    let key = AdministrativeKey::create_with(&path, binding(), &backend)?;
    let (guard, _) = lock(&path)?;
    assert!(key.command_with(command(&key), &backend).is_err());
    drop(guard);
    for bad in [
        b"{\"version\":1,\"version\":1}".to_vec(),
        vec![b' '; MAX_BYTES as usize + 1],
    ] {
        std::fs::write(&path, &bad)?;
        let reads = backend.reads.get();
        assert!(AdministrativeKey::open_with(&path, &binding(), &backend).is_err());
        assert_eq!(std::fs::read(&path)?, bad);
        assert_eq!(backend.reads.get(), reads);
    }
    assert_eq!(backend.writes.get(), 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn administrative_reference_and_ancestor_links_are_refused() -> Result<()> {
    use std::os::unix::fs::symlink;
    let backend = TestBackend::default();
    let dir = tempfile::tempdir()?;
    let real = dir.path().join("real");
    std::fs::create_dir(&real)?;
    let alias = dir.path().join("alias");
    symlink(&real, &alias)?;
    assert!(AdministrativeKey::create_with(&alias.join(FILE), binding(), &backend).is_err());
    let original = real.join("other");
    std::fs::write(&original, b"untouched")?;
    let path = real.join(FILE);
    symlink(&original, &path)?;
    assert!(AdministrativeKey::open_with(&path, &binding(), &backend).is_err());
    assert_eq!(std::fs::read(&original)?, b"untouched");
    assert_eq!(backend.writes.get(), 0);
    Ok(())
}

#[cfg(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
#[test]
#[ignore = "Requires native protected storage; Linux uses disposable Secret Service"]
fn real_native_administrative_key_reopens_signs_and_missing_secret_cannot_be_replaced() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(FILE);
    let key = AdministrativeKey::create(&path, binding())?;
    let original = std::fs::read(&path)?;
    let public = key.public_key().to_owned();
    let request = key.sign_enrollment(enrollment(&key))?;
    request.digest()?;
    let record = secret(&key.envelope, &Native)?.context("Missing native credential")?;
    assert!(!original.windows(32).any(|s| s == record.seed));
    drop(key);
    let key = AdministrativeKey::open(&path, &binding())?;
    assert_eq!(public, key.public_key());
    key.sign_command(command(&key))?;
    #[cfg(not(windows))]
    {
        Native.delete(&key.envelope.id, &key.envelope.protected)?;
        assert!(key.sign_command(command(&key)).is_err());
        assert!(AdministrativeKey::open(&path, &binding()).is_err());
        assert!(AdministrativeKey::create(&path, binding()).is_err());
    }
    AdministrativeKey::erase_for_device(&path, &binding().scope.pin, &binding().controller_node)?;
    assert!(!path.exists());
    Ok(())
}

#[cfg(any(
    windows,
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
#[test]
#[ignore = "Requires native protected storage; Linux uses disposable Secret Service"]
fn leaving_removes_the_separate_native_key_and_preserves_external_files() -> Result<()> {
    use super::super::{DeviceController, vault::Vault};
    let dir = tempfile::tempdir()?;
    let profile = dir.path().join("profile");
    std::fs::create_dir(&profile)?;
    let vault = Vault::create(
        &profile.join("device.bin"),
        None,
        binding().scope.pin.clone(),
    )?;
    let node = STANDARD.encode(vault.key().verifying_key().to_bytes());
    let mut b = binding();
    b.controller_node = node;
    let key = AdministrativeKey::create(&profile.join(FILE), b)?;
    let envelope = key.envelope.clone();
    drop(key);
    drop(vault);
    let shared = dir.path().join("saved-document.txt");
    std::fs::write(&shared, b"keep")?;
    std::fs::write(profile.with_extension("leaving"), b"")?;
    DeviceController::finish_leave(&profile)?;
    assert!(!profile.exists());
    assert_eq!(std::fs::read(shared)?, b"keep");
    #[cfg(not(windows))]
    assert!(Native.open(&envelope.id, &envelope.protected)?.is_none());
    #[cfg(windows)]
    let _ = envelope;
    Ok(())
}
