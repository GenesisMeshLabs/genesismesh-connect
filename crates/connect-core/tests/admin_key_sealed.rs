//! Separate process: explicit headless backend cannot change another test's OS
//! store selection. All master/credential files here are disposable fixtures.
#[cfg(target_os = "linux")]
#[test]
fn headless_administrative_custody_uses_sealed_records_and_never_replaces_a_missing_key()
-> anyhow::Result<()> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use chrono::{Duration, Utc};
    use connect_core::{
        authority::TrustPin,
        device::{AdministrativeBinding, AdministrativeKey, use_sealed_store},
        owner_control::{ControlScope, EnrollmentIntent, Permission},
    };
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = tempfile::tempdir()?;
    let profile = dir.path().join("profile");
    std::fs::create_dir(&profile)?;
    let master = dir.path().join("fixture-master-key");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&master)?;
    file.write_all(&[7; 32])?;
    drop(file);
    let sealed = dir.path().join("sealed");
    use_sealed_store(sealed.clone(), &master)?;
    let public = |seed| {
        STANDARD.encode(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    };
    let binding = AdministrativeBinding {
        scope: ControlScope {
            pin: TrustPin {
                network_name: "Sealed admin fixture".into(),
                root_public_key: public(1),
            },
            host_node: public(2),
        },
        controller_node: public(3),
    };
    let reference = profile.join("administrative-key.json");
    let key = AdministrativeKey::create(&reference, binding.clone())?;
    let public = key.public_key().to_owned();
    let before = std::fs::read(&reference)?;
    let entries = std::fs::read_dir(&sealed)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(entries.len(), 1);
    let record = entries[0].path();
    let encrypted = std::fs::read(&record)?;
    assert!(!String::from_utf8_lossy(&encrypted).contains("administrative-key"));
    assert_eq!(
        std::fs::metadata(&record)?.permissions().mode() & 0o777,
        0o600
    );
    drop(key);
    let key = AdministrativeKey::open(&reference, &binding)?;
    assert_eq!(key.public_key(), public);
    let now = Utc::now();
    let signed = key.sign_enrollment(EnrollmentIntent {
        version: 1,
        id: uuid::Uuid::new_v4().to_string(),
        scope: binding.scope.clone(),
        controller_node: binding.controller_node.clone(),
        administrative_key: public,
        permissions: [Permission::ListPairing].into_iter().collect(),
        created_at: now,
        expires_at: now + Duration::seconds(120),
        grant_expires_at: now + Duration::minutes(10),
    })?;
    signed.digest()?;
    let mut damaged = encrypted.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    std::fs::write(&record, &damaged)?;
    assert!(AdministrativeKey::open(&reference, &binding).is_err());
    assert_eq!(std::fs::read(&record)?, damaged);
    std::fs::write(&record, &encrypted)?;
    AdministrativeKey::open(&reference, &binding)?;
    std::fs::remove_file(record)?;
    assert!(key.sign_enrollment(signed.intent).is_err());
    assert!(AdministrativeKey::open(&reference, &binding).is_err());
    assert!(AdministrativeKey::create(&reference, binding).is_err());
    assert_eq!(std::fs::read(&reference)?, before);
    Ok(())
}
