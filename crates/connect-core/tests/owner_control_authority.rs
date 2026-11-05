//! Real core membership/revocation qualification for the control contract.
//! This is not a remote-owner transport or actual pairing-dispatch acceptance.
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use connect_core::{
    authority::{LocalAuthority, TrustStore},
    owner::OwnerRuntime,
    owner_control::*,
};
use ed25519_dalek::SigningKey;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}

#[tokio::test]
#[ignore = "Requires pinned CONNECT_NA_PYTHON and a disposable native credential store"]
async fn real_core_membership_is_separate_from_admin_enrollment_and_revocation_wins() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let python = std::env::var_os("CONNECT_NA_PYTHON").context("Set CONNECT_NA_PYTHON")?;
    let mut owner = OwnerRuntime::start_python(
        std::path::Path::new(&python),
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../apps/connect/authority/main.py"),
        &dir.path().join("authority"),
    )?;
    let info = owner.create("Owner control qualification")?;
    let authority = LocalAuthority::new(&info.url)?;
    let scope = ControlScope {
        pin: info.pin.clone(),
        host_node: public(&key(31)),
    };
    let mut trust_store = TrustStore::create(&dir.path().join("trust.json"), info.pin)?;
    let member = key(32);
    let admin = key(33);
    // Guided Connect devices are registered sharing/edge hosts; the fixed
    // remove-device adapter revokes that registered certificate lineage.
    let invite = owner.invite(&public(&member), true)?;
    let (device, _) = authority
        .enroll_host(member, &key(34), &invite, &mut trust_store)
        .await?;
    let trust = authority.refresh(&mut trust_store).await?;
    let now = Utc::now();
    let peer = VerifiedController::from_session(
        &scope,
        &trust,
        device.certificate(),
        &device.public_key(),
        now,
    )?;
    let mut registry = ControlStore::create(&dir.path().join("control.json"), scope.clone(), now)?;
    let enrollment = EnrollmentRequest::sign(
        EnrollmentIntent {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            scope: scope.clone(),
            controller_node: device.public_key(),
            administrative_key: public(&admin),
            permissions: [Permission::ListPairing].into_iter().collect(),
            created_at: now,
            expires_at: now + Duration::seconds(120),
            grant_expires_at: now + Duration::minutes(10),
        },
        &admin,
    )?;
    let command = OwnerCommand::sign(
        CommandIntent {
            version: 1,
            grant_id: enrollment.intent.id.clone(),
            nonce: uuid::Uuid::new_v4().to_string(),
            scope: scope.clone(),
            controller_node: device.public_key(),
            action: OwnerAction::ListPairing,
            created_at: now,
            expires_at: now + Duration::seconds(120),
        },
        &admin,
    )?;
    assert!(
        registry.reserve(&command, &peer, now).is_err(),
        "a genuine core member is not an administrator"
    );
    let digest = enrollment.digest()?;
    registry.enroll_locally(enrollment, &digest, &peer, now)?;
    let reserved = registry.reserve(&command, &peer, now)?;
    assert_eq!(reserved.action(), &OwnerAction::ListPairing);
    let removal = owner.remove_device(&device.public_key())?;
    assert!(removal.revoked > 0);
    let current = authority.refresh(&mut trust_store).await?;
    assert!(
        VerifiedController::from_session(
            &scope,
            &current,
            device.certificate(),
            &device.public_key(),
            Utc::now()
        )
        .is_err(),
        "real signed CRL refuses the controller despite its saved admin grant"
    );
    Ok(())
}
