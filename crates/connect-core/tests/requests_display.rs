//! Default production display must not open or initialize qualified command state.
#![cfg(all(target_os = "linux", not(feature = "owner-requests-qualification")))]
#[path = "support/embedded_owner.rs"]
mod support;
use anyhow::Result;
use connect_core::{
    authority::TrustPin,
    device::{DeviceController, RequestsAvailability},
};
#[test]
fn default_display_ignores_unqualified_command_state_without_creating_admin_keys_or_markers()
-> Result<()> {
    support::sealed_store();
    let dir = tempfile::tempdir()?;
    let profile = dir.path().join("device");
    let device = DeviceController::prepare_remote(
        &profile,
        TrustPin {
            network_name: "Fixture".into(),
            root_public_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
        },
    )?;
    let journal = profile.join("owner-commands.json");
    std::fs::write(&journal, b"unqualified fixture bytes")?;
    let view = device.owner_requests_overview()?;
    assert_eq!(view.availability, RequestsAvailability::Unavailable);
    assert!(!view.can_check && !view.attention && view.entry.is_none());
    assert_eq!(std::fs::read(journal)?, b"unqualified fixture bytes");
    assert!(!profile.join("administrative-key.json").exists());
    assert!(!profile.join("owner-commands.owner-commands-lock").exists());
    Ok(())
}
