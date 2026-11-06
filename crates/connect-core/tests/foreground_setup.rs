use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use connect_core::owner::{
    NativeOwnerTransport, OwnerRuntime,
    foreground::{ForegroundSetup, NativeSetupConfig, SetupChoice, abandon_unstarted_create},
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Calls {
    ops: Vec<String>,
}
struct Native {
    calls: Arc<Mutex<Calls>>,
    configured: bool,
    invalid: &'static str,
}
fn key(n: u8) -> String {
    STANDARD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[n; 32])
            .verifying_key()
            .to_bytes(),
    )
}
impl NativeOwnerTransport for Native {
    fn request(&mut self, request: Value) -> Result<Value> {
        let op = request["op"].as_str().unwrap();
        self.calls.lock().unwrap().ops.push(op.into());
        let pin = json!({"root_public_key":key(if self.invalid == "foreign" { 2 } else { 1 }),"network_name":"Home"});
        Ok(match op {
            "status" => {
                json!({"configured":self.configured,"running":false,"foreground_only":true,"production_create_enabled":self.invalid=="production"})
            }
            "create" if self.invalid == "fail_create" => {
                anyhow::bail!("Root authentication declined")
            }
            "create" | "open" => {
                self.configured = true;
                json!({"url":if self.invalid=="remote" {"http://192.0.2.1:3000"} else {"http://127.0.0.1:3000"},
                    "pin":pin,"managed":self.invalid!="unmanaged"})
            }
            "capabilities" | "pairing_ready" => {
                json!({"schema":1,"core_version":include_str!("../../../apps/connect/authority/core-requirements.txt")
                .lines().find_map(|line|line.strip_prefix("genesis-mesh==")).unwrap(),
                "pin":pin,"transport":if self.invalid=="desktop" {"local_inherited_pipe"} else {"local_android_embedded"},
                "operations":["connect.access.update.v1","connect.pairing.requests.v1"]})
            }
            _ => panic!("Unexpected setup operation"),
        })
    }
    fn close(&mut self) {}
}
fn runtime(configured: bool, invalid: &'static str) -> (OwnerRuntime, Arc<Mutex<Calls>>) {
    let calls = Arc::new(Mutex::new(Calls::default()));
    (
        OwnerRuntime::from_native(Box::new(Native {
            calls: calls.clone(),
            configured,
            invalid,
        })),
        calls,
    )
}
fn config(path: &Path) -> Result<NativeSetupConfig> {
    NativeSetupConfig::new(path.to_owned())
}
fn create() -> SetupChoice {
    SetupChoice::Create {
        name: "Home".into(),
    }
}

#[test]
fn explicit_open_never_creates_a_journal_or_authority_and_existing_setup_is_exclusive() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let (owner, calls) = runtime(false, "");
    assert!(ForegroundSetup::begin(owner, config(dir.path())?, SetupChoice::Open).is_err());
    assert!(std::fs::read_dir(dir.path())?.next().is_none());
    assert!(calls.lock().unwrap().ops.is_empty());
    let (owner, _) = runtime(false, "");
    let setup = ForegroundSetup::begin(owner, config(dir.path())?, create())?;
    let (owner, _) = runtime(false, "");
    assert!(ForegroundSetup::begin(owner, config(dir.path())?, SetupChoice::Open).is_err());
    drop(setup);
    let before = std::fs::read(dir.path().join("foreground-setup.json"))?;
    let (owner, calls) = runtime(false, "");
    assert!(ForegroundSetup::begin(owner, config(dir.path())?, create()).is_err());
    assert!(!calls.lock().unwrap().ops.iter().any(|op| op == "create"));
    assert_eq!(
        before,
        std::fs::read(dir.path().join("foreground-setup.json"))?
    );
    Ok(())
}

#[test]
fn existing_custody_or_device_and_unqualified_status_never_allow_creation() -> Result<()> {
    for (configured, invalid, device) in [
        (true, "", false),
        (false, "production", false),
        (false, "", true),
    ] {
        let dir = tempfile::tempdir()?;
        if device {
            std::fs::create_dir(dir.path().join("device"))?;
        }
        let (owner, calls) = runtime(configured, invalid);
        assert!(ForegroundSetup::begin(owner, config(dir.path())?, create()).is_err());
        assert!(!dir.path().join("foreground-setup.json").exists());
        assert!(!calls.lock().unwrap().ops.iter().any(|op| op == "create"));
    }
    Ok(())
}

#[test]
fn foreign_pin_remote_origin_or_wrong_transport_stops_before_device_preparation() -> Result<()> {
    for invalid in ["remote", "unmanaged", "desktop"] {
        let dir = tempfile::tempdir()?;
        let (owner, _) = runtime(false, invalid);
        let mut setup = ForegroundSetup::begin(owner, config(dir.path())?, create())?;
        assert!(setup.open_authority().is_err());
        assert!(setup.prepare_device().is_err());
        assert!(!dir.path().join("device").exists());
    }
    let dir = tempfile::tempdir()?;
    let (owner, _) = runtime(false, "");
    let mut setup = ForegroundSetup::begin(owner, config(dir.path())?, create())?;
    setup.open_authority()?;
    drop(setup);
    let (owner, calls) = runtime(true, "foreign");
    let mut setup = ForegroundSetup::begin(owner, config(dir.path())?, SetupChoice::Open)?;
    assert!(setup.open_authority().is_err());
    assert!(setup.prepare_device().is_err());
    assert!(!calls.lock().unwrap().ops.iter().any(|op| op == "create"));
    Ok(())
}

#[test]
fn malformed_changed_or_missing_journals_are_preserved_without_fallback() -> Result<()> {
    for mutation in ["duplicate", "oversized", "missing", "changed"] {
        let dir = tempfile::tempdir()?;
        let (owner, recorded) = runtime(false, "");
        let mut setup = ForegroundSetup::begin(owner, config(dir.path())?, create())?;
        let path = dir.path().join("foreground-setup.json");
        if mutation == "changed" {
            std::fs::write(&path, b"{}")?;
            assert!(setup.open_authority().is_err());
            assert_eq!(std::fs::read(&path)?, b"{}");
            assert!(!recorded.lock().unwrap().ops.iter().any(|op| op == "create"));
        }
        drop(setup);
        match mutation {
            "duplicate" => std::fs::write(&path, b"{\"schema\":1,\"schema\":1}")?,
            "oversized" => std::fs::write(&path, vec![b' '; 4097])?,
            "missing" => std::fs::remove_file(&path)?, // Disposable fixture mutation only.
            _ => {}
        }
        let (owner, calls) = runtime(true, "");
        assert!(ForegroundSetup::begin(owner, config(dir.path())?, SetupChoice::Open).is_err());
        assert!(calls.lock().unwrap().ops.is_empty());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn native_storage_refuses_linked_configuration_or_journals() -> Result<()> {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir()?;
    let other = tempfile::tempdir()?;
    symlink(other.path(), dir.path().join("linked"))?;
    assert!(NativeSetupConfig::new(dir.path().join("linked")).is_err());
    let (owner, _) = runtime(false, "");
    let setup = ForegroundSetup::begin(owner, config(dir.path())?, create())?;
    drop(setup);
    let path = dir.path().join("foreground-setup.json");
    let retained = std::fs::read(&path)?;
    std::fs::rename(&path, other.path().join("saved"))?;
    symlink(other.path().join("saved"), &path)?;
    let (owner, _) = runtime(true, "");
    assert!(ForegroundSetup::begin(owner, config(dir.path())?, SetupChoice::Open).is_err());
    assert_eq!(retained, std::fs::read(other.path().join("saved"))?);
    Ok(())
}

#[test]
fn create_that_never_reached_its_authority_can_be_abandoned_and_retried() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (owner, _) = runtime(false, "fail_create");
    let mut setup = ForegroundSetup::begin(owner, config(dir.path())?, create())?;
    assert!(setup.open_authority().is_err());
    drop(setup);
    // The recorded attempt alone refuses another Create.
    let (owner, _) = runtime(false, "");
    assert!(ForegroundSetup::begin(owner, config(dir.path())?, create()).is_err());
    // A backend that still holds custody or state keeps the record for review.
    let (owner, _) = runtime(true, "");
    assert!(!abandon_unstarted_create(owner, &config(dir.path())?)?);
    assert!(dir.path().join("foreground-setup.json").exists());
    // Nothing anywhere: the record goes, and Create starts again.
    let (owner, _) = runtime(false, "");
    assert!(abandon_unstarted_create(owner, &config(dir.path())?)?);
    assert!(std::fs::read_dir(dir.path())?.next().is_none());
    let (owner, _) = runtime(false, "");
    let mut setup = ForegroundSetup::begin(owner, config(dir.path())?, create())?;
    setup.open_authority()?;
    Ok(())
}

#[test]
fn setup_that_reached_its_authority_is_never_abandoned() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (owner, _) = runtime(false, "");
    let mut setup = ForegroundSetup::begin(owner, config(dir.path())?, create())?;
    setup.open_authority()?;
    drop(setup);
    let (owner, _) = runtime(false, "");
    assert!(abandon_unstarted_create(owner, &config(dir.path())?).is_err());
    assert!(dir.path().join("foreground-setup.json").exists());
    Ok(())
}
