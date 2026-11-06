//! Native backend protocol/lifetime checks, without native custody claims.
use anyhow::{Result, bail};
use connect_core::{
    authority::TrustPin,
    owner::{NativeOwnerTransport, OwnerRuntime},
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Observed {
    calls: Vec<Value>,
    closes: usize,
}
enum Reply {
    Normal,
    Failed,
    Oversized,
}
struct Native {
    observed: Arc<Mutex<Observed>>,
    reply: Reply,
}
impl NativeOwnerTransport for Native {
    fn request(&mut self, request: Value) -> Result<Value> {
        self.observed.lock().unwrap().calls.push(request.clone());
        match self.reply {
            Reply::Failed => bail!("Unconfirmed native result"),
            Reply::Oversized => return Ok(json!("x".repeat(512 * 1024))),
            Reply::Normal => {}
        }
        let pin = json!({"root_public_key":"root", "network_name":"Home"});
        Ok(match request["op"].as_str().unwrap() {
            "create" | "open" => json!({"url":"http://127.0.0.1:12345", "pin":pin, "managed":true}),
            "capabilities" | "pairing_ready" => json!({"schema":1,
                "core_version":include_str!("../../../apps/connect/authority/core-requirements.txt").lines()
                    .find_map(|line| line.trim().strip_prefix("genesis-mesh==")).unwrap(),
                "pin":pin,"transport":"local_android_embedded",
                "operations":["connect.access.update.v1", "connect.pairing.requests.v1"]}),
            "space_list" => json!([]),
            _ => bail!("Unexpected fixture operation"),
        })
    }
    fn close(&mut self) {
        self.observed.lock().unwrap().closes += 1;
    }
}
fn runtime(reply: Reply) -> (OwnerRuntime, Arc<Mutex<Observed>>) {
    let observed = Arc::new(Mutex::new(Observed::default()));
    (
        OwnerRuntime::from_native(Box::new(Native {
            observed: observed.clone(),
            reply,
        })),
        observed,
    )
}

#[test]
fn typed_native_calls_use_existing_capability_checks_and_close_once() -> Result<()> {
    let (mut owner, observed) = runtime(Reply::Normal);
    let info = owner.create("Home")?;
    let pin = TrustPin {
        root_public_key: "root".into(),
        network_name: "Home".into(),
    };
    assert_eq!(info.pin, pin);
    owner.capabilities()?.require_access_update(&pin)?;
    owner.pairing_ready(&pin)?;
    assert!(owner.space_list()?.is_empty());
    assert!(owner.is_running());
    drop(owner);
    let observed = observed.lock().unwrap();
    assert_eq!(observed.calls.len(), 4);
    assert_eq!(observed.calls[0], json!({"op":"create", "name":"Home"}));
    assert_eq!(observed.closes, 1);
    Ok(())
}

#[test]
fn uncertain_native_reply_cannot_be_replayed_or_followed_by_another_operation() {
    let (mut owner, observed) = runtime(Reply::Failed);
    assert!(owner.open().is_err());
    assert!(!owner.is_running());
    assert!(owner.open().is_err());
    assert_eq!(observed.lock().unwrap().calls.len(), 1);
    drop(owner);
    assert_eq!(observed.lock().unwrap().closes, 1);
}

#[test]
fn native_backend_cannot_export_keys_or_import_paths() {
    let (mut owner, observed) = runtime(Reply::Normal);
    assert!(owner.backup().is_err());
    assert!(owner.attach(Path::new("/untrusted/settings")).is_err());
    assert!(
        owner
            .restore(
                Path::new("/untrusted/staging"),
                "root",
                "config",
                &Default::default()
            )
            .is_err()
    );
    assert!(observed.lock().unwrap().calls.is_empty());
    assert!(owner.is_running());
}

#[test]
fn oversized_request_never_dispatches_and_oversized_reply_stops_reuse() {
    let (mut owner, observed) = runtime(Reply::Normal);
    assert!(owner.create(&"x".repeat(16 * 1024)).is_err());
    assert!(observed.lock().unwrap().calls.is_empty());
    let (mut oversized, observed) = runtime(Reply::Oversized);
    assert!(oversized.open().is_err());
    assert!(!oversized.is_running());
    assert!(oversized.open().is_err());
    assert_eq!(observed.lock().unwrap().calls.len(), 1);
}
