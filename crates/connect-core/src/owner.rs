//! Owner-computer orchestration. Only a local inherited pipe reaches the sidecar.
//! No operator credentials or generic administrative requests cross device links.
pub mod foreground;
pub mod inspection;
pub mod native;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerInfo {
    pub url: String,
    pub pin: crate::authority::TrustPin,
    pub managed: bool,
}

/// Fixed embedded discovery, without desktop files or authority activation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedStatus {
    pub configured: bool,
    pub running: bool,
    pub foreground_only: bool,
    pub production_create_enabled: bool,
}

/// Readiness of the fixed adapter reached over our inherited local pipe.
/// This does not describe remote-owner enrollment, all core flags, or permission.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapabilities {
    pub schema: u8,
    pub core_version: String,
    pub pin: crate::authority::TrustPin,
    pub transport: String,
    pub operations: Vec<String>,
}
pub(crate) fn required_core_version() -> Result<&'static str> {
    include_str!("../../../apps/connect/authority/core-requirements.txt")
        .lines()
        .find_map(|line| line.trim().strip_prefix("genesis-mesh=="))
        .context("Missing packaged authority version")
}
impl RuntimeCapabilities {
    pub fn require_pairing(&self, pin: &crate::authority::TrustPin) -> Result<()> {
        ensure!(
            self.schema == 1
                && matches!(
                    self.transport.as_str(),
                    "local_inherited_pipe" | "local_android_embedded"
                )
                && self.core_version == required_core_version()?
                && &self.pin == pin
                && self
                    .operations
                    .iter()
                    .any(|op| op == "connect.pairing.requests.v1"),
            "Update the managed network computer before using pairing Requests"
        );
        Ok(())
    }
    pub fn require_access_update(&self, pin: &crate::authority::TrustPin) -> Result<()> {
        let expected = required_core_version()?;
        ensure!(
            self.schema == 1
                && matches!(
                    self.transport.as_str(),
                    "local_inherited_pipe" | "local_android_embedded"
                ),
            "Update the network computer: its Connect adapter is incompatible"
        );
        ensure!(
            self.core_version == expected,
            "Update the network computer: its Genesis Mesh version is incompatible"
        );
        ensure!(
            &self.pin == pin,
            "The network computer belongs to a different network"
        );
        ensure!(
            self.operations
                .iter()
                .any(|op| op == "connect.access.update.v1"),
            "Update the network computer to manage access"
        );
        Ok(())
    }
}

/// A staged network: the owner keys (plaintext, held only in memory) and the
/// staging directory holding the database snapshot and public files.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerBackup {
    pub staging: std::path::PathBuf,
    pub root: String,
    pub config: String,
    pub keys: std::collections::BTreeMap<String, String>,
}
impl Drop for OwnerBackup {
    fn drop(&mut self) {
        for value in self.keys.values_mut() {
            zeroize::Zeroize::zeroize(value);
        }
    }
}

/// One device's folder shared with chosen devices, as the network computer's
/// registry keeps it. The authority holds its policy and the host's attestation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Space {
    pub collection: String,
    pub name: String,
    pub host: String,
    /// Entries from before inboxes have no kind: they are folders.
    #[serde(default)]
    pub kind: crate::session::sharing::SpaceKind,
    pub subject: String,
    pub recipients: Vec<String>,
    pub created_at: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub attestation_id: String,
    pub valid_until: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_expires_at: Option<String>,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicy {
    #[cfg_attr(
        feature = "operation-schemas",
        schemars(range(min = 1, max = 9007199254740991u64))
    )]
    pub version: u64,
    #[cfg_attr(feature = "operation-schemas", schemars(length(min = 1, max = 31)))]
    pub recipients: Vec<String>,
    #[cfg_attr(
        feature = "operation-schemas",
        schemars(with = "Option<chrono::DateTime<chrono::Utc>>")
    )]
    pub expires_at: Option<String>,
    #[cfg_attr(
        feature = "operation-schemas",
        schemars(range(min = 1, max = 9007199254740991u64))
    )]
    pub max_bytes: u64,
    #[cfg_attr(feature = "operation-schemas", schemars(range(min = 1, max = 3600)))]
    pub max_seconds: u32,
    /// Core validates gate types and semantics. Native code also bounds encoded
    /// rule bytes and checks reserved/duplicate IDs; JSON Schema alone cannot.
    #[cfg_attr(feature = "operation-schemas", schemars(length(max = 24)))]
    pub extra_gates: Vec<Value>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessUpdate {
    pub space: Space,
    pub settings: AccessPolicy,
}

/// What removing a device from the network did.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Removal {
    /// Certificates revoked now; none when it was removed before, or never
    /// joined as a device of its own.
    pub revoked: u32,
    /// Spaces stopped: those it shared, and those left with nobody.
    pub stopped: Vec<String>,
    /// Spaces that no longer name it.
    pub changed: Vec<String>,
}

/// The Spaces `host` still has in the registry but no longer shares: saved
/// shares count, running or not, so a folder that could not be opened is
/// never mistaken for a stopped one.
pub fn orphaned(
    spaces: &[Space],
    host: &str,
    saved: &[crate::session::sharing::ShareConfig],
) -> Vec<String> {
    spaces
        .iter()
        .filter(|space| {
            space.host == host && !saved.iter().any(|s| s.collection_id == space.collection)
        })
        .map(|space| space.collection.clone())
        .collect()
}

/// What the network computer's authority bridge asks of the owner runtime on
/// a device's behalf. The host is always the authenticated device.
#[derive(Debug)]
pub enum OwnerCall {
    PairingCompletion {
        node: String,
        certificate: Value,
        query: crate::device::pairing_completion::CompletionQuery,
    },
    Control {
        node: String,
        certificate: Value,
        request: crate::owner_control::ControlEnvelope,
    },
    ResourceCapabilities {
        host: String,
        collection: String,
    },
    /// Create or change a Space for `host`; never adopts an existing policy.
    Share {
        host: String,
        collection: String,
        name: String,
        recipients: Vec<String>,
        kind: crate::session::sharing::SpaceKind,
    },
    Access {
        host: String,
        collection: String,
        settings: Option<AccessPolicy>,
    },
    Remove {
        host: String,
        collection: String,
    },
}
pub struct OwnerRequest {
    pub call: OwnerCall,
    pub reply: tokio::sync::oneshot::Sender<Result<Value>>,
}
/// The bridge's way to the owner runtime: whoever holds the runtime (the app
/// or the node) answers each request in turn.
pub type OwnerHandle = tokio::sync::mpsc::Sender<OwnerRequest>;

/// Copying a large authority database takes longer than ordinary operations.
const RECOVERY_LIMIT: Duration = Duration::from_secs(600);

/// Trusted native application adapter, never an IPC command or remote proxy.
/// Implementations serialize fixed operations and keep custody inside native code.
pub trait NativeOwnerTransport: Send {
    fn request(&mut self, request: Value) -> Result<Value>;
    fn close(&mut self);
}

pub struct OwnerRuntime {
    child: Option<Child>,
    input: Option<ChildStdin>,
    replies: mpsc::Receiver<Value>,
    /// A request was sent and its final reply has not been read.
    awaiting: bool,
    native: Option<Box<dyn NativeOwnerTransport>>,
    native_failed: bool,
}
impl OwnerRuntime {
    pub fn embedded_status(&mut self) -> Result<EmbeddedStatus> {
        ensure!(
            self.native.is_some(),
            "Embedded discovery requires a native backend"
        );
        let status: EmbeddedStatus = serde_json::from_value(self.request(json!({"op":"status"}))?)?;
        ensure!(
            status.foreground_only && !status.production_create_enabled,
            "Unsupported embedded authority profile"
        );
        Ok(status)
    }
    pub fn pairing_ready(&mut self, pin: &crate::authority::TrustPin) -> Result<()> {
        let readiness: RuntimeCapabilities =
            serde_json::from_value(self.request(json!({"op":"pairing_ready"}))?)?;
        readiness.require_pairing(pin)
    }
    /// Only the native app selects this backend; frontend input cannot supply it.
    pub fn from_native(transport: Box<dyn NativeOwnerTransport>) -> Self {
        let (_, replies) = mpsc::channel();
        Self {
            child: None,
            input: None,
            replies,
            awaiting: false,
            native: Some(transport),
            native_failed: false,
        }
    }
    pub fn resource_capabilities(
        &mut self,
        host: &str,
        collection: &str,
    ) -> Result<crate::operations::ResourceCapabilities> {
        Ok(serde_json::from_value(self.request(
            json!({"op":"resource_capabilities","host":host,"collection":collection}),
        )?)?)
    }
    pub fn capabilities(&mut self) -> Result<RuntimeCapabilities> {
        Ok(serde_json::from_value(
            self.request(json!({"op":"capabilities"}))?,
        )?)
    }
    pub fn start(executable: &Path, directory: &Path) -> Result<Self> {
        ensure!(
            executable.is_absolute() && directory.is_absolute(),
            "Invalid local runtime path"
        );
        let mut command = Command::new(executable);
        command.arg("--state").arg(directory);
        Self::spawn(command)
    }

    /// Explicit developer/test entry point; release applications use a bundled
    /// sidecar, never an implicit dependency on a developer Python installation.
    #[cfg(debug_assertions)]
    pub fn start_python(python: &Path, script: &Path, directory: &Path) -> Result<Self> {
        ensure!(
            python.is_absolute() && script.is_absolute() && directory.is_absolute(),
            "Invalid developer runtime path"
        );
        let mut command = Command::new(python);
        command
            .arg("-u")
            .arg(script)
            .arg("--state")
            .arg(directory)
            .env("PYTHONDONTWRITEBYTECODE", "1");
        Self::spawn(command)
    }

    fn spawn(mut command: Command) -> Result<Self> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        command.env("CONNECT_NATIVE_SECRETS", "1");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("The local network runtime could not start")?;
        let input = child.stdin.take().context("Missing network setup pipe")?;
        let output = child
            .stdout
            .take()
            .context("Missing network response pipe")?;
        let (sender, replies) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            loop {
                let mut line = Vec::new();
                let outcome = Read::by_ref(&mut reader)
                    .take(64 * 1024 + 1)
                    .read_until(b'\n', &mut line);
                if !matches!(outcome, Ok(size) if size > 0 && size <= 64 * 1024) {
                    break;
                }
                let parsed = serde_json::from_slice(&line);
                // Replies can carry owner keys for a recovery file.
                zeroize::Zeroize::zeroize(&mut line);
                let Ok(value) = parsed else {
                    break;
                };
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        let runtime = Self {
            child: Some(child),
            input: Some(input),
            replies,
            awaiting: false,
            native: None,
            native_failed: false,
        };
        let hello = runtime
            .replies
            .recv_timeout(Duration::from_secs(30))
            .context("The local network runtime did not become ready")?;
        ensure!(
            hello == json!({"protocol":1}),
            "Unexpected local network runtime"
        );
        Ok(runtime)
    }

    fn request(&mut self, request: Value) -> Result<Value> {
        self.request_within(request, Duration::from_secs(30))
    }

    /// One fixed operation. If it fails after the request was sent and before
    /// its final reply arrived (a timeout, say), the runtime is stopped for
    /// good: a late reply must never be read as the answer to a later request.
    fn request_within(&mut self, request: Value, limit: Duration) -> Result<Value> {
        if let Some(native) = self.native.as_mut() {
            ensure!(
                !self.native_failed,
                "Restart Connect to review the unfinished local operation"
            );
            ensure!(
                !matches!(
                    request.get("op").and_then(Value::as_str),
                    Some("backup" | "restore" | "attach")
                ),
                "This native authority does not export keys or import desktop settings"
            );
            ensure!(
                serde_json::to_vec(&request)?.len() <= 16 * 1024,
                "Network setup request is too large"
            );
            let outcome = native.request(request).and_then(|reply| {
                ensure!(
                    serde_json::to_vec(&reply)?.len() <= 512 * 1024,
                    "Network reply is too large"
                );
                Ok(reply)
            });
            if outcome.is_err() {
                self.native_failed = true;
            }
            return outcome;
        }
        let outcome = self.exchange(request, limit);
        if outcome.is_err() && self.awaiting {
            self.input.take();
            if let Some(child) = self.child.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        outcome
    }

    fn exchange(&mut self, request: Value, limit: Duration) -> Result<Value> {
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&request)?);
        drop(request);
        ensure!(
            bytes.len() <= 16 * 1024,
            "Network setup request is too large"
        );
        let input = self.input.as_mut().context("Network runtime was closed")?;
        self.awaiting = true;
        input.write_all(&bytes)?;
        input.write_all(b"\n")?;
        input.flush()?;
        let deadline = std::time::Instant::now() + limit;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let mut storage_operations = 0;
        // Other targets have no nested native-store requests; their first
        // runtime response is the operation's final result.
        #[cfg_attr(
            not(any(target_os = "macos", target_os = "linux")),
            allow(clippy::never_loop)
        )]
        let mut reply = loop {
            #[allow(unused_mut)] // Native storage replies are handled only on Unix desktops.
            let Ok(mut reply) = self
                .replies
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            else {
                anyhow::bail!(
                    "The local network operation did not finish. Restart Connect to reopen your network."
                );
            };
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if let Some(request) = reply.get_mut("native_storage") {
                storage_operations += 1;
                ensure!(storage_operations <= 16, "Too many native storage requests");
                let result = crate::device::owner_store::request(request);
                // Clear key-bearing JSON as soon as the private reply is sent.
                *request = Value::Null;
                let mut response = zeroize::Zeroizing::new(serde_json::to_vec(&match result {
                    Ok(value) => json!({"ok":value}),
                    Err(_) => {
                        json!({"error":"Unlock the system credential store to use the saved network owner keys. Existing state was preserved."})
                    }
                })?);
                let input = self.input.as_mut().context("Network runtime was closed")?;
                input.write_all(&response)?;
                input.write_all(b"\n")?;
                input.flush()?;
                response.clear();
                continue;
            }
            break reply;
        };
        self.awaiting = false;
        if let Some(error) = reply.get("error").and_then(Value::as_str) {
            anyhow::bail!("{}", error);
        }
        reply
            .get_mut("ok")
            .map(Value::take)
            .context("Invalid local network response")
    }
    pub fn create(&mut self, name: &str) -> Result<OwnerInfo> {
        Ok(serde_json::from_value(
            self.request(json!({"op":"create","name":name}))?,
        )?)
    }
    pub fn open(&mut self) -> Result<OwnerInfo> {
        Ok(serde_json::from_value(self.request(json!({"op":"open"}))?)?)
    }
    pub fn attach(&mut self, config: &Path) -> Result<OwnerInfo> {
        Ok(serde_json::from_value(
            self.request(json!({"op":"attach","config":config}))?,
        )?)
    }
    /// Whether the authority process is still running and usable. It is not
    /// after it exited, or after a request it never answered.
    pub fn is_running(&mut self) -> bool {
        if self.native.is_some() {
            return !self.native_failed;
        }
        self.input.is_some()
            && self
                .child
                .as_mut()
                .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
    }
    /// Stage the network for a recovery file: files inside the owner's private
    /// directory, the owner keys only in this reply.
    pub fn backup(&mut self) -> Result<OwnerBackup> {
        // A phone's own owner stages its network in its private storage, after
        // the root key's authentication; a desktop owner stages its directory.
        let op = if self.native.is_some() {
            "recovery_export"
        } else {
            "backup"
        };
        let backup: OwnerBackup =
            serde_json::from_value(self.request_within(json!({ "op": op }), RECOVERY_LIMIT)?)?;
        ensure!(
            backup.staging.is_absolute() && !backup.keys.is_empty() && backup.keys.len() <= 16,
            "Invalid network recovery staging"
        );
        Ok(backup)
    }
    /// Install a network from files staged beside the owner directory.
    pub fn restore(
        &mut self,
        staging: &Path,
        root: &str,
        config: &str,
        keys: &std::collections::BTreeMap<String, String>,
    ) -> Result<OwnerInfo> {
        let request = if self.native.is_some() {
            // Only the network's four identity keys, from files native code staged.
            ensure!(
                staging.is_absolute()
                    && keys
                        .keys()
                        .map(String::as_str)
                        .eq(["member", "na", "operator", "root"]),
                "The recovery file is incomplete"
            );
            json!({"op":"recovery_import","staging":staging,"keys":keys})
        } else {
            json!({"op":"restore","staging":staging,"root":root,"config":config,"keys":keys})
        };
        Ok(serde_json::from_value(
            self.request_within(request, RECOVERY_LIMIT)?,
        )?)
    }
    pub fn invite(&mut self, node: &str, host: bool) -> Result<String> {
        self.request(json!({"op":"invite","node":node,"host":host}))?["invite"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 512)
            .map(str::to_owned)
            .context("The network did not provide an invitation")
    }
    /// Create a Space, or change its name and devices; only its host may.
    /// `subject` is for a desktop enrolled before devices had their own.
    pub fn space_share(
        &mut self,
        host: &str,
        collection: &str,
        name: &str,
        recipients: &[String],
        subject: Option<&str>,
        kind: crate::session::sharing::SpaceKind,
    ) -> Result<Space> {
        let mut request = json!({"op":"space_share","host":host,"collection":collection,"name":name,"recipients":recipients,"kind":kind});
        if let Some(subject) = subject {
            request["subject"] = json!(subject);
        }
        Ok(serde_json::from_value(self.request(request)?)?)
    }
    /// Give a folder this computer shared before Spaces its registry entry,
    /// keeping its existing policy. Never offered to other devices.
    pub fn space_adopt(
        &mut self,
        host: &str,
        collection: &str,
        name: &str,
        recipients: &[String],
        subject: &str,
    ) -> Result<Space> {
        Ok(serde_json::from_value(self.request(json!({
            "op":"space_adopt","host":host,"collection":collection,"name":name,
            "recipients":recipients,"subject":subject,
        }))?)?)
    }
    /// Stop a Space: its policy is deactivated. False if it did not exist.
    pub fn space_remove(&mut self, host: &str, collection: &str) -> Result<bool> {
        Ok(serde_json::from_value(self.request(
            json!({"op":"space_remove","host":host,"collection":collection}),
        )?)?)
    }
    /// Take a device off the network: its certificates are revoked, its
    /// Spaces stop, and the Spaces shared with it no longer name it. Asking
    /// again finishes what a failure left undone.
    pub fn remove_device(&mut self, node: &str) -> Result<Removal> {
        Ok(serde_json::from_value(
            self.request(json!({"op":"remove_device","node":node}))?,
        )?)
    }
    pub fn space_list(&mut self) -> Result<Vec<Space>> {
        Ok(serde_json::from_value(
            self.request(json!({"op":"space_list"}))?,
        )?)
    }
    pub fn access_get(&mut self, host: &str, collection: &str) -> Result<AccessPolicy> {
        Ok(serde_json::from_value(self.request(
            json!({"op":"access_get","host":host,"collection":collection}),
        )?)?)
    }
    pub fn access_update(
        &mut self,
        host: &str,
        collection: &str,
        settings: &AccessPolicy,
    ) -> Result<AccessUpdate> {
        Ok(serde_json::from_value(self.request(
            json!({"op":"access_update","host":host,"collection":collection,"settings":settings}),
        )?)?)
    }
    /// Renew the Spaces whose policy ends within 30 days; returns them.
    pub fn space_renew(&mut self) -> Result<Vec<String>> {
        Ok(serde_json::from_value(
            self.request(json!({"op":"space_renew"}))?,
        )?)
    }
    /// Answer one bridge request.
    pub fn answer(&mut self, call: OwnerCall) -> Result<Value> {
        Ok(match call {
            OwnerCall::Control { .. } | OwnerCall::PairingCompletion { .. } => anyhow::bail!(
                "Update the network computer: this host has no owner Requests adapter"
            ),
            OwnerCall::ResourceCapabilities { host, collection } => {
                serde_json::to_value(self.resource_capabilities(&host, &collection)?)?
            }
            OwnerCall::Share {
                host,
                collection,
                name,
                recipients,
                kind,
            } => serde_json::to_value(self.space_share(
                &host,
                &collection,
                &name,
                &recipients,
                None,
                kind,
            )?)?,
            OwnerCall::Access {
                host,
                collection,
                settings,
            } => match settings {
                Some(settings) => {
                    serde_json::to_value(self.access_update(&host, &collection, &settings)?)?
                }
                None => serde_json::to_value(self.access_get(&host, &collection)?)?,
            },
            OwnerCall::Remove { host, collection } => {
                json!(self.space_remove(&host, &collection)?)
            }
        })
    }
    pub fn share(&mut self, host: &str, peer: &str, collection: &str) -> Result<Value> {
        self.request(json!({"op":"share","host":host,"peer":peer,"collection":collection}))
    }
    pub fn share_for_subject(
        &mut self,
        host: &str,
        peer: &str,
        collection: &str,
        subject: &str,
    ) -> Result<Value> {
        self.request(
            json!({"op":"share","host":host,"peer":peer,"collection":collection,"subject":subject}),
        )
    }
}
impl Drop for OwnerRuntime {
    fn drop(&mut self) {
        if let Some(native) = self.native.as_mut() {
            native.close();
        }
        let Some(child) = self.child.as_mut() else {
            return;
        };
        // EOF lets the managed authority close its server and SQLite database.
        self.input.take();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_is_not_inferred_from_an_operation_name_or_version_alone() -> Result<()> {
        let pin = crate::authority::TrustPin {
            root_public_key: "root".into(),
            network_name: "Home".into(),
        };
        let version = include_str!("../../../apps/connect/authority/core-requirements.txt")
            .lines()
            .find_map(|line| line.trim().strip_prefix("genesis-mesh=="))
            .unwrap();
        let valid = json!({"schema":1,"core_version":version,"pin":pin,"transport":"local_inherited_pipe","operations":["connect.access.update.v1"]});
        serde_json::from_value::<RuntimeCapabilities>(valid.clone())?
            .require_access_update(&pin)?;
        for (field, value) in [
            ("schema", json!(2)),
            ("core_version", json!("0.0.0")),
            ("transport", json!("remote")),
            ("operations", json!([])),
            (
                "pin",
                json!({"network_name":"Other","root_public_key":"other"}),
            ),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(
                serde_json::from_value::<RuntimeCapabilities>(changed)?
                    .require_access_update(&pin)
                    .is_err()
            );
        }
        let mut untyped = valid;
        untyped["admin_url"] = json!("https://untrusted.invalid");
        assert!(serde_json::from_value::<RuntimeCapabilities>(untyped).is_err());
        Ok(())
    }

    #[test]
    fn only_spaces_the_host_no_longer_saves_are_orphaned() {
        let space = |collection: &str, host: &str| Space {
            access_expires_at: None,
            collection: collection.into(),
            name: "Photos".into(),
            host: host.into(),
            kind: Default::default(),
            subject: "connect-device-test".into(),
            recipients: vec!["phone".into()],
            created_at: "2026-10-27T00:00:00+00:00".into(),
            policy_id: format!("connect-{collection}"),
            policy_version: 1,
            attestation_id: "a".into(),
            valid_until: "2027-01-25T00:00:00+00:00".into(),
        };
        let saved = |collection: &str| crate::session::sharing::ShareConfig {
            collection_id: collection.into(),
            ..Default::default()
        };
        let spaces = [
            space("kept", "computer"),
            space("stopped", "computer"),
            space("theirs", "laptop"),
        ];
        assert_eq!(
            orphaned(&spaces, "computer", &[saved("kept")]),
            ["stopped"],
            "A saved share stays even when it could not be opened"
        );
        assert!(orphaned(&spaces, "computer", &[saved("kept"), saved("stopped")]).is_empty());
        assert_eq!(orphaned(&spaces, "laptop", &[]), ["theirs"]);
    }
}
