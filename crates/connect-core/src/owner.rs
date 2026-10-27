//! Owner-computer orchestration. Only a local inherited pipe reaches the sidecar.
//! No operator credentials or generic administrative requests cross device links.
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
    pub subject: String,
    pub recipients: Vec<String>,
    pub created_at: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub attestation_id: String,
    pub valid_until: String,
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
    /// Create or change a Space for `host`; never adopts an existing policy.
    Share {
        host: String,
        collection: String,
        name: String,
        recipients: Vec<String>,
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

pub struct OwnerRuntime {
    child: Child,
    input: Option<ChildStdin>,
    replies: mpsc::Receiver<Value>,
    /// A request was sent and its final reply has not been read.
    awaiting: bool,
}
impl OwnerRuntime {
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
            child,
            input: Some(input),
            replies,
            awaiting: false,
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
        let outcome = self.exchange(request, limit);
        if outcome.is_err() && self.awaiting {
            self.input.take();
            let _ = self.child.kill();
            let _ = self.child.wait();
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
        self.input.is_some() && matches!(self.child.try_wait(), Ok(None))
    }
    /// Stage the network for a recovery file: files inside the owner's private
    /// directory, the owner keys only in this reply.
    pub fn backup(&mut self) -> Result<OwnerBackup> {
        let backup: OwnerBackup =
            serde_json::from_value(self.request_within(json!({"op":"backup"}), RECOVERY_LIMIT)?)?;
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
        Ok(serde_json::from_value(self.request_within(
            json!({"op":"restore","staging":staging,"root":root,"config":config,"keys":keys}),
            RECOVERY_LIMIT,
        )?)?)
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
    ) -> Result<Space> {
        let mut request = json!({"op":"space_share","host":host,"collection":collection,"name":name,"recipients":recipients});
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
    pub fn space_list(&mut self) -> Result<Vec<Space>> {
        Ok(serde_json::from_value(
            self.request(json!({"op":"space_list"}))?,
        )?)
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
            OwnerCall::Share {
                host,
                collection,
                name,
                recipients,
            } => serde_json::to_value(self.space_share(
                &host,
                &collection,
                &name,
                &recipients,
                None,
            )?)?,
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
        // EOF lets the managed authority close its server and SQLite database.
        self.input.take();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_spaces_the_host_no_longer_saves_are_orphaned() {
        let space = |collection: &str, host: &str| Space {
            collection: collection.into(),
            name: "Photos".into(),
            host: host.into(),
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
