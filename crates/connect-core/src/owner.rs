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

pub struct OwnerRuntime {
    child: Child,
    input: Option<ChildStdin>,
    replies: mpsc::Receiver<Value>,
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
                let Ok(value) = serde_json::from_slice(&line) else {
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
        let bytes = serde_json::to_vec(&request)?;
        ensure!(
            bytes.len() <= 16 * 1024,
            "Network setup request is too large"
        );
        let input = self.input.as_mut().context("Network runtime was closed")?;
        input.write_all(&bytes)?;
        input.write_all(b"\n")?;
        input.flush()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let mut storage_operations = 0;
        // Other targets have no nested native-store requests; their first
        // runtime response is the operation's final result.
        #[cfg_attr(
            not(any(target_os = "macos", target_os = "linux")),
            allow(clippy::never_loop)
        )]
        let reply = loop {
            #[allow(unused_mut)] // Native storage replies are handled only on Unix desktops.
            let mut reply = self
                .replies
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .context("The local network operation did not finish")?;
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
        if let Some(error) = reply.get("error").and_then(Value::as_str) {
            anyhow::bail!("{}", error);
        }
        reply
            .get("ok")
            .cloned()
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
    /// Stage the network for a recovery file: files inside the owner's private
    /// directory, the owner keys only in this reply.
    pub fn backup(&mut self) -> Result<OwnerBackup> {
        let backup: OwnerBackup = serde_json::from_value(self.request(json!({"op":"backup"}))?)?;
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
        Ok(serde_json::from_value(self.request(json!({
            "op":"restore","staging":staging,"root":root,"config":config,"keys":keys
        }))?)?)
    }
    pub fn invite(&mut self, node: &str, host: bool) -> Result<String> {
        self.request(json!({"op":"invite","node":node,"host":host}))?["invite"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 512)
            .map(str::to_owned)
            .context("The network did not provide an invitation")
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
