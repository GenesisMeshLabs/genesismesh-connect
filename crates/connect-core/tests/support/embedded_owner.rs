//! Disposable native-backend/core fixtures, never devices or startup-failure tests.
#![allow(dead_code)] // Shared helpers serve separately selected fixture binaries.

use anyhow::{Context, Result, ensure};
use connect_core::owner::{
    NativeOwnerTransport, OwnerRuntime,
    foreground::{ForegroundSetup, NativeSetupConfig, SetupChoice},
};
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Mutex, OnceLock, mpsc},
    time::Duration,
};
use zeroize::Zeroizing;

pub fn sealed_store() {
    static STORE: OnceLock<tempfile::TempDir> = OnceLock::new();
    STORE.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [9u8; 32]).unwrap();
        connect_core::device::use_sealed_store(dir.path().join("sealed"), &key).unwrap();
        dir
    });
}
struct Fixture {
    child: Child,
    input: ChildStdin,
    replies: mpsc::Receiver<Value>,
    lose: Loss,
    invite: Arc<Mutex<Option<Zeroizing<String>>>>,
}
impl NativeOwnerTransport for Fixture {
    fn request(&mut self, request: Value) -> Result<Value> {
        writeln!(self.input, "{}", serde_json::to_string(&request)?)?;
        self.input.flush()?;
        let reply = self.replies.recv_timeout(Duration::from_secs(20))?;
        let lost = {
            let mut loss = self.lose.lock().unwrap();
            if *loss == request["op"].as_str() {
                loss.take();
                true
            } else {
                false
            }
        };
        if lost {
            anyhow::bail!("Fixture lost native response");
        }
        ensure!(
            reply.get("error").is_none(),
            "Fixture core operation refused: {}",
            reply["error"]
        );
        let result = reply.get("ok").cloned().context("Missing fixture result")?;
        if request["op"] == "invite" {
            *self.invite.lock().unwrap() = Some(Zeroizing::new(
                result["invite"]
                    .as_str()
                    .context("Missing fixture invite")?
                    .into(),
            ));
        }
        Ok(result)
    }
    fn close(&mut self) {
        let _ = writeln!(self.input, "{{\"fixture_close\":true}}");
        let _ = self.input.flush();
        let _ = self.child.wait();
    }
}
pub type Loss = Arc<Mutex<Option<&'static str>>>;
pub type Invite = Arc<Mutex<Option<Zeroizing<String>>>>;
pub fn backend(path: &Path, lose: Option<&'static str>) -> Result<(OwnerRuntime, Invite)> {
    let (runtime, invite, _) = controlled_backend(path, lose)?;
    Ok((runtime, invite))
}
pub fn controlled_backend(
    path: &Path,
    lose: Option<&'static str>,
) -> Result<(OwnerRuntime, Invite, Loss)> {
    let python = std::env::var_os("CONNECT_FOREGROUND_FIXTURE_PYTHON")
        .context("Set the disposable fixture's pinned-core Python")?;
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/foreground_owner.py");
    let mut child = Command::new(python)
        .arg(script)
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let input = child.stdin.take().unwrap();
    let output = child.stdout.take().unwrap();
    let (tx, replies) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(output);
        loop {
            let mut line = vec![];
            if !matches!(Read::by_ref(&mut reader).take(512*1024+1).read_until(b'\n', &mut line), Ok(n) if n>0 && n<=512*1024)
            {
                break;
            }
            let parsed = serde_json::from_slice(&line);
            zeroize::Zeroize::zeroize(&mut line);
            let Ok(value) = parsed else { break };
            if tx.send(value).is_err() {
                break;
            }
        }
    });
    let invite = Arc::new(Mutex::new(None));
    let lose = Arc::new(Mutex::new(lose));
    Ok((
        OwnerRuntime::from_native(Box::new(Fixture {
            child,
            input,
            replies,
            lose: lose.clone(),
            invite: invite.clone(),
        })),
        invite,
        lose,
    ))
}
pub fn begin(
    root: &Path,
    choice: SetupChoice,
    lose: Option<&'static str>,
) -> Result<ForegroundSetup> {
    sealed_store();
    let native = root.join("native");
    std::fs::create_dir_all(&native)?;
    let (runtime, _) = backend(&root.join("backend"), lose)?;
    ForegroundSetup::begin(runtime, NativeSetupConfig::new(native)?, choice)
}
pub fn calls(root: &Path, op: &str) -> usize {
    std::fs::read_to_string(root.join("backend/fixture-calls.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| serde_json::from_str::<String>(line).unwrap() == op)
        .count()
}
pub fn core_calls(root: &Path, route: &str) -> usize {
    std::fs::read_to_string(root.join("backend/fixture-http.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter(|line| serde_json::from_str::<String>(line).unwrap() == route)
        .count()
}
pub fn create() -> SetupChoice {
    SetupChoice::Create {
        name: "Phone fixture".into(),
    }
}
