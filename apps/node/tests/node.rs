//! The node as a real process: init, run under its control socket, pair a
//! device, keep serving it across a restart. Both sides keep their secrets in
//! sealed stores under their own master keys, as on a server.
#![cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};
use connect_core::{
    Connectivity,
    device::{DeviceController, PairedDevice},
    session::{pairing::PairCard, sharing::SpaceKind},
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

fn owner_binary() -> Result<PathBuf> {
    std::env::var_os("CONNECT_OWNER_BINARY")
        .map(PathBuf::from)
        .context("Set CONNECT_OWNER_BINARY to the packaged authority")
}

/// A sealed store directory and its master key credential.
fn sealed(root: &Path, name: &str) -> Result<(PathBuf, PathBuf)> {
    let credentials = root.join(format!("{name}-credentials"));
    std::fs::create_dir_all(&credentials)?;
    let mut key = [0; 32];
    getrandom::fill(&mut key)?;
    std::fs::write(credentials.join("connect-master-key"), key)?;
    Ok((root.join(format!("{name}-store")), credentials))
}

/// Each test runs a server with its own authority; one at a time keeps their
/// timing like a real network's on a busy machine.
fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    ONE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Devices in this test process keep their secrets in one sealed store; a
/// process chooses its store once.
fn devices_sealed() {
    static STORE: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    STORE.get_or_init(|| {
        let root = tempfile::tempdir().expect("temporary directory");
        let (store, credentials) = sealed(root.path(), "devices").expect("sealed store");
        connect_core::device::use_sealed_store(
            store,
            &credentials.join(connect_core::device::MASTER_KEY_CREDENTIAL),
        )
        .expect("sealed store");
        root
    });
}

struct Server {
    state: PathBuf,
    store: PathBuf,
    credentials: PathBuf,
}
impl Server {
    fn command(&self, args: &[&str]) -> Result<Command> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_genesismesh-connect-node"));
        command
            .args(args)
            .arg("--state")
            .arg(&self.state)
            .arg("--authority")
            .arg(owner_binary()?)
            .env("CONNECT_SEALED_STORE", &self.store)
            .env("CREDENTIALS_DIRECTORY", &self.credentials);
        Ok(command)
    }
    fn run(&self) -> Result<Child> {
        let child = self.command(&["run"])?.spawn()?;
        let deadline = Instant::now() + Duration::from_secs(60);
        while UnixStream::connect(self.state.join("control.sock")).is_err() {
            ensure!(Instant::now() < deadline, "The node did not start");
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(child)
    }
    fn control(&self, request: Value) -> Result<Value> {
        let mut stream = UnixStream::connect(self.state.join("control.sock"))?;
        writeln!(stream, "{request}")?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        let mut reply: Value = serde_json::from_str(&line)?;
        if let Some(error) = reply.get("error") {
            anyhow::bail!("{error}");
        }
        Ok(reply["ok"].take())
    }
}

fn stop(mut child: Child) -> Result<()> {
    Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait()?.is_none() {
        if Instant::now() > deadline {
            child.kill()?;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

#[test]
#[ignore = "Requires the packaged, standalone owner runtime"]
fn a_server_node_pairs_a_device_and_keeps_serving_it_after_a_restart() -> Result<()> {
    let _one = one_at_a_time();
    let directory = tempfile::tempdir()?;
    devices_sealed();
    let (store, credentials) = sealed(directory.path(), "server")?;
    let server = Server {
        state: directory.path().join("server"),
        store,
        credentials,
    };
    let init = server
        .command(&["init", "--name", "Server network"])?
        .output()?;
    ensure!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let again = server.command(&["init"])?.output()?;
    ensure!(!again.status.success(), "init never replaces a network");
    let child = server.run()?;
    let outcome = (|| {
        server.control(json!({"op":"connection","setting":"local_network"}))?;
        let status = server.control(json!({"op":"status"}))?;
        assert_eq!(status["network"], "Server network");
        assert_eq!(status["connection"]["network"], "local_network");
        assert!(status["connection"]["network_computer"].as_bool().unwrap());
        assert_eq!(status["devices"], json!([]));

        let runtime = tokio::runtime::Runtime::new()?;
        let begun = server.control(json!({"op":"pair_begin","name":"Test server"}))?;
        let card = PairCard::parse(begun["link"].as_str().context("Missing link")?)?;
        assert_eq!(card.connectivity(), Connectivity::LocalNetwork);
        let profile = directory.path().join("phone");
        let mut phone = DeviceController::prepare_remote(&profile, card.pin.clone())?;
        let mut joining =
            runtime.block_on(phone.request_pairing(card.clone(), "Test phone".into()))?;
        let pending = server.control(json!({"op":"pair_pending"}))?;
        assert_eq!(pending["name"], "Test phone");
        assert_eq!(pending["code"], json!(joining.code));
        let id = pending["id"]
            .as_str()
            .context("Missing request")?
            .to_owned();
        let approval = std::thread::scope(|scope| {
            let approval = scope.spawn(|| server.control(json!({"op":"pair_approve","id":id})));
            let joined = runtime.block_on(async {
                let grant = joining.grant().await?;
                phone.use_bridge(grant.route).await?;
                phone.enroll_host(&grant.invitation).await?;
                phone.start(&card.host_node).await?;
                phone
                    .send(&grant.session_ticket, "Phone verifies server")
                    .await?;
                let ticket = phone.status()?.ticket.context("Missing phone address")?;
                phone.remember_pairing(PairedDevice {
                    name: card.host_name.clone(),
                    node: card.host_node.clone(),
                    ticket: grant.session_ticket,
                })?;
                joining.finish(ticket).await?;
                joining.close().await;
                Ok::<_, anyhow::Error>(())
            });
            (joined, approval.join().expect("approval thread"))
        });
        approval.0?;
        approval.1?;
        let status = server.control(json!({"op":"status"}))?;
        assert_eq!(status["devices"], json!(["Test phone"]));
        runtime.block_on(phone.refresh())?;
        assert_eq!(
            phone.status()?.connectivity.network,
            Connectivity::LocalNetwork,
            "The device follows the server's setting"
        );

        let recovery = server.control(json!({"op":"recovery","name":"server.gmrecovery"}))?;
        assert_eq!(recovery["key"].as_str().map(str::len), Some(39));
        assert!(server.state.join("recovery/server.gmrecovery").is_file());
        assert!(
            server
                .control(json!({"op":"recovery","name":"server.gmrecovery"}))
                .is_err(),
            "A recovery file is never overwritten"
        );
        assert!(
            server
                .control(json!({"op":"recovery","name":"../outside"}))
                .is_err(),
            "Recovery files stay in the state directory"
        );
        // One process owns the state at a time.
        let second = server.command(&["run"])?.output()?;
        assert!(!second.status.success());
        assert!(
            UnixStream::connect(server.state.join("control.sock")).is_ok(),
            "A refused second run leaves the live socket alone"
        );
        Ok::<_, anyhow::Error>((runtime, phone))
    })();
    stop(child)?;
    let (runtime, mut phone) = outcome?;
    // After a restart the server listens on its saved ports, so the device
    // reaches it again from its saved addresses.
    let child = server.run()?;
    let outcome = (|| {
        runtime.block_on(phone.refresh())?;
        let saved = phone
            .paired_device()
            .context("Missing saved server")?
            .ticket
            .clone();
        runtime.block_on(phone.send(&saved, "Phone reaches the restarted server"))?;
        let status = server.control(json!({"op":"status"}))?;
        assert_eq!(status["devices"], json!(["Test phone"]));
        Ok::<_, anyhow::Error>(())
    })();
    runtime.block_on(phone.stop());
    stop(child)?;
    outcome
}

/// A random version 4 UUID for a request.
fn request_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// Pair a device with the running server the way the app does.
fn join(
    server: &Server,
    runtime: &tokio::runtime::Runtime,
    profile: &Path,
    name: &str,
) -> Result<DeviceController> {
    let begun = server.control(json!({"op":"pair_begin","name":"Home server"}))?;
    let card = PairCard::parse(begun["link"].as_str().context("Missing link")?)?;
    let mut device = DeviceController::prepare_remote(profile, card.pin.clone())?;
    let mut joining = runtime.block_on(device.request_pairing(card.clone(), name.into()))?;
    let pending = server.control(json!({"op":"pair_pending"}))?;
    let id = pending["id"]
        .as_str()
        .context("Missing request")?
        .to_owned();
    let (joined, approval) = std::thread::scope(|scope| {
        let approval = scope.spawn(|| server.control(json!({"op":"pair_approve","id":id})));
        let joined = runtime.block_on(async {
            let grant = joining.grant().await?;
            device.use_bridge(grant.route).await?;
            device.enroll_host(&grant.invitation).await?;
            device.start(&card.host_node).await?;
            device
                .send(&grant.session_ticket, "Device verifies server")
                .await?;
            let ticket = device.status()?.ticket.context("Missing device address")?;
            device.remember_pairing(PairedDevice {
                name: card.host_name.clone(),
                node: card.host_node.clone(),
                ticket: grant.session_ticket,
            })?;
            joining.finish(ticket).await?;
            joining.close().await;
            Ok::<_, anyhow::Error>(())
        });
        (joined, approval.join().expect("approval thread"))
    });
    joined?;
    approval?;
    Ok(device)
}

#[test]
#[ignore = "Requires the packaged, standalone owner runtime"]
fn a_device_shares_a_folder_with_another_through_the_server() -> Result<()> {
    let _one = one_at_a_time();
    use connect_core::session::sharing::ReadRequest;
    let directory = tempfile::tempdir()?;
    devices_sealed();
    let (store, credentials) = sealed(directory.path(), "server")?;
    let server = Server {
        state: directory.path().join("server"),
        store,
        credentials,
    };
    let init = server.command(&["init", "--name", "Home"])?.output()?;
    ensure!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let runtime = tokio::runtime::Runtime::new()?;
    let child = server.run()?;
    let outcome = (|| {
        server.control(json!({"op":"connection","setting":"local_network"}))?;
        let mut pc = join(&server, &runtime, &directory.path().join("pc"), "Home PC")?;
        let mut phone = join(&server, &runtime, &directory.path().join("phone"), "Phone")?;
        runtime.block_on(pc.check_network())?;
        runtime.block_on(phone.check_network())?;
        let pc_node = pc.status()?.node_public_key;
        let phone_node = phone.status()?.node_public_key;
        let server_node = phone.status()?.bridge_host_node.context("Missing server")?;

        // The PC shares a folder with the phone; the server issues the Space.
        let photos = directory.path().join("photos");
        std::fs::create_dir(&photos)?;
        std::fs::write(photos.join("beach.txt"), b"Sand and sea")?;
        let shared = runtime.block_on(pc.share_space(
            None,
            photos.clone(),
            "Family photos".into(),
            vec![phone_node.clone()],
            SpaceKind::Folder,
        ))?;
        assert_eq!(shared.name, "Family photos");
        assert_eq!(shared.recipients, vec![phone_node.clone()]);
        assert_eq!(pc.status()?.shares, vec![shared.clone()]);
        // Another Space, shared only with the server: the phone never sees it.
        let private = directory.path().join("private");
        std::fs::create_dir(&private)?;
        std::fs::write(private.join("diary.txt"), b"Not for the phone")?;
        let hidden = runtime.block_on(pc.share_space(
            None,
            private,
            "Private".into(),
            vec![server_node.clone()],
            SpaceKind::Folder,
        ))?;
        let status = server.control(json!({"op":"status"}))?;
        let mut listed: Vec<String> = status["spaces"]
            .as_array()
            .context("Missing spaces")?
            .iter()
            .map(|s| {
                format!(
                    "{} on {}",
                    s["name"].as_str().unwrap_or("?"),
                    s["host"].as_str().unwrap_or("?")
                )
            })
            .collect();
        listed.sort();
        assert_eq!(listed, ["Family photos on Home PC", "Private on Home PC"]);

        // The phone learns only the Space that names it, and browses and
        // reads it directly from the PC.
        runtime.block_on(phone.check_network())?;
        let spaces = phone.status()?.spaces;
        assert_eq!(spaces.len(), 1);
        assert_eq!(
            (
                spaces[0].name.as_str(),
                spaces[0].host.as_str(),
                &spaces[0].grant
            ),
            ("Family photos", pc_node.as_str(), &None)
        );
        let pc_ticket = phone
            .status()?
            .members
            .into_iter()
            .find(|m| m.node == pc_node)
            .context("The phone does not know the PC")?
            .ticket;
        let session = phone.session()?;
        let page = runtime.block_on(session.browse_from(
            &pc_node,
            &pc_ticket,
            None,
            Vec::new(),
            Some(shared.collection_id.clone()),
        ))?;
        assert_eq!(page.collection_id, shared.collection_id);
        assert_eq!(
            page.files
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["beach.txt"]
        );
        let read = runtime.block_on(session.read_file_from(
            Some(&pc_node),
            &pc_ticket,
            ReadRequest {
                request_id: request_id()?,
                collection_id: shared.collection_id.clone(),
                file_name: "beach.txt".into(),
                expected_sha256: None,
            },
        ))?;
        assert_eq!(read.text.as_deref(), Some("Sand and sea"));
        // An app from before Spaces names none and gets the Space shared with it.
        let legacy =
            runtime.block_on(session.browse_from(&pc_node, &pc_ticket, None, Vec::new(), None))?;
        assert_eq!(legacy.collection_id, shared.collection_id);
        // The Space that does not name the phone releases nothing to it.
        assert!(
            runtime
                .block_on(session.browse_from(
                    &pc_node,
                    &pc_ticket,
                    None,
                    Vec::new(),
                    Some(hidden.collection_id.clone()),
                ))
                .is_err()
        );

        // Only the PC can change or stop its Spaces: the phone cannot take
        // the Space over through the server, nor stop it.
        let decoy = directory.path().join("decoy");
        std::fs::create_dir(&decoy)?;
        assert!(
            runtime
                .block_on(phone.share_space(
                    Some(shared.collection_id.clone()),
                    decoy,
                    "Taken".into(),
                    vec![server_node.clone()],
                    SpaceKind::Folder,
                ))
                .is_err(),
            "The server refuses a Space that belongs to another device"
        );
        assert!(
            runtime
                .block_on(phone.unshare_space(&shared.collection_id))
                .is_err()
        );
        let status = server.control(json!({"op":"status"}))?;
        assert_eq!(status["spaces"].as_array().map(Vec::len), Some(2));
        assert!(runtime.block_on(pc.unshare_space(&shared.collection_id))?);
        assert_eq!(pc.status()?.shares, vec![hidden.clone()]);
        let status = server.control(json!({"op":"status"}))?;
        assert_eq!(status["spaces"].as_array().map(Vec::len), Some(1));
        runtime.block_on(phone.check_network())?;
        assert!(phone.status()?.spaces.is_empty());
        assert!(
            runtime
                .block_on(phone.session()?.browse_from(
                    &pc_node,
                    &pc_ticket,
                    None,
                    Vec::new(),
                    Some(shared.collection_id.clone()),
                ))
                .is_err(),
            "A stopped Space serves nothing"
        );
        // Even a device that kept serving the folder releases nothing: the
        // authority no longer has an active policy for it.
        runtime.block_on(pc.set_space(shared.clone()))?;
        let refused = runtime.block_on(phone.session()?.browse_from(
            &pc_node,
            &pc_ticket,
            None,
            Vec::new(),
            Some(shared.collection_id.clone()),
        ));
        assert!(
            refused
                .err()
                .is_some_and(|e| e.to_string().contains("access was not allowed")),
            "The authority denies a stopped Space"
        );
        runtime.block_on(pc.drop_space(&shared.collection_id))?;

        // The server removes the phone from the network: the phone's own
        // Space and the one only it could see stop, and the one shared with
        // it and the server no longer names it.
        let folder = |name: &str| -> Result<std::path::PathBuf> {
            let path = directory.path().join(name);
            std::fs::create_dir(&path)?;
            std::fs::write(path.join("note.txt"), name)?;
            Ok(path)
        };
        let for_phone = runtime.block_on(pc.share_space(
            None,
            folder("for-phone")?,
            "For the phone".into(),
            vec![phone_node.clone()],
            SpaceKind::Folder,
        ))?;
        let both = runtime.block_on(pc.share_space(
            None,
            folder("both")?,
            "Both".into(),
            vec![phone_node.clone(), server_node.clone()],
            SpaceKind::Folder,
        ))?;
        let notes = runtime.block_on(phone.share_space(
            None,
            folder("notes")?,
            "Phone notes".into(),
            vec![pc_node.clone()],
            SpaceKind::Folder,
        ))?;
        let revocations = pc.status()?.trust_checkpoint.crl_sequence;
        let removed = server.command(&["remove", "Phone"])?.output()?;
        ensure!(
            removed.status.success(),
            "remove failed: {}",
            String::from_utf8_lossy(&removed.stderr)
        );
        assert!(
            String::from_utf8_lossy(&removed.stdout).contains("Phone is no longer on the network")
        );
        let status = server.control(json!({"op":"status"}))?;
        assert_eq!(status["devices"], json!(["Home PC"]));
        let mut listed: Vec<String> = status["spaces"]
            .as_array()
            .context("Missing spaces")?
            .iter()
            .map(|s| s["name"].as_str().unwrap_or("?").to_owned())
            .collect();
        listed.sort();
        assert_eq!(listed, ["Both", "Private"]);
        assert!(
            server
                .control(json!({"op":"remove","name":"Phone"}))
                .is_err_and(|e| e.to_string().contains("No device is called")),
            "A removed device is no longer listed"
        );
        // The PC learns it at its next refreshes: the phone is no longer a
        // member, "Both" names only the server, and the Space only the
        // phone could see stops once two listings in a row leave it out.
        runtime.block_on(pc.check_network())?;
        assert!(
            pc.status()?
                .shares
                .iter()
                .any(|s| s.collection_id == for_phone.collection_id),
            "One listing is not enough to stop a Space"
        );
        runtime.block_on(pc.check_network())?;
        let status = pc.status()?;
        assert!(status.members.iter().all(|m| m.node != phone_node));
        assert!(
            status
                .shares
                .iter()
                .all(|s| s.collection_id != for_phone.collection_id)
        );
        let kept = status
            .shares
            .iter()
            .find(|s| s.collection_id == both.collection_id)
            .context("The PC stopped a Space that still has a device")?;
        assert_eq!(kept.recipients, vec![server_node.clone()]);
        // The PC has seen the phone's certificates revoked, and the phone
        // reaches neither the server nor the PC.
        assert!(pc.status()?.trust_checkpoint.crl_sequence > revocations);
        assert!(
            runtime.block_on(phone.check_network()).is_err() || phone.status()?.problem.is_some()
        );
        assert!(
            runtime
                .block_on(phone.session()?.browse_from(
                    &pc_node,
                    &pc_ticket,
                    None,
                    Vec::new(),
                    Some(both.collection_id.clone()),
                ))
                .is_err(),
            "A removed device reaches nothing"
        );
        assert!(
            !server.control(json!({"op":"status"}))?["spaces"]
                .as_array()
                .context("Missing spaces")?
                .iter()
                .any(|s| s["name"] == notes.name.as_str())
        );
        assert!(runtime.block_on(pc.unshare_space(&both.collection_id))?);
        Ok::<_, anyhow::Error>((pc, phone))
    })();
    stop(child)?;
    let (mut pc, mut phone) = outcome?;
    // With the server down, the PC still stops sharing at once; the server
    // has not confirmed, so the PC finishes the job when it is back.
    let hidden = pc.status()?.shares[0].collection_id.clone();
    assert!(!runtime.block_on(pc.unshare_space(&hidden))?);
    assert!(pc.status()?.shares.is_empty());
    // The registry survives a restart of the server.
    let child = server.run()?;
    let outcome = (|| {
        let status = server.control(json!({"op":"status"}))?;
        assert_eq!(status["spaces"][0]["name"], "Private");
        runtime.block_on(pc.check_network())?;
        let status = server.control(json!({"op":"status"}))?;
        assert_eq!(
            status["spaces"],
            json!([]),
            "The PC asks the server again to forget the Space it stopped"
        );
        Ok::<_, anyhow::Error>(())
    })();
    runtime.block_on(pc.stop());
    runtime.block_on(phone.stop());
    stop(child)?;
    outcome
}

/// Send `bytes` as `name` into `host`'s inbox, window by window, declaring
/// `declared` as the whole file's SHA-256. Returns the name it was saved as.
fn send_file(
    runtime: &tokio::runtime::Runtime,
    device: &DeviceController,
    host: &connect_core::device::PairedDevice,
    inbox: &str,
    name: &str,
    bytes: &[u8],
    declared: Option<String>,
) -> Result<Option<String>> {
    let session = device.session()?;
    send_with(runtime, &session, host, inbox, name, bytes, declared)
}

/// The same, from a running session, so several devices can send at once.
fn send_with(
    runtime: &tokio::runtime::Runtime,
    session: &connect_core::session::SessionEndpoint,
    host: &connect_core::device::PairedDevice,
    inbox: &str,
    name: &str,
    bytes: &[u8],
    declared: Option<String>,
) -> Result<Option<String>> {
    use connect_core::session::sharing::send::{MIN_WINDOW_BYTES, Outcome, Request};
    use std::io::Write as _;
    let mut file = tempfile::tempfile()?;
    file.write_all(bytes)?;
    let digest = declared.unwrap_or_else(|| sha256(bytes));
    let (mut token, mut offset, mut waits) = (None, 0u64, 0);
    loop {
        let sent = runtime.block_on(session.send_window_to(
            &host.node,
            &host.ticket,
            &mut Request {
                request_id: request_id()?,
                collection_id: inbox.into(),
                file_name: name.into(),
                size: bytes.len() as u64,
                sha256: digest.clone(),
                token: token.clone(),
                offset,
                // The smallest windows: the most authority requests per file.
                length: MIN_WINDOW_BYTES,
            },
            &mut file,
        ));
        // A busy device, or one whose network computer did not answer in
        // time on a loaded machine, takes the window later, as in the app.
        let window = match sent {
            Err(error) if waits < 30 && error.to_string().contains("receiving other files") => {
                waits += 1;
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
            sent => sent?,
        };
        let window = match window {
            Outcome::Sent(window) => window,
            Outcome::ContinueAt { token: kept, at } => {
                token = Some(kept);
                offset = at;
                continue;
            }
            other => anyhow::bail!("Unexpected answer: {other:?}"),
        };
        offset += window.bytes as u64;
        token = Some(window.token);
        if window.done {
            return Ok(window.saved_as);
        }
    }
}

/// A SHA-256 in lowercase hex, without another dependency in this test.
fn sha256(bytes: &[u8]) -> String {
    let mut command = Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("sha256sum");
    command
        .stdin
        .take()
        .expect("stdin")
        .write_all(bytes)
        .expect("write");
    let output = command.wait_with_output().expect("sha256sum output");
    String::from_utf8_lossy(&output.stdout)[..64].to_owned()
}

#[test]
#[ignore = "Requires the packaged, standalone owner runtime"]
fn a_device_sends_files_into_another_devices_inbox() -> Result<()> {
    let _one = one_at_a_time();
    let directory = tempfile::tempdir()?;
    devices_sealed();
    let (store, credentials) = sealed(directory.path(), "server")?;
    let server = Server {
        state: directory.path().join("server"),
        store,
        credentials,
    };
    let init = server.command(&["init", "--name", "Home"])?.output()?;
    ensure!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let runtime = tokio::runtime::Runtime::new()?;
    let child = server.run()?;
    let outcome = (|| {
        server.control(json!({"op":"connection","setting":"local_network"}))?;
        let mut pc = join(&server, &runtime, &directory.path().join("pc"), "Home PC")?;
        let mut phone = join(&server, &runtime, &directory.path().join("phone"), "Phone")?;
        let mut tablet = join(
            &server,
            &runtime,
            &directory.path().join("tablet"),
            "Tablet",
        )?;
        for device in [&mut pc, &mut phone, &mut tablet] {
            runtime.block_on(device.check_network())?;
        }
        let phone_node = phone.status()?.node_public_key;
        let pc_node = pc.status()?.node_public_key;

        // The PC accepts files from the phone into its inbox folder.
        let received = directory.path().join("received");
        std::fs::create_dir(&received)?;
        std::fs::write(received.join("photo.jpg"), b"already here")?;
        let inbox = runtime.block_on(pc.share_space(
            None,
            received.clone(),
            "Inbox".into(),
            vec![phone_node.clone()],
            SpaceKind::Inbox,
        ))?;
        assert_eq!(inbox.kind, SpaceKind::Inbox);
        for device in [&mut phone, &mut tablet] {
            runtime.block_on(device.check_network())?;
        }
        let listed = phone.status()?.spaces;
        assert_eq!(
            listed
                .iter()
                .map(|s| (s.name.as_str(), s.kind))
                .collect::<Vec<_>>(),
            [("Inbox", SpaceKind::Inbox)]
        );
        let pc_from = |device: &DeviceController| -> Result<connect_core::device::PairedDevice> {
            device
                .status()?
                .members
                .into_iter()
                .find(|m| m.node == pc_node)
                .context("Missing PC")
        };

        // Several windows, each decided by the PC for the whole file.
        let photo: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let saved = send_file(
            &runtime,
            &phone,
            &pc_from(&phone)?,
            &inbox.collection_id,
            "photo.jpg",
            &photo,
            None,
        )?;
        assert_eq!(
            saved.as_deref(),
            Some("photo (2).jpg"),
            "An existing file is never replaced"
        );
        assert_eq!(std::fs::read(received.join("photo (2).jpg"))?, photo);
        assert_eq!(std::fs::read(received.join("photo.jpg"))?, b"already here");
        let again = send_file(
            &runtime,
            &phone,
            &pc_from(&phone)?,
            &inbox.collection_id,
            "photo.jpg",
            &photo,
            None,
        )?;
        assert_eq!(again.as_deref(), Some("photo (3).jpg"));
        let empty = send_file(
            &runtime,
            &phone,
            &pc_from(&phone)?,
            &inbox.collection_id,
            "empty.txt",
            b"",
            None,
        )?;
        assert_eq!(empty.as_deref(), Some("empty.txt"));

        // A file that does not match its declared digest is never saved.
        let wrong = send_file(
            &runtime,
            &phone,
            &pc_from(&phone)?,
            &inbox.collection_id,
            "tampered.bin",
            &photo,
            Some("0".repeat(64)),
        );
        assert!(wrong.is_err());
        assert!(!received.join("tampered.bin").exists());

        // A device the inbox does not name is refused before any byte, and a
        // shared folder or an unknown inbox accepts nothing.
        let refused = send_file(
            &runtime,
            &tablet,
            &pc_from(&tablet)?,
            &inbox.collection_id,
            "spam.txt",
            b"spam",
            None,
        );
        assert!(
            refused
                .err()
                .is_some_and(|e| e.to_string().contains("isn't accepting files"))
        );
        assert!(!received.join("spam.txt").exists());
        let photos = directory.path().join("photos");
        std::fs::create_dir(&photos)?;
        let folder = runtime.block_on(pc.share_space(
            None,
            photos.clone(),
            "Photos".into(),
            vec![phone_node.clone()],
            SpaceKind::Folder,
        ))?;
        // Both refusals reach the PC and come back as denials, not as a
        // connection failure.
        let into_folder = send_file(
            &runtime,
            &phone,
            &pc_from(&phone)?,
            &folder.collection_id,
            "into-folder.txt",
            b"no",
            None,
        );
        assert!(
            into_folder
                .err()
                .is_some_and(|e| e.to_string().contains("isn't accepting files")),
            "A folder accepts no files"
        );
        assert!(!photos.join("into-folder.txt").exists());
        // And an inbox is never browsed.
        let session = phone.session()?;
        let host = pc_from(&phone)?;
        assert!(
            runtime
                .block_on(session.browse_from(
                    &host.node,
                    &host.ticket,
                    None,
                    Vec::new(),
                    Some(inbox.collection_id.clone())
                ))
                .err()
                .is_some_and(|e| e.to_string().contains("access was not allowed")),
            "An inbox is never browsed"
        );
        // Two trusted devices sending into one inbox at once take turns, and
        // both files arrive whole.
        let shared = directory.path().join("shared-inbox");
        std::fs::create_dir(&shared)?;
        let both = runtime.block_on(pc.share_space(
            None,
            shared.clone(),
            "Family inbox".into(),
            vec![phone_node.clone(), tablet.status()?.node_public_key],
            SpaceKind::Inbox,
        ))?;
        for device in [&mut phone, &mut tablet] {
            runtime.block_on(device.check_network())?;
        }
        let large: Vec<u8> = (0..1_500_000u32).map(|i| (i % 241) as u8).collect();
        let (from_phone, from_tablet) = (phone.session()?, tablet.session()?);
        let (phone_host, tablet_host) = (pc_from(&phone)?, pc_from(&tablet)?);
        let (a, b) = std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                send_with(
                    &runtime,
                    &from_phone,
                    &phone_host,
                    &both.collection_id,
                    "a.bin",
                    &large,
                    None,
                )
            });
            let b = scope.spawn(|| {
                send_with(
                    &runtime,
                    &from_tablet,
                    &tablet_host,
                    &both.collection_id,
                    "b.bin",
                    &large,
                    None,
                )
            });
            (a.join().expect("phone"), b.join().expect("tablet"))
        });
        assert_eq!(a?.as_deref(), Some("a.bin"));
        assert_eq!(b?.as_deref(), Some("b.bin"));
        assert_eq!(std::fs::read(shared.join("a.bin"))?, large);
        assert_eq!(std::fs::read(shared.join("b.bin"))?, large);
        let names: Vec<String> = std::fs::read_dir(&received)?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<std::io::Result<_>>()?;
        let mut names = names;
        names.sort();
        assert_eq!(
            names,
            ["empty.txt", "photo (2).jpg", "photo (3).jpg", "photo.jpg"]
        );
        Ok::<_, anyhow::Error>((pc, phone, tablet))
    })();
    stop(child)?;
    let (mut pc, mut phone, mut tablet) = outcome?;
    for device in [&mut pc, &mut phone, &mut tablet] {
        runtime.block_on(device.stop());
    }
    Ok(())
}

#[test]
#[ignore = "Requires the packaged, standalone owner runtime"]
fn transfers_continue_where_they_stopped() -> Result<()> {
    let _one = one_at_a_time();
    use connect_core::session::sharing::{
        browse,
        download::{self, MIN_WINDOW_BYTES},
        send::{Outcome, Request},
    };
    use std::io::{Read as _, Seek as _, Write as _};
    let directory = tempfile::tempdir()?;
    devices_sealed();
    let (store, credentials) = sealed(directory.path(), "server")?;
    let server = Server {
        state: directory.path().join("server"),
        store,
        credentials,
    };
    let init = server.command(&["init", "--name", "Home"])?.output()?;
    ensure!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let runtime = tokio::runtime::Runtime::new()?;
    let child = server.run()?;
    let outcome = (|| {
        server.control(json!({"op":"connection","setting":"local_network"}))?;
        let pc_path = directory.path().join("pc");
        let mut pc = join(&server, &runtime, &pc_path, "Home PC")?;
        let mut phone = join(&server, &runtime, &directory.path().join("phone"), "Phone")?;
        runtime.block_on(pc.check_network())?;
        runtime.block_on(phone.check_network())?;
        let phone_node = phone.status()?.node_public_key;
        let pc_node = pc.status()?.node_public_key;
        let received = directory.path().join("received");
        std::fs::create_dir(&received)?;
        let inbox = runtime.block_on(pc.share_space(
            None,
            received.clone(),
            "Inbox".into(),
            vec![phone_node.clone()],
            SpaceKind::Inbox,
        ))?;
        let photos = directory.path().join("photos");
        std::fs::create_dir(&photos)?;
        let film: Vec<u8> = (0..300_000u32).map(|i| (i % 239) as u8).collect();
        std::fs::write(photos.join("film.bin"), &film)?;
        let folder = runtime.block_on(pc.share_space(
            None,
            photos,
            "Photos".into(),
            vec![phone_node.clone()],
            SpaceKind::Folder,
        ))?;
        runtime.block_on(phone.check_network())?;
        let pc_ticket = || -> Result<String> {
            Ok(phone
                .status()?
                .members
                .into_iter()
                .find(|m| m.node == pc_node)
                .context("Missing PC")?
                .ticket)
        };

        // A send: one window, then the PC restarts, losing everything in
        // memory; the phone carries on from what the PC kept.
        let video: Vec<u8> = (0..200_000u32).map(|i| (i % 233) as u8).collect();
        let mut file = tempfile::tempfile()?;
        file.write_all(&video)?;
        let window = |token: Option<String>, offset: u64| Request {
            request_id: request_id().unwrap(),
            collection_id: inbox.collection_id.clone(),
            file_name: "video.bin".into(),
            size: video.len() as u64,
            sha256: sha256(&video),
            token,
            offset,
            length: MIN_WINDOW_BYTES,
        };
        let mut opening = window(None, 0);
        let first = match runtime.block_on(phone.session()?.send_window_to(
            &pc_node,
            &pc_ticket()?,
            &mut opening,
            &mut file,
        ))? {
            Outcome::Sent(first) => first,
            other => anyhow::bail!("Unexpected first window: {other:?}"),
        };
        assert_eq!(opening.token.as_ref(), Some(&first.token));
        runtime.block_on(pc.stop());
        drop(pc);
        let mut pc = DeviceController::open(&pc_path)?;
        pc.restore_managed_share()?;
        runtime.block_on(pc.reconnect_saved())?;
        // The same file started again, as after the phone's app restarted,
        // continues the transfer the PC kept on disk.
        let again = runtime.block_on(phone.session()?.send_window_to(
            &pc_node,
            &pc_ticket()?,
            &mut window(None, 0),
            &mut file,
        ))?;
        assert!(
            matches!(&again, Outcome::ContinueAt { token, at } if *token == first.token && *at == first.bytes as u64),
            "{again:?}"
        );
        // A window sent again at the old place learns where the file stands.
        let resumed = runtime.block_on(phone.session()?.send_window_to(
            &pc_node,
            &pc_ticket()?,
            &mut window(Some(first.token.clone()), 0),
            &mut file,
        ))?;
        let mut offset = match resumed {
            Outcome::ContinueAt { token, at } => {
                assert_eq!(token, first.token);
                at
            }
            other => anyhow::bail!("Expected to continue: {other:?}"),
        };
        assert_eq!(offset, first.bytes as u64);
        let saved = loop {
            match runtime.block_on(phone.session()?.send_window_to(
                &pc_node,
                &pc_ticket()?,
                &mut window(Some(first.token.clone()), offset),
                &mut file,
            ))? {
                Outcome::Sent(next) if next.done => break next.saved_as,
                Outcome::Sent(next) => offset += next.bytes as u64,
                other => anyhow::bail!("Unexpected window: {other:?}"),
            }
        };
        assert_eq!(saved.as_deref(), Some("video.bin"));
        assert_eq!(std::fs::read(received.join("video.bin"))?, video);
        // The last window asked again, as after a lost confirmation, learns
        // where the file went, and it is not saved twice.
        let again = runtime.block_on(phone.session()?.send_window_to(
            &pc_node,
            &pc_ticket()?,
            &mut window(Some(first.token.clone()), offset),
            &mut file,
        ))?;
        assert!(
            matches!(&again, Outcome::Saved { saved_as } if saved_as == "video.bin"),
            "{again:?}"
        );
        assert_eq!(std::fs::read_dir(&received)?.count(), 1);
        // A transfer the PC no longer has starts over.
        let lost = runtime.block_on(phone.session()?.send_window_to(
            &pc_node,
            &pc_ticket()?,
            &mut window(Some(request_id()?), MIN_WINDOW_BYTES as u64),
            &mut file,
        ))?;
        assert!(matches!(lost, Outcome::StartOver));

        // A download: the first window, then a fresh start at the offset
        // with no token, as after a restart of either device.
        let session = phone.session()?;
        let page = runtime.block_on(session.browse_from(
            &pc_node,
            &pc_ticket()?,
            None,
            Vec::new(),
            Some(folder.collection_id.clone()),
        ))?;
        let entry = page
            .files
            .iter()
            .find(|f| f.name == "film.bin" && f.kind == browse::Kind::File)
            .context("Missing film")?
            .clone();
        let mut output = tempfile::tempfile()?;
        let request = |token: Option<String>, offset: u64| download::Request {
            request_id: request_id().unwrap(),
            collection_id: folder.collection_id.clone(),
            file_name: entry.name.clone(),
            directory: Vec::new(),
            version: entry.version.clone(),
            size: entry.bytes,
            token,
            offset,
            length: MIN_WINDOW_BYTES,
        };
        let first = runtime.block_on(session.download_window_from(
            &pc_node,
            &pc_ticket()?,
            request(None, 0),
            &mut output,
        ))?;
        let mut offset = first.bytes as u64;
        // Asked again without its token, as after a lost answer, the PC
        // continues the snapshot it has.
        let reused = runtime.block_on(session.download_window_from(
            &pc_node,
            &pc_ticket()?,
            request(None, offset),
            &mut output,
        ))?;
        assert_eq!(reused.token, first.token);
        offset += reused.bytes as u64;
        // The PC restarts: its snapshot is gone, and the old token with it.
        runtime.block_on(pc.stop());
        drop(pc);
        let mut pc = DeviceController::open(&pc_path)?;
        pc.restore_managed_share()?;
        runtime.block_on(pc.reconnect_saved())?;
        let session = phone.session()?;
        let expired = runtime
            .block_on(session.download_window_from(
                &pc_node,
                &pc_ticket()?,
                request(Some(first.token.clone()), offset),
                &mut output,
            ))
            .err()
            .context("The old token was taken")?;
        assert!(
            expired.to_string().contains("no longer has this download"),
            "{expired}"
        );
        let mut token = None;
        loop {
            let next = runtime.block_on(session.download_window_from(
                &pc_node,
                &pc_ticket()?,
                request(token.clone(), offset),
                &mut output,
            ))?;
            assert_eq!(next.sha256, first.sha256, "The same version, the same file");
            offset += next.bytes as u64;
            token = Some(next.token);
            if next.done {
                break;
            }
        }
        output.rewind()?;
        let mut downloaded = Vec::new();
        output.read_to_end(&mut downloaded)?;
        assert_eq!(downloaded, film);
        // A file changed in between is refused, never stitched.
        std::fs::write(
            directory.path().join("photos").join("film.bin"),
            b"a new film",
        )?;
        let mut other = tempfile::tempfile()?;
        other.write_all(&film[..MIN_WINDOW_BYTES as usize])?;
        assert!(
            runtime
                .block_on(session.download_window_from(
                    &pc_node,
                    &pc_ticket()?,
                    request(None, u64::from(MIN_WINDOW_BYTES)),
                    &mut other,
                ))
                .is_err(),
            "A changed file is not continued"
        );
        Ok::<_, anyhow::Error>((pc, phone))
    })();
    stop(child)?;
    let (mut pc, mut phone) = outcome?;
    runtime.block_on(pc.stop());
    runtime.block_on(phone.stop());
    Ok(())
}
