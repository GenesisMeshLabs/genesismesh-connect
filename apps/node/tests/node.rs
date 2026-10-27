//! The node as a real process: init, run under its control socket, pair a
//! device, keep serving it across a restart. Both sides keep their secrets in
//! sealed stores under their own master keys, as on a server.
#![cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};
use connect_core::{
    Connectivity,
    device::{DeviceController, PairedDevice},
    session::pairing::PairCard,
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
    let directory = tempfile::tempdir()?;
    let (phone_store, phone_credentials) = sealed(directory.path(), "phone")?;
    connect_core::device::use_sealed_store(
        phone_store,
        &phone_credentials.join(connect_core::device::MASTER_KEY_CREDENTIAL),
    )?;
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
