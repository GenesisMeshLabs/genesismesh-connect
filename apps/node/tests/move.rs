//! Moving a desktop network onto a server: a phone paired with the desktop
//! keeps working with the server after a recovery file is restored there,
//! without pairing again.
#![cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};
use connect_core::{
    Connectivity,
    device::{DeviceController, PairedDevice},
    owner::OwnerRuntime,
    recovery,
    session::{bridge::BridgeRoute, pairing::PairGrant},
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn owner_binary() -> Result<PathBuf> {
    std::env::var_os("CONNECT_OWNER_BINARY")
        .map(PathBuf::from)
        .context("Set CONNECT_OWNER_BINARY to the packaged authority")
}

fn master_key(directory: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(directory)?;
    let mut key = [0; 32];
    getrandom::fill(&mut key)?;
    std::fs::write(directory.join("connect-master-key"), key)?;
    Ok(directory.to_owned())
}

fn node(state: &Path, store: &Path, credentials: &Path, args: &[&str]) -> Result<Command> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_genesismesh-connect-node"));
    command
        .args(args)
        .arg("--state")
        .arg(state)
        .arg("--authority")
        .arg(owner_binary()?)
        .env("CONNECT_SEALED_STORE", store)
        .env("CREDENTIALS_DIRECTORY", credentials);
    Ok(command)
}

fn control(state: &Path, request: Value) -> Result<Value> {
    let mut stream = UnixStream::connect(state.join("control.sock"))?;
    writeln!(stream, "{request}")?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    let mut reply: Value = serde_json::from_str(&line)?;
    if let Some(error) = reply.get("error") {
        anyhow::bail!("{error}");
    }
    Ok(reply["ok"].take())
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
fn a_desktop_network_moves_onto_a_server_and_its_phone_keeps_working() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path();
    // This process plays the desktop and the phone.
    connect_core::device::use_sealed_store(
        path.join("local-store"),
        &master_key(&path.join("local-credentials"))?.join("connect-master-key"),
    )?;
    let runtime = tokio::runtime::Runtime::new()?;

    // The desktop network computer, private on this network.
    let mut owner = OwnerRuntime::start(&owner_binary()?, &path.join("desktop/network-owner"))?;
    let info = owner.create("Moving network")?;
    let mut desktop = DeviceController::prepare(
        &path.join("desktop/device"),
        info.url.clone(),
        info.pin.clone(),
    )?;
    desktop.enable_managed_connectivity()?;
    let desktop_node = desktop.status()?.node_public_key;
    let invitation = owner.invite(&desktop_node, true)?;
    runtime.block_on(desktop.enroll_host(&invitation))?;
    runtime.block_on(desktop.set_network_connectivity(Connectivity::LocalNetwork))?;

    // A phone pairs with the desktop, as in the app.
    let pair = runtime.block_on(desktop.create_pairing("Desktop".into()))?;
    let card = connect_core::session::pairing::PairCard::parse(&pair.card().link()?)?;
    let mut phone = DeviceController::prepare_remote(&path.join("phone"), card.pin.clone())?;
    let mut joining = runtime.block_on(phone.request_pairing(card.clone(), "Phone".into()))?;
    let request = pair.pending().context("No pending approval")?;
    let invitation = owner.invite(&request.node, true)?;
    runtime.block_on(desktop.start(&request.node))?;
    let host = desktop.status()?;
    let completion = pair.approve(
        &request.id,
        PairGrant {
            invitation,
            route: BridgeRoute {
                host_node: host.node_public_key.clone(),
                ticket: host.bridge_ticket.context("Missing authority connection")?,
            },
            session_ticket: host.ticket.context("Missing device connection")?,
        },
    )?;
    runtime.block_on(async {
        let grant = joining.grant().await?;
        phone.use_bridge(grant.route).await?;
        phone.enroll_host(&grant.invitation).await?;
        phone.start(&card.host_node).await?;
        phone
            .send(&grant.session_ticket, "Phone verifies desktop")
            .await?;
        let ticket = phone.status()?.ticket.context("Missing phone address")?;
        phone.remember_pairing(PairedDevice {
            name: card.host_name.clone(),
            node: card.host_node.clone(),
            ticket: grant.session_ticket,
        })?;
        let finish = joining.finish(ticket);
        let approve = async {
            let joined = completion.await?;
            desktop
                .send(&joined.ticket, "Desktop verifies phone")
                .await?;
            desktop.remember_pairing(PairedDevice {
                name: request.name.clone(),
                node: request.node.clone(),
                ticket: joined.ticket,
            })?;
            joined
                .confirm
                .send(true)
                .map_err(|_| anyhow::anyhow!("Phone disconnected"))?;
            Ok::<_, anyhow::Error>(())
        };
        let (a, b) = tokio::join!(finish, approve);
        a?;
        b?;
        joining.close().await;
        pair.close().await;
        Ok::<_, anyhow::Error>(())
    })?;

    // The owner saves a recovery file, then the desktop goes away.
    let file = path.join("desktop.gmrecovery");
    let key = recovery::create(
        &mut owner,
        info.pin.clone(),
        desktop.recovery_identity()?,
        &file,
    )?;
    runtime.block_on(desktop.stop());
    drop(desktop);
    drop(owner);

    // The server restores it and runs it.
    let (state, store) = (path.join("server"), path.join("server-store"));
    let credentials = master_key(&path.join("server-credentials"))?;
    let mut restore = node(
        &state,
        &store,
        &credentials,
        &["restore", file.to_str().unwrap()],
    )?
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()?;
    writeln!(
        restore.stdin.take().context("Missing stdin")?,
        "{}",
        key.as_str()
    )?;
    let restored = restore.wait_with_output()?;
    ensure!(
        restored.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let server = node(&state, &store, &credentials, &["run"])?.spawn()?;
    let outcome = (|| {
        let deadline = Instant::now() + Duration::from_secs(60);
        while UnixStream::connect(state.join("control.sock")).is_err() {
            ensure!(Instant::now() < deadline, "The node did not start");
            std::thread::sleep(Duration::from_millis(200));
        }
        let status = control(&state, json!({"op":"status"}))?;
        assert_eq!(status["network"], "Moving network");
        assert_eq!(status["devices"], json!(["Phone"]));
        assert_eq!(status["connection"]["network"], "local_network");
        // The phone reaches the same network computer, now on the server,
        // from the addresses it already saved.
        runtime.block_on(phone.refresh())?;
        let saved = phone
            .paired_device()
            .context("Missing saved computer")?
            .ticket
            .clone();
        runtime.block_on(phone.send(&saved, "Phone reaches the server"))?;
        Ok::<_, anyhow::Error>(())
    })();
    runtime.block_on(phone.stop());
    stop(server)?;
    outcome
}
