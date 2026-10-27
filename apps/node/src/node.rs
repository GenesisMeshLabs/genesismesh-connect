use anyhow::{Context, Result, bail, ensure};
use connect_core::{
    Connectivity,
    device::{DeviceController, PairedDevice},
    owner::{OwnerInfo, OwnerRuntime},
    recovery,
    session::{
        bridge::BridgeRoute,
        pairing::{PairGrant, PairHost},
    },
};
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};
use zeroize::Zeroizing;

const USAGE: &str = "\
Usage: genesismesh-connect-node <command> [--state DIR] [--authority FILE]

Set up once:
  init [--name NAME]   Create a network on this server
  restore FILE         Bring a network back from a recovery file (key on stdin)

Under systemd:
  run                  Keep the network available

While the service runs:
  pair [--name NAME]   Add a device; NAME is how this server appears on it
  status               Show the network, its connection and its devices
  connection public|private
                       Public relays, or private: local network only
  recovery NAME        Write recovery/NAME in the state directory and show its
                       key once

--state defaults to /var/lib/genesismesh-connect. --authority defaults to the
genesismesh-authority runtime installed beside this program.";

struct Options {
    command: String,
    state: PathBuf,
    authority: Option<PathBuf>,
    name: Option<String>,
    arguments: Vec<String>,
}

impl Options {
    fn parse(args: Vec<String>) -> Result<Self> {
        let mut args = args.into_iter();
        let mut options = Self {
            command: String::new(),
            state: PathBuf::from("/var/lib/genesismesh-connect"),
            authority: None,
            name: None,
            arguments: Vec::new(),
        };
        while let Some(arg) = args.next() {
            let mut value =
                |flag: &str| args.next().with_context(|| format!("{flag} needs a value"));
            match arg.as_str() {
                "--state" => options.state = PathBuf::from(value("--state")?),
                "--authority" => options.authority = Some(PathBuf::from(value("--authority")?)),
                "--name" => options.name = Some(value("--name")?),
                _ if options.command.is_empty() => options.command = arg,
                _ => options.arguments.push(arg),
            }
        }
        ensure!(
            options.state.is_absolute(),
            "--state must be an absolute directory"
        );
        Ok(options)
    }
    fn argument(&self, what: &str) -> Result<&str> {
        match self.arguments.as_slice() {
            [one] => Ok(one),
            _ => bail!("Give the {what}\n\n{USAGE}"),
        }
    }
    fn paths(&self) -> Result<Paths> {
        let authority = match &self.authority {
            Some(path) => path.clone(),
            None => std::env::current_exe()?.with_file_name("genesismesh-authority"),
        };
        ensure!(
            authority.is_absolute(),
            "--authority must be an absolute path"
        );
        Ok(Paths {
            owner: self.state.join("network-owner"),
            profile: self.state.join("device"),
            socket: self.state.join("control.sock"),
            state: self.state.clone(),
            authority,
        })
    }
}

struct Paths {
    state: PathBuf,
    owner: PathBuf,
    profile: PathBuf,
    socket: PathBuf,
    authority: PathBuf,
}

impl Paths {
    /// The state directory belongs to the service's user alone.
    fn prepare(&self) -> Result<()> {
        std::fs::create_dir_all(&self.state)?;
        std::fs::set_permissions(&self.state, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    fn configured(&self) -> bool {
        self.owner.join("owner.json").exists() || self.profile.exists()
    }
    fn start(&self, directory: &Path) -> Result<OwnerRuntime> {
        OwnerRuntime::start(&self.authority, directory)
    }
    /// One process at a time owns the network's state: `init`, `restore` or
    /// `run`. The lock lasts as long as the returned file.
    fn lock(&self) -> Result<std::fs::File> {
        self.prepare()?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.state.join(".lock"))?;
        file.try_lock().map_err(|_| {
            anyhow::anyhow!(
                "Another Connect node command is using this network. Try again when it finishes."
            )
        })?;
        Ok(file)
    }
}

/// The node keeps its identities only in a sealed store under the master key
/// systemd delivers; it never uses a desktop keyring or plaintext.
fn seal() -> Result<()> {
    let directory = std::env::var_os("CONNECT_SEALED_STORE").map(PathBuf::from);
    let credentials = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
    let (Some(directory), Some(credentials)) = (directory, credentials) else {
        bail!(
            "The node keeps its keys in a sealed store under a systemd credential. \
             Use the genesismesh-connect command or the systemd service."
        );
    };
    connect_core::device::use_sealed_store(
        directory,
        &credentials.join(connect_core::device::MASTER_KEY_CREDENTIAL),
    )
}

pub async fn main(args: Vec<String>) -> Result<()> {
    let options = Options::parse(args)?;
    let paths = options.paths()?;
    match options.command.as_str() {
        "init" => {
            seal()?;
            let _lock = paths.lock()?;
            init(&paths, options.name.as_deref().unwrap_or("Home network")).await
        }
        "restore" => {
            seal()?;
            let _lock = paths.lock()?;
            restore(&paths, options.argument("recovery file")?)
        }
        "run" => {
            seal()?;
            let _lock = paths.lock()?;
            run(&paths).await
        }
        "pair" => pair(&paths, options.name.as_deref().unwrap_or("Network server")).await,
        "status" => status(&paths).await,
        "connection" => {
            let setting = match options.argument("setting: public or private")? {
                "public" => Connectivity::PublicRelays,
                "private" => Connectivity::LocalNetwork,
                other => bail!("Choose public or private, not {other:?}"),
            };
            request(&paths, json!({"op":"connection","setting":setting})).await?;
            println!("{}", describe(setting));
            Ok(())
        }
        "recovery" => recovery_file(&paths, options.argument("recovery file name")?).await,
        "" | "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        other => bail!("Unknown command {other:?}\n\n{USAGE}"),
    }
}

fn describe(connectivity: Connectivity) -> &'static str {
    match connectivity {
        Connectivity::PublicRelays => "Public relays: devices reach this server from anywhere.",
        Connectivity::LocalNetwork => {
            "Private: devices connect only on this server's local network."
        }
    }
}

async fn init(paths: &Paths, name: &str) -> Result<()> {
    ensure!(
        !paths.configured(),
        "This server already has a network. It has been preserved."
    );
    let mut owner = Some(paths.start(&paths.owner)?);
    let mut device = None;
    let outcome = async {
        let runtime = owner.as_mut().context("Missing network runtime")?;
        let info = runtime.create(name)?;
        let controller = device.insert(DeviceController::prepare(
            &paths.profile,
            info.url.clone(),
            info.pin.clone(),
        )?);
        controller.enable_managed_connectivity()?;
        let node = controller.status()?.node_public_key;
        let invitation = runtime.invite(&node, true)?;
        controller.enroll_host(&invitation).await?;
        Ok::<_, anyhow::Error>(info)
    }
    .await;
    let info = match outcome {
        Ok(info) => info,
        Err(error) => {
            // Nothing half-made stays behind: stop the authority, then remove
            // the network and this server's identity with its sealed record.
            drop(owner);
            if let Some(device) = device {
                device.discard().ok();
            }
            std::fs::remove_dir_all(&paths.profile).ok();
            std::fs::remove_dir_all(&paths.owner).ok();
            return Err(error);
        }
    };
    println!(
        "Network \"{}\" is ready. Start the service, then add devices with the pair command.\n\
         Write a recovery file soon (the recovery command): it is the only way back if this \
         server's disk or TPM is lost.",
        info.pin.network_name
    );
    Ok(())
}

/// Read the recovery key without showing it on a terminal.
fn read_key() -> Result<Zeroizing<String>> {
    use std::io::IsTerminal;
    let terminal = std::io::stdin().is_terminal();
    eprint!("Recovery key: ");
    if terminal {
        std::process::Command::new("stty")
            .arg("-echo")
            .status()
            .ok();
    }
    let mut key = Zeroizing::new(String::new());
    let read = std::io::stdin().read_line(&mut key);
    if terminal {
        std::process::Command::new("stty").arg("echo").status().ok();
        eprintln!();
    }
    read?;
    Ok(key)
}

fn restore(paths: &Paths, file: &str) -> Result<()> {
    ensure!(
        !paths.configured(),
        "This server already has a network. It has been preserved."
    );
    ensure!(
        Path::new(file).is_absolute(),
        "Give the recovery file's full path"
    );
    let file = std::fs::canonicalize(file).context("Choose an existing recovery file")?;
    let key = read_key()?;
    let restored = recovery::restore(&file, &key, &paths.owner, &paths.profile, |dir: &Path| {
        paths.start(dir)
    })?;
    println!(
        "Network \"{}\" is back on this server. Devices reconnect when they next reach it. \
         Retire the computer the recovery file came from, and delete the copy of the file \
         you placed on this server.",
        restored.info.pin.network_name
    );
    Ok(())
}

struct Node {
    owner: OwnerRuntime,
    info: OwnerInfo,
    device: DeviceController,
    pairing: Option<Arc<PairHost>>,
    /// Recovery files are written here, inside the service's state.
    recovery: PathBuf,
}
type Shared = Arc<Mutex<Node>>;

async fn run(paths: &Paths) -> Result<()> {
    ensure!(
        paths.owner.join("owner.json").exists() && paths.profile.exists(),
        "Create a network with init, or bring one back with restore, first"
    );
    let mut owner = paths.start(&paths.owner)?;
    let info = owner.open()?;
    let mut device = DeviceController::open(&paths.profile)?;
    device.rebind_owned_authority(info.url.clone(), &info.pin)?;
    if let Err(error) = device.reconnect_saved().await {
        eprintln!("Saved devices are not reachable yet: {error:#}");
    }
    println!(
        "Network \"{}\" is running. {}",
        info.pin.network_name,
        describe(device.status()?.connectivity.network)
    );
    let node: Shared = Arc::new(Mutex::new(Node {
        owner,
        info,
        device,
        pairing: None,
        recovery: paths.state.join("recovery"),
    }));
    match std::fs::remove_file(&paths.socket) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    let listener = UnixListener::bind(&paths.socket)?;
    std::fs::set_permissions(&paths.socket, std::fs::Permissions::from_mode(0o600))?;
    let control = tokio::spawn(serve(listener, node.clone()));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                let mut node = node.lock().await;
                // Without its authority the network is not available; exit so
                // systemd restarts the whole node.
                if !node.owner.is_running() {
                    node.device.stop().await;
                    let _ = std::fs::remove_file(&paths.socket);
                    bail!("The network's authority stopped");
                }
                if node.device.needs_maintenance()
                    && let Err(error) = node.device.refresh().await
                {
                    eprintln!("Trust refresh failed; connections are paused: {error:#}");
                }
            }
            _ = terminate.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    control.abort();
    let mut node = node.lock().await;
    if let Some(pairing) = node.pairing.take() {
        pairing.close().await;
    }
    node.device.stop().await;
    let _ = std::fs::remove_file(&paths.socket);
    Ok(())
}

async fn serve(listener: UnixListener, node: Shared) {
    while let Ok((stream, _)) = listener.accept().await {
        let node = node.clone();
        tokio::spawn(async move {
            let _ = answer(stream, node).await;
        });
    }
}

/// One JSON request and one JSON reply per connection.
async fn answer(stream: UnixStream, node: Shared) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    BufReader::new(read.take(64 * 1024))
        .read_line(&mut line)
        .await?;
    let outcome = match serde_json::from_str(&line) {
        Ok(request) => handle(&node, request).await,
        Err(_) => Err(anyhow::anyhow!("Unreadable request")),
    };
    let reply = match outcome {
        Ok(value) => json!({"ok":value}),
        Err(error) => json!({"error":format!("{error:#}")}),
    };
    write
        .write_all(serde_json::to_string(&reply)?.as_bytes())
        .await?;
    write.write_all(b"\n").await?;
    Ok(())
}

async fn handle(node: &Shared, request: Value) -> Result<Value> {
    match request["op"].as_str().context("Missing operation")? {
        "status" => {
            let node = node.lock().await;
            let status = node.device.status()?;
            Ok(json!({
                "network": status.network,
                "connection": status.connectivity,
                "devices": status.devices.iter().map(|d| d.name.clone()).collect::<Vec<_>>(),
                "ready": status.ready,
                "certificate_expires_at": status.certificate_expires_at,
                "problem": status.problem,
            }))
        }
        "pair_begin" => {
            let name = request["name"]
                .as_str()
                .context("Name this server for the device")?;
            let mut node = node.lock().await;
            if let Some(previous) = node.pairing.take() {
                previous.close().await;
            }
            let host = node.device.create_pairing(name.into()).await?;
            let card = host.card();
            let link = json!({"link":card.link()?,"expires_at":card.expires_at});
            node.pairing = Some(host);
            Ok(link)
        }
        "pair_pending" => {
            let node = node.lock().await;
            Ok(json!(node.pairing.as_ref().and_then(|p| p.pending())))
        }
        "pair_approve" => {
            approve(node, request["id"].as_str().context("Missing request")?).await?;
            Ok(json!(true))
        }
        "pair_reject" => {
            let node = node.lock().await;
            node.pairing
                .as_ref()
                .context("No device is waiting")?
                .reject(request["id"].as_str().context("Missing request")?)?;
            Ok(json!(true))
        }
        "pair_cancel" => {
            if let Some(pairing) = node.lock().await.pairing.take() {
                pairing.close().await;
            }
            Ok(json!(true))
        }
        "connection" => {
            let setting: Connectivity = serde_json::from_value(request["setting"].clone())?;
            node.lock()
                .await
                .device
                .set_network_connectivity(setting)
                .await?;
            Ok(json!(true))
        }
        "recovery" => {
            let name = request["name"].as_str().context("Missing file name")?;
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
                    && !name.starts_with('.'),
                "Name the recovery file with letters, digits, dots, dashes or underscores"
            );
            let mut node = node.lock().await;
            std::fs::create_dir_all(&node.recovery)?;
            std::fs::set_permissions(&node.recovery, std::fs::Permissions::from_mode(0o700))?;
            let path = node.recovery.join(name);
            ensure!(!path.exists(), "That recovery file already exists");
            let identity = node.device.recovery_identity()?;
            let pin = node.info.pin.clone();
            let key = tokio::task::block_in_place(|| {
                recovery::create(&mut node.owner, pin, identity, &path)
            })?;
            Ok(json!({"key":key.as_str(),"path":path}))
        }
        _ => bail!("Unsupported operation"),
    }
}

/// The owner approved this request: enroll the device, then require its final
/// proof over a real connection before remembering it, as on a desktop.
async fn approve(node: &Shared, id: &str) -> Result<()> {
    let (pair, request, completion) = {
        let mut node = node.lock().await;
        let pair = node.pairing.clone().context("Start pairing first")?;
        let request = pair
            .pending()
            .filter(|r| r.id == id)
            .context("This device is no longer waiting")?;
        let invitation = tokio::task::block_in_place(|| node.owner.invite(&request.node, true))?;
        node.device.start(&request.node).await?;
        let status = node.device.status()?;
        let grant = PairGrant {
            invitation,
            route: BridgeRoute {
                host_node: status.node_public_key,
                ticket: status
                    .bridge_ticket
                    .context("Authority connection is unavailable")?,
            },
            session_ticket: status.ticket.context("Device connection is unavailable")?,
        };
        let completion = pair.approve(id, grant)?;
        (pair, request, completion)
    };
    let joined = tokio::time::timeout(Duration::from_secs(80), completion)
        .await
        .context("The other device did not finish joining")?
        .context("The other device disconnected")?;
    // The device waits briefly for confirmation, so its final proof is checked
    // without holding the node while other work runs.
    let session = node.lock().await.device.session()?;
    if let Err(error) = session
        .round_trip_to(
            Some(&request.node),
            &joined.ticket,
            "Connect pairing verification",
        )
        .await
    {
        let _ = joined.confirm.send(false);
        return Err(error);
    }
    let mut node = node.lock().await;
    node.device.remember_pairing(PairedDevice {
        name: request.name,
        node: request.node,
        ticket: joined.ticket,
    })?;
    let _ = joined.confirm.send(true);
    // A newer invitation from another terminal stays open.
    if node
        .pairing
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, &pair))
    {
        node.pairing = None;
    }
    // The device needs this server's final confirmation before it closes.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        pair.close().await;
    });
    Ok(())
}

async fn request(paths: &Paths, request: Value) -> Result<Value> {
    let mut stream = UnixStream::connect(&paths.socket).await.with_context(|| {
        format!(
            "Is the Connect node running? Could not open {}",
            paths.socket.display()
        )
    })?;
    stream
        .write_all(serde_json::to_string(&request)?.as_bytes())
        .await?;
    stream.write_all(b"\n").await?;
    let mut line = String::new();
    BufReader::new(stream.take(64 * 1024))
        .read_line(&mut line)
        .await?;
    let mut reply: Value = serde_json::from_str(&line).context("The node did not answer")?;
    if let Some(error) = reply.get("error").and_then(Value::as_str) {
        bail!("{error}");
    }
    Ok(reply["ok"].take())
}

async fn status(paths: &Paths) -> Result<()> {
    let status = request(paths, json!({"op":"status"})).await?;
    let connection: connect_core::Connectivity =
        serde_json::from_value(status["connection"]["network"].clone())?;
    println!("Network: {}", status["network"].as_str().unwrap_or("?"));
    println!("Connection: {}", describe(connection));
    let devices: Vec<String> = serde_json::from_value(status["devices"].clone())?;
    if devices.is_empty() {
        println!("Devices: none yet. Add one with the pair command.");
    } else {
        println!("Devices: {}", devices.join(", "));
    }
    if let Some(problem) = status["problem"].as_str() {
        println!("Problem: {problem}");
    }
    Ok(())
}

async fn pair(paths: &Paths, name: &str) -> Result<()> {
    let begun = request(paths, json!({"op":"pair_begin","name":name})).await?;
    println!(
        "On the device, open Connect, choose Join a network and paste this invitation:\n\n{}\n",
        begun["link"].as_str().context("Missing invitation")?
    );
    println!("It works once and expires in five minutes. Waiting for the device...");
    let deadline = Instant::now() + Duration::from_secs(300);
    let pending = loop {
        let pending = request(paths, json!({"op":"pair_pending"})).await?;
        if !pending.is_null() {
            break pending;
        }
        if Instant::now() > deadline {
            request(paths, json!({"op":"pair_cancel"})).await?;
            bail!("The invitation expired. Run pair again for a new one.");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    let id = pending["id"].as_str().context("Missing request")?;
    println!(
        "\"{}\" asks to join. Its code is {}.",
        pending["name"].as_str().unwrap_or("A device"),
        pending["code"].as_str().unwrap_or("?")
    );
    print!("Does the device show the same code? Allow it [y/N]: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut answer = String::new();
    BufReader::new(tokio::io::stdin())
        .read_line(&mut answer)
        .await?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        request(paths, json!({"op":"pair_approve","id":id})).await?;
        println!("Paired. The device is connected to this network.");
    } else {
        request(paths, json!({"op":"pair_reject","id":id})).await?;
        println!("Not allowed. The invitation can no longer be used.");
    }
    Ok(())
}

async fn recovery_file(paths: &Paths, name: &str) -> Result<()> {
    let reply = request(paths, json!({"op":"recovery","name":name})).await?;
    println!(
        "Recovery file written to {}.\n\nRecovery key: {}\n\n\
         Write the key down now; it is not shown again. Copy the file somewhere safe, \
         apart from the key, then delete it here: anyone with both can restore this network.",
        reply["path"].as_str().context("Missing recovery file")?,
        reply["key"].as_str().context("Missing recovery key")?
    );
    Ok(())
}
