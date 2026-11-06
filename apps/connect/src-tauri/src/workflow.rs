//! Local owner operations. The web UI supplies names, never keys or admin URLs.
use connect_core::{
    device::DeviceController,
    owner::{OwnerHandle, OwnerInfo, OwnerRequest, OwnerRuntime},
    session::bridge::SpaceView,
};
use serde::Serialize;
use std::path::PathBuf;
use tauri::Manager;
use tokio::sync::Mutex;

pub(crate) struct OwnerSlot {
    pub(crate) runtime: Option<OwnerRuntime>,
    pub(crate) info: Option<OwnerInfo>,
    pub(crate) problem: Option<String>,
    pub(crate) pairing: Option<std::sync::Arc<connect_core::session::pairing::PairHost>>,
    pub(crate) joining: Option<String>,
    /// Held while this phone runs its own network; another setup must not overlap.
    #[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
    pub(crate) lease: Option<connect_core::owner::foreground::ForegroundLease>,
}
pub struct WorkflowState {
    pub(crate) directory: PathBuf,
    pub(crate) slot: Mutex<OwnerSlot>,
    /// Devices' Space requests reach this computer's owner runtime here.
    pub(crate) owner: OwnerHandle,
}
#[derive(Serialize)]
pub struct NetworkStatus {
    runtime_available: bool,
    /// This phone runs the network itself, while Connect is open.
    phone: bool,
    owner: bool,
    network_name: Option<String>,
    problem: Option<String>,
}
fn runtime_available() -> bool {
    if cfg!(all(target_os = "android", feature = "android-owner-qualification")) {
        return true;
    }
    #[cfg(debug_assertions)]
    if std::env::var_os("CONNECT_NA_PYTHON").is_some() {
        return cfg!(any(windows, target_os = "macos", target_os = "linux"));
    }
    cfg!(any(windows, target_os = "macos", target_os = "linux"))
        && std::env::current_exe()
            .ok()
            .is_some_and(|p| p.with_file_name(runtime_name()).is_file())
}
fn runtime_name() -> &'static str {
    if cfg!(windows) {
        "genesismesh-authority.exe"
    } else {
        "genesismesh-authority"
    }
}
#[cfg_attr(all(target_os = "android", feature = "android-owner-qualification"), allow(dead_code))]
fn start(directory: &std::path::Path) -> anyhow::Result<OwnerRuntime> {
    anyhow::ensure!(
        cfg!(any(windows, target_os = "macos", target_os = "linux")),
        "Create your network on a desktop or NAS"
    );
    #[cfg(debug_assertions)]
    if let Some(python) = std::env::var_os("CONNECT_NA_PYTHON") {
        return OwnerRuntime::start_python(
            &PathBuf::from(python),
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../authority/main.py"),
            directory,
        );
    }
    OwnerRuntime::start(
        &std::env::current_exe()?.with_file_name(runtime_name()),
        directory,
    )
}
pub fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let desktop = app.state::<crate::desktop::DesktopState>();
    let directory = desktop
        .profile
        .parent()
        .ok_or("Missing application directory")?
        .join("network-owner");
    // Mobile foreground setup uses native custody discovery, never desktop files
    // and never automatic authority startup. Its private coordinator is below.
    let configured = cfg!(any(windows, target_os = "macos", target_os = "linux"))
        && directory.join("owner.json").is_file();
    let (owner, requests) = tokio::sync::mpsc::channel(8);
    app.manage(WorkflowState {
        directory,
        slot: Mutex::new(OwnerSlot {
            runtime: None,
            info: None,
            problem: None,
            pairing: None,
            joining: None,
            #[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
            lease: None,
        }),
        owner,
    });
    tauri::async_runtime::spawn(answer_owner(app.handle().clone(), requests));
    tauri::async_runtime::spawn(keep_spaces(app.handle().clone()));
    #[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
    tauri::async_runtime::spawn(keep_phone_network(app.handle().clone()));
    if configured {
        let handle = app.handle().clone();
        tauri::async_runtime::spawn(async move {
            let state = handle.state::<WorkflowState>();
            let directory = state.directory.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let mut runtime = start(&directory)?;
                let info = runtime.open()?;
                Ok::<_, anyhow::Error>((runtime, info))
            })
            .await;
            let mut owner = state.slot.lock().await;
            match outcome {
                Ok(Ok((runtime, info))) => {
                    let desktop = handle.state::<crate::desktop::DesktopState>();
                    let mut slot = desktop.slot.lock().await;
                    if let Some(controller) = &mut slot.controller
                        && let Err(error) =
                            controller.rebind_owned_authority(info.url.clone(), &info.pin)
                    {
                        owner.problem = Some(error.to_string());
                        return;
                    }
                    owner.runtime = Some(runtime);
                    owner.info = Some(info);
                    if let Some(controller) = &mut slot.controller {
                        controller.serve_owner(state.owner.clone());
                        if let Err(error) = controller.restore_managed_share() {
                            owner.problem = Some(error.to_string());
                        }
                        if let Err(error) = controller.reconnect_saved().await {
                            slot.problem = Some(error.to_string());
                        }
                    }
                }
                Ok(Err(error)) => owner.problem = Some(error.to_string()),
                Err(_) => owner.problem = Some("The local network could not reopen.".into()),
            }
        });
    }
    Ok(())
}

#[tauri::command]
pub async fn network_status(
    state: tauri::State<'_, WorkflowState>,
) -> Result<NetworkStatus, String> {
    let slot = state.slot.lock().await;
    Ok(NetworkStatus {
        runtime_available: runtime_available(),
        phone: cfg!(all(target_os = "android", feature = "android-owner-qualification")),
        owner: slot.info.is_some()
            || (cfg!(any(windows, target_os = "macos", target_os = "linux"))
                && state.directory.join("owner.json").is_file())
            || phone_setup_marker(&state.directory),
        network_name: slot.info.as_ref().map(|i| i.pin.network_name.clone()),
        problem: slot.problem.clone(),
    })
}

/// Foreground phone setup: Create and launch-time Open in the owner build only.
#[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
pub(crate) async fn prepare_foreground_phone(
    app: tauri::AppHandle,
    choice: connect_core::owner::foreground::SetupChoice,
) -> anyhow::Result<connect_core::owner::foreground::ForegroundNetwork> {
    use connect_core::owner::foreground::{ForegroundSetup, NativeSetupConfig};
    // The fixed qualification app's OS-private directory is selected natively.
    // Neither owner.json nor a frontend-selected path/origin participates.
    let config = NativeSetupConfig::new(app.path().app_data_dir()?.canonicalize()?)?;
    let mut setup = tokio::task::spawn_blocking(move || {
        let runtime = crate::android_owner::prepare(&app)?;
        let mut setup = ForegroundSetup::begin(runtime, config, choice)?;
        setup.open_authority()?;
        setup.prepare_device()?;
        setup.request_invitation()?;
        Ok::<_, anyhow::Error>(setup)
    })
    .await??;
    setup.enroll_device().await?;
    setup.finish()
}

#[tauri::command]
pub async fn network_create(
    name: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, crate::desktop::DesktopState>,
) -> Result<(), String> {
    #[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
    {
        let _ = (&state, &desktop);
        return create_phone_network(app, name).await;
    }
    #[cfg(not(all(target_os = "android", feature = "android-owner-qualification")))]
    {
        let _ = app;
        install_network(Some(name), None, &state, &desktop).await
    }
}

/// Reopen this phone's network after it stopped, for example when Android
/// closed the app. Elsewhere the network computer reopens on its own.
#[tauri::command]
pub async fn network_reopen(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
    {
        if !phone_network_saved(&app) {
            return Err("This phone has no network to reopen.".into());
        }
        let result = open_phone_network(app.clone()).await;
        app.state::<WorkflowState>().slot.lock().await.problem = result.clone().err();
        result
    }
    #[cfg(not(all(target_os = "android", feature = "android-owner-qualification")))]
    {
        let _ = app;
        Err("Reopen your network on the computer that runs it.".into())
    }
}

/// The foreground setup journal sits beside the device profile; its presence
/// means this phone created a network, finished or not.
fn phone_setup_marker(owner_directory: &std::path::Path) -> bool {
    cfg!(all(target_os = "android", feature = "android-owner-qualification"))
        && owner_directory.parent().is_some_and(|parent| {
            parent.join("foreground-setup.json").exists()
                || parent.join("foreground-setup.lock").exists()
        })
}

/// One phone setup at a time: Create, Open and reopening never overlap.
#[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
static PHONE_SETUP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
struct SetupTurn;
#[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
impl SetupTurn {
    fn take() -> Option<Self> {
        use std::sync::atomic::Ordering::SeqCst;
        PHONE_SETUP
            .compare_exchange(false, true, SeqCst, SeqCst)
            .ok()
            .map(|_| Self)
    }
}
#[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
impl Drop for SetupTurn {
    fn drop(&mut self) {
        PHONE_SETUP.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
fn phone_network_saved(app: &tauri::AppHandle) -> bool {
    phone_setup_marker(&app.state::<WorkflowState>().directory)
}

/// Create a network run by this phone. Saved progress makes an interrupted
/// creation reviewable; it is never repeated as a new identity.
#[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
async fn create_phone_network(app: tauri::AppHandle, name: String) -> Result<(), String> {
    let _turn = SetupTurn::take().ok_or("Your network is already being set up.")?;
    {
        let state = app.state::<WorkflowState>();
        let desktop = app.state::<crate::desktop::DesktopState>();
        let owner = state.slot.lock().await;
        let slot = desktop.slot.lock().await;
        if slot.controller.is_some() || desktop.profile.exists() {
            return Err("This phone already has a network identity. It has been preserved.".into());
        }
        if owner.runtime.is_some() || phone_setup_marker(&state.directory) {
            return Err(
                "This phone already started a network. Reopen it instead of creating another."
                    .into(),
            );
        }
    }
    let name = name.trim().to_owned();
    let network = prepare_foreground_phone(
        app.clone(),
        connect_core::owner::foreground::SetupChoice::Create { name },
    )
    .await
    .map_err(|e| e.to_string())?;
    adopt_phone_network(&app, network).await;
    Ok(())
}

/// Reopen this phone's network in the foreground. Only saved, completed work is
/// opened; an unfinished step stays for review and is never repeated.
#[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
pub(crate) async fn open_phone_network(app: tauri::AppHandle) -> Result<(), String> {
    // Another setup is under way; it leaves the network open or says why not.
    let Some(_turn) = SetupTurn::take() else {
        return Ok(());
    };
    let (runtime, device, lease) = {
        let state = app.state::<WorkflowState>();
        let mut owner = state.slot.lock().await;
        if owner.runtime.as_mut().is_some_and(OwnerRuntime::is_running) {
            return Ok(());
        }
        let desktop = app.state::<crate::desktop::DesktopState>();
        let mut slot = desktop.slot.lock().await;
        let device = if owner.runtime.is_some() {
            slot.controller.take()
        } else {
            None
        };
        (owner.runtime.take(), device, owner.lease.take())
    };
    // A stopped session closes its native owner before another may begin; the
    // device and the setup lease go with it and are reopened below.
    drop(runtime);
    if let Some(mut device) = device {
        device.stop().await;
    }
    drop(lease);
    let mut attempt = 0;
    let network = loop {
        match prepare_foreground_phone(
            app.clone(),
            connect_core::owner::foreground::SetupChoice::Open,
        )
        .await
        {
            Ok(network) => break network,
            // The native close above settles on the plugin's worker first.
            Err(_) if attempt < 3 => {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            }
            Err(error) => return Err(error.to_string()),
        }
    };
    adopt_phone_network(&app, network).await;
    let desktop = app.state::<crate::desktop::DesktopState>();
    let mut slot = desktop.slot.lock().await;
    if let Some(device) = slot.controller.as_mut() {
        if let Err(error) = device.restore_managed_share() {
            slot.problem = Some(error.to_string());
        } else if let Err(error) = device.reconnect_saved().await {
            slot.problem = Some(error.to_string());
        }
    }
    Ok(())
}

/// While Connect runs, keep this phone's network open: at launch, and again
/// whenever its native session stopped. Opening never repeats a write.
#[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
async fn keep_phone_network(app: tauri::AppHandle) {
    let mut wait = std::time::Duration::from_secs(1);
    loop {
        tokio::time::sleep(wait).await;
        wait = std::time::Duration::from_secs(15);
        if !phone_network_saved(&app) {
            continue;
        }
        let stopped = {
            let state = app.state::<WorkflowState>();
            let mut owner = state.slot.lock().await;
            !owner.runtime.as_mut().is_some_and(OwnerRuntime::is_running)
        };
        if stopped {
            let result = open_phone_network(app.clone()).await;
            app.state::<WorkflowState>().slot.lock().await.problem = result.err();
        }
    }
}

#[cfg(all(target_os = "android", feature = "android-owner-qualification"))]
async fn adopt_phone_network(
    app: &tauri::AppHandle,
    network: connect_core::owner::foreground::ForegroundNetwork,
) {
    let state = app.state::<WorkflowState>();
    let desktop = app.state::<crate::desktop::DesktopState>();
    let mut owner = state.slot.lock().await;
    let mut slot = desktop.slot.lock().await;
    let connect_core::owner::foreground::ForegroundNetwork {
        runtime,
        info,
        mut device,
        lease,
    } = network;
    device.serve_owner(state.owner.clone());
    owner.runtime = Some(runtime);
    owner.info = Some(info);
    owner.lease = Some(lease);
    owner.problem = None;
    slot.controller = Some(device);
    slot.problem = None;
}
#[tauri::command]
pub async fn network_attach(
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, crate::desktop::DesktopState>,
) -> Result<bool, String> {
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = (state, desktop);
        Err("Select your existing network on the computer that runs it.".into())
    }
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    {
        let Some(config) = rfd::AsyncFileDialog::new()
            .add_filter("Genesis Mesh settings", &["toml"])
            .set_title("Choose the existing authority's Genesis Mesh settings")
            .pick_file()
            .await
        else {
            return Ok(false);
        };
        install_network(None, Some(config.path().to_owned()), &state, &desktop).await?;
        Ok(true)
    }
}
#[cfg_attr(all(target_os = "android", feature = "android-owner-qualification"), allow(dead_code))]
async fn install_network(
    name: Option<String>,
    config: Option<PathBuf>,
    state: &WorkflowState,
    desktop: &crate::desktop::DesktopState,
) -> Result<(), String> {
    let mut owner = state.slot.lock().await;
    let mut slot = desktop.slot.lock().await;
    if slot.controller.is_some() {
        return Err("This computer already has a network identity. It has been preserved.".into());
    }
    if owner.runtime.is_some() || state.directory.join("owner.json").exists() {
        return Err(
            "A network is already configured. Reopen it instead of creating another identity."
                .into(),
        );
    }
    let directory = state.directory.clone();
    let (mut runtime, info) = tokio::task::spawn_blocking(move || {
        let mut runtime = start(&directory)?;
        let info = match (name, config) {
            (Some(name), None) => runtime.create(&name)?,
            (None, Some(config)) => runtime.attach(&config)?,
            _ => anyhow::bail!("Choose one network setup method"),
        };
        Ok::<_, anyhow::Error>((runtime, info))
    })
    .await
    .map_err(|_| "Network setup did not finish.".to_owned())?
    .map_err(|e| e.to_string())?;
    let mut device =
        DeviceController::prepare(&desktop.profile, info.url.clone(), info.pin.clone())
            .map_err(|e| e.to_string())?;
    let node = device.status().map_err(|e| e.to_string())?.node_public_key;
    device
        .enable_managed_connectivity()
        .map_err(|e| e.to_string())?;
    device.serve_owner(state.owner.clone());
    let outcome = tokio::task::spawn_blocking(move || {
        let invitation = runtime.invite(&node, true);
        (runtime, invitation)
    })
    .await
    .map_err(|_| "The network invitation was not confirmed.".to_owned())?;
    runtime = outcome.0;
    owner.runtime = Some(runtime);
    owner.info = Some(info);
    // Preserve the device even after an uncertain enrollment; never silently
    // generate a different key and consume another invite on an automatic retry.
    let invitation = match outcome.1 {
        Ok(value) => value,
        Err(error) => {
            slot.controller = Some(device);
            return Err(error.to_string());
        }
    };
    let joined = device.enroll_host(&invitation).await;
    slot.controller = Some(device);
    joined.map_err(|e| e.to_string())?;
    slot.problem = None;
    Ok(())
}

/// Save an encrypted recovery file for this network computer and return its
/// recovery key, shown to the owner once. `None` when the owner cancels.
#[tauri::command]
pub async fn recovery_create(
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, crate::desktop::DesktopState>,
) -> Result<Option<String>, String> {
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = (state, desktop);
        Err("Create recovery files on your network computer.".into())
    }
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    {
        let Some(file) = rfd::AsyncFileDialog::new()
            .add_filter("Connect recovery file", &["gmrecovery"])
            .set_file_name("Genesis Mesh recovery.gmrecovery")
            .set_title("Save your network's recovery file")
            .save_file()
            .await
        else {
            return Ok(None);
        };
        let mut owner = state.slot.lock().await;
        let identity = {
            let slot = desktop.slot.lock().await;
            slot.controller
                .as_ref()
                .ok_or("Set up this computer first")?
                .recovery_identity()
                .map_err(|e| e.to_string())?
        };
        let pin = owner
            .info
            .as_ref()
            .ok_or("Your network is still opening")?
            .pin
            .clone();
        let mut runtime = owner
            .runtime
            .take()
            .ok_or("The network computer is not ready")?;
        let path = file.path().to_owned();
        let (runtime, key) = tokio::task::spawn_blocking(move || {
            let key = connect_core::recovery::create(&mut runtime, pin, identity, &path);
            (runtime, key)
        })
        .await
        .map_err(|_| "The recovery file was not written.".to_owned())?;
        owner.runtime = Some(runtime);
        Ok(Some(key.map_err(|e| e.to_string())?.to_string()))
    }
}

/// Bring a network back on this computer from a recovery file and its key.
/// `false` when the owner cancels choosing the file.
#[tauri::command]
pub async fn recovery_restore(
    key: String,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, crate::desktop::DesktopState>,
) -> Result<bool, String> {
    let key = zeroize::Zeroizing::new(key);
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = (key, state, desktop);
        Err("Restore your network on a desktop computer.".into())
    }
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    {
        let Some(file) = rfd::AsyncFileDialog::new()
            .add_filter("Connect recovery file", &["gmrecovery"])
            .set_title("Choose your network's recovery file")
            .pick_file()
            .await
        else {
            return Ok(false);
        };
        let mut owner = state.slot.lock().await;
        let mut slot = desktop.slot.lock().await;
        if slot.controller.is_some()
            || owner.runtime.is_some()
            || state.directory.join("owner.json").exists()
        {
            return Err("This computer already has a network. It has been preserved.".into());
        }
        let (directory, profile, path) = (
            state.directory.clone(),
            desktop.profile.clone(),
            file.path().to_owned(),
        );
        let restored = tokio::task::spawn_blocking(move || {
            connect_core::recovery::restore(&path, &key, &directory, &profile, start)
        })
        .await
        .map_err(|_| "The network was not restored.".to_owned())?
        .map_err(|e| e.to_string())?;
        owner.runtime = Some(restored.owner);
        owner.info = Some(restored.info);
        owner.problem = None;
        let mut device = restored.device;
        device.serve_owner(state.owner.clone());
        if let Err(error) = device.reconnect_saved().await {
            slot.problem = Some(error.to_string());
        }
        slot.controller = Some(device);
        Ok(true)
    }
}

/// Answer devices' Space requests, one at a time, with this computer's owner
/// runtime while it runs one.
async fn answer_owner(
    app: tauri::AppHandle,
    mut requests: tokio::sync::mpsc::Receiver<OwnerRequest>,
) {
    while let Some(request) = requests.recv().await {
        let state = app.state::<WorkflowState>();
        let mut owner = state.slot.lock().await;
        if let connect_core::owner::OwnerCall::PairingCompletion {
            node,
            certificate,
            query,
        } = request.call
        {
            let desktop = app.state::<crate::desktop::DesktopState>();
            let mut slot = desktop.slot.lock().await;
            let result = match slot.controller.as_mut() {
                Some(device) => device
                    .answer_pairing_completion(&node, &certificate, query)
                    .await
                    .and_then(|answer| Ok(serde_json::to_value(answer)?)),
                None => Err(anyhow::anyhow!("Your network is still opening")),
            };
            let _ = request.reply.send(result);
            continue;
        }
        if let connect_core::owner::OwnerCall::Control {
            node,
            certificate,
            request: envelope,
        } = request.call
        {
            let desktop = app.state::<crate::desktop::DesktopState>();
            let mut slot = desktop.slot.lock().await;
            let result = match (owner.runtime.as_mut(), slot.controller.as_mut()) {
                (Some(runtime), Some(device)) => {
                    device
                        .answer_owner_control(runtime, &node, &certificate, envelope)
                        .await
                }
                _ => Err(anyhow::anyhow!("Your network is still opening")),
            };
            let _ = request.reply.send(result);
            continue;
        }
        let Some(mut runtime) = owner.runtime.take() else {
            let _ = request
                .reply
                .send(Err(anyhow::anyhow!("Your network is still opening")));
            continue;
        };
        let call = request.call;
        let outcome = tokio::task::spawn_blocking(move || {
            let result = runtime.answer(call);
            (runtime, result)
        })
        .await;
        let result = match outcome {
            Ok((runtime, result)) => {
                owner.runtime = Some(runtime);
                result
            }
            Err(_) => Err(anyhow::anyhow!("The network computer is not ready")),
        };
        let _ = request.reply.send(result);
    }
}

/// On the network computer, every 30 seconds: renew Spaces once a day, show
/// this computer the Spaces it shares or that name it, and give a folder it
/// shared before Spaces a place in the registry.
async fn keep_spaces(app: tauri::AppHandle) {
    let mut renewed: Option<std::time::Instant> = None;
    let mut wait = std::time::Duration::from_secs(5);
    loop {
        tokio::time::sleep(wait).await;
        wait = std::time::Duration::from_secs(30);
        if let Err(error) = spaces_once(&app, &mut renewed).await {
            app.state::<WorkflowState>().slot.lock().await.problem = Some(error.to_string());
        }
    }
}

async fn spaces_once(
    app: &tauri::AppHandle,
    renewed: &mut Option<std::time::Instant>,
) -> anyhow::Result<()> {
    let state = app.state::<WorkflowState>();
    let desktop = app.state::<crate::desktop::DesktopState>();
    // Sharing and stopping take the owner lock too, so this snapshot of this
    // computer's own Spaces holds until the registry work below is done.
    let mut owner = state.slot.lock().await;
    if owner.runtime.is_none() {
        return Ok(());
    }
    let status = {
        let slot = desktop.slot.lock().await;
        match slot.controller.as_ref() {
            Some(device) => device.status()?,
            None => return Ok(()),
        }
    };
    let renew = renewed.is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(24 * 3600));
    let mut recipients: Vec<String> = Vec::new();
    for node in status.devices.iter().map(|d| &d.node) {
        if node != &status.node_public_key && !recipients.contains(node) {
            recipients.push(node.clone());
        }
    }
    recipients.truncate(31);
    let node = status.node_public_key.clone();
    let subject = status.sharing_subject.clone();
    let shares = status.shares.clone();
    let mut runtime = owner.runtime.take().expect("runtime checked above");
    let outcome = tokio::task::spawn_blocking(move || {
        let result = (|| {
            if renew {
                runtime.space_renew()?;
            }
            // A folder shared before Spaces keeps its policy and gets an entry.
            let mut moved = Vec::new();
            if let Some(subject) = subject.filter(|_| !recipients.is_empty()) {
                for share in shares.iter().filter(|share| share.name.is_empty()) {
                    let name = folder_name(&share.directory);
                    if let Ok(space) = runtime.space_adopt(
                        &node,
                        &share.collection_id,
                        &name,
                        &recipients,
                        &subject,
                    ) {
                        moved.push((space, share.directory.clone()));
                    }
                }
            }
            // This computer's Spaces it no longer saves are removed again,
            // for example after a stop the runtime could not finish.
            let mut spaces = runtime.space_list()?;
            for collection in connect_core::owner::orphaned(&spaces, &node, &shares) {
                let _ = runtime.space_remove(&node, &collection);
            }
            spaces = runtime.space_list()?;
            Ok::<_, anyhow::Error>((spaces, moved))
        })();
        (runtime, result)
    })
    .await
    .map_err(|_| anyhow::anyhow!("The network computer is not ready"))?;
    owner.runtime = Some(outcome.0);
    let (spaces, moved) = outcome.1?;
    if renew {
        *renewed = Some(std::time::Instant::now());
    }
    let mut slot = desktop.slot.lock().await;
    let Some(device) = slot.controller.as_mut() else {
        return Ok(());
    };
    // Published while no change can come between the list and its copy.
    device.publish_spaces(spaces.clone());
    drop(owner);
    let mut problem = None;
    for (space, directory) in moved {
        // Only a folder still shared as it was gets its new form; a failure
        // leaves it as it was, for the next pass.
        let still = device
            .status()?
            .shares
            .iter()
            .any(|s| s.collection_id == space.collection && s.name.is_empty());
        if let Some(view) = SpaceView::of(space, &status.node_public_key).filter(|_| still)
            && let Err(error) = device
                .set_space(DeviceController::space_config(view, directory)?)
                .await
        {
            problem = Some(error.to_string());
        }
    }
    let views = spaces
        .into_iter()
        .filter_map(|space| SpaceView::of(space, &status.node_public_key))
        .collect();
    // This computer's Spaces stopped in the registry, for example when the
    // last device they named was removed, stop here too.
    for collection in device.apply_spaces(views)?.ended {
        device.drop_space(&collection).await?;
    }
    if problem.is_some() {
        slot.problem = problem;
    }
    Ok(())
}

/// A Space's name from its folder: at most 64 characters, none of them
/// control characters.
pub(crate) fn folder_name(directory: &std::path::Path) -> String {
    let name: String = directory
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    if name.trim().is_empty() {
        "Shared folder".into()
    } else {
        name
    }
}
