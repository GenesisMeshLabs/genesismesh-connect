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
    owner: bool,
    network_name: Option<String>,
    problem: Option<String>,
}
fn runtime_available() -> bool {
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
    let configured = directory.join("owner.json").is_file();
    let (owner, requests) = tokio::sync::mpsc::channel(8);
    app.manage(WorkflowState {
        directory,
        slot: Mutex::new(OwnerSlot {
            runtime: None,
            info: None,
            problem: None,
            pairing: None,
            joining: None,
        }),
        owner,
    });
    tauri::async_runtime::spawn(answer_owner(app.handle().clone(), requests));
    tauri::async_runtime::spawn(keep_spaces(app.handle().clone()));
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
        owner: state.directory.join("owner.json").is_file(),
        network_name: slot.info.as_ref().map(|i| i.pin.network_name.clone()),
        problem: slot.problem.clone(),
    })
}

#[tauri::command]
pub async fn network_create(
    name: String,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, crate::desktop::DesktopState>,
) -> Result<(), String> {
    install_network(Some(name), None, &state, &desktop).await
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
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
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
    // This computer's own view first; the two locks are never held together.
    let status = {
        let slot = desktop.slot.lock().await;
        match slot.controller.as_ref() {
            Some(device) => device.status()?,
            None => return Ok(()),
        }
    };
    let renew = renewed.is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(24 * 3600));
    let legacy: Vec<_> = status
        .shares
        .iter()
        .filter(|share| share.name.is_empty())
        .cloned()
        .collect();
    let mut recipients: Vec<String> = Vec::new();
    for node in status.devices.iter().map(|d| &d.node) {
        if node != &status.node_public_key && !recipients.contains(node) {
            recipients.push(node.clone());
        }
    }
    recipients.truncate(31);
    let node = status.node_public_key.clone();
    let subject = status.sharing_subject.clone();
    let (spaces, moved) = {
        let mut owner = state.slot.lock().await;
        let Some(mut runtime) = owner.runtime.take() else {
            return Ok(());
        };
        let outcome = tokio::task::spawn_blocking(move || {
            let result = (|| {
                if renew {
                    runtime.space_renew()?;
                }
                let mut moved = Vec::new();
                if let Some(subject) = subject.filter(|_| !recipients.is_empty()) {
                    for share in legacy {
                        let name: String = share
                            .directory
                            .file_name()
                            .map_or_else(
                                || "Shared folder".into(),
                                |s| s.to_string_lossy().into_owned(),
                            )
                            .chars()
                            .take(64)
                            .collect();
                        let space = runtime.space_share(
                            &node,
                            &share.collection_id,
                            &name,
                            &recipients,
                            Some(&subject),
                        )?;
                        moved.push((space, share.directory));
                    }
                }
                Ok::<_, anyhow::Error>((runtime.space_list()?, moved))
            })();
            (runtime, result)
        })
        .await
        .map_err(|_| anyhow::anyhow!("The network computer is not ready"))?;
        owner.runtime = Some(outcome.0);
        outcome.1?
    };
    if renew {
        *renewed = Some(std::time::Instant::now());
    }
    let mut slot = desktop.slot.lock().await;
    let Some(device) = slot.controller.as_mut() else {
        return Ok(());
    };
    for (space, directory) in moved {
        let view = SpaceView::of(space, &status.node_public_key)
            .ok_or_else(|| anyhow::anyhow!("Unexpected shared folder"))?;
        device
            .set_space(DeviceController::space_config(view, directory)?)
            .await?;
    }
    let views = spaces
        .into_iter()
        .filter_map(|space| SpaceView::of(space, &status.node_public_key))
        .collect();
    device.apply_spaces(views)?;
    Ok(())
}
