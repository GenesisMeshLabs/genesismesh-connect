//! Local owner operations. The web UI supplies names, never keys or admin URLs.
use connect_core::{
    device::DeviceController,
    owner::{OwnerInfo, OwnerRuntime},
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
    app.manage(WorkflowState {
        directory,
        slot: Mutex::new(OwnerSlot {
            runtime: None,
            info: None,
            problem: None,
            pairing: None,
            joining: None,
        }),
    });
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
        if let Err(error) = device.reconnect_saved().await {
            slot.problem = Some(error.to_string());
        }
        slot.controller = Some(device);
        Ok(true)
    }
}
