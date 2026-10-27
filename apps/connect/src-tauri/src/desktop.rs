use connect_core::{
    authority::TrustPin,
    device::{DeviceController, DeviceStatus},
    session::{SessionReport, bridge::BridgeRoute},
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use tauri::Manager;
use tokio::sync::Mutex;

pub(crate) struct Slot {
    pub(crate) controller: Option<DeviceController>,
    pub(crate) problem: Option<String>,
}
pub struct DesktopState {
    pub(crate) profile: PathBuf,
    pub(crate) slot: Mutex<Slot>,
}

#[derive(Serialize)]
pub struct DesktopStatus {
    supported: bool,
    device: Option<DeviceStatus>,
    problem: Option<String>,
}
#[derive(Deserialize)]
pub struct PrepareSettings {
    authority: Option<String>,
    network: String,
    root_public_key: String,
}

pub fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let profile = app.path().app_data_dir()?.join("device");
    // Native UI smoke tests use a disposable profile without touching the user's
    // device. Release builds always use the OS application data directory.
    #[cfg(debug_assertions)]
    let profile = match std::env::var_os("CONNECT_TEST_PROFILE") {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err("CONNECT_TEST_PROFILE must be absolute".into());
            }
            path
        }
        None => profile,
    };
    let (controller, problem) = if profile.exists() {
        match DeviceController::open(&profile) {
            Ok(device) => (Some(device), None),
            Err(error) => (
                None,
                Some(format!("Stored device could not be opened: {error}")),
            ),
        }
    } else {
        (None, None)
    };
    app.manage(DesktopState {
        profile,
        slot: Mutex::new(Slot {
            controller,
            problem,
        }),
    });
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let state = handle.state::<DesktopState>();
            let mut slot = state.slot.lock().await;
            if let Some(controller) = &mut slot.controller
                && controller.needs_maintenance()
            {
                // Restore phone connections after launch. Owner restoration is
                // handled after rebinding its authority, never against an old port.
                if controller.status().is_ok_and(|s| s.authority_via_bridge) {
                    match controller.restore_managed_share() {
                        Ok(()) => {
                            let _ = controller.reconnect_saved().await;
                            let _ = controller.refresh().await;
                        }
                        Err(error) => slot.problem = Some(error.to_string()),
                    }
                } else {
                    let _ = controller.refresh().await;
                }
            }
            drop(slot);
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    Ok(())
}

fn message(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[tauri::command]
pub async fn device_status(state: tauri::State<'_, DesktopState>) -> Result<DesktopStatus, String> {
    let slot = state.slot.lock().await;
    Ok(DesktopStatus {
        supported: connect_core::device::secure_storage_supported(),
        device: slot
            .controller
            .as_ref()
            .map(|c| c.status())
            .transpose()
            .map_err(message)?,
        problem: slot.problem.clone(),
    })
}
#[tauri::command]
pub async fn device_prepare(
    settings: PrepareSettings,
    state: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    let mut slot = state.slot.lock().await;
    if slot.controller.is_some() {
        return Err("This device is already prepared".into());
    }
    let pin = TrustPin {
        root_public_key: settings.root_public_key,
        network_name: settings.network,
    };
    slot.controller = Some(
        match settings.authority {
            Some(authority) => DeviceController::prepare(&state.profile, authority, pin),
            None => DeviceController::prepare_remote(&state.profile, pin),
        }
        .map_err(message)?,
    );
    slot.problem = None;
    Ok(())
}
#[tauri::command]
pub async fn device_enroll(
    invite: String,
    sharing_host: Option<bool>,
    state: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    let mut slot = state.slot.lock().await;
    let device = slot
        .controller
        .as_mut()
        .ok_or("Prepare this device first")?;
    if sharing_host.unwrap_or(false) {
        device.enroll_host(&invite).await.map_err(message)
    } else {
        device.enroll(&invite).await.map_err(message)
    }
}

#[tauri::command]
pub async fn device_configure_sharing(
    config: Option<connect_core::session::sharing::ShareConfig>,
    state: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    let mut slot = state.slot.lock().await;
    slot.controller
        .as_mut()
        .ok_or("Prepare this device first")?
        .configure_sharing(config)
        .map_err(message)
}
#[tauri::command]
pub async fn device_read(
    ticket: String,
    collection_id: String,
    file_name: String,
    expected_sha256: Option<String>,
    state: tauri::State<'_, DesktopState>,
) -> Result<connect_core::session::sharing::ReadReport, String> {
    let session = {
        let slot = state.slot.lock().await;
        slot.controller
            .as_ref()
            .ok_or("Prepare this device first")?
            .session()
            .map_err(message)?
    };
    session
        .read_file(
            &ticket,
            connect_core::session::sharing::ReadRequest {
                request_id: uuid::Uuid::new_v4().to_string(),
                collection_id,
                file_name,
                expected_sha256,
            },
        )
        .await
        .map_err(message)
}
#[tauri::command]
pub async fn device_start(
    peer: String,
    state: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    let mut slot = state.slot.lock().await;
    slot.controller
        .as_mut()
        .ok_or("Prepare this device first")?
        .start(&peer)
        .await
        .map_err(message)
}

#[tauri::command]
pub async fn device_use_bridge(
    route: BridgeRoute,
    state: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    let mut slot = state.slot.lock().await;
    slot.controller
        .as_mut()
        .ok_or("Prepare this device first")?
        .use_bridge(route)
        .await
        .map_err(message)
}
#[tauri::command]
pub async fn device_use_local_authority(
    state: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    let mut slot = state.slot.lock().await;
    slot.controller
        .as_mut()
        .ok_or("Prepare this device first")?
        .use_local_authority()
        .map_err(message)
}
#[tauri::command]
pub async fn device_stop(state: tauri::State<'_, DesktopState>) -> Result<(), String> {
    let mut slot = state.slot.lock().await;
    if let Some(controller) = &mut slot.controller {
        controller.stop().await;
    }
    Ok(())
}
#[tauri::command]
pub async fn device_refresh(state: tauri::State<'_, DesktopState>) -> Result<(), String> {
    let mut slot = state.slot.lock().await;
    if let Some(controller) = &mut slot.controller {
        controller.refresh().await.map_err(message)?;
    }
    Ok(())
}
#[tauri::command]
pub async fn device_send(
    ticket: String,
    message: String,
    state: tauri::State<'_, DesktopState>,
) -> Result<SessionReport, String> {
    let session = {
        let slot = state.slot.lock().await;
        slot.controller
            .as_ref()
            .ok_or("Prepare this device first")?
            .session()
            .map_err(self::message)?
    };
    session
        .round_trip(&ticket, &message)
        .await
        .map_err(self::message)
}
