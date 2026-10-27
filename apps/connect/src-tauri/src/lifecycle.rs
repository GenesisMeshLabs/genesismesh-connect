//! Explicit device-local lifecycle. Leaving never revokes other members or
//! deletes a network computer's authority, shared folders or exported files.
use crate::{desktop::DesktopState, workflow::WorkflowState};
use connect_core::device::DeviceController;
use tauri::Manager;

#[tauri::command]
pub async fn disconnect_network(app: tauri::AppHandle) -> Result<(), String> {
    let desktop = app.state::<DesktopState>();
    let _idle = desktop
        .transfers
        .try_write()
        .map_err(|_| "Finish or cancel the current transfer first.")?;
    let state = app.state::<WorkflowState>();
    let mut owner = state.slot.lock().await;
    if owner.joining.is_some() {
        return Err("Finish joining the network first.".into());
    }
    crate::services::clear(&app.state::<crate::services::Services>());
    let mut slot = desktop.slot.lock().await;
    slot.controller
        .as_mut()
        .ok_or("Join a network first.")?
        .disconnect()
        .await
        .map_err(|e| e.to_string())?;
    if let Some(pair) = owner.pairing.take() {
        pair.close().await;
    }
    slot.problem = None;
    Ok(())
}

#[tauri::command]
pub async fn reconnect_network(desktop: tauri::State<'_, DesktopState>) -> Result<(), String> {
    let mut slot = desktop.slot.lock().await;
    let result = slot
        .controller
        .as_mut()
        .ok_or("Join a network first.")?
        .reconnect()
        .await
        .map_err(|e| e.to_string());
    slot.problem = result.as_ref().err().cloned();
    result
}

#[tauri::command]
pub async fn leave_network(app: tauri::AppHandle) -> Result<(), String> {
    let desktop = app.state::<DesktopState>();
    let _idle = desktop
        .transfers
        .try_write()
        .map_err(|_| "Finish or cancel the current transfer before leaving.")?;
    let state = app.state::<WorkflowState>();
    let mut owner = state.slot.lock().await;
    if owner.runtime.is_some() || state.directory.join("owner.json").exists() {
        return Err(
            "This is the network computer. Disconnect it instead to preserve your network.".into(),
        );
    }
    if owner.joining.is_some() {
        return Err("Finish joining the network first.".into());
    }
    let mut slot = desktop.slot.lock().await;
    if !DeviceController::leaving(&desktop.profile) {
        slot.controller
            .as_mut()
            .ok_or("This device has no network to leave.")?
            .begin_leave()
            .await
            .map_err(|e| e.to_string())?;
    }
    crate::services::clear(&app.state::<crate::services::Services>());
    // Once marked, no error may put the old identity back into service.
    slot.controller = None;
    crate::sends::clear_network(&app.state::<crate::sends::Sends>());
    if let Some(pair) = owner.pairing.take() {
        pair.close().await;
    }
    let cleanup = crate::downloads::clear_network(&app.state::<crate::downloads::Downloads>())
        .and_then(|()| DeviceController::finish_leave(&desktop.profile));
    slot.problem = cleanup
        .as_ref()
        .err()
        .map(|e| format!("Leaving is unfinished: {e}. Tap Leave network to retry."));
    cleanup.map_err(|e| e.to_string())?;
    owner.problem = None;
    Ok(())
}
