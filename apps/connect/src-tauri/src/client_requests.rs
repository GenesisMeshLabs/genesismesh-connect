//! Read-only saved device-request inspection. No review/sign/execute/archive IPC.
use crate::desktop::DesktopState;
use connect_core::device::PairingRequestsOverview;
#[tauri::command]
pub async fn client_requests_status(
    state: tauri::State<'_, DesktopState>,
) -> Result<PairingRequestsOverview, String> {
    let _idle = state
        .transfers
        .try_read()
        .map_err(|_| "Your connection is changing. Refresh when it finishes.")?;
    let slot = state
        .slot
        .try_lock()
        .map_err(|_| "This device is busy. Refresh in a moment.")?;
    slot.controller.as_ref().ok_or("Open your network first.")?.owner_requests_overview()
        .map_err(|_|"Your saved device request could not be read. Keep the existing network and device identity, then refresh.".into())
}
#[tauri::command]
pub async fn client_requests_check(
    state: tauri::State<'_, DesktopState>,
) -> Result<PairingRequestsOverview, String> {
    let _idle = state
        .transfers
        .try_read()
        .map_err(|_| "Your connection is changing. Check status when it finishes.")?;
    let mut slot = state
        .slot
        .try_lock()
        .map_err(|_| "This device is busy. Check status in a moment.")?;
    slot.controller.as_mut().ok_or("Open your network first.")?.check_owner_requests_overview().await
        .map_err(|_|"Couldn’t confirm this saved device request. Keep Connect open on your network host, then check again. The approval or rejection was not resent.".into())
}
