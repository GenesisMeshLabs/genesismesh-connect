//! Member-device saved enrollment inspection/readback only, on every platform.
//! No identity, URL, path, request ID, signing input or presence flag from IPC.
use crate::desktop::DesktopState;
use connect_core::device::EnrollmentOverview;

#[tauri::command]
pub async fn client_admin_status(
    state: tauri::State<'_, DesktopState>,
) -> Result<EnrollmentOverview, String> {
    let _idle = state
        .transfers
        .try_read()
        .map_err(|_| "Your connection is changing. Refresh when it finishes.")?;
    let slot = state
        .slot
        .try_lock()
        .map_err(|_| "This device is busy. Refresh in a moment.")?;
    slot.controller.as_ref().ok_or("Open your network first.")?.owner_enrollment_overview()
        .map_err(|_|"Your saved request could not be read. Keep the existing network and device identity, then refresh.")
        .map_err(String::from)
}
#[tauri::command]
pub async fn client_admin_check(
    state: tauri::State<'_, DesktopState>,
) -> Result<EnrollmentOverview, String> {
    let _idle = state
        .transfers
        .try_read()
        .map_err(|_| "Your connection is changing. Check status when it finishes.")?;
    let mut slot = state
        .slot
        .try_lock()
        .map_err(|_| "This device is busy. Check status in a moment.")?;
    slot.controller.as_mut().ok_or("Open your network first.")?.check_owner_enrollment_overview().await
        .map_err(|_|"Couldn’t confirm this saved request. Unlock this device and keep Connect open on your network computer, then check again. Your saved request was not resent or replaced.")
        .map_err(String::from)
}
