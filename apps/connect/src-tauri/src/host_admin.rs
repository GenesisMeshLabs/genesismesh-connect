//! Desktop-local typed review only. No caller can choose a presence provider,
//! supply a key/authority URL, or reach these operations over the member bridge.
use crate::{desktop::DesktopState, workflow::WorkflowState};
use connect_core::owner_control::{
    LocalAdminInput, LocalAdminOutcome, LocalAdminReference, LocalAdminReview, LocalAdminView,
    LocalAdministration, UnavailableAdminPresence,
};
use serde::Serialize;
use tauri::Manager;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct HostAdminState(pub Mutex<LocalAdministration>);
#[derive(Serialize)]
pub struct HostAdminStatus {
    location: &'static str,
    mutation_ready: bool,
    readiness: &'static str,
    view: Option<LocalAdminView>,
}
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
const PRESENCE_REQUIRED: &str = "Device authentication is not available for administration in this build. You can inspect requests and review changes. Enabling or changing administrator permissions stays locked.";

#[tauri::command]
pub async fn host_admin_status(app: tauri::AppHandle) -> Result<HostAdminStatus, String> {
    if !cfg!(desktop) {
        return Ok(HostAdminStatus {
            location: "unsupported",
            mutation_ready: false,
            readiness: "Review administrator requests on your supported network computer.",
            view: None,
        });
    }
    let workflow = app.state::<WorkflowState>();
    let desktop = app.state::<DesktopState>();
    let book = app.state::<HostAdminState>();
    let _idle = desktop
        .transfers
        .try_read()
        .map_err(|_| "Your connection is changing. Refresh when it finishes.")?;
    let mut owner = workflow
        .slot
        .try_lock()
        .map_err(|_| "Your network computer is handling another request. Refresh in a moment.")?;
    let Some(runtime) = owner.runtime.as_mut() else {
        return Ok(HostAdminStatus {
            location: "member",
            mutation_ready: false,
            readiness: "Administrator requests are reviewed on the computer that runs your network.",
            view: None,
        });
    };
    let mut slot = desktop
        .slot
        .try_lock()
        .map_err(|_| "This device is busy. Refresh in a moment.")?;
    let device = slot.controller.as_mut().ok_or("Open your network first.")?;
    let admin = book
        .0
        .try_lock()
        .map_err(|_| "Another administrator review is open. Refresh in a moment.")?;
    let view = admin.view(runtime, device).await.map_err(error)?;
    Ok(HostAdminStatus {
        location: "host",
        mutation_ready: false,
        readiness: PRESENCE_REQUIRED,
        view: Some(view),
    })
}
#[tauri::command]
pub async fn host_admin_review(
    query: LocalAdminInput,
    app: tauri::AppHandle,
) -> Result<LocalAdminReview, String> {
    if !cfg!(desktop) {
        return Err("Review this request on your network computer.".into());
    }
    let workflow = app.state::<WorkflowState>();
    let desktop = app.state::<DesktopState>();
    let book = app.state::<HostAdminState>();
    let _idle = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the connection change to finish.")?;
    let mut owner = workflow
        .slot
        .try_lock()
        .map_err(|_| "Your network computer is busy. Refresh before reviewing.")?;
    let runtime = owner
        .runtime
        .as_mut()
        .ok_or("Review this on your network computer.")?;
    let mut slot = desktop
        .slot
        .try_lock()
        .map_err(|_| "This device is busy. Refresh before reviewing.")?;
    let device = slot.controller.as_mut().ok_or("Open your network first.")?;
    book.0
        .try_lock()
        .map_err(|_| "Another review is in progress.")?
        .review(runtime, device, query)
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn host_admin_commit(
    reference: LocalAdminReference,
    app: tauri::AppHandle,
) -> Result<LocalAdminOutcome, String> {
    if !cfg!(desktop) {
        return Err("Administrator changes are unavailable on this device.".into());
    }
    let workflow = app.state::<WorkflowState>();
    let desktop = app.state::<DesktopState>();
    let book = app.state::<HostAdminState>();
    let _idle = desktop
        .transfers
        .try_read()
        .map_err(|_| "Your connection is changing. Check status before continuing.")?;
    let mut owner = workflow
        .slot
        .try_lock()
        .map_err(|_| "Your network computer is busy. Check status before continuing.")?;
    let runtime = owner
        .runtime
        .as_mut()
        .ok_or("Review this on your network computer.")?;
    let mut slot = desktop
        .slot
        .try_lock()
        .map_err(|_| "This device is busy. Check status before continuing.")?;
    let device = slot.controller.as_mut().ok_or("Open your network first.")?;
    // Deliberately unavailable until native user-presence qualification. A DOM
    // click, a stored credential, config flag or debug environment cannot enable it.
    book.0
        .try_lock()
        .map_err(|_| "Another administrator change is in progress. Check status.")?
        .commit(runtime, device, reference, &mut UnavailableAdminPresence)
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn host_admin_check(
    reference: LocalAdminReference,
    app: tauri::AppHandle,
) -> Result<LocalAdminOutcome, String> {
    if !cfg!(desktop) {
        return Err("Check this change on its network computer.".into());
    }
    let workflow = app.state::<WorkflowState>();
    let desktop = app.state::<DesktopState>();
    let book = app.state::<HostAdminState>();
    let _idle = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the connection change to finish, then check status.")?;
    let mut owner = workflow
        .slot
        .try_lock()
        .map_err(|_| "Your network computer is busy. Check status in a moment.")?;
    let runtime = owner
        .runtime
        .as_mut()
        .ok_or("Check this on its network computer.")?;
    let mut slot = desktop
        .slot
        .try_lock()
        .map_err(|_| "This device is busy. Check status in a moment.")?;
    let device = slot.controller.as_mut().ok_or("Open your network first.")?;
    book.0
        .try_lock()
        .map_err(|_| "Another review is in progress. Check status in a moment.")?
        .check(runtime, device, reference)
        .await
        .map_err(error)
}
