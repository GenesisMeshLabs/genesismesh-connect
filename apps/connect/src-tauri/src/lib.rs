use connect_core::{EndpointStatus, NetworkMode, ProbeEndpoint, RoundTripReport};
use std::sync::Arc;
use tokio::sync::Mutex;
mod consumer;
mod desktop;
mod downloads;
mod workflow;

#[derive(Default)]
struct AppState(Mutex<Option<Arc<ProbeEndpoint>>>);

#[tauri::command]
async fn start_endpoint(
    mode: NetworkMode,
    state: tauri::State<'_, AppState>,
) -> Result<EndpointStatus, String> {
    let mut slot = state.0.lock().await;
    if slot.is_some() {
        return Err("Stop the running endpoint first".into());
    }
    let endpoint = Arc::new(
        ProbeEndpoint::bind(mode)
            .await
            .map_err(|e| format!("{e:#}"))?,
    );
    let status = endpoint.status().map_err(|e| format!("{e:#}"))?;
    *slot = Some(endpoint);
    Ok(status)
}

#[tauri::command]
async fn endpoint_status(
    state: tauri::State<'_, AppState>,
) -> Result<Option<EndpointStatus>, String> {
    state
        .0
        .lock()
        .await
        .as_ref()
        .map(|endpoint| endpoint.status().map_err(|e| format!("{e:#}")))
        .transpose()
}

#[tauri::command]
async fn stop_endpoint(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let endpoint = state.0.lock().await.take();
    if let Some(endpoint) = endpoint {
        endpoint.close().await;
    }
    Ok(())
}

#[tauri::command]
async fn send_probe(
    ticket: String,
    message: String,
    state: tauri::State<'_, AppState>,
) -> Result<RoundTripReport, String> {
    let endpoint = state
        .0
        .lock()
        .await
        .clone()
        .ok_or("Start this device first")?;
    endpoint
        .round_trip(&ticket, &message)
        .await
        .map_err(|e| format!("{e:#}"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_opener::init());
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_view::init());
    #[cfg(windows)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _, _| {
        use tauri::Manager;
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.set_focus();
        }
    }));
    builder
        .plugin(tauri_plugin_deep_link::init())
        .manage(AppState::default())
        .setup(|app| {
            desktop::setup(app)?;
            workflow::setup(app)?;
            downloads::setup(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_endpoint,
            endpoint_status,
            stop_endpoint,
            send_probe,
            workflow::network_status,
            workflow::network_create,
            workflow::network_attach,
            workflow::recovery_create,
            workflow::recovery_restore,
            consumer::pair_cancel,
            consumer::home_status,
            consumer::pair_begin,
            consumer::pair_approve,
            consumer::pair_reject,
            consumer::pair_join,
            consumer::share_folder,
            consumer::stop_sharing,
            consumer::browse_files,
            consumer::open_file,
            downloads::download_file,
            downloads::download_status,
            downloads::cancel_download,
            downloads::open_download,
            downloads::save_download,
            consumer::check_connection,
            consumer::check_network,
            consumer::select_device,
            consumer::forget_device,
            consumer::set_network_connection,
            consumer::set_device_local_only,
            desktop::device_status,
            desktop::device_prepare,
            desktop::device_enroll,
            desktop::device_configure_sharing,
            desktop::device_read,
            desktop::device_start,
            desktop::device_use_bridge,
            desktop::device_use_local_authority,
            desktop::device_stop,
            desktop::device_refresh,
            desktop::device_send
        ])
        .run(tauri::generate_context!())
        .expect("Connect could not start");
}
