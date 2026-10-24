use connect_core::{EndpointStatus, NetworkMode, ProbeEndpoint, RoundTripReport};
use std::sync::Arc;
use tokio::sync::Mutex;

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
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            start_endpoint,
            endpoint_status,
            stop_endpoint,
            send_probe
        ])
        .run(tauri::generate_context!())
        .expect("Connect could not start");
}
