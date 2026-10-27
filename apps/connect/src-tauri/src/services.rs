//! Service resources and access-policy editing. All identities, host addresses
//! and grants come from native verified state, never caller-provided tickets.
use crate::{consumer, desktop::DesktopState, workflow::WorkflowState};
use connect_core::{
    device::DeviceController,
    owner::{AccessPolicy, AccessUpdate},
    session::{
        bridge::SpaceView,
        sharing::{SpaceKind, service::Target},
    },
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::Manager;
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};

fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
#[derive(Clone, Serialize)]
pub struct OpenService {
    pub id: String,
    pub name: String,
    pub kind: SpaceKind,
    pub address: String,
    pub url: Option<String>,
    pub problem: Option<String>,
}
struct Tunnel {
    view: OpenService,
    task: JoinHandle<()>,
    problem: Arc<Mutex<Option<String>>>,
}
#[derive(Default)]
pub struct Services(Mutex<BTreeMap<String, Tunnel>>);
impl Drop for Tunnel {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub fn setup(app: &mut tauri::App) {
    app.manage(Services::default());
}
pub fn clear(state: &Services) {
    state.0.lock().expect("services").clear();
}
#[tauri::command]
pub async fn share_service(
    name: String,
    kind: SpaceKind,
    port: u16,
    recipients: Vec<String>,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
    services: tauri::State<'_, Services>,
) -> Result<bool, String> {
    if !kind.is_service() {
        return Err("Choose Web app, SSH or TCP service".into());
    }
    if name.trim().is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err("Name this service (up to 64 characters).".into());
    }
    let target = Target {
        port,
        max_bytes: connect_core::transfer_limits::MAX_FILE_BYTES,
        max_seconds: 3600,
    };
    target.validate().map_err(error)?;
    if services
        .0
        .lock()
        .map_err(error)?
        .values()
        .any(|t| t.view.address == format!("127.0.0.1:{port}"))
    {
        return Err("A Connect connection cannot be shared again.".into());
    }
    let _idle = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the network change to finish")?;
    let mut owner = state.slot.lock().await;
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Join your network first")?;
    let status = device.status().map_err(error)?;
    if status.disconnected {
        return Err("This device is disconnected".into());
    }
    let recipients = consumer::validate_recipients(recipients, &consumer::recipients_for(&status))?;
    // Empty private directory is only bookkeeping for the shared resource
    // store; service kind is never reachable through any file protocol.
    let directory = desktop.profile.join("service-resources");
    std::fs::create_dir_all(&directory).map_err(error)?;
    match owner.runtime.as_mut() {
        Some(runtime) => {
            let subject = status.sharing_subject.ok_or("No sharing identity")?;
            // Validate the actual local authority port before granting access.
            if status
                .authority
                .as_deref()
                .is_some_and(|url| url.trim_end_matches('/').ends_with(&format!(":{port}")))
            {
                return Err("The network authority cannot be shared as a service".into());
            }
            let space = runtime
                .space_share(
                    &status.node_public_key,
                    &uuid::Uuid::new_v4().to_string(),
                    name.trim(),
                    &recipients,
                    Some(&subject),
                    kind,
                )
                .map_err(error)?;
            let view =
                SpaceView::of(space, &status.node_public_key).ok_or("Invalid service grant")?;
            let mut config = DeviceController::space_config(view, directory).map_err(error)?;
            config.service = Some(target);
            device.set_space(config).await.map_err(error)?;
            device.publish_spaces(runtime.space_list().map_err(error)?);
        }
        None => {
            drop(owner);
            device
                .share_service(directory, name.trim().into(), recipients, kind, target)
                .await
                .map_err(error)?;
        }
    }
    Ok(true)
}
#[tauri::command]
pub async fn get_access_policy(
    id: String,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<AccessPolicy, String> {
    let mut owner = state.slot.lock().await;
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Join your network first")?;
    let status = device.status().map_err(error)?;
    if !status.shares.iter().any(|s| s.collection_id == id) {
        return Err("Only the sharing device can manage access".into());
    }
    match owner.runtime.as_mut() {
        Some(runtime) => runtime
            .access_get(&status.node_public_key, &id)
            .map_err(error),
        None => serde_json::from_value(device.access_policy(id, None).await.map_err(error)?)
            .map_err(error),
    }
}
#[tauri::command]
pub async fn update_access_policy(
    id: String,
    settings: AccessPolicy,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<AccessPolicy, String> {
    let _idle = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the network change to finish")?;
    let mut owner = state.slot.lock().await;
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Join your network first")?;
    let status = device.status().map_err(error)?;
    if status.disconnected {
        return Err("This device is disconnected".into());
    }
    let mut config = status
        .shares
        .iter()
        .find(|s| s.collection_id == id)
        .cloned()
        .ok_or("Only the sharing device can manage access")?;
    consumer::validate_recipients(
        settings.recipients.clone(),
        &consumer::recipients_for(&status),
    )?;
    let updated: AccessUpdate = match owner.runtime.as_mut() {
        Some(runtime) => runtime
            .access_update(&status.node_public_key, &id, &settings)
            .map_err(error)?,
        None => serde_json::from_value(
            device
                .access_policy(id.clone(), Some(settings))
                .await
                .map_err(error)?,
        )
        .map_err(error)?,
    };
    config.recipients = updated.settings.recipients.clone();
    config.attestation_id = updated.space.attestation_id;
    if let Some(target) = &mut config.service {
        target.max_bytes = updated.settings.max_bytes;
        target.max_seconds = updated.settings.max_seconds;
    }
    device.set_space(config).await.map_err(error)?;
    if let Some(runtime) = owner.runtime.as_mut() {
        device.publish_spaces(runtime.space_list().map_err(error)?);
    }
    Ok(updated.settings)
}
#[tauri::command]
pub async fn open_service(id: String, app: tauri::AppHandle) -> Result<OpenService, String> {
    let state = app.state::<Services>();
    if let Some(tunnel) = state
        .0
        .lock()
        .map_err(error)?
        .get(&id)
        .filter(|t| !t.task.is_finished())
    {
        return Ok(tunnel.view.clone());
    }
    let desktop = app.state::<DesktopState>();
    let _idle = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the network change to finish")?;
    let (kind, name) = {
        let slot = desktop.slot.lock().await;
        let device = slot.controller.as_ref().ok_or("Join your network first")?;
        let status = device.status().map_err(error)?;
        if status.disconnected {
            return Err("This device is disconnected".into());
        }
        let space = status
            .spaces
            .iter()
            .find(|s| s.collection == id && s.host != status.node_public_key && s.kind.is_service())
            .ok_or("Service is not shared with this device")?;
        (space.kind, space.name.clone())
    };
    // Bind only loopback; no LAN listener or externally reachable proxy.
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(error)?;
    let port = listener.local_addr().map_err(error)?.port();
    let view = OpenService {
        id: id.clone(),
        name,
        kind,
        address: format!("127.0.0.1:{port}"),
        url: (kind == SpaceKind::Web).then(|| format!("http://127.0.0.1:{port}/")),
        problem: None,
    };
    let handle = app.clone();
    let collection = id.clone();
    let problem = Arc::new(Mutex::new(None));
    let feedback = problem.clone();
    let task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        let lifetime = tokio::time::sleep(Duration::from_secs(3600));
        tokio::pin!(lifetime);
        loop {
            tokio::select! {biased;
                _=&mut lifetime=>break,
                item=listener.accept()=>{
                    let Ok((tcp,_))=item else {break};if tasks.len()>=8{drop(tcp);continue;}
                    let handle=handle.clone();let collection=collection.clone();let feedback=feedback.clone();
                    tasks.spawn(async move{
                        let result=async{
                            let desktop=handle.state::<DesktopState>();
                            let(session,peer)=consumer::session(&desktop,Some(&collection)).await.map_err(anyhow::Error::msg)?;
                            session.forward_service(&peer.node,&peer.ticket,&collection,kind,tcp).await
                        }.await;
                        if let Err(error)=result{*feedback.lock().expect("service problem")=Some(error.to_string());}
                    });
                },
                _=tasks.join_next(),if !tasks.is_empty()=>{},
            }
        }
        tasks.shutdown().await;
    });
    let mut tunnels = state.0.lock().map_err(error)?;
    tunnels.retain(|_, t| !t.task.is_finished());
    if tunnels.len() >= 8 {
        task.abort();
        return Err("Close an open service before opening another".into());
    }
    tunnels.insert(
        id,
        Tunnel {
            view: view.clone(),
            task,
            problem,
        },
    );
    Ok(view)
}
#[tauri::command]
pub fn service_connections(state: tauri::State<'_, Services>) -> Result<Vec<OpenService>, String> {
    let mut tunnels = state.0.lock().map_err(error)?;
    tunnels.retain(|_, t| !t.task.is_finished());
    Ok(tunnels
        .values()
        .map(|t| {
            let mut view = t.view.clone();
            view.problem = t.problem.lock().expect("service problem").clone();
            view
        })
        .collect())
}
#[tauri::command]
pub fn close_service(id: String, state: tauri::State<'_, Services>) -> Result<(), String> {
    state.0.lock().map_err(error)?.remove(&id);
    Ok(())
}
#[tauri::command]
pub async fn launch_service(id: String, app: tauri::AppHandle) -> Result<(), String> {
    let url = app
        .state::<Services>()
        .0
        .lock()
        .map_err(error)?
        .get(&id)
        .filter(|t| !t.task.is_finished())
        .and_then(|t| t.view.url.clone())
        .ok_or("Open the web app connection first")?;
    #[cfg(desktop)]
    {
        use tauri_plugin_opener::OpenerExt;
        app.opener().open_url(url, None::<&str>).map_err(error)?;
    }
    #[cfg(mobile)]
    {
        use tauri_plugin_view::ViewExt;
        tokio::task::spawn_blocking(move || app.view().web(tauri_plugin_view::WebRequest { url }))
            .await
            .map_err(error)?
            .map_err(error)?;
    }
    Ok(())
}
