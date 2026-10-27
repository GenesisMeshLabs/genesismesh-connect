//! Ordinary user actions. Keys, transport routes and policy identifiers are
//! obtained from verified native state, not text fields in the normal UI.
use crate::{desktop::DesktopState, workflow::WorkflowState};
#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
use connect_core::session::sharing::ShareConfig;
use connect_core::{
    Connectivity,
    device::{ConnectivityStatus, DeviceController, PairedDevice},
    session::{
        pairing::{PairCard, PairGrant, PairRequest},
        sharing::{ReadReport, ReadRequest, browse::Page},
    },
};
use serde::Serialize;
use tauri::Manager;

fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
#[derive(Serialize)]
pub struct HomeDevice {
    id: String,
    name: String,
    selected: bool,
    authority_connection: bool,
}
#[derive(Serialize)]
pub struct HomeStatus {
    owner: bool,
    configured: bool,
    network: Option<String>,
    peer: Option<String>,
    devices: Vec<HomeDevice>,
    selected_device: Option<String>,
    ready: bool,
    sharing: Option<String>,
    joining: Option<String>,
    request: Option<PairRequest>,
    problem: Option<String>,
    legacy: bool,
    connection: Option<ConnectivityStatus>,
}
#[tauri::command]
pub async fn home_status(
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<HomeStatus, String> {
    let owner = state.slot.lock().await;
    let slot = desktop.slot.lock().await;
    let device = slot
        .controller
        .as_ref()
        .map(|c| c.status())
        .transpose()
        .map_err(error)?;
    let configured = device.as_ref().is_some_and(|d| d.certificate_id.is_some());
    Ok(HomeStatus {
        owner: owner.runtime.is_some(),
        configured,
        devices: device
            .as_ref()
            .map(|d| {
                d.devices
                    .iter()
                    .map(|p| HomeDevice {
                        id: p.node.clone(),
                        name: p.name.clone(),
                        selected: d.peer_node.as_ref() == Some(&p.node),
                        authority_connection: d.bridge_host_node.as_ref() == Some(&p.node),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        selected_device: device.as_ref().and_then(|d| d.peer_node.clone()),
        network: device.as_ref().map(|d| d.network.clone()),
        peer: device
            .as_ref()
            .and_then(|d| d.paired_device.as_ref().map(|p| p.name.clone())),
        ready: device.as_ref().is_some_and(|d| d.ready),
        sharing: device.as_ref().and_then(|d| {
            d.sharing_config
                .as_ref()
                .and_then(|c| c.directory.file_name())
                .map(|s| s.to_string_lossy().into_owned())
        }),
        joining: owner.joining.clone(),
        request: owner.pairing.as_ref().and_then(|p| p.pending()),
        problem: owner
            .problem
            .clone()
            .or_else(|| slot.problem.clone())
            .or_else(|| device.as_ref().and_then(|d| d.problem.clone())),
        legacy: configured
            && owner.runtime.is_none()
            && !state.directory.join("owner.json").is_file()
            && device.as_ref().is_some_and(|d| d.paired_device.is_none()),
        connection: device.map(|d| d.connectivity),
    })
}
/// How every device reaches this network. Only the network computer decides.
#[tauri::command]
pub async fn set_network_connection(
    setting: Connectivity,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    desktop
        .slot
        .lock()
        .await
        .controller
        .as_mut()
        .ok_or("Set up this computer first")?
        .set_network_connectivity(setting)
        .await
        .map_err(error)
}
/// Keep this device on the local network even when the network allows relays.
#[tauri::command]
pub async fn set_device_local_only(
    enabled: bool,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    desktop
        .slot
        .lock()
        .await
        .controller
        .as_mut()
        .ok_or("Join your network first")?
        .set_own_connectivity(enabled.then_some(Connectivity::LocalNetwork))
        .await
        .map_err(error)
}
#[derive(Serialize)]
pub struct JoinLink {
    link: String,
    expires_at: i64,
}
#[tauri::command]
pub async fn pair_begin(
    name: String,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<JoinLink, String> {
    let mut owner = state.slot.lock().await;
    if owner.runtime.is_none() {
        return Err("Add devices from your network computer.".into());
    }
    let mut slot = desktop.slot.lock().await;
    let host = slot
        .controller
        .as_mut()
        .ok_or("Set up this computer first")?
        .create_pairing(name)
        .await
        .map_err(error)?;
    let card = host.card();
    let result = JoinLink {
        link: card.link().map_err(error)?,
        expires_at: card.expires_at,
    };
    owner.pairing = Some(host);
    owner.problem = None;
    Ok(result)
}
#[tauri::command]
pub async fn pair_reject(id: String, state: tauri::State<'_, WorkflowState>) -> Result<(), String> {
    state
        .slot
        .lock()
        .await
        .pairing
        .as_ref()
        .ok_or("No device is waiting")?
        .reject(&id)
        .map_err(error)
}
#[tauri::command]
pub async fn pair_cancel(state: tauri::State<'_, WorkflowState>) -> Result<(), String> {
    let pair = state.slot.lock().await.pairing.take();
    if let Some(pair) = pair {
        pair.close().await;
    }
    Ok(())
}
#[tauri::command]
pub async fn pair_approve(id: String, app: tauri::AppHandle) -> Result<(), String> {
    let workflow = app.state::<WorkflowState>();
    let desktop = app.state::<DesktopState>();
    let (pair, request, completion) = {
        let mut owner = workflow.slot.lock().await;
        let pair = owner.pairing.clone().ok_or("Create a join link first")?;
        let request = pair
            .pending()
            .filter(|r| r.id == id)
            .ok_or("This device is no longer waiting")?;
        let mut runtime = owner
            .runtime
            .take()
            .ok_or("The network computer is not ready")?;
        let node = request.node.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let invite = runtime.invite(&node, true);
            (runtime, invite)
        })
        .await
        .map_err(|_| "Could not prepare approval")?;
        owner.runtime = Some(outcome.0);
        let invitation = outcome.1.map_err(error)?;
        let mut slot = desktop.slot.lock().await;
        let device = slot
            .controller
            .as_mut()
            .ok_or("Network device is unavailable")?;
        device.start(&request.node).await.map_err(error)?;
        let status = device.status().map_err(error)?;
        let grant = PairGrant {
            invitation,
            route: connect_core::session::bridge::BridgeRoute {
                host_node: status.node_public_key,
                ticket: status
                    .bridge_ticket
                    .ok_or("Authority connection is unavailable")?,
            },
            session_ticket: status.ticket.ok_or("Device connection is unavailable")?,
        };
        let completion = pair.approve(&id, grant).map_err(error)?;
        (pair, request, completion)
    };
    let joined = tokio::time::timeout(std::time::Duration::from_secs(80), completion)
        .await
        .map_err(|_| "The other device did not finish joining")?
        .map_err(|_| "The other device disconnected")?;
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Device is unavailable")?;
    // Ticket bytes alone are never persisted as a trusted device relationship.
    let verified = device
        .send(&joined.ticket, "Connect pairing verification")
        .await;
    if let Err(e) = verified {
        let _ = joined.confirm.send(false);
        return Err(error(e));
    }
    device
        .remember_pairing(PairedDevice {
            name: request.name,
            node: request.node,
            ticket: joined.ticket,
        })
        .map_err(error)?;
    let _ = joined.confirm.send(true);
    drop(slot);
    // The server needs to deliver its final confirmation before it is closed.
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        pair.close().await;
    });
    Ok(())
}
#[tauri::command]
pub async fn pair_join(link: String, name: String, app: tauri::AppHandle) -> Result<(), String> {
    let card = PairCard::parse(&link).map_err(error)?;
    connect_core::session::pairing::valid_name(&name).map_err(error)?;
    let state = app.state::<WorkflowState>();
    let mut owner = state.slot.lock().await;
    if owner.joining.is_some() {
        return Err("A join request is already running".into());
    }
    owner.joining = Some("Connecting to your computer…".into());
    owner.problem = None;
    drop(owner);
    tauri::async_runtime::spawn(async move {
        let outcome = join(&app, card, name).await;
        let state = app.state::<WorkflowState>();
        let mut owner = state.slot.lock().await;
        owner.joining = None;
        if let Err(e) = outcome {
            owner.problem = Some(e.to_string());
        }
    });
    Ok(())
}
async fn join(app: &tauri::AppHandle, card: PairCard, name: String) -> anyhow::Result<()> {
    let desktop = app.state::<DesktopState>();
    let state = app.state::<WorkflowState>();
    // Take the controller out while awaiting the owner's decision; status and
    // the UI remain responsive. Put it back even on failure, preserving its key.
    let mut device = {
        let mut slot = desktop.slot.lock().await;
        if let Some(device) = slot.controller.take() {
            device
        } else {
            DeviceController::prepare_remote(&desktop.profile, card.pin.clone())?
        }
    };
    let result = async {
        let mut pairing = device.request_pairing(card.clone(), name).await?;
        state.slot.lock().await.joining = Some(format!(
            "Waiting for approval on {}. Compare code {}.",
            card.host_name, pairing.code
        ));
        let result = async {
            let grant = pairing.grant().await?;
            state.slot.lock().await.joining =
                Some("Approved. Finishing your secure connection…".into());
            device.use_bridge(grant.route).await?;
            device.enroll_host(&grant.invitation).await?;
            device.start(&card.host_node).await?;
            device
                .send(&grant.session_ticket, "Connect pairing verification")
                .await?;
            let ticket = device
                .status()?
                .ticket
                .ok_or_else(|| anyhow::anyhow!("Connection is unavailable"))?;
            device.remember_pairing(PairedDevice {
                name: card.host_name,
                node: card.host_node,
                ticket: grant.session_ticket,
            })?;
            pairing.finish(ticket).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        pairing.close().await;
        result
    }
    .await;
    desktop.slot.lock().await.controller = Some(device);
    result
}
#[tauri::command]
pub async fn share_folder(
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<bool, String> {
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = (state, desktop);
        Err("Sharing mobile documents is being added. Choose a folder on your network computer for now.".into())
    }
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    {
        // Picker is native and cannot be controlled by a peer-supplied path.
        let Some(folder) = rfd::AsyncFileDialog::new()
            .set_title("Choose a folder to share read-only")
            .pick_folder()
            .await
        else {
            return Ok(false);
        };
        let mut owner = state.slot.lock().await;
        let mut slot = desktop.slot.lock().await;
        let device = slot
            .controller
            .as_mut()
            .ok_or("Set up this computer first")?;
        let peer = device
            .paired_device()
            .cloned()
            .ok_or("Add your phone before sharing a folder")?;
        let host = device.status().map_err(error)?.node_public_key;
        let subject = device
            .status()
            .map_err(error)?
            .sharing_subject
            .ok_or("This device has no sharing identity")?;
        let collection = uuid::Uuid::new_v4().to_string();
        let config = owner
            .runtime
            .as_mut()
            .ok_or("Share from the network computer")?
            .share_for_subject(&host, &peer.node, &collection, &subject)
            .map_err(error)?;
        let config = ShareConfig {
            directory: folder.path().to_owned(),
            collection_id: collection,
            policy_id: config["policy_id"]
                .as_str()
                .ok_or("Missing folder permission")?
                .into(),
            attestation_id: config["attestation_id"]
                .as_str()
                .ok_or("Missing folder permission")?
                .into(),
        };
        device.stop().await;
        let changed = device.save_managed_share(Some(config)).map_err(error);
        let resumed = device.reconnect_saved().await.map_err(error);
        changed?;
        resumed?;
        Ok(true)
    }
}
#[tauri::command]
pub async fn stop_sharing(desktop: tauri::State<'_, DesktopState>) -> Result<(), String> {
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Device is unavailable")?;
    device.stop().await;
    device.save_managed_share(None).map_err(error)?;
    device.reconnect_saved().await.map_err(error)
}
pub(crate) async fn session(
    desktop: &DesktopState,
) -> Result<
    (
        std::sync::Arc<connect_core::session::SessionEndpoint>,
        PairedDevice,
    ),
    String,
> {
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Join your network first")?;
    device.reconnect_saved().await.map_err(error)?;
    device.refresh().await.map_err(error)?;
    Ok((
        device.session().map_err(error)?,
        device
            .paired_device()
            .cloned()
            .ok_or("Add your other device first")?,
    ))
}
#[tauri::command]
pub async fn browse_files(
    after: Option<String>,
    directory: Option<Vec<String>>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<Page, String> {
    let (session, peer) = session(&desktop).await?;
    session
        .browse_from(
            &peer.node,
            &peer.ticket,
            after,
            directory.unwrap_or_default(),
        )
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn open_file(
    collection_id: String,
    name: String,
    sha256: String,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<ReadReport, String> {
    let (session, peer) = session(&desktop).await?;
    session
        .read_file_from(
            Some(&peer.node),
            &peer.ticket,
            ReadRequest {
                request_id: uuid::Uuid::new_v4().to_string(),
                collection_id,
                file_name: name,
                expected_sha256: Some(sha256),
            },
        )
        .await
        .map_err(error)
}
#[tauri::command]
pub async fn check_connection(desktop: tauri::State<'_, DesktopState>) -> Result<(), String> {
    let (session, peer) = session(&desktop).await?;
    session
        .round_trip_to(Some(&peer.node), &peer.ticket, "Connect availability check")
        .await
        .map_err(error)?;
    Ok(())
}

#[tauri::command]
pub async fn select_device(
    id: String,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    desktop
        .slot
        .lock()
        .await
        .controller
        .as_mut()
        .ok_or("Join your network first")?
        .select_device(&id)
        .await
        .map_err(error)
}

#[tauri::command]
pub async fn forget_device(
    id: String,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    desktop
        .slot
        .lock()
        .await
        .controller
        .as_mut()
        .ok_or("Join your network first")?
        .forget_device(&id)
        .await
        .map_err(error)
}
