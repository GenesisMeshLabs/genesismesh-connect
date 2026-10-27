//! Ordinary user actions. Keys, transport routes and policy identifiers are
//! obtained from verified native state, not text fields in the normal UI.
use crate::{desktop::DesktopState, workflow::WorkflowState};
use connect_core::{
    Connectivity,
    device::{ConnectivityStatus, DeviceController, PairedDevice},
    session::{
        pairing::{PairCard, PairGrant, PairRequest},
        sharing::{ReadReport, ReadRequest, SpaceKind, browse::Page},
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
    /// Listed by the network computer rather than paired with this device.
    member: bool,
}
/// A shared folder as the Files view shows it.
#[derive(Serialize)]
pub struct HomeSpace {
    id: String,
    name: String,
    /// The device sharing it, by name.
    host: String,
    host_id: String,
    /// Shared from this device.
    own: bool,
    /// A folder to browse, or an inbox to send files into.
    kind: SpaceKind,
}
#[derive(Serialize)]
pub struct HomeStatus {
    disconnected: bool,
    can_leave: bool,
    leaving: bool,
    owner: bool,
    configured: bool,
    network: Option<String>,
    peer: Option<String>,
    devices: Vec<HomeDevice>,
    selected_device: Option<String>,
    ready: bool,
    sharing: Option<String>,
    /// Shared folders: this device's, and other devices' shared with it.
    spaces: Vec<HomeSpace>,
    /// This device can share its folders.
    can_share: bool,
    can_share_folder: bool,
    joining: Option<String>,
    request: Option<PairRequest>,
    problem: Option<String>,
    legacy: bool,
    connection: Option<ConnectivityStatus>,
    /// Downloads that stopped before they finished, to continue.
    unfinished: Vec<crate::downloads::Unfinished>,
}
#[tauri::command]
pub async fn home_status(
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
    downloads: tauri::State<'_, crate::downloads::Downloads>,
) -> Result<HomeStatus, String> {
    let owner = state.slot.lock().await;
    let display = desktop.display_status()?;
    let device = display.device.as_deref();
    let configured = device.as_ref().is_some_and(|d| d.certificate_id.is_some());
    Ok(HomeStatus {
        disconnected: device.is_some_and(|d| d.disconnected),
        can_leave: !state.directory.join("owner.json").exists()
            && owner.runtime.is_none()
            && (device.is_some() || DeviceController::leaving(&desktop.profile)),
        leaving: DeviceController::leaving(&desktop.profile),
        owner: owner.runtime.is_some(),
        configured,
        devices: device
            .as_ref()
            .map(|d| {
                let paired = d.devices.iter().map(|p| (p, false));
                let members = d.members.iter().map(|p| (p, true));
                paired
                    .chain(members)
                    .map(|(p, member)| HomeDevice {
                        id: p.node.clone(),
                        name: p.name.clone(),
                        selected: d.peer_node.as_ref() == Some(&p.node),
                        authority_connection: d.bridge_host_node.as_ref() == Some(&p.node),
                        member,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        selected_device: device.as_ref().and_then(|d| d.peer_node.clone()),
        network: device.as_ref().map(|d| d.network.clone()),
        peer: device
            .as_ref()
            .and_then(|d| d.paired_device.as_ref().map(|p| p.name.clone())),
        ready: !display.updating && device.as_ref().is_some_and(|d| d.ready),
        sharing: device.as_ref().and_then(|d| {
            d.sharing_config
                .as_ref()
                .and_then(|c| c.directory.file_name())
                .map(|s| s.to_string_lossy().into_owned())
        }),
        spaces: device.map(home_spaces).unwrap_or_default(),
        can_share: device.as_ref().is_some_and(|d| d.sharing_host),
        can_share_folder: cfg!(desktop),
        joining: owner.joining.clone(),
        request: owner.pairing.as_ref().and_then(|p| p.pending()),
        problem: owner
            .problem
            .clone()
            .or_else(|| display.problem.clone())
            .or_else(|| device.as_ref().and_then(|d| d.problem.clone())),
        legacy: configured
            && owner.runtime.is_none()
            && !state.directory.join("owner.json").is_file()
            && device.as_ref().is_some_and(|d| d.paired_device.is_none()),
        connection: device.map(|d| ConnectivityStatus {
            network: d.connectivity.network,
            own: d.connectivity.own,
            effective: d.connectivity.effective,
            network_computer: d.connectivity.network_computer,
            guided: d.connectivity.guided,
        }),
        unfinished: crate::downloads::unfinished(&downloads),
    })
}
/// This device's Spaces first, then those other devices share with it, with
/// the sharing device's name where this device knows it.
fn home_spaces(status: &connect_core::device::DeviceStatus) -> Vec<HomeSpace> {
    let name_of = |node: &str| {
        status
            .devices
            .iter()
            .chain(&status.members)
            .find(|d| d.node == node)
            .map_or_else(|| "Another device".to_owned(), |d| d.name.clone())
    };
    let mut spaces: Vec<HomeSpace> = status
        .shares
        .iter()
        .map(|share| HomeSpace {
            id: share.collection_id.clone(),
            name: if share.name.is_empty() {
                share.directory.file_name().map_or_else(
                    || "Shared folder".into(),
                    |s| s.to_string_lossy().into_owned(),
                )
            } else {
                share.name.clone()
            },
            host: "This device".into(),
            host_id: status.node_public_key.clone(),
            own: true,
            kind: share.kind,
        })
        .collect();
    spaces.extend(
        status
            .spaces
            .iter()
            .filter(|space| space.host != status.node_public_key)
            .map(|space| HomeSpace {
                id: space.collection.clone(),
                name: space.name.clone(),
                host: name_of(&space.host),
                host_id: space.host.clone(),
                own: false,
                kind: space.kind,
            }),
    );
    spaces
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
/// Select a resource natively, then publish only to the chosen devices.
#[tauri::command]
pub async fn share_folder(
    recipients: Option<Vec<String>>,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<bool, String> {
    #[cfg(mobile)]
    {
        let _ = (recipients, state, desktop);
        Err(
            "Choose individual files on this device. Folder sharing is available on computers."
                .into(),
        )
    }
    #[cfg(desktop)]
    {
        let _network = desktop
            .transfers
            .clone()
            .try_read_owned()
            .map_err(|_| "This device is changing networks")?;
        let Some(folder) = rfd::AsyncFileDialog::new()
            .set_title("Choose a folder to share")
            .pick_folder()
            .await
        else {
            return Ok(false);
        };
        let directory = folder.path().to_owned();
        let name = crate::workflow::folder_name(&directory);
        publish_directory(
            SpaceKind::Folder,
            directory,
            name,
            recipients,
            &state,
            &desktop,
        )
        .await
    }
}
#[tauri::command]
pub async fn receive_files(
    recipients: Option<Vec<String>>,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<bool, String> {
    let _network = desktop
        .transfers
        .clone()
        .try_read_owned()
        .map_err(|_| "This device is changing networks")?;
    #[cfg(desktop)]
    let directory = {
        let Some(folder) = rfd::AsyncFileDialog::new()
            .set_title("Choose where received files are saved")
            .pick_folder()
            .await
        else {
            return Ok(false);
        };
        folder.path().to_owned()
    };
    // A phone receives into Connect's private storage: no impossible folder
    // picker or filesystem path to type. Native open/export remains available.
    #[cfg(mobile)]
    let directory = {
        let path = desktop
            .profile
            .parent()
            .ok_or("Missing app storage")?
            .join("Received");
        std::fs::create_dir_all(&path).map_err(error)?;
        path
    };
    publish_directory(
        SpaceKind::Inbox,
        directory,
        "Inbox".into(),
        recipients,
        &state,
        &desktop,
    )
    .await
}
#[tauri::command]
pub async fn share_file(
    recipients: Option<Vec<String>>,
    media: Option<bool>,
    app: tauri::AppHandle,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<bool, String> {
    let _network = desktop
        .transfers
        .clone()
        .try_read_owned()
        .map_err(|_| "This device is changing networks")?;
    let Some(picked) = crate::picking::file(&app, media.unwrap_or(false))
        .await
        .map_err(error)?
    else {
        return Ok(false);
    };
    // Validate before joining a provider-controlled name onto a private path.
    connect_core::validate_shared_file_name(&picked.name).map_err(error)?;
    let name = picked.name.chars().take(64).collect::<String>();
    let root = desktop.profile.join("shared-files");
    std::fs::create_dir_all(&root).map_err(error)?;
    let folder = tempfile::Builder::new()
        .prefix("file-")
        .tempdir_in(&root)
        .map_err(error)?;
    let directory = folder.path().to_owned();
    let destination = directory.clone();
    tokio::task::spawn_blocking(move || crate::picking::copy(&picked, &destination))
        .await
        .map_err(error)?
        .map_err(error)?;
    let result = publish_directory(
        SpaceKind::Folder,
        directory,
        name,
        recipients,
        &state,
        &desktop,
    )
    .await?;
    // Keep this app-owned snapshot for the lifetime of the share/profile.
    let _ = folder.keep();
    Ok(result)
}
pub(crate) fn recipients_for(status: &connect_core::device::DeviceStatus) -> Vec<String> {
    let mut available = Vec::new();
    for node in status.bridge_host_node.iter().chain(
        status
            .devices
            .iter()
            .chain(&status.members)
            .map(|d| &d.node),
    ) {
        if node != &status.node_public_key && !available.contains(node) {
            available.push(node.clone());
        }
    }
    available.truncate(31);
    available
}
pub(crate) fn validate_recipients(
    chosen: Vec<String>,
    available: &[String],
) -> Result<Vec<String>, String> {
    let unique: std::collections::BTreeSet<_> = chosen.into_iter().collect();
    if unique.is_empty() || unique.len() > 31 || unique.iter().any(|node| !available.contains(node))
    {
        return Err("Choose one or more devices from this network.".into());
    }
    Ok(unique.into_iter().collect())
}
async fn publish_directory(
    kind: SpaceKind,
    directory: std::path::PathBuf,
    name: String,
    chosen: Option<Vec<String>>,
    state: &WorkflowState,
    desktop: &DesktopState,
) -> Result<bool, String> {
    let mut owner = state.slot.lock().await;
    let mut slot = desktop.slot.lock().await;
    let device = slot
        .controller
        .as_mut()
        .ok_or("Set up this computer first")?;
    let status = device.status().map_err(error)?;
    // Only identities from the current verified network can receive access.
    let available = recipients_for(&status);
    let recipients = chosen.unwrap_or_else(|| available.clone());
    let recipients = validate_recipients(recipients, &available)?;
    match owner.runtime.as_mut() {
        // The network computer issues its own Spaces directly.
        Some(runtime) => {
            let subject = status
                .sharing_subject
                .ok_or("This device has no sharing identity")?;
            let collection = uuid::Uuid::new_v4().to_string();
            let space = runtime
                .space_share(
                    &status.node_public_key,
                    &collection,
                    &name,
                    &recipients,
                    Some(&subject),
                    kind,
                )
                .map_err(error)?;
            let view = connect_core::session::bridge::SpaceView::of(space, &status.node_public_key)
                .ok_or("Unexpected shared folder")?;
            let config = connect_core::device::DeviceController::space_config(view, directory)
                .map_err(error)?;
            device.set_space(config).await.map_err(error)?;
            // Devices see the new Space at once.
            if let Ok(spaces) = runtime.space_list() {
                device.publish_spaces(spaces);
            }
        }
        None => {
            drop(owner);
            device
                .share_space(None, directory, name, recipients, kind)
                .await
                .map_err(error)?;
        }
    }
    Ok(true)
}
/// Stop sharing one Space, or every Space when none is named. Returns whether
/// the network computer confirmed; otherwise it finishes when reachable.
#[tauri::command]
pub async fn stop_sharing(
    id: Option<String>,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<bool, String> {
    let mut owner = state.slot.lock().await;
    if owner.runtime.is_none() && state.directory.join("owner.json").is_file() {
        return Err("Your network is still opening. Try again in a moment.".into());
    }
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Device is unavailable")?;
    let status = device.status().map_err(error)?;
    let ids: Vec<String> = match id {
        Some(id) => vec![id],
        None => status
            .shares
            .iter()
            .map(|s| s.collection_id.clone())
            .collect(),
    };
    let mut confirmed = true;
    for id in ids {
        match owner.runtime.as_mut() {
            Some(runtime) => {
                // Stop serving first: nothing is released while the network
                // computer forgets it.
                device.drop_space(&id).await.map_err(error)?;
                // If this fails, the next pass over the Spaces removes it.
                confirmed &= runtime.space_remove(&status.node_public_key, &id).is_ok();
                if let Ok(spaces) = runtime.space_list() {
                    device.publish_spaces(spaces);
                }
            }
            None => confirmed &= device.unshare_space(&id).await.map_err(error)?,
        }
        if let Some(stopped) = status.shares.iter().find(|share| share.collection_id == id) {
            crate::picking::remove_shared_copy(&desktop.profile, &stopped.directory)
                .map_err(error)?;
        }
    }
    drop(owner);
    Ok(confirmed)
}
/// A running session and the device to reach: the one sharing `space` when
/// this device knows that Space, otherwise the selected device.
pub(crate) async fn session(
    desktop: &DesktopState,
    space: Option<&str>,
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
    let status = device.status().map_err(error)?;
    let host = space
        .and_then(|id| status.spaces.iter().find(|s| s.collection == id))
        .map(|s| s.host.clone());
    let peer = match host {
        Some(host) => status
            .devices
            .iter()
            .chain(&status.members)
            .find(|d| d.node == host)
            .cloned()
            .ok_or("The device sharing this folder isn’t on your network right now")?,
        None => device
            .paired_device()
            .cloned()
            .ok_or("Add your other device first")?,
    };
    Ok((device.session().map_err(error)?, peer))
}
#[tauri::command]
pub async fn browse_files(
    after: Option<String>,
    directory: Option<Vec<String>>,
    space: Option<String>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<Page, String> {
    let (session, peer) = session(&desktop, space.as_deref()).await?;
    session
        .browse_from(
            &peer.node,
            &peer.ticket,
            after,
            directory.unwrap_or_default(),
            space,
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
    let (session, peer) = session(&desktop, Some(&collection_id)).await?;
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
    let (session, peer) = session(&desktop, None).await?;
    session
        .round_trip_to(Some(&peer.node), &peer.ticket, "Connect availability check")
        .await
        .map_err(error)?;
    Ok(())
}

/// Ask the network computer for its devices now, when Devices opens.
#[tauri::command]
pub async fn check_network(desktop: tauri::State<'_, DesktopState>) -> Result<(), String> {
    let mut slot = desktop.slot.lock().await;
    match slot.controller.as_mut() {
        Some(device) => device.check_network().await.map_err(error),
        None => Ok(()),
    }
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

/// On the network computer: take a device off the network. It is revoked
/// first, so nothing accepts it while its Spaces change; asking again
/// finishes a removal that failed part way.
#[tauri::command]
pub async fn remove_device(
    id: String,
    state: tauri::State<'_, WorkflowState>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    let mut owner = state.slot.lock().await;
    let mut runtime = owner
        .runtime
        .take()
        .ok_or("Remove devices on your network computer.")?;
    let saved = {
        let slot = desktop.slot.lock().await;
        slot.controller
            .as_ref()
            .ok_or("Device is unavailable")
            .and_then(|device| device.status().map_err(|_| "Device is unavailable"))
            .map(|status| status.devices.iter().any(|d| d.node == id))
    };
    if !matches!(saved, Ok(true)) {
        owner.runtime = Some(runtime);
        return Err(saved
            .err()
            .unwrap_or("Choose a device of this network")
            .into());
    }
    let node = id.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let removed = runtime
            .remove_device(&node)
            .and_then(|removal| Ok((removal, runtime.space_list()?)));
        (runtime, removed)
    })
    .await
    .map_err(|_| "Could not remove the device")?;
    owner.runtime = Some(outcome.0);
    let (removal, spaces) = outcome.1.map_err(error)?;
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Device is unavailable")?;
    device.forget_device(&id).await.map_err(error)?;
    // The device is off the network now; what follows only tidies this
    // computer, and its next pass over the Spaces finishes what fails here.
    let tidied = async {
        device.publish_spaces(spaces.clone());
        let own_node = device.status()?.node_public_key;
        // This computer's Spaces that changed take their new grants now.
        device.apply_spaces(
            spaces
                .into_iter()
                .filter_map(|space| connect_core::session::bridge::SpaceView::of(space, &own_node))
                .collect(),
        )?;
        let own: Vec<String> = device
            .status()?
            .shares
            .into_iter()
            .map(|share| share.collection_id)
            .filter(|collection| removal.stopped.contains(collection))
            .collect();
        for collection in own {
            device.drop_space(&collection).await?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(problem) = tidied {
        slot.problem = Some(problem.to_string());
    }
    Ok(())
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

fn own_inbox(
    status: &connect_core::device::DeviceStatus,
    collection: &str,
) -> Result<std::path::PathBuf, String> {
    status
        .shares
        .iter()
        .find(|s| s.collection_id == collection && s.kind == SpaceKind::Inbox)
        .map(|s| s.directory.clone())
        .ok_or("Choose this device's inbox".into())
}
#[tauri::command]
pub async fn browse_received(
    space: String,
    directory: Vec<String>,
    after: Option<String>,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<Page, String> {
    let collection_id = space;
    let root = {
        let slot = desktop.slot.lock().await;
        let status = slot
            .controller
            .as_ref()
            .ok_or("Open this device first")?
            .status()
            .map_err(error)?;
        own_inbox(&status, &collection_id)?
    };
    tokio::task::spawn_blocking(move || {
        connect_core::session::sharing::local_browse(
            &root,
            &collection_id,
            &directory,
            after.as_deref(),
        )
    })
    .await
    .map_err(error)?
    .map_err(error)
}
#[tauri::command]
pub async fn export_received(
    collection_id: String,
    directory: Vec<String>,
    name: String,
    version: String,
    app: tauri::AppHandle,
    desktop: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    let _network = desktop
        .transfers
        .clone()
        .try_read_owned()
        .map_err(|_| "This device is changing networks")?;
    let root = {
        let slot = desktop.slot.lock().await;
        let status = slot
            .controller
            .as_ref()
            .ok_or("Open this device first")?
            .status()
            .map_err(error)?;
        own_inbox(&status, &collection_id)?
    };
    connect_core::validate_shared_file_name(&name).map_err(error)?;
    let cache = app
        .path()
        .app_cache_dir()
        .map_err(error)?
        .join("connect-downloads")
        .join("local-exports");
    std::fs::create_dir_all(&cache).map_err(error)?;
    // Keep the export alive while the OS share sheet reads it. These private
    // copies are removed on restart or leave, never the original received file.
    let export = tempfile::Builder::new()
        .prefix("export-")
        .tempdir_in(&cache)
        .map_err(error)?;
    let path = export.path().join(&name);
    let destination = export.path().to_owned();
    tokio::task::spawn_blocking(move || {
        let mut file =
            connect_core::session::sharing::local_file(&root, &directory, &name, &version)?;
        crate::picking::copy_file(&mut file, &name, &destination)
    })
    .await
    .map_err(error)?
    .map_err(error)?;
    #[cfg(desktop)]
    {
        let _ = app;
        let Some(chosen) = rfd::AsyncFileDialog::new()
            .set_title("Save received file")
            .set_file_name(path.file_name().unwrap().to_string_lossy())
            .save_file()
            .await
        else {
            return Ok(());
        };
        std::fs::copy(&path, chosen.path()).map_err(error)?;
    }
    #[cfg(mobile)]
    {
        use tauri_plugin_view::ViewExt;
        app.view()
            .view(tauri_plugin_view::ViewRequest {
                path: Some(path.to_string_lossy().into_owned()),
                share: true,
            })
            .map_err(error)?;
        let _ = export.keep();
    }
    Ok(())
}
#[cfg(test)]
mod sharing_selection_tests {
    use super::*;
    #[test]
    fn recipients_are_explicit_unique_and_network_bound() {
        let available = vec!["phone".into(), "tablet".into()];
        assert_eq!(
            validate_recipients(vec!["phone".into(), "phone".into()], &available).unwrap(),
            vec!["phone"]
        );
        assert!(validate_recipients(vec![], &available).is_err());
        assert!(validate_recipients(vec!["outsider".into()], &available).is_err());
    }
}
