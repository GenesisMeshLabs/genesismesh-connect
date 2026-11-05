//! Guided access changes. The UI submits choices for review, then only the
//! stored review ID and digest. Native code re-resolves identity and current
//! policy; the existing authority remains the authorization/enforcement point.
use crate::{
    consumer,
    desktop::DesktopState,
    workflow::{OwnerSlot, WorkflowState},
};
use connect_core::{
    access_workflow::{AccessContext, AccessJournal, AccessRecord, Stage},
    authority::TrustPin,
    device::{DeviceController, DeviceStatus},
    operations::{
        AccessCommitInput, AccessOutcome, AccessReviewInput, OperationId, ResourceCapabilities,
        ResourceQuery,
    },
    owner::{AccessPolicy, AccessUpdate},
};
use tauri::Manager;

fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
/// Public descriptions only. Discovery does not grant any operation rights.
#[tauri::command]
pub fn operation_registry() -> Vec<connect_core::operations::OperationDescriptor> {
    connect_core::operations::registry().to_vec()
}
fn item_name(name: &str) -> String {
    if name.trim().is_empty() {
        "Shared item".into()
    } else {
        name.into()
    }
}
fn context(status: &DeviceStatus) -> Result<AccessContext, String> {
    if status.disconnected {
        return Err("Reconnect this device before managing access.".into());
    }
    Ok(AccessContext {
        pin: TrustPin {
            root_public_key: status.root_public_key.clone(),
            network_name: status.network.clone(),
        },
        actor: status.node_public_key.clone(),
        audience: if status.connectivity.network_computer {
            status.node_public_key.clone()
        } else {
            status
                .bridge_host_node
                .clone()
                .ok_or("Connect to your network computer to manage access.")?
        },
    })
}
fn journal(desktop: &DesktopState) -> Result<AccessJournal, String> {
    AccessJournal::open(
        &desktop
            .profile
            .parent()
            .ok_or("Missing application directory")?
            .join("access-workflows.json"),
    )
    .map_err(error)
}
async fn read(
    owner: &mut OwnerSlot,
    device: &mut DeviceController,
    id: &str,
) -> Result<AccessPolicy, String> {
    let status = device.status().map_err(error)?;
    if !status.shares.iter().any(|s| s.collection_id == id) {
        return Err("Only the sharing device can manage access.".into());
    }
    match owner.runtime.as_mut() {
        Some(runtime) => runtime
            .access_get(&status.node_public_key, id)
            .map_err(error),
        None => serde_json::from_value(device.access_policy(id.into(), None).await.map_err(error)?)
            .map_err(error),
    }
}
async fn capabilities(
    owner: &mut OwnerSlot,
    device: &mut DeviceController,
    collection: &str,
) -> Result<ResourceCapabilities, String> {
    let status = device.status().map_err(error)?;
    let context = context(&status)?;
    if !status.shares.iter().any(|s| s.collection_id == collection) {
        return Err("Only the sharing device can manage access.".into());
    }
    let result = match owner.runtime.as_mut() {
        Some(runtime) => runtime
            .resource_capabilities(&context.actor, collection)
            .map_err(error)?,
        None => device
            .resource_capabilities(collection.into())
            .await
            .map_err(|e| format!("{e:#}"))?,
    };
    result
        .require(
            &context.pin,
            &context.actor,
            collection,
            OperationId::ResourceCapabilities,
        )
        .map_err(error)?;
    result
        .require(
            &context.pin,
            &context.actor,
            collection,
            OperationId::InspectAccess,
        )
        .map_err(error)?;
    Ok(result)
}

#[tauri::command]
pub async fn get_resource_capabilities(
    request: ResourceQuery,
    app: tauri::AppHandle,
) -> Result<ResourceCapabilities, String> {
    request.validate().map_err(error)?;
    let desktop = app.state::<DesktopState>();
    let workflow = app.state::<WorkflowState>();
    let _idle = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the network change to finish.")?;
    let mut owner = workflow.slot.lock().await;
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Join your network first.")?;
    device.refresh().await.map_err(error)?;
    capabilities(&mut owner, device, &request.collection).await
}

async fn refresh_projection(
    owner: &mut OwnerSlot,
    device: &mut DeviceController,
    collection: &str,
    settings: &AccessPolicy,
) -> Result<bool, String> {
    let status = device.status().map_err(error)?;
    let view = if let Some(runtime) = owner.runtime.as_mut() {
        let spaces = runtime.space_list().map_err(error)?;
        let view = spaces
            .iter()
            .find(|s| s.collection == collection && s.host == status.node_public_key)
            .cloned()
            .and_then(|s| connect_core::session::bridge::SpaceView::of(s, &status.node_public_key));
        device.publish_spaces(spaces);
        view
    } else {
        device.check_network().await.map_err(error)?;
        device
            .status()
            .map_err(error)?
            .spaces
            .into_iter()
            .find(|s| s.collection == collection && s.host == status.node_public_key)
    };
    let Some(grant) = view.and_then(|view| view.grant) else {
        return Ok(false);
    };
    let Some(mut config) = device
        .status()
        .map_err(error)?
        .shares
        .into_iter()
        .find(|s| s.collection_id == collection)
    else {
        return Ok(false);
    };
    if grant.policy_id != config.policy_id || grant.recipients != settings.recipients {
        return Ok(false);
    }
    config.recipients = settings.recipients.clone();
    config.attestation_id = grant.attestation_id;
    if let Some(target) = &mut config.service {
        target.max_bytes = settings.max_bytes;
        target.max_seconds = settings.max_seconds;
    }
    device.set_space(config).await.map_err(error)?;
    Ok(true)
}

#[tauri::command]
pub async fn review_access_policy(
    request: AccessReviewInput,
    app: tauri::AppHandle,
) -> Result<AccessRecord, String> {
    request.validate().map_err(error)?;
    let AccessReviewInput {
        collection: id,
        settings,
    } = request;
    let desktop = app.state::<DesktopState>();
    let workflow = app.state::<WorkflowState>();
    let _idle = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the network change to finish.")?;
    let mut owner = workflow.slot.lock().await;
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Join your network first.")?;
    device.refresh().await.map_err(error)?;
    let status = device.status().map_err(error)?;
    let context = context(&status)?;
    let share = status
        .shares
        .iter()
        .find(|s| s.collection_id == id)
        .ok_or("Only the sharing device can manage access.")?;
    consumer::validate_recipients(
        settings.recipients.clone(),
        &consumer::recipients_for(&status),
    )?;
    let available = capabilities(&mut owner, device, &id).await?;
    available
        .require(&context.pin, &context.actor, &id, OperationId::UpdateAccess)
        .map_err(error)?;
    let current = read(&mut owner, device, &id).await?;
    if available.policy_version != current.version {
        return Err("Access changed while checking features. Reload its settings.".into());
    }
    journal(&desktop)?
        .prepare(
            context,
            id,
            item_name(&share.name),
            current,
            settings,
            std::time::SystemTime::now().into(),
        )
        .map_err(error)
}

#[tauri::command]
pub async fn commit_access_policy(
    request: AccessCommitInput,
    app: tauri::AppHandle,
) -> Result<AccessOutcome, String> {
    request.validate().map_err(error)?;
    let AccessCommitInput { id, digest } = request;
    let desktop = app.state::<DesktopState>();
    let workflow = app.state::<WorkflowState>();
    let _idle = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the network change to finish.")?;
    let mut owner = workflow.slot.lock().await;
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Join your network first.")?;
    device.refresh().await.map_err(error)?;
    let status = device.status().map_err(error)?;
    let context = context(&status)?;
    let mut journal = journal(&desktop)?;
    let review = journal.get(&id, &context).map_err(error)?;
    let collection = &review.intent.collection;
    let mut config = status
        .shares
        .iter()
        .find(|s| &s.collection_id == collection)
        .cloned()
        .ok_or("This item is no longer shared from this device.")?;
    if item_name(&config.name) != review.intent.name {
        return Err("This shared item changed. Review its current settings again.".into());
    }
    consumer::validate_recipients(
        review.intent.after.recipients.clone(),
        &consumer::recipients_for(&status),
    )?;
    let available = capabilities(&mut owner, device, collection).await?;
    available
        .require(
            &context.pin,
            &context.actor,
            collection,
            OperationId::UpdateAccess,
        )
        .map_err(error)?;
    let current = read(&mut owner, device, collection).await?;
    if available.policy_version != current.version {
        return Err("Access changed while checking features. Reload its settings.".into());
    }
    journal
        .submit(
            &id,
            &digest,
            &context,
            current,
            std::time::SystemTime::now().into(),
        )
        .map_err(error)?;
    let result: Result<AccessUpdate, String> = match owner.runtime.as_mut() {
        Some(runtime) => runtime
            .access_update(&status.node_public_key, collection, &review.intent.after)
            .map_err(error),
        None => match device
            .access_policy(collection.clone(), Some(review.intent.after.clone()))
            .await
        {
            Ok(value) => serde_json::from_value(value).map_err(error),
            Err(e) => Err(error(e)),
        },
    };
    let mut local_applied = false;
    let problem = match result {
        Ok(updated) => {
            journal.core_accepted(&id).map_err(error)?;
            config.recipients = updated.settings.recipients;
            config.attestation_id = updated.space.attestation_id;
            if let Some(target) = &mut config.service { target.max_bytes = updated.settings.max_bytes; target.max_seconds = updated.settings.max_seconds; }
            match device.set_space(config).await { Ok(()) => { local_applied = true; None }, Err(_) => Some("Your network accepted the change, but this device could not finish refreshing its shared item. Check status before trying anything else.".into()) }
        },
        Err(_) => Some("The change was sent, but its result could not be confirmed. Check status; it will not be sent again automatically.".into()),
    };
    // Always read back, including after a lost mutation reply. No blind retry.
    let record = match read(&mut owner, device, collection).await {
        Ok(current) => journal.observe(&id, current).map_err(error)?,
        Err(_) => {
            journal.uncertain(&id).map_err(error)?;
            journal.get(&id, &context).map_err(error)?
        }
    };
    if !local_applied
        && record.stage == Stage::StateObserved
        && let Some(settings) = &record.observed
    {
        local_applied = refresh_projection(&mut owner, device, collection, settings)
            .await
            .unwrap_or(false);
    }
    if let Some(runtime) = owner.runtime.as_mut()
        && let Ok(spaces) = runtime.space_list()
    {
        device.publish_spaces(spaces);
    }
    Ok(AccessOutcome {
        record,
        local_applied,
        problem,
    })
}

#[tauri::command]
pub async fn access_workflow_status(
    collection: String,
    check: bool,
    workflow_id: Option<String>,
    app: tauri::AppHandle,
) -> Result<Option<AccessOutcome>, String> {
    let desktop = app.state::<DesktopState>();
    let workflow = app.state::<WorkflowState>();
    let _idle = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the network change to finish.")?;
    let mut owner = workflow.slot.lock().await;
    let mut slot = desktop.slot.lock().await;
    let device = slot.controller.as_mut().ok_or("Join your network first.")?;
    let context = context(&device.status().map_err(error)?)?;
    let mut journal = journal(&desktop)?;
    let Some(mut record) = journal
        .list(&context, &collection)
        .into_iter()
        .rev()
        .find(|r| match &workflow_id {
            Some(id) => &r.intent.id == id,
            None => !matches!(r.stage, Stage::Prepared | Stage::Cancelled),
        })
    else {
        return Ok(None);
    };
    if check && !matches!(record.stage, Stage::Prepared | Stage::Cancelled) {
        device.check_network().await.map_err(error)?;
        let current = read(&mut owner, device, &collection).await?;
        record = journal.observe(&record.intent.id, current).map_err(error)?;
    }
    // Compare the saved local projection separately from authority readback.
    // Matching authority state never claims the share restarted successfully.
    let status = device.status().map_err(error)?;
    let mut local_applied = record.observed.as_ref().is_some_and(|settings| {
        status.shares.iter().any(|s| {
            s.collection_id == collection
                && s.recipients == settings.recipients
                && s.service.as_ref().is_none_or(|t| {
                    t.max_bytes == settings.max_bytes && t.max_seconds == settings.max_seconds
                })
        })
    });
    if check
        && record.stage == Stage::StateObserved
        && let Some(settings) = &record.observed
    {
        local_applied = refresh_projection(&mut owner, device, &collection, settings)
            .await
            .unwrap_or(false);
    }
    Ok(Some(AccessOutcome {
        record,
        local_applied,
        problem: None,
    }))
}

#[tauri::command]
pub async fn cancel_access_review(id: String, app: tauri::AppHandle) -> Result<(), String> {
    let desktop = app.state::<DesktopState>();
    let slot = desktop.slot.lock().await;
    let context = context(
        &slot
            .controller
            .as_ref()
            .ok_or("Join your network first.")?
            .status()
            .map_err(error)?,
    )?;
    journal(&desktop)?.cancel(&id, &context).map_err(error)
}
