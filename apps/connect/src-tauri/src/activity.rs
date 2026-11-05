//! Device-local access history. No remote owner, execution or import endpoint.
use crate::desktop::DesktopState;
use connect_core::{
    access_workflow::{
        AccessJournal,
        history::{
            HistoryContext, HistoryPage, HistoryQuery, HistoryScope, LocalAccessRecord,
            LocalRecordQuery, RecoveryHint,
        },
    },
    authority::TrustPin,
    device::DeviceStatus,
    operations::AccessOutcome,
};
use tauri::Manager;

fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn context(status: DeviceStatus) -> HistoryContext {
    let audience = if status.connectivity.network_computer {
        Some(status.node_public_key.clone())
    } else {
        status.bridge_host_node
    };
    HistoryContext {
        scope: HistoryScope {
            pin: TrustPin {
                root_public_key: status.root_public_key,
                network_name: status.network,
            },
            actor: status.node_public_key,
        },
        audience,
        owned: status.shares.into_iter().map(|s| s.collection_id).collect(),
        disconnected: status.disconnected,
    }
}
async fn current(desktop: &DesktopState) -> Result<HistoryContext, String> {
    let slot = desktop.slot.lock().await;
    Ok(context(
        slot.controller
            .as_ref()
            .ok_or("Open this device’s network to see its local activity.")?
            .status()
            .map_err(error)?,
    ))
}

#[tauri::command]
pub async fn get_access_activity(
    request: HistoryQuery,
    app: tauri::AppHandle,
) -> Result<HistoryPage, String> {
    request.validate().map_err(error)?;
    let desktop = app.state::<DesktopState>();
    let _network = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the network change to finish.")?;
    let context = current(&desktop).await?;
    let path = crate::access::journal_path(&desktop)?;
    tokio::task::spawn_blocking(move || {
        AccessJournal::open(&path)?.history_page(&context, &request)
    })
    .await
    .map_err(error)?
    .map_err(error)
}

#[tauri::command]
pub async fn get_activity_record(
    request: LocalRecordQuery,
    app: tauri::AppHandle,
) -> Result<LocalAccessRecord, String> {
    request.validate().map_err(error)?;
    let desktop = app.state::<DesktopState>();
    let _network = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the network change to finish.")?;
    read_local_record(&desktop, request).await
}

async fn read_local_record(
    desktop: &DesktopState,
    request: LocalRecordQuery,
) -> Result<LocalAccessRecord, String> {
    let context = current(desktop).await?;
    let path = crate::access::journal_path(desktop)?;
    tokio::task::spawn_blocking(move || {
        AccessJournal::open(&path)?.history_record(&context.scope, &request.id)
    })
    .await
    .map_err(error)?
    .map_err(error)
}

#[tauri::command]
pub async fn check_activity_record(
    request: LocalRecordQuery,
    app: tauri::AppHandle,
) -> Result<AccessOutcome, String> {
    request.validate().map_err(error)?;
    let summary = {
        let desktop = app.state::<DesktopState>();
        let _network = desktop
            .transfers
            .try_read()
            .map_err(|_| "Wait for the network change to finish.")?;
        let context = current(&desktop).await?;
        let path = crate::access::journal_path(&desktop)?;
        tokio::task::spawn_blocking(move || {
            AccessJournal::open(&path)?.history_summary(&context, &request.id)
        })
        .await
        .map_err(error)?
        .map_err(error)?
    };
    if summary.recovery != RecoveryHint::CheckStatus {
        return Err("This historical record cannot be checked here. Review the item on its network computer instead.".into());
    }
    // This existing command re-resolves the live root, actor, audience, owned
    // resource and active journal ID. It reads status, never resends a write.
    crate::access::access_workflow_status(summary.collection, true, Some(summary.id), app)
        .await?
        .ok_or(
            "This record no longer belongs to the active network computer. Refresh Activity."
                .into(),
        )
}

use connect_core::access_workflow::history::RecordExport;

#[tauri::command]
pub async fn export_activity_record(
    request: LocalRecordQuery,
    app: tauri::AppHandle,
) -> Result<RecordExport, String> {
    request.validate().map_err(error)?;
    let desktop = app.state::<DesktopState>();
    let _network = desktop
        .transfers
        .try_read()
        .map_err(|_| "Wait for the network change to finish.")?;
    let local = read_local_record(&desktop, request).await?;
    let name = format!("Connect-access-{}.json", local.record.intent.id);
    let bytes = local.document().map_err(error)?.into_bytes();
    #[cfg(desktop)]
    {
        use std::io::Write;
        let Some(chosen) = rfd::AsyncFileDialog::new()
            .set_title("Save local access record")
            .add_filter("JSON record", &["json"])
            .set_file_name(&name)
            .save_file()
            .await
        else {
            return Ok(RecordExport::Cancelled);
        };
        let path = chosen.path().to_owned();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut pending = tempfile::NamedTempFile::new_in(
                path.parent()
                    .ok_or_else(|| anyhow::anyhow!("Choose a folder for the record"))?,
            )?;
            pending.write_all(&bytes)?;
            pending.as_file().sync_all()?;
            pending.persist(path)?;
            Ok(())
        })
        .await
        .map_err(error)?
        .map_err(error)?;
        Ok(RecordExport::Saved)
    }
    #[cfg(mobile)]
    {
        use tauri_plugin_view::ViewExt;
        // Reuse the private export cache and its existing restart/leave cleanup.
        let cache = app
            .path()
            .app_cache_dir()
            .map_err(error)?
            .join("connect-downloads")
            .join("local-exports");
        std::fs::create_dir_all(&cache).map_err(error)?;
        let export = tempfile::Builder::new()
            .prefix("access-record-")
            .tempdir_in(cache)
            .map_err(error)?;
        let path = export.path().join(name);
        std::fs::write(&path, bytes).map_err(error)?;
        app.view()
            .view(tauri_plugin_view::ViewRequest {
                path: Some(path.to_string_lossy().into_owned()),
                share: true,
            })
            .map_err(error)?;
        let _ = export.keep();
        Ok(RecordExport::ShareSheetOpened)
    }
}
