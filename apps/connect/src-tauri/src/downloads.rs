//! Verified files stay in native private storage. The UI receives opaque IDs,
//! progress and bounded text previews, never filesystem paths or bulk bytes.
use anyhow::{Context, Result, ensure};
use connect_core::session::sharing::download::{
    MAX_FILE_BYTES, MAX_WINDOW_BYTES, MIN_WINDOW_BYTES, Request,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};
use tauri::Manager;
use tokio::sync::watch;

#[derive(Clone, Serialize)]
pub struct Progress {
    id: String,
    name: String,
    total: u64,
    received: u64,
    state: String,
    problem: Option<String>,
    text: Option<String>,
    can_open: bool,
}
struct Saved {
    _directory: tempfile::TempDir,
    path: PathBuf,
}
struct Job {
    progress: Progress,
    cancel: watch::Sender<bool>,
    saved: Option<Arc<Saved>>,
}
pub struct Downloads {
    directory: PathBuf,
    job: Arc<Mutex<Option<Job>>>,
    budget: Arc<tokio::sync::Semaphore>,
}
pub fn setup(app: &mut tauri::App) -> Result<()> {
    let directory = app.path().app_cache_dir()?.join("connect-downloads");
    std::fs::create_dir_all(&directory)?;
    ensure!(
        std::fs::symlink_metadata(&directory)?.is_dir()
            && !std::fs::symlink_metadata(&directory)?
                .file_type()
                .is_symlink(),
        "Invalid download cache"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    }
    app.manage(Downloads {
        directory,
        job: Arc::new(Mutex::new(None)),
        budget: Arc::new(tokio::sync::Semaphore::new(1)),
    });
    Ok(())
}
fn extension(name: &str) -> String {
    Path::new(name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}
fn cache_usage(directory: &Path) -> Result<u64> {
    let mut bytes = 0u64;
    for (index, entry) in std::fs::read_dir(directory)?.enumerate() {
        ensure!(
            index < 16,
            "Download cache is full. Clear Connect’s temporary downloads before trying again."
        );
        let entry = entry?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Unexpected download cache entry"
        );
        for (index, file) in std::fs::read_dir(entry.path())?.enumerate() {
            ensure!(index < 2, "Unexpected download cache contents");
            let file = file?;
            let metadata = std::fs::symlink_metadata(file.path())?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "Unexpected download cache file"
            );
            bytes = bytes
                .checked_add(metadata.len())
                .context("Download cache is full")?;
        }
    }
    Ok(bytes)
}
fn viewable(name: &str) -> bool {
    matches!(
        extension(name).as_str(),
        "pdf"
            | "txt"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "heic"
            | "mp4"
            | "mov"
            | "mp3"
            | "m4a"
            | "wav"
            | "docx"
            | "xlsx"
            | "pptx"
    )
}
fn leaf(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && !name
                .chars()
                .any(|c| c.is_control() || "/\\:*?\"<>|".contains(c))
            && name != "."
            && name != ".."
            && !name.ends_with(['.', ' ']),
        "Choose a valid file"
    );
    Ok(())
}
fn update(jobs: &Mutex<Option<Job>>, id: &str, action: impl FnOnce(&mut Job)) {
    if let Some(job) = jobs
        .lock()
        .expect("download state")
        .as_mut()
        .filter(|j| j.progress.id == id)
    {
        action(job);
    }
}
#[tauri::command]
pub async fn download_file(
    collection_id: String,
    directory: Option<Vec<String>>,
    name: String,
    version: String,
    size: u64,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let directories = directory.unwrap_or_default();
    leaf(&name).map_err(|e| e.to_string())?;
    if size > MAX_FILE_BYTES {
        return Err("Choose a file up to 1 GB.".into());
    }
    let state = app.state::<Downloads>();
    let permit = state
        .budget
        .clone()
        .try_acquire_owned()
        .map_err(|_| "Finish or cancel the current download first.")?;
    let (mut session, mut peer) = crate::consumer::session(
        &app.state::<crate::desktop::DesktopState>(),
        Some(&collection_id),
    )
    .await?;
    let handle = app.clone();
    let id = uuid::Uuid::new_v4().to_string();
    let (cancel, mut canceled) = watch::channel(false);
    *state.job.lock().expect("download state") = Some(Job {
        progress: Progress {
            id: id.clone(),
            name: name.clone(),
            total: size,
            received: 0,
            state: "downloading".into(),
            problem: None,
            text: None,
            can_open: viewable(&name),
        },
        cancel,
        saved: None,
    });
    let directory = state.directory.clone();
    let jobs = state.job.clone();
    let task_id = id.clone();
    tauri::async_runtime::spawn(async move {
        let transfer = async {
            ensure!(
                cache_usage(&directory)?.saturating_add(size) <= 2 * MAX_FILE_BYTES,
                "Download cache is full. Clear Connect’s temporary downloads before trying again."
            );
            let directory = tempfile::Builder::new()
                .prefix("gm-download-")
                .tempdir_in(directory)?;
            let path = directory.path().join(&name);
            let mut output = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)?;
            let mut token = None;
            let mut digest = None;
            let mut offset = 0;
            let mut length = MIN_WINDOW_BYTES;
            loop {
                let started = Instant::now();
                let mut request = Request {
                    request_id: uuid::Uuid::new_v4().to_string(),
                    collection_id: collection_id.clone(),
                    file_name: name.clone(),
                    directory: directories.clone(),
                    version: version.clone(),
                    size,
                    token: token.clone(),
                    offset,
                    length,
                };
                let (mut retries, mut attempts) = (0, 0u32);
                let window = loop {
                    match session
                        .download_window_from(
                            &peer.node,
                            &peer.ticket,
                            request.clone(),
                            &mut output,
                        )
                        .await
                    {
                        Ok(window) => break window,
                        Err(error)
                            if retries < 5
                                && (error.to_string() == "Trust changed during download"
                                    || error.to_string() == "Connection is suspended") =>
                        {
                            retries += 1;
                            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        }
                        // The connection dropped or the sharing device
                        // restarted: wait, reach it again, and if its snapshot
                        // is gone, take a fresh one of the same version from
                        // where this download stands.
                        Err(_) if attempts < 6 => {
                            attempts += 1;
                            tokio::time::sleep(std::time::Duration::from_secs(
                                1 << attempts.min(5),
                            ))
                            .await;
                            if let Ok((again, host)) = crate::consumer::session(
                                &handle.state::<crate::desktop::DesktopState>(),
                                Some(&collection_id),
                            )
                            .await
                            {
                                (session, peer) = (again, host);
                            }
                            if attempts >= 2 {
                                request.token = None;
                                request.request_id = uuid::Uuid::new_v4().to_string();
                            }
                        }
                        Err(error) => return Err(error),
                    }
                };
                // Any fresh snapshot must be of the very same file.
                ensure!(
                    digest.as_ref().is_none_or(|d| d == &window.sha256),
                    "File digest changed during download"
                );
                token = Some(window.token);
                digest = Some(window.sha256);
                offset += window.bytes as u64;
                update(&jobs, &task_id, |job| job.progress.received = offset);
                if window.done {
                    break;
                }
                // Keep each independently authorized window short on slow links.
                let seconds = started.elapsed().as_secs_f64().max(0.1);
                length = ((window.bytes as f64 / seconds * 1.5) as u32)
                    .clamp(MIN_WINDOW_BYTES, MAX_WINDOW_BYTES)
                    .min(length.saturating_mul(4));
            }
            update(&jobs, &task_id, |job| {
                job.progress.state = "verifying".into()
            });
            output.sync_all()?;
            let expected = digest.context("Missing file digest")?;
            let text_name = name.clone();
            let verified =
                tokio::task::spawn_blocking(move || -> Result<(Saved, Option<String>)> {
                    let _permit = permit;
                    let saved = Saved {
                        _directory: directory,
                        path,
                    };
                    // Drop the open handle before its owning directory on errors,
                    // including cancellation while this blocking hash finishes.
                    let mut output = output;
                    output.seek(SeekFrom::Start(0))?;
                    let mut hash = Sha256::new();
                    let mut buffer = [0u8; 65536];
                    loop {
                        let count = output.read(&mut buffer)?;
                        if count == 0 {
                            break;
                        }
                        hash.update(&buffer[..count]);
                    }
                    let digest: String =
                        hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
                    ensure!(
                        digest == expected && output.metadata()?.len() == size,
                        "Downloaded file could not be verified"
                    );
                    if size <= 65536
                        && matches!(
                            extension(&text_name).as_str(),
                            "txt" | "md" | "json" | "csv" | "log"
                        )
                    {
                        output.seek(SeekFrom::Start(0))?;
                        let mut bytes = Vec::new();
                        output.take(65537).read_to_end(&mut bytes)?;
                        Ok((saved, String::from_utf8(bytes).ok()))
                    } else {
                        Ok((saved, None))
                    }
                })
                .await??;
            Ok::<_, anyhow::Error>(verified)
        };
        let outcome = tokio::select! { biased;
            _=canceled.changed()=>Err(anyhow::anyhow!("Download canceled")),
            result=transfer=>result,
        };
        update(&jobs, &task_id, |job| match outcome {
            Ok((saved, text)) => {
                job.saved = Some(Arc::new(saved));
                job.progress.text = text;
                job.progress.state = "complete".into();
            }
            Err(error) => {
                job.progress.state = if *canceled.borrow() {
                    "canceled"
                } else {
                    "failed"
                }
                .into();
                job.progress.problem = Some(error.to_string());
            }
        });
    });
    Ok(id)
}
#[tauri::command]
pub fn download_status(id: String, state: tauri::State<'_, Downloads>) -> Result<Progress, String> {
    state
        .job
        .lock()
        .expect("download state")
        .as_ref()
        .filter(|j| j.progress.id == id)
        .map(|j| j.progress.clone())
        .ok_or("Download is no longer available".into())
}
#[tauri::command]
pub fn cancel_download(id: String, state: tauri::State<'_, Downloads>) -> Result<(), String> {
    let jobs = state.job.lock().expect("download state");
    let job = jobs
        .as_ref()
        .filter(|j| j.progress.id == id)
        .ok_or("Download is no longer available")?;
    job.cancel.send_replace(true);
    Ok(())
}
fn saved(state: &Downloads, id: &str) -> Result<Arc<Saved>, String> {
    state
        .job
        .lock()
        .expect("download state")
        .as_ref()
        .filter(|j| j.progress.id == id && j.progress.state == "complete")
        .and_then(|j| j.saved.clone())
        .ok_or("Finish downloading this file first.".into())
}
#[tauri::command]
pub async fn open_download(id: String, app: tauri::AppHandle) -> Result<(), String> {
    let file = saved(&app.state::<Downloads>(), &id)?;
    if !viewable(file.path.file_name().unwrap().to_str().unwrap_or("")) {
        return Err("Save this file to open it in another app.".into());
    }
    #[cfg(desktop)]
    {
        use tauri_plugin_opener::OpenerExt;
        app.opener()
            .open_path(file.path.to_string_lossy(), None::<&str>)
            .map_err(|e| e.to_string())?;
    }
    #[cfg(mobile)]
    {
        use tauri_plugin_view::ViewExt;
        app.view()
            .view(tauri_plugin_view::ViewRequest {
                path: Some(file.path.to_string_lossy().into_owned()),
                share: false,
            })
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
#[tauri::command]
pub async fn save_download(id: String, app: tauri::AppHandle) -> Result<bool, String> {
    let file = saved(&app.state::<Downloads>(), &id)?;
    #[cfg(desktop)]
    {
        let name = file.path.file_name().unwrap().to_string_lossy();
        let Some(destination) = rfd::AsyncFileDialog::new()
            .set_title("Save a copy")
            .set_file_name(name.as_ref())
            .save_file()
            .await
        else {
            return Ok(false);
        };
        tokio::task::spawn_blocking(move || std::fs::copy(&file.path, destination.path()))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        Ok(true)
    }
    #[cfg(mobile)]
    {
        use tauri_plugin_view::ViewExt;
        app.view()
            .view(tauri_plugin_view::ViewRequest {
                path: Some(file.path.to_string_lossy().into_owned()),
                share: true,
            })
            .map_err(|e| e.to_string())?;
        Ok(true)
    }
}
