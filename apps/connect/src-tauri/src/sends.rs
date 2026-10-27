//! Sending a file into another device's inbox. The file is read in place;
//! the UI receives progress and the name the receiving device saved it as,
//! never paths or bytes.
use anyhow::{Context, Result, ensure};
use connect_core::session::sharing::send::{
    MAX_FILE_BYTES, MAX_WINDOW_BYTES, MIN_WINDOW_BYTES, Request,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
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
    sent: u64,
    state: String,
    problem: Option<String>,
    saved_as: Option<String>,
}
struct Job {
    progress: Progress,
    cancel: watch::Sender<bool>,
}
pub struct Sends {
    job: Arc<Mutex<Option<Job>>>,
}
pub fn setup(app: &mut tauri::App) {
    app.manage(Sends {
        job: Arc::new(Mutex::new(None)),
    });
}
fn update(jobs: &Mutex<Option<Job>>, id: &str, action: impl FnOnce(&mut Job)) {
    if let Some(job) = jobs
        .lock()
        .expect("send state")
        .as_mut()
        .filter(|j| j.progress.id == id)
    {
        action(job);
    }
}

/// Choose a file with the native picker and send it into the inbox `space`.
/// Returns the job to follow, or none when the owner cancels the picker.
#[tauri::command]
pub async fn send_file(space: String, app: tauri::AppHandle) -> Result<Option<String>, String> {
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = (space, app);
        Err("Sending from phones is being added. Send from a computer for now.".into())
    }
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    {
        let state = app.state::<Sends>();
        if state
            .job
            .lock()
            .expect("send state")
            .as_ref()
            .is_some_and(|j| j.progress.state == "sending" || j.progress.state == "checking")
        {
            return Err("Finish or cancel the current send first.".into());
        }
        // Picker is native and cannot be controlled by a peer-supplied path.
        let Some(picked) = rfd::AsyncFileDialog::new()
            .set_title("Choose a file to send")
            .pick_file()
            .await
        else {
            return Ok(None);
        };
        let path = picked.path().to_owned();
        let name: String = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        let size = metadata.len();
        // The file is read again for each window: a change shows here.
        let modified = metadata.modified().ok();
        if size > MAX_FILE_BYTES {
            return Err("Choose a file up to 1 GB.".into());
        }
        let (session, peer) =
            crate::consumer::session(&app.state::<crate::desktop::DesktopState>(), Some(&space))
                .await?;
        let id = uuid::Uuid::new_v4().to_string();
        let (cancel, mut canceled) = watch::channel(false);
        *state.job.lock().expect("send state") = Some(Job {
            progress: Progress {
                id: id.clone(),
                name: name.clone(),
                total: size,
                sent: 0,
                state: "checking".into(),
                problem: None,
                saved_as: None,
            },
            cancel,
        });
        let jobs = state.job.clone();
        let task_id = id.clone();
        tauri::async_runtime::spawn(async move {
            let transfer = async {
                // The receiving device checks the whole file against this.
                let (mut file, digest) = tokio::task::spawn_blocking(move || {
                    let mut file = file;
                    let mut hash = Sha256::new();
                    let mut buffer = vec![0u8; 65536];
                    let mut total = 0u64;
                    loop {
                        let count = file.read(&mut buffer)?;
                        if count == 0 {
                            break;
                        }
                        hash.update(&buffer[..count]);
                        total += count as u64;
                    }
                    ensure!(total == size, "The file changed while it was being read");
                    let digest: String =
                        hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
                    Ok::<_, anyhow::Error>((file, digest))
                })
                .await??;
                update(&jobs, &task_id, |job| job.progress.state = "sending".into());
                let (mut token, mut offset, mut length) = (None, 0u64, MIN_WINDOW_BYTES);
                loop {
                    let now = file.metadata()?;
                    ensure!(
                        now.len() == size && now.modified().ok() == modified,
                        "The file changed while it was being sent. Send it again."
                    );
                    let started = Instant::now();
                    let request = Request {
                        request_id: uuid::Uuid::new_v4().to_string(),
                        collection_id: space.clone(),
                        file_name: name.clone(),
                        size,
                        sha256: digest.clone(),
                        token: token.clone(),
                        offset,
                        length,
                    };
                    let window = session
                        .send_window_to(&peer.node, &peer.ticket, request, &mut file)
                        .await?;
                    offset += window.bytes as u64;
                    token = Some(window.token);
                    update(&jobs, &task_id, |job| job.progress.sent = offset);
                    if window.done {
                        return window
                            .saved_as
                            .context("The other device did not save the file");
                    }
                    // Keep each separately decided window short on slow links.
                    let seconds = started.elapsed().as_secs_f64().max(0.1);
                    length = ((window.bytes as f64 / seconds * 1.5) as u32)
                        .clamp(MIN_WINDOW_BYTES, MAX_WINDOW_BYTES)
                        .min(length.saturating_mul(4));
                }
            };
            let outcome = tokio::select! { biased;
                _ = canceled.changed() => Err(anyhow::anyhow!("Sending canceled")),
                result = transfer => result,
            };
            update(&jobs, &task_id, |job| match outcome {
                Ok(saved_as) => {
                    job.progress.saved_as = Some(saved_as);
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
        Ok(Some(id))
    }
}
#[tauri::command]
pub fn send_status(id: String, state: tauri::State<'_, Sends>) -> Result<Progress, String> {
    state
        .job
        .lock()
        .expect("send state")
        .as_ref()
        .filter(|j| j.progress.id == id)
        .map(|j| j.progress.clone())
        .ok_or("This send is no longer available".into())
}
#[tauri::command]
pub fn cancel_send(id: String, state: tauri::State<'_, Sends>) -> Result<(), String> {
    let jobs = state.job.lock().expect("send state");
    let job = jobs
        .as_ref()
        .filter(|j| j.progress.id == id)
        .ok_or("This send is no longer available")?;
    job.cancel.send_replace(true);
    Ok(())
}
