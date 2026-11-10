//! Sending files into another device's inbox, one after another. Each file is
//! read in place; the UI receives progress and the names the receiving device
//! saved them as, never paths or bytes.
use anyhow::{Context, Result, ensure};
use connect_core::session::sharing::send::{
    MAX_FILE_BYTES, MAX_WINDOW_BYTES, MIN_WINDOW_BYTES, Outcome, Request,
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
    /// The file being sent, counting from 1, of how many chosen.
    index: usize,
    count: usize,
    /// What the receiving device saved each finished file as, in order.
    saved: Vec<String>,
}
struct Job {
    progress: Progress,
    cancel: watch::Sender<bool>,
}
pub struct Sends {
    job: Arc<Mutex<Option<Job>>>,
}
pub(crate) fn clear_network(state: &Sends) {
    state.job.lock().expect("send state").take();
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

/// A chosen file, opened and measured before anything is sent.
struct Item {
    file: std::fs::File,
    name: String,
    size: u64,
    modified: Option<std::time::SystemTime>,
}

/// Choose files with the native picker and send them into the inbox `space`,
/// one after another. Returns the job to follow, or none when the owner
/// cancels the picker. A file that fails stops the ones after it.
#[tauri::command]
pub async fn send_file(
    space: String,
    media: Option<bool>,
    app: tauri::AppHandle,
) -> Result<Option<String>, String> {
    let network = app
        .state::<crate::desktop::DesktopState>()
        .transfers
        .clone()
        .try_read_owned()
        .map_err(|_| "This device is changing networks. Try again shortly.")?;
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
    let picked = crate::picking::files(&app, media.unwrap_or(false), true)
        .await
        .map_err(|e| e.to_string())?;
    if picked.is_empty() {
        return Ok(None);
    }
    let mut queue = Vec::with_capacity(picked.len());
    for one in &picked {
        connect_core::validate_shared_file_name(&one.name).map_err(|e| e.to_string())?;
        let file = std::fs::File::open(&one.path).map_err(|e| e.to_string())?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        // Each file is read again for each window: a change shows there.
        if metadata.len() > MAX_FILE_BYTES {
            return Err(format!(
                "{} exceeds the supported exact byte-count range.",
                one.name
            ));
        }
        queue.push(Item {
            file,
            name: one.name.clone(),
            size: metadata.len(),
            modified: metadata.modified().ok(),
        });
    }
    let (mut session, mut peer) =
        crate::consumer::session(&app.state::<crate::desktop::DesktopState>(), Some(&space))
            .await?;
    let handle = app.clone();
    let id = uuid::Uuid::new_v4().to_string();
    let (cancel, mut canceled) = watch::channel(false);
    *state.job.lock().expect("send state") = Some(Job {
        progress: Progress {
            id: id.clone(),
            name: queue[0].name.clone(),
            total: queue[0].size,
            sent: 0,
            state: "checking".into(),
            problem: None,
            saved_as: None,
            index: 1,
            count: queue.len(),
            saved: Vec::new(),
        },
        cancel,
    });
    let jobs = state.job.clone();
    let task_id = id.clone();
    tauri::async_runtime::spawn(async move {
        let _network = network;
        let _picked = picked;
        let mut outcome = Ok(());
        for (index, item) in queue.into_iter().enumerate() {
            update(&jobs, &task_id, |job| {
                job.progress.index = index + 1;
                job.progress.name = item.name.clone();
                job.progress.total = item.size;
                job.progress.sent = 0;
                job.progress.state = "checking".into();
            });
            let sending = send_one(
                &handle,
                &space,
                &jobs,
                &task_id,
                (&mut session, &mut peer),
                item,
                canceled.clone(),
            );
            let result = tokio::select! { biased;
                _ = canceled.changed() => Err(anyhow::anyhow!("Sending canceled")),
                result = sending => result,
            };
            match result {
                Ok(saved_as) => update(&jobs, &task_id, |job| {
                    job.progress.saved.push(saved_as.clone());
                    job.progress.saved_as = Some(saved_as);
                }),
                Err(error) => {
                    outcome = Err(error);
                    break;
                }
            }
        }
        update(&jobs, &task_id, |job| match outcome {
            Ok(()) => job.progress.state = "complete".into(),
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

/// Send one file, window by window, and return what the receiving device
/// saved it as. After a dropped connection or a restart of either device the
/// same window is asked again, and the other device says where the file stands.
async fn send_one(
    handle: &tauri::AppHandle,
    space: &str,
    jobs: &Mutex<Option<Job>>,
    task_id: &str,
    (session, peer): (
        &mut Arc<connect_core::session::SessionEndpoint>,
        &mut connect_core::device::PairedDevice,
    ),
    item: Item,
    checking_cancel: watch::Receiver<bool>,
) -> Result<String> {
    let Item {
        file,
        name,
        size,
        modified,
    } = item;
    // The receiving device checks the whole file against this.
    let (mut file, digest) = tokio::task::spawn_blocking(move || {
        let mut file = file;
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; 65536];
        let mut total = 0u64;
        loop {
            ensure!(!*checking_cancel.borrow(), "Sending canceled");
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            total += count as u64;
        }
        ensure!(total == size, "The file changed while it was being read");
        let digest: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
        Ok::<_, anyhow::Error>((file, digest))
    })
    .await??;
    update(jobs, task_id, |job| job.progress.state = "sending".into());
    let (mut token, mut offset, mut length) = (None, 0u64, MIN_WINDOW_BYTES);
    let mut started_over = false;
    // Answers in a row that only move the file along, and all that was
    // sent: a device that keeps taking the file back is not followed for ever.
    let (mut continued, mut sent) = (0, 0u64);
    loop {
        let now = file.metadata()?;
        ensure!(
            now.len() == size && now.modified().ok() == modified,
            "The file changed while it was being sent. Send it again."
        );
        let started = Instant::now();
        let mut request = Request {
            request_id: uuid::Uuid::new_v4().to_string(),
            collection_id: space.to_owned(),
            file_name: name.clone(),
            size,
            sha256: digest.clone(),
            token: token.clone(),
            offset,
            length,
        };
        // A busy inbox takes the window a little later; after a dropped
        // connection or a restart of either device, the same window is asked
        // again, with the token the other device named.
        let (mut waits, mut attempts) = (0, 0u32);
        let window = loop {
            match session
                .send_window_to(&peer.node, &peer.ticket, &mut request, &mut file)
                .await
            {
                Ok(outcome) => break outcome,
                Err(error) if waits < 30 && error.to_string().contains("receiving other files") => {
                    waits += 1;
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                Err(error)
                    if attempts < 6 && !error.to_string().contains("isn't accepting files") =>
                {
                    attempts += 1;
                    tokio::time::sleep(std::time::Duration::from_secs(1 << attempts.min(5))).await;
                    if let Ok((again, host)) = crate::consumer::session(
                        &handle.state::<crate::desktop::DesktopState>(),
                        Some(space),
                    )
                    .await
                    {
                        (*session, *peer) = (again, host);
                    }
                }
                Err(error) => return Err(error),
            }
        };
        let window = match window {
            Outcome::Sent(window) => {
                continued = 0;
                sent += window.bytes as u64;
                ensure!(
                    sent <= size.saturating_mul(4) + u64::from(MAX_WINDOW_BYTES),
                    "The other device does not take this file"
                );
                window
            }
            // The last window's confirmation was lost.
            Outcome::Saved { saved_as } => {
                update(jobs, task_id, |job| job.progress.sent = size);
                return Ok(saved_as);
            }
            // The other device holds the file up to here.
            Outcome::ContinueAt { token: kept, at } => {
                ensure!(continued < 32, "The other device does not take this file");
                continued += 1;
                token = Some(kept);
                offset = at;
                update(jobs, task_id, |job| job.progress.sent = offset);
                continue;
            }
            // It no longer has the transfer: once, from the start.
            Outcome::StartOver => {
                ensure!(
                    !started_over,
                    "The other device lost this file. Send it again."
                );
                started_over = true;
                (token, offset) = (None, 0);
                continue;
            }
        };
        offset += window.bytes as u64;
        token = Some(window.token);
        update(jobs, task_id, |job| job.progress.sent = offset);
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
