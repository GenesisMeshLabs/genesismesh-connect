//! Verified files stay in native private storage. The UI receives opaque IDs,
//! progress and bounded text previews, never filesystem paths or bulk bytes.
//! Each download has its own folder in the cache. An unfinished one keeps its
//! bytes there with a small record of what was verified, so it continues
//! after the app restarts or the sharing device was away.
use anyhow::{Context, Result, ensure};
use connect_core::session::sharing::download::{
    MAX_FILE_BYTES, MAX_WINDOW_BYTES, MIN_WINDOW_BYTES, Request,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tauri::Manager;
use tokio::sync::watch;

/// The record beside an unfinished download's bytes.
const RECORD: &str = "download.json";
/// The folder that holds a download's bytes, apart from its record, so no
/// file's name can be the record's.
const BYTES: &str = "file";
/// Unfinished downloads nobody continues are dropped after a week, and at
/// most this many are kept, the newest: both when the app starts.
const KEPT_FOR: Duration = Duration::from_secs(7 * 24 * 3600);
const MAX_UNFINISHED: usize = 8;

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
/// What the app keeps of an unfinished download beside its bytes.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    collection_id: String,
    directory: Vec<String>,
    name: String,
    version: String,
    size: u64,
    /// The whole file's digest, once the sharing device named it.
    sha256: Option<String>,
    /// Bytes verified in order from the start.
    received: u64,
}
impl Record {
    fn same_file(&self, other: &Record) -> bool {
        self.collection_id == other.collection_id
            && self.directory == other.directory
            && self.name == other.name
            && self.version == other.version
            && self.size == other.size
    }
    /// The name becomes a file here; the Space and folders are only asked
    /// for, and the sharing device checks them.
    fn check(&self) -> Result<()> {
        leaf(&self.name)?;
        let hex = |value: &str| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit());
        ensure!(
            !self.collection_id.is_empty()
                && self.collection_id.len() <= 128
                && self.directory.len() <= 16
                && self
                    .directory
                    .iter()
                    .all(|segment| !segment.is_empty() && segment.len() <= 255)
                && self.size <= MAX_FILE_BYTES
                && self.received <= self.size
                && hex(&self.version)
                && self.sha256.as_deref().is_none_or(hex),
            "Unexpected download"
        );
        Ok(())
    }
}
/// An unfinished download, as the UI lists it.
#[derive(Clone, Serialize)]
pub struct Unfinished {
    id: String,
    name: String,
    received: u64,
    total: u64,
}
/// A download's own folder in the cache, removed when dropped unless it is
/// kept to continue later.
struct Folder {
    path: PathBuf,
    keep: bool,
}
impl Drop for Folder {
    fn drop(&mut self) {
        if !self.keep {
            discard(&self.path);
        }
    }
}
struct Saved {
    _folder: Folder,
    path: PathBuf,
}
/// Whether a download was stopped, and whether its bytes stay to continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    No,
    Keep,
    Discard,
}
struct Job {
    progress: Progress,
    cancel: watch::Sender<Stop>,
    saved: Option<Arc<Saved>>,
}
pub struct Downloads {
    directory: PathBuf,
    job: Arc<Mutex<Option<Job>>>,
    /// Unfinished downloads by folder, except the one running.
    unfinished: Arc<Mutex<BTreeMap<String, Record>>>,
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
    let unfinished = load(&directory)?;
    app.manage(Downloads {
        directory,
        job: Arc::new(Mutex::new(None)),
        unfinished: Arc::new(Mutex::new(unfinished)),
        budget: Arc::new(tokio::sync::Semaphore::new(1)),
    });
    Ok(())
}
/// Remove a cache entry, a folder or anything else, never following a link.
fn discard(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            let _ = std::fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(path);
        }
        Err(_) => {}
    }
}
/// The unfinished downloads a previous run left, each cut back to what it
/// recorded, the newest within the limit. Anything else in the cache goes,
/// finished downloads included: they last only while the app runs.
fn load(directory: &Path) -> Result<BTreeMap<String, Record>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        let loaded = (|| {
            let id = path
                .file_name()
                .and_then(|n| n.to_str())
                .context("Unexpected download folder")?
                .to_owned();
            uuid::Uuid::parse_str(&id)?;
            let metadata = std::fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "Unexpected download folder"
            );
            let _ = std::fs::remove_file(path.join(format!("{RECORD}.tmp")));
            let written = std::fs::symlink_metadata(path.join(RECORD))?;
            ensure!(
                written.is_file() && written.len() <= 64 * 1024,
                "Unexpected download record"
            );
            let age = written.modified()?.elapsed().unwrap_or_default();
            ensure!(age < KEPT_FOR, "Expired");
            let record: Record = serde_json::from_slice(&std::fs::read(path.join(RECORD))?)?;
            record.check()?;
            let bytes = path.join(BYTES).join(&record.name);
            ensure!(
                std::fs::symlink_metadata(path.join(BYTES))?.is_dir()
                    && std::fs::symlink_metadata(&bytes)?.is_file()
                    && std::fs::read_dir(&path)?.count() == 2
                    && std::fs::read_dir(path.join(BYTES))?.count() == 1,
                "Unexpected download folder"
            );
            let data = File::options().write(true).open(&bytes)?;
            ensure!(data.metadata()?.len() >= record.received, "Short download");
            data.set_len(record.received)?;
            Ok::<_, anyhow::Error>((age, id, record))
        })();
        match loaded {
            Ok(found_one) => found.push(found_one),
            Err(_) => discard(&path),
        }
    }
    found.sort_by_key(|(age, ..)| *age);
    let mut kept = BTreeMap::new();
    for (index, (_, id, record)) in found.into_iter().enumerate() {
        if index < MAX_UNFINISHED {
            kept.insert(id, record);
        } else {
            discard(&directory.join(id));
        }
    }
    Ok(kept)
}
/// Write a record whole or not at all.
fn store(path: &Path, record: &Record) -> Result<()> {
    let pending = path.with_extension("json.tmp");
    let mut file = File::create(&pending)?;
    file.write_all(&serde_json::to_vec(record)?)?;
    file.sync_all()?;
    std::fs::rename(&pending, path)?;
    Ok(())
}
fn extension(name: &str) -> String {
    Path::new(name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}
/// The cache's size, apart from the folder `except`.
fn cache_usage(directory: &Path, except: &str) -> Result<u64> {
    let mut bytes = 0u64;
    for (index, entry) in std::fs::read_dir(directory)?.enumerate() {
        ensure!(
            index < 16,
            "Download cache is full. Discard an unfinished download before trying again."
        );
        let entry = entry?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Unexpected download cache entry"
        );
        if entry.file_name() == except {
            continue;
        }
        bytes = bytes
            .checked_add(folder_size(&entry.path(), true)?)
            .context("Download cache is full")?;
    }
    Ok(bytes)
}
/// A download folder's size: its record and, one level down, its bytes.
fn folder_size(path: &Path, outer: bool) -> Result<u64> {
    let mut bytes = 0u64;
    for (index, file) in std::fs::read_dir(path)?.enumerate() {
        ensure!(index < 3, "Unexpected download cache contents");
        let file = file?;
        let metadata = std::fs::symlink_metadata(file.path())?;
        let size = if outer
            && file.file_name() == BYTES
            && metadata.is_dir()
            && !metadata.file_type().is_symlink()
        {
            folder_size(&file.path(), false)?
        } else {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "Unexpected download cache file"
            );
            metadata.len()
        };
        bytes = bytes.checked_add(size).context("Download cache is full")?;
    }
    Ok(bytes)
}
/// A download's bytes, cut back to what was verified. Bytes missing, for
/// example after the system cleared its cache, mean starting again.
fn open_bytes(folder: &Path, record: &mut Record) -> Result<File> {
    std::fs::create_dir_all(folder.join(BYTES))?;
    let output = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(folder.join(BYTES).join(&record.name))?;
    if output.metadata()?.len() < record.received {
        record.received = 0;
        record.sha256 = None;
    }
    output.set_len(record.received)?;
    Ok(output)
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
/// What a window's whole-file digest says about the file.
#[derive(Debug, PartialEq, Eq)]
enum Change {
    Same,
    /// It changed without a new version: start again from the beginning.
    Restart,
    /// It changed again: give up on it.
    Refuse,
}
fn change(known: Option<&str>, window: &str, restarted: bool) -> Change {
    match known {
        Some(known) if known != window && restarted => Change::Refuse,
        Some(known) if known != window => Change::Restart,
        _ => Change::Same,
    }
}
/// What becomes of a download that did not finish.
#[derive(Debug, PartialEq, Eq)]
enum Settle {
    /// Its bytes go.
    Discard,
    /// It is listed to continue later.
    List,
    /// Nothing is left of it.
    Leave,
}
fn settle(stopped: Stop, refused: bool, recorded: bool) -> Settle {
    if stopped == Stop::Discard || refused {
        Settle::Discard
    } else if recorded {
        Settle::List
    } else {
        Settle::Leave
    }
}
/// Check the whole file against its digest; a small text file comes back to
/// preview.
fn verify(mut output: File, expected: &str, size: u64, name: &str) -> Result<Option<String>> {
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
    let digest: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    ensure!(
        digest == expected && output.metadata()?.len() == size,
        "Downloaded file could not be verified"
    );
    if size <= 65536
        && matches!(
            extension(name).as_str(),
            "txt" | "md" | "json" | "csv" | "log"
        )
    {
        output.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        output.take(65537).read_to_end(&mut bytes)?;
        Ok(String::from_utf8(bytes).ok())
    } else {
        Ok(None)
    }
}
/// The unfinished downloads, for the home screen.
pub fn unfinished(state: &Downloads) -> Vec<Unfinished> {
    state
        .unfinished
        .lock()
        .expect("download state")
        .iter()
        .map(|(id, record)| Unfinished {
            id: id.clone(),
            name: record.name.clone(),
            received: record.received,
            total: record.size,
        })
        .collect()
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
    if size > MAX_FILE_BYTES {
        return Err("Choose a file up to 1 GB.".into());
    }
    let record = Record {
        collection_id,
        directory: directory.unwrap_or_default(),
        name,
        version,
        size,
        sha256: None,
        received: 0,
    };
    record.check().map_err(|e| e.to_string())?;
    // The same file left unfinished continues where it stopped.
    let existing = app
        .state::<Downloads>()
        .unfinished
        .lock()
        .expect("download state")
        .iter()
        .find(|(_, kept)| kept.same_file(&record))
        .map(|(id, _)| id.clone());
    start(app, existing, record).await
}
/// Continue an unfinished download.
#[tauri::command]
pub async fn resume_download(id: String, app: tauri::AppHandle) -> Result<String, String> {
    let record = app
        .state::<Downloads>()
        .unfinished
        .lock()
        .expect("download state")
        .get(&id)
        .cloned()
        .ok_or("This download is no longer available")?;
    start(app, Some(id), record).await
}
/// Drop an unfinished download and its bytes.
#[tauri::command]
pub fn discard_download(id: String, state: tauri::State<'_, Downloads>) -> Result<(), String> {
    if state
        .unfinished
        .lock()
        .expect("download state")
        .remove(&id)
        .is_some()
    {
        discard(&state.directory.join(id));
    }
    Ok(())
}
async fn start(
    app: tauri::AppHandle,
    existing: Option<String>,
    record: Record,
) -> Result<String, String> {
    let state = app.state::<Downloads>();
    let permit = state
        .budget
        .clone()
        .try_acquire_owned()
        .map_err(|_| "Finish or cancel the current download first.")?;
    let (mut session, mut peer) = crate::consumer::session(
        &app.state::<crate::desktop::DesktopState>(),
        Some(&record.collection_id),
    )
    .await?;
    // Off the list while it runs; it comes back if it stops unfinished.
    let kept = existing.and_then(|id| {
        let kept = state.unfinished.lock().expect("download state").remove(&id);
        kept.map(|kept| (id, kept))
    });
    let (folder_id, mut record) =
        kept.unwrap_or_else(|| (uuid::Uuid::new_v4().to_string(), record));
    let handle = app.clone();
    let id = uuid::Uuid::new_v4().to_string();
    let (cancel, mut canceled) = watch::channel(Stop::No);
    *state.job.lock().expect("download state") = Some(Job {
        progress: Progress {
            id: id.clone(),
            name: record.name.clone(),
            total: record.size,
            received: record.received,
            state: "downloading".into(),
            problem: None,
            text: None,
            can_open: viewable(&record.name),
        },
        cancel,
        saved: None,
    });
    let cache = state.directory.clone();
    let jobs = state.job.clone();
    let unfinished = state.unfinished.clone();
    let task_id = id.clone();
    tauri::async_runtime::spawn(async move {
        let folder_path = cache.join(&folder_id);
        let size = record.size;
        // A file that keeps changing: nothing to continue.
        let mut refused = false;
        let transfer = async {
            std::fs::create_dir_all(&cache)?;
            ensure!(
                cache_usage(&cache, &folder_id)?.saturating_add(size) <= 2 * MAX_FILE_BYTES,
                "Download cache is full. Discard an unfinished download before trying again."
            );
            // A new download's folder goes again if it cannot be recorded.
            let mut folder = Folder {
                path: folder_path.clone(),
                keep: folder_path.exists(),
            };
            std::fs::create_dir_all(&folder_path)?;
            // Recorded first, so a download that fails from here is listed.
            store(&folder_path.join(RECORD), &record)?;
            folder.keep = true;
            let mut output = open_bytes(&folder_path, &mut record)?;
            store(&folder_path.join(RECORD), &record)?;
            update(&jobs, &task_id, |job| {
                job.progress.received = record.received
            });
            let mut restarted = false;
            let mut token = None;
            let mut digest = record.sha256.clone();
            let mut offset = record.received;
            let mut length = MIN_WINDOW_BYTES;
            // A download that had every byte when it stopped is only checked.
            let mut done = offset == size && digest.is_some();
            while !done {
                let started = Instant::now();
                let mut request = Request {
                    request_id: uuid::Uuid::new_v4().to_string(),
                    collection_id: record.collection_id.clone(),
                    file_name: record.name.clone(),
                    directory: record.directory.clone(),
                    version: record.version.clone(),
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
                            tokio::time::sleep(Duration::from_millis(300)).await;
                        }
                        // The connection dropped, the sharing device is busy,
                        // or it restarted: wait and reach it again. When it no
                        // longer has the snapshot, or refuses the token, the
                        // next attempt asks without it, from where this
                        // download stands; a refusal without a token ends this
                        // attempt, and the download stays listed to continue.
                        Err(error)
                            if attempts < 6
                                && (request.token.is_some()
                                    || !error.to_string().contains("isn't available")) =>
                        {
                            attempts += 1;
                            tokio::time::sleep(Duration::from_secs(1 << attempts.min(5))).await;
                            if let Ok((again, host)) = crate::consumer::session(
                                &handle.state::<crate::desktop::DesktopState>(),
                                Some(&record.collection_id),
                            )
                            .await
                            {
                                (session, peer) = (again, host);
                            }
                            let error = error.to_string();
                            if error.contains("isn't available")
                                || error.contains("no longer has this download")
                            {
                                request.token = None;
                                request.request_id = uuid::Uuid::new_v4().to_string();
                            }
                        }
                        Err(error) => return Err(error),
                    }
                };
                match change(digest.as_deref(), &window.sha256, restarted) {
                    Change::Same => {}
                    // The file changed without a new version: from the start.
                    Change::Restart => {
                        restarted = true;
                        output.set_len(0)?;
                        (token, digest, offset) = (Some(window.token), None, 0);
                        record.received = 0;
                        record.sha256 = None;
                        store(&folder_path.join(RECORD), &record)?;
                        update(&jobs, &task_id, |job| job.progress.received = 0);
                        continue;
                    }
                    Change::Refuse => {
                        refused = true;
                        anyhow::bail!("This file keeps changing on the sharing device.");
                    }
                }
                token = Some(window.token);
                digest = Some(window.sha256);
                offset += window.bytes as u64;
                // What was verified is on disk before it is recorded.
                output.sync_data()?;
                record.received = offset;
                record.sha256 = digest.clone();
                store(&folder_path.join(RECORD), &record)?;
                update(&jobs, &task_id, |job| job.progress.received = offset);
                done = window.done;
                // Keep each independently authorized window short on slow links.
                let seconds = started.elapsed().as_secs_f64().max(0.1);
                length = ((window.bytes as f64 / seconds * 1.5) as u32)
                    .clamp(MIN_WINDOW_BYTES, MAX_WINDOW_BYTES)
                    .min(length.saturating_mul(4));
            }
            output.sync_all()?;
            let expected = digest.context("Missing file digest")?;
            Ok::<_, anyhow::Error>((folder, output, expected))
        };
        let downloaded = tokio::select! { biased;
            _=canceled.changed()=>Err(anyhow::anyhow!("Download canceled")),
            result=transfer=>result,
        };
        // With every byte here, the check runs to its end; a stop meanwhile
        // decides what becomes of the download once it has.
        let outcome = match downloaded {
            Ok((mut folder, output, expected)) => {
                update(&jobs, &task_id, |job| {
                    job.progress.state = "verifying".into()
                });
                let name = record.name.clone();
                let checked =
                    tokio::task::spawn_blocking(move || verify(output, &expected, size, &name))
                        .await
                        .map_err(anyhow::Error::from)
                        .and_then(|checked| checked);
                match (checked, *canceled.borrow()) {
                    // Going back while every byte was here: listed again, and
                    // checked when it continues.
                    (Ok(_), Stop::Keep) => Err(anyhow::anyhow!("Download stopped")),
                    (Ok(text), Stop::No) => {
                        // Finished: the folder goes with the job, and nothing
                        // is left to continue.
                        folder.keep = false;
                        let _ = std::fs::remove_file(folder_path.join(RECORD));
                        Ok((
                            Saved {
                                path: folder_path.join(BYTES).join(&record.name),
                                _folder: folder,
                            },
                            text,
                        ))
                    }
                    // Canceled, or bytes that do not verify: nothing is kept.
                    (checked, _) => {
                        folder.keep = false;
                        Err(checked
                            .err()
                            .unwrap_or_else(|| anyhow::anyhow!("Download canceled")))
                    }
                }
            }
            Err(error) => Err(error),
        };
        let stopped = *canceled.borrow();
        if outcome.is_err() {
            match settle(stopped, refused, folder_path.join(RECORD).is_file()) {
                Settle::Discard => discard(&folder_path),
                Settle::List => {
                    unfinished
                        .lock()
                        .expect("download state")
                        .insert(folder_id, record);
                }
                Settle::Leave => {}
            }
        }
        // Another download may start only now, and finds this one listed.
        drop(permit);
        update(&jobs, &task_id, |job| match outcome {
            Ok((saved, text)) => {
                job.saved = Some(Arc::new(saved));
                job.progress.text = text;
                job.progress.state = "complete".into();
            }
            Err(error) => {
                job.progress.state = if stopped == Stop::No {
                    "failed"
                } else {
                    "canceled"
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
/// Stop a download: its bytes go, or with `keep` stay to continue later.
#[tauri::command]
pub fn cancel_download(
    id: String,
    keep: Option<bool>,
    state: tauri::State<'_, Downloads>,
) -> Result<(), String> {
    let jobs = state.job.lock().expect("download state");
    let job = jobs
        .as_ref()
        .filter(|j| j.progress.id == id)
        .ok_or("Download is no longer available")?;
    job.cancel.send_replace(if keep == Some(true) {
        Stop::Keep
    } else {
        Stop::Discard
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, received: u64) -> Record {
        Record {
            collection_id: uuid::Uuid::new_v4().to_string(),
            directory: vec!["Photos".into(), "Summer: 2026".into()],
            name: name.into(),
            version: "a".repeat(64),
            size: 1000,
            sha256: Some("b".repeat(64)),
            received,
        }
    }
    /// An unfinished download as the app leaves it: its bytes, with `extra`
    /// past what was recorded, and its record.
    fn unfinished(cache: &Path, record: &Record, extra: u64) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let folder = cache.join(&id);
        std::fs::create_dir_all(folder.join(BYTES))?;
        std::fs::write(
            folder.join(BYTES).join(&record.name),
            vec![7u8; (record.received + extra) as usize],
        )?;
        store(&folder.join(RECORD), record)?;
        Ok(id)
    }

    #[test]
    fn unfinished_downloads_are_taken_up_and_everything_else_goes() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let kept = record("movie.mp4", 600);
        let kept_id = unfinished(cache.path(), &kept, 100)?;
        // A finished download from the last run has no record.
        let finished = cache.path().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&finished)?;
        std::fs::write(finished.join("photo.jpg"), b"done")?;
        // One nobody continued for a week.
        let stale_id = unfinished(cache.path(), &record("old.bin", 10), 0)?;
        File::options()
            .write(true)
            .open(cache.path().join(&stale_id).join(RECORD))?
            .set_modified(std::time::SystemTime::now() - KEPT_FOR)?;
        // One with something else beside it, a record that claims more than
        // its bytes, a folder that is not the app's, and a stray file.
        let crowded_id = unfinished(cache.path(), &record("a.bin", 10), 0)?;
        std::fs::write(cache.path().join(&crowded_id).join("other"), b"x")?;
        let short = record("b.bin", 10);
        let short_id = unfinished(cache.path(), &short, 0)?;
        std::fs::write(
            cache.path().join(&short_id).join(BYTES).join("b.bin"),
            b"123",
        )?;
        std::fs::create_dir(cache.path().join("not-a-download"))?;
        std::fs::write(cache.path().join("stray.bin"), b"x")?;
        // An interrupted record write.
        std::fs::write(
            cache.path().join(&kept_id).join(format!("{RECORD}.tmp")),
            b"{",
        )?;

        let loaded = load(cache.path())?;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&kept_id), Some(&kept));
        assert_eq!(
            std::fs::metadata(cache.path().join(&kept_id).join(BYTES).join("movie.mp4"))?.len(),
            600,
            "Bytes past what was verified are cut off"
        );
        let left: Vec<String> = std::fs::read_dir(cache.path())?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_>>()?;
        assert_eq!(left, vec![kept_id.clone()]);
        assert_eq!(std::fs::read_dir(cache.path().join(&kept_id))?.count(), 2);
        assert_eq!(
            cache_usage(cache.path(), "")?,
            600 + std::fs::metadata(cache.path().join(&kept_id).join(RECORD))?.len()
        );
        assert_eq!(cache_usage(cache.path(), &kept_id)?, 0);
        Ok(())
    }

    #[test]
    fn a_file_can_have_the_records_name() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let named = record(RECORD, 300);
        let id = unfinished(cache.path(), &named, 0)?;
        let loaded = load(cache.path())?;
        assert_eq!(loaded.get(&id), Some(&named));
        let mut again = named.clone();
        let output = open_bytes(&cache.path().join(&id), &mut again)?;
        assert_eq!((output.metadata()?.len(), again.received), (300, 300));
        // The record is still the record.
        let written: Record =
            serde_json::from_slice(&std::fs::read(cache.path().join(&id).join(RECORD))?)?;
        assert_eq!(written, named);
        Ok(())
    }

    #[test]
    fn bytes_are_cut_back_to_what_was_verified_or_started_again() -> Result<()> {
        let cache = tempfile::tempdir()?;
        // More bytes than recorded: a window broke off.
        let mut longer = record("a.bin", 400);
        let id = unfinished(cache.path(), &longer, 50)?;
        let output = open_bytes(&cache.path().join(&id), &mut longer)?;
        assert_eq!((output.metadata()?.len(), longer.received), (400, 400));
        assert!(longer.sha256.is_some());
        // Fewer than recorded, or none: the bytes went, so it starts again,
        // never filled in.
        let mut shorter = record("b.bin", 400);
        let id = unfinished(cache.path(), &shorter, 0)?;
        std::fs::write(cache.path().join(&id).join(BYTES).join("b.bin"), b"12")?;
        let output = open_bytes(&cache.path().join(&id), &mut shorter)?;
        assert_eq!((output.metadata()?.len(), shorter.received), (0, 0));
        assert!(shorter.sha256.is_none());
        let mut gone = record("c.bin", 400);
        let output = open_bytes(&cache.path().join("cleared"), &mut gone)?;
        assert_eq!((output.metadata()?.len(), gone.received), (0, 0));
        Ok(())
    }

    #[test]
    fn only_the_newest_unfinished_downloads_are_kept() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let mut ids = Vec::new();
        for index in 0..MAX_UNFINISHED + 2 {
            let id = unfinished(cache.path(), &record("file.bin", 5), 0)?;
            File::options()
                .write(true)
                .open(cache.path().join(&id).join(RECORD))?
                .set_modified(
                    std::time::SystemTime::now() - Duration::from_secs(60 * index as u64),
                )?;
            ids.push(id);
        }
        let loaded = load(cache.path())?;
        assert_eq!(loaded.len(), MAX_UNFINISHED);
        assert!(
            ids[..MAX_UNFINISHED]
                .iter()
                .all(|id| loaded.contains_key(id))
        );
        assert!(
            ids[MAX_UNFINISHED..]
                .iter()
                .all(|id| !cache.path().join(id).exists())
        );
        Ok(())
    }

    #[test]
    fn a_record_names_a_file_this_device_can_keep() {
        assert!(record("movie.mp4", 1000).check().is_ok());
        assert!(record("../escape", 0).check().is_err());
        assert!(record("C:evil", 0).check().is_err());
        assert!(record("movie.mp4", 1001).check().is_err());
        let mut odd = record("movie.mp4", 0);
        odd.sha256 = Some("not hex".into());
        assert!(odd.check().is_err());
        let mut deep = record("movie.mp4", 0);
        deep.directory = vec!["a".into(); 17];
        assert!(deep.check().is_err());
        let a = record("movie.mp4", 0);
        let mut b = a.clone();
        b.received = 500;
        b.sha256 = None;
        assert!(a.same_file(&b), "Progress does not make it another file");
        b.version = "c".repeat(64);
        assert!(!a.same_file(&b));
    }

    #[test]
    fn a_file_that_changed_starts_again_once() {
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        assert_eq!(change(None, &a, false), Change::Same);
        assert_eq!(change(Some(&a), &a, true), Change::Same);
        assert_eq!(change(Some(&a), &b, false), Change::Restart);
        assert_eq!(change(Some(&a), &b, true), Change::Refuse);
    }

    #[test]
    fn a_stopped_download_is_listed_unless_it_was_dropped() {
        // Going back, a failure, or a refusal of one window: listed again.
        assert_eq!(settle(Stop::Keep, false, true), Settle::List);
        assert_eq!(settle(Stop::No, false, true), Settle::List);
        // Cancel, Discard, or a file that keeps changing: its bytes go.
        assert_eq!(settle(Stop::Discard, false, true), Settle::Discard);
        assert_eq!(settle(Stop::No, true, true), Settle::Discard);
        // Bytes that did not verify went with their record.
        assert_eq!(settle(Stop::Keep, false, false), Settle::Leave);
    }

    #[test]
    fn only_bytes_that_match_their_digest_are_kept() -> Result<()> {
        let folder = tempfile::tempdir()?;
        let path = folder.path().join("note.txt");
        std::fs::write(&path, b"hello")?;
        let digest: String = Sha256::digest(b"hello")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let open = || File::options().read(true).write(true).open(&path);
        assert_eq!(
            verify(open()?, &digest, 5, "note.txt")?.as_deref(),
            Some("hello")
        );
        assert!(verify(open()?, &digest, 5, "note.bin")?.is_none());
        assert!(verify(open()?, &"0".repeat(64), 5, "note.txt").is_err());
        assert!(verify(open()?, &digest, 6, "note.txt").is_err());
        Ok(())
    }

    #[test]
    fn a_folder_goes_unless_it_is_kept() -> Result<()> {
        let cache = tempfile::tempdir()?;
        let path = cache.path().join("folder");
        std::fs::create_dir(&path)?;
        drop(Folder {
            path: path.clone(),
            keep: true,
        });
        assert!(path.exists());
        drop(Folder {
            path: path.clone(),
            keep: false,
        });
        assert!(!path.exists());
        Ok(())
    }
}
