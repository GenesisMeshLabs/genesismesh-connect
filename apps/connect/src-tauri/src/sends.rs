//! Sending files into another device's inbox, one after another. Each file is
//! read in place; the UI receives progress and the names the receiving device
//! saved them as, never paths or bytes.
//!
//! A send that stops before it finishes, because it failed or because the app
//! closed, keeps a small record of where each file stands. Continuing asks the
//! receiving device where the file it was sending stands, and never sends
//! again a file that arrived. When a file may have arrived but the receiving
//! device no longer says, it is not sent again either: the person is told to
//! check.
use anyhow::{Context, Result, bail, ensure};
use connect_core::session::sharing::send::{
    MAX_FILE_BYTES, MAX_WINDOW_BYTES, MIN_WINDOW_BYTES, NotIntact, Outcome, Request,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
use tauri::Manager;
use tokio::sync::watch;

/// The record of the send that has not finished.
const RECORD: &str = "send.json";
const MAX_RECORD: u64 = 1024 * 1024;
/// A send nobody continues is forgotten after a week.
const KEPT_FOR: Duration = Duration::from_secs(7 * 24 * 3600);
/// How long a send waits to reach the receiving device before anything is
/// sent, as while this device's network opens after a restart: the same two
/// minutes reads wait (`waiting.ts`).
const REACH_FOR: Duration = Duration::from_secs(120);

#[derive(Clone, Serialize)]
pub struct Progress {
    id: String,
    /// The inbox the files go to.
    space: String,
    name: String,
    total: u64,
    sent: u64,
    /// checking, sending, complete, failed, canceled, or interrupted: the app
    /// closed while it was sending.
    state: String,
    problem: Option<String>,
    saved_as: Option<String>,
    /// The file being sent, counting from 1, of how many chosen.
    index: usize,
    count: usize,
    /// What the receiving device saved each finished file as, in order.
    saved: Vec<String>,
    /// Files that may have arrived although the receiving device no longer
    /// says: they are not sent again.
    unsure: Vec<String>,
    /// The file being sent may have arrived; continuing asks first.
    maybe_arrived: bool,
    /// The send stopped and can continue where it stopped.
    kept: bool,
}
struct Job {
    progress: Progress,
    cancel: watch::Sender<bool>,
}
/// One chosen file, as the record keeps it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: PathBuf,
    name: String,
    size: u64,
    /// When it last changed, in nanoseconds since 1970, if known.
    modified: Option<u128>,
    /// A copy this app made of a file picked on a phone, removed with the
    /// record or once it arrived.
    temporary: bool,
    /// The whole file's digest, once worked out.
    sha256: Option<String>,
    saved_as: Option<String>,
    /// It may have arrived, but the receiving device no longer says.
    unsure: bool,
}
/// What the app keeps of a send that has not finished.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    id: String,
    space: String,
    files: Vec<Entry>,
    /// The file being sent, from 0; every one before it arrived or is unsure.
    index: usize,
    /// Where the receiving device last said the current file stood.
    token: Option<String>,
    offset: u64,
    /// Where the window on its way when the record was written ends: one
    /// that reaches the end of the file may have completed it.
    pending: Option<u64>,
}
impl Record {
    fn check(&self, picked: &Path) -> Result<()> {
        uuid::Uuid::parse_str(&self.id)?;
        let hex = |value: &str| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit());
        ensure!(
            !self.space.is_empty()
                && self.space.len() <= 128
                && !self.files.is_empty()
                && self.files.len() <= crate::picking::MAX_SELECTION
                && self.index < self.files.len()
                && self
                    .token
                    .as_deref()
                    .is_none_or(|t| uuid::Uuid::parse_str(t).is_ok()),
            "Unexpected send"
        );
        let current = &self.files[self.index];
        ensure!(
            self.offset <= current.size
                && self
                    .pending
                    .is_none_or(|end| end >= self.offset && end <= current.size),
            "Unexpected send"
        );
        for (index, entry) in self.files.iter().enumerate() {
            connect_core::validate_shared_file_name(&entry.name)?;
            let finished = entry.saved_as.is_some() || entry.unsure;
            ensure!(
                entry.size <= MAX_FILE_BYTES
                    && entry.path.is_absolute()
                    && finished == (index < self.index)
                    && !(entry.saved_as.is_some() && entry.unsure)
                    && entry
                        .saved_as
                        .as_deref()
                        .is_none_or(|n| !n.is_empty() && n.len() <= 255)
                    && entry.sha256.as_deref().is_none_or(hex)
                    // Only a copy this app made is ever removed.
                    && (finished || !entry.temporary || in_folder(&entry.path, picked)),
                "Unexpected send"
            );
        }
        Ok(())
    }
    /// Where continuing starts with the file it was sending.
    fn start(&self) -> Start {
        Start {
            token: self.token.clone(),
            offset: self.offset,
            maybe_done: self.pending == Some(self.files[self.index].size),
        }
    }
    fn progress(&self, state: &str, problem: Option<String>) -> Progress {
        let current = &self.files[self.index];
        Progress {
            id: self.id.clone(),
            space: self.space.clone(),
            name: current.name.clone(),
            total: current.size,
            sent: self.offset,
            state: state.into(),
            problem,
            saved_as: None,
            index: self.index + 1,
            count: self.files.len(),
            saved: self
                .files
                .iter()
                .filter_map(|f| f.saved_as.clone())
                .collect(),
            unsure: unsure(&self.files),
            maybe_arrived: self.start().maybe_done,
            kept: true,
        }
    }
}
/// Whether `path` names a file directly in `folder`, however either is spelled.
fn in_folder(path: &Path, folder: &Path) -> bool {
    let parent = path.parent().and_then(|p| p.canonicalize().ok());
    parent.is_some() && parent == folder.canonicalize().ok() && path.file_name().is_some()
}
/// The copies a record still needs: those of files that have not arrived.
fn copies(record: &Record) -> impl Iterator<Item = &Path> {
    record.files[record.index..]
        .iter()
        .filter(|f| f.temporary && f.saved_as.is_none() && !f.unsure)
        .map(|f| f.path.as_path())
}
fn unsure(files: &[Entry]) -> Vec<String> {
    files
        .iter()
        .filter(|f| f.unsure)
        .map(|f| f.name.clone())
        .collect()
}
fn nanos(time: Option<SystemTime>) -> Option<u128> {
    time.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
}

pub struct Sends {
    directory: PathBuf,
    job: Arc<Mutex<Option<Job>>>,
    record: Arc<Mutex<Option<Record>>>,
}
impl Sends {
    fn open(directory: PathBuf, picked: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&directory)?;
        let metadata = std::fs::symlink_metadata(&directory)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Invalid send records"
        );
        let record = load(&directory.join(RECORD), &picked);
        tidy_picked(&picked, record.as_ref());
        // A send the app closed during shows where it stopped.
        let job = record.as_ref().map(|record| Job {
            progress: record.progress("interrupted", None),
            cancel: watch::channel(false).0,
        });
        Ok(Self {
            directory,
            job: Arc::new(Mutex::new(job)),
            record: Arc::new(Mutex::new(record)),
        })
    }
    fn path(&self) -> PathBuf {
        self.directory.join(RECORD)
    }
    fn running(&self) -> bool {
        self.job
            .lock()
            .expect("send state")
            .as_ref()
            .is_some_and(|j| j.progress.state == "sending" || j.progress.state == "checking")
    }
}
/// The record a previous run left, if it can be continued. Anything else
/// there goes.
fn load(path: &Path, picked: &Path) -> Option<Record> {
    let _ = std::fs::remove_file(path.with_extension("json.tmp"));
    let loaded = (|| {
        let written = std::fs::symlink_metadata(path).ok()?;
        let fresh = written.modified().ok()?.elapsed().unwrap_or_default() < KEPT_FOR;
        let record = (written.is_file() && written.len() <= MAX_RECORD && fresh)
            .then(|| std::fs::read(path).ok())
            .flatten()
            .and_then(|bytes| serde_json::from_slice::<Record>(&bytes).ok())
            .filter(|record| record.check(picked).is_ok());
        Some(record)
    })();
    match loaded {
        Some(Some(record)) => Some(record),
        Some(None) => {
            discard(path, None);
            None
        }
        None => None,
    }
}
/// Copies of picked files the record no longer needs, left when the app
/// closed during a send or a share, go.
fn tidy_picked(picked: &Path, record: Option<&Record>) {
    let Ok(entries) = std::fs::read_dir(picked) else {
        return;
    };
    let needed: Vec<&std::ffi::OsStr> = record
        .map(|r| copies(r).filter_map(Path::file_name).collect())
        .unwrap_or_default();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_file = std::fs::symlink_metadata(&path).is_ok_and(|m| !m.is_dir());
        if is_file && !needed.contains(&entry.file_name().as_os_str()) {
            let _ = std::fs::remove_file(&path);
        }
    }
}
/// Write the record whole or not at all.
fn store(path: &Path, record: &Record) -> Result<()> {
    let pending = path.with_extension("json.tmp");
    let mut file = std::fs::File::create(&pending)?;
    file.write_all(&serde_json::to_vec(record)?)?;
    file.sync_all()?;
    std::fs::rename(&pending, path)?;
    Ok(())
}
/// Remove the record and the copies it kept.
fn discard(path: &Path, record: Option<&Record>) {
    let _ = std::fs::remove_file(path);
    for copy in record.into_iter().flat_map(copies) {
        let _ = std::fs::remove_file(copy);
    }
}
/// Change the record of send `id` and write it; a record that cannot be
/// written leaves the send running, only less able to continue.
fn remember(
    records: &Mutex<Option<Record>>,
    path: &Path,
    id: &str,
    change: impl FnOnce(&mut Record),
) {
    let mut records = records.lock().expect("send record");
    if let Some(record) = records.as_mut().filter(|r| r.id == id) {
        change(record);
        let _ = store(path, record);
    }
}
fn forget(records: &Mutex<Option<Record>>, path: &Path, id: &str) {
    let mut records = records.lock().expect("send record");
    if records.as_ref().is_some_and(|r| r.id == id) {
        discard(path, records.take().as_ref());
    }
}

/// Called with the exclusive transfer guard, after the device has stopped.
pub(crate) fn clear_network(state: &Sends) {
    state.job.lock().expect("send state").take();
    let record = state.record.lock().expect("send record").take();
    discard(&state.path(), record.as_ref());
}
/// A network left while the app was closed takes its unfinished send along.
pub(crate) fn clear_previous_network(app: &tauri::App) -> Result<()> {
    let directory = app.path().app_cache_dir()?.join("connect-sends");
    let picked = app.path().app_cache_dir()?.join("connect-picked");
    let record = load(&directory.join(RECORD), &picked);
    discard(&directory.join(RECORD), record.as_ref());
    tidy_picked(&picked, None);
    Ok(())
}
pub fn setup(app: &mut tauri::App) -> Result<()> {
    let cache = app.path().app_cache_dir()?;
    app.manage(Sends::open(
        cache.join("connect-sends"),
        cache.join("connect-picked"),
    )?);
    Ok(())
}
/// The send this device is running or left unfinished, for the home screen.
pub fn current(state: &Sends) -> Option<Progress> {
    state
        .job
        .lock()
        .expect("send state")
        .as_ref()
        .map(|j| j.progress.clone())
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
    modified: Option<SystemTime>,
    /// The digest the record kept: the file must still match it.
    sha256: Option<String>,
}
/// Open a file the record names again, as it was when chosen.
fn reopen(entry: &Entry) -> Result<Item> {
    let changed = || {
        format!(
            "{} is no longer where it was, or it changed since it was chosen. Discard this send and choose the files again.",
            entry.name
        )
    };
    let file = std::fs::File::open(&entry.path).with_context(changed)?;
    let metadata = file.metadata().with_context(changed)?;
    let modified = metadata.modified().ok();
    ensure!(
        metadata.is_file() && metadata.len() == entry.size && nanos(modified) == entry.modified,
        changed()
    );
    Ok(Item {
        file,
        name: entry.name.clone(),
        size: entry.size,
        modified,
        sha256: entry.sha256.clone(),
    })
}

/// The receiving device's session, asked again while this device's network
/// opens or the other device cannot be reached yet, for at most two minutes
/// or until the person stops waiting. Nothing has been sent while it waits.
async fn reach(
    app: &tauri::AppHandle,
    space: &str,
    wait: Option<String>,
) -> Result<
    (
        Arc<connect_core::session::SessionEndpoint>,
        connect_core::device::PairedDevice,
    ),
    String,
> {
    let mut wait = crate::waits::Wait::new(wait);
    let started = Instant::now();
    loop {
        // A pass that refreshes trust may save a renewal: it is never cut short.
        match crate::consumer::session(&app.state::<crate::desktop::DesktopState>(), Some(space))
            .await
        {
            Ok(found) => return Ok(found),
            Err(error) if started.elapsed() >= REACH_FOR || !waits_for(&error) => {
                return Err(error);
            }
            Err(_) => {}
        }
        for _ in 0..4 {
            if wait.stopped() {
                return Err(crate::waits::STOPPED.into());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}
/// Whether an error can pass by waiting: not a device without a network.
fn waits_for(error: &str) -> bool {
    !["Join your network first", "Add your other device first"].contains(&error)
}

/// Choose files with the native picker and send them into the inbox `space`,
/// one after another. Returns the job to follow, or none when the owner
/// cancels the picker. A file that fails stops the ones after it; what is
/// left can continue.
#[tauri::command]
pub async fn send_file(
    space: String,
    media: Option<bool>,
    wait: Option<String>,
    app: tauri::AppHandle,
) -> Result<Option<String>, String> {
    let network = app
        .state::<crate::desktop::DesktopState>()
        .transfers
        .clone()
        .try_read_owned()
        .map_err(|_| "This device is changing networks. Try again shortly.")?;
    let state = app.state::<Sends>();
    if state.running() {
        return Err("Finish or cancel the current send first.".into());
    }
    if state.record.lock().expect("send record").is_some() {
        return Err("Continue or discard the unfinished send first.".into());
    }
    // The device first: files are chosen once it can take them, and the
    // wait, if any, is never shown over the picker.
    let (session, peer) = reach(&app, &space, wait).await?;
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
            sha256: None,
        });
    }
    let id = uuid::Uuid::new_v4().to_string();
    let mut files = Vec::with_capacity(picked.len());
    for (one, item) in picked.into_iter().zip(&queue) {
        let (path, temporary) = one.keep();
        files.push(Entry {
            path: std::path::absolute(path).map_err(|e| e.to_string())?,
            name: item.name.clone(),
            size: item.size,
            modified: nanos(item.modified),
            temporary,
            sha256: None,
            saved_as: None,
            unsure: false,
        });
    }
    let record = Record {
        id: id.clone(),
        space: space.clone(),
        files,
        index: 0,
        token: None,
        offset: 0,
        pending: None,
    };
    let _ = store(&state.path(), &record);
    *state.record.lock().expect("send record") = Some(record.clone());
    begin(&app, record, queue, (session, peer), network);
    Ok(Some(id))
}
/// Continue a send that stopped, with the file it was sending; the files
/// that arrived are not sent again.
#[tauri::command]
pub async fn resume_send(
    id: String,
    wait: Option<String>,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let network = app
        .state::<crate::desktop::DesktopState>()
        .transfers
        .clone()
        .try_read_owned()
        .map_err(|_| "This device is changing networks. Try again shortly.")?;
    let state = app.state::<Sends>();
    if state.running() {
        return Err("Finish or cancel the current send first.".into());
    }
    let record = state
        .record
        .lock()
        .expect("send record")
        .clone()
        .filter(|r| r.id == id)
        .ok_or("This send is no longer available")?;
    let queue = record.files[record.index..]
        .iter()
        .map(reopen)
        .collect::<Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    let peer = reach(&app, &record.space, wait).await?;
    begin(&app, record, queue, peer, network);
    Ok(id)
}
/// Drop a send that stopped, and the copies it kept.
#[tauri::command]
pub fn discard_send(id: String, state: tauri::State<'_, Sends>) -> Result<(), String> {
    if state.running() {
        return Err("Cancel the current send first.".into());
    }
    forget(&state.record, &state.path(), &id);
    let mut job = state.job.lock().expect("send state");
    if job.as_ref().is_some_and(|j| j.progress.id == id) {
        job.take();
    }
    Ok(())
}

/// Send what is left of `record`, the files of `queue` in order, from where
/// the record says the first of them stands.
fn begin(
    app: &tauri::AppHandle,
    record: Record,
    queue: Vec<Item>,
    (session, peer): (
        Arc<connect_core::session::SessionEndpoint>,
        connect_core::device::PairedDevice,
    ),
    network: tokio::sync::OwnedRwLockReadGuard<()>,
) {
    let state = app.state::<Sends>();
    let (cancel, canceled) = watch::channel(false);
    let mut progress = record.progress("checking", None);
    progress.kept = false;
    *state.job.lock().expect("send state") = Some(Job { progress, cancel });
    let mut inbox = Peer {
        handle: app.clone(),
        space: record.space.clone(),
        session,
        peer,
    };
    let (jobs, records, path) = (state.job.clone(), state.record.clone(), state.path());
    tauri::async_runtime::spawn(async move {
        let _network = network;
        run(&mut inbox, &jobs, &records, &path, record, queue, canceled).await;
    });
}
async fn run(
    inbox: &mut impl Inbox,
    jobs: &Mutex<Option<Job>>,
    records: &Mutex<Option<Record>>,
    path: &Path,
    record: Record,
    queue: Vec<Item>,
    mut canceled: watch::Receiver<bool>,
) {
    let id = record.id.clone();
    let mut start = record.start();
    let mut outcome = Ok(());
    for (index, item) in (record.index..).zip(queue) {
        let name = item.name.clone();
        update(jobs, &id, |job| {
            job.progress.index = index + 1;
            job.progress.name = item.name.clone();
            job.progress.total = item.size;
            job.progress.sent = start.offset;
            job.progress.maybe_arrived = false;
            job.progress.state = "checking".into();
        });
        let sending = send_one(
            inbox,
            &record.space,
            jobs,
            &id,
            item,
            std::mem::take(&mut start),
            canceled.clone(),
            |step| {
                remember(records, path, &id, |r| match step {
                    Step::Digest(digest) => r.files[index].sha256 = Some(digest.to_owned()),
                    Step::Window { token, offset, end } => {
                        (r.token, r.offset, r.pending) =
                            (token.map(str::to_owned), offset, Some(end));
                    }
                    Step::Refused => r.pending = None,
                })
            },
        );
        let result = tokio::select! { biased;
            _ = canceled.changed() => Err(anyhow::anyhow!("Sending canceled")),
            result = sending => result,
        };
        match result {
            Ok(arrived) => {
                remember(records, path, &id, |r| {
                    let entry = &mut r.files[index];
                    match &arrived {
                        Arrived::Saved(saved_as) => entry.saved_as = Some(saved_as.clone()),
                        Arrived::Unsure => entry.unsure = true,
                    }
                    if entry.temporary {
                        let _ = std::fs::remove_file(&entry.path);
                    }
                    if index + 1 < r.files.len() {
                        (r.index, r.token, r.offset, r.pending) = (index + 1, None, 0, None);
                    }
                });
                update(jobs, &id, |job| match arrived {
                    Arrived::Saved(saved_as) => {
                        job.progress.saved.push(saved_as.clone());
                        job.progress.saved_as = Some(saved_as);
                    }
                    Arrived::Unsure => job.progress.unsure.push(name),
                });
            }
            Err(error) => {
                outcome = Err(error);
                break;
            }
        }
    }
    let stopped = *canceled.borrow();
    // A send that finished or was canceled has nothing to continue.
    if outcome.is_ok() || stopped {
        forget(records, path, &id);
    }
    let kept = records
        .lock()
        .expect("send record")
        .as_ref()
        .is_some_and(|r| r.id == id);
    update(jobs, &id, |job| {
        job.progress.kept = kept;
        match outcome {
            Ok(()) => job.progress.state = "complete".into(),
            Err(error) => {
                job.progress.state = if stopped { "canceled" } else { "failed" }.into();
                job.progress.problem = Some(error.to_string());
            }
        }
    });
}

/// Where windows go: the receiving device, or a stand-in in tests.
trait Inbox {
    async fn window(&mut self, request: &mut Request, file: &mut std::fs::File) -> Result<Outcome>;
    /// After a dropped connection: connect again, if the device can be found.
    async fn reconnect(&mut self);
    /// How long to wait before asking again.
    fn pause(&self, seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }
}
struct Peer {
    handle: tauri::AppHandle,
    space: String,
    session: Arc<connect_core::session::SessionEndpoint>,
    peer: connect_core::device::PairedDevice,
}
impl Inbox for Peer {
    async fn window(&mut self, request: &mut Request, file: &mut std::fs::File) -> Result<Outcome> {
        self.session
            .send_window_to(&self.peer.node, &self.peer.ticket, request, file)
            .await
    }
    async fn reconnect(&mut self) {
        if let Ok((session, peer)) = crate::consumer::session(
            &self.handle.state::<crate::desktop::DesktopState>(),
            Some(&self.space),
        )
        .await
        {
            (self.session, self.peer) = (session, peer);
        }
    }
}
/// Where a file's sending starts: from the beginning, or where a send that
/// stopped left it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Start {
    token: Option<String>,
    offset: u64,
    /// The window on its way when it stopped reached the end of the file.
    maybe_done: bool,
}
/// What sending one file came to.
#[derive(Debug, PartialEq, Eq)]
enum Arrived {
    Saved(String),
    /// It may have arrived, but the receiving device no longer says.
    Unsure,
}
/// What the record keeps as a file goes.
enum Step<'a> {
    Digest(&'a str),
    /// A window is about to go from `offset`, ending at `end`.
    Window {
        token: Option<&'a str>,
        offset: u64,
        end: u64,
    },
    /// The receiving device refused that window before any byte of it.
    Refused,
}

/// Send one file, window by window, and return what the receiving device
/// saved it as. After a dropped connection or a restart of either device the
/// same window is asked again, and the other device says where the file stands.
#[allow(clippy::too_many_arguments)]
async fn send_one(
    inbox: &mut impl Inbox,
    space: &str,
    jobs: &Mutex<Option<Job>>,
    task_id: &str,
    item: Item,
    start: Start,
    checking_cancel: watch::Receiver<bool>,
    mut keep: impl FnMut(Step<'_>),
) -> Result<Arrived> {
    let Item {
        file,
        name,
        size,
        modified,
        sha256,
    } = item;
    // A first window that reached the end may have saved the file, and only
    // the token it never learned could ask: sending it again could save a
    // second copy.
    if start.maybe_done && start.token.is_none() {
        update(jobs, task_id, |job| job.progress.maybe_arrived = true);
        return Ok(Arrived::Unsure);
    }
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
    if sha256.as_ref().is_some_and(|kept| *kept != digest) {
        bail!("{name} changed since it was chosen. Discard this send and choose the files again.");
    }
    keep(Step::Digest(&digest));
    update(jobs, task_id, |job| job.progress.state = "sending".into());
    let Start {
        mut token,
        mut offset,
        mut maybe_done,
    } = start;
    let mut length = MIN_WINDOW_BYTES;
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
        // Written before the window goes: if the app closes now, continuing
        // knows this window may have reached the other device.
        keep(Step::Window {
            token: token.as_deref(),
            offset,
            end: (offset + u64::from(length)).min(size),
        });
        // A busy inbox takes the window a little later; after a dropped
        // connection or a restart of either device, the same window is asked
        // again, with the token the other device named.
        let (mut waits, mut attempts) = (0, 0u32);
        let window = loop {
            match inbox.window(&mut request, &mut file).await {
                Ok(outcome) => break outcome,
                Err(error) if waits < 30 && error.to_string().contains("receiving other files") => {
                    waits += 1;
                    tokio::time::sleep(inbox.pause(2)).await;
                }
                // The other device checked the whole file and did not save
                // it. The same bytes cannot match again: nothing is asked or
                // sent a second time, and nothing of it may be there.
                Err(error) if error.is::<NotIntact>() => {
                    keep(Step::Refused);
                    bail!(
                        "{name} did not arrive intact, so the other device did not save it. It may have changed while it was being sent. Discard this send and choose the file again."
                    );
                }
                Err(error)
                    if attempts < 6 && !error.to_string().contains("isn't accepting files") =>
                {
                    attempts += 1;
                    tokio::time::sleep(inbox.pause(1 << attempts.min(5))).await;
                    inbox.reconnect().await;
                }
                Err(error) => {
                    if error.to_string().contains("isn't accepting files") {
                        keep(Step::Refused);
                    }
                    return Err(error);
                }
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
                return Ok(Arrived::Saved(saved_as));
            }
            // The other device holds the file up to here.
            Outcome::ContinueAt { token: kept, at } => {
                ensure!(continued < 32, "The other device does not take this file");
                continued += 1;
                maybe_done = false;
                token = Some(kept);
                offset = at;
                update(jobs, task_id, |job| job.progress.sent = offset);
                continue;
            }
            // It no longer has the transfer. A file whose last window may
            // have arrived is not sent again: it may be there.
            Outcome::StartOver if maybe_done => {
                update(jobs, task_id, |job| job.progress.maybe_arrived = true);
                return Ok(Arrived::Unsure);
            }
            // Otherwise once, from the start.
            Outcome::StartOver => {
                ensure!(
                    !started_over,
                    "The other device lost this file. Send it again."
                );
                started_over = true;
                (token, offset) = (None, 0);
                update(jobs, task_id, |job| job.progress.sent = 0);
                continue;
            }
        };
        maybe_done = false;
        offset += window.bytes as u64;
        token = Some(window.token);
        update(jobs, task_id, |job| job.progress.sent = offset);
        if window.done {
            return window
                .saved_as
                .map(Arrived::Saved)
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

#[cfg(test)]
mod tests;
