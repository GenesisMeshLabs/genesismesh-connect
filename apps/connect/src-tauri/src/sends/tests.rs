//! A send stopped by an app that closed, continued after a restart: against a
//! stand-in for the receiving device that keeps unfinished files and
//! remembers saved ones, as the real inbox does.
use super::*;
use connect_core::session::sharing::send::Window;
use std::{
    collections::BTreeMap,
    io::{Seek, SeekFrom},
};
use tokio::sync::oneshot;

/// The receiving device, as far as a sender can tell.
#[derive(Default)]
struct Stand {
    /// Unfinished files by token: name, size and the bytes so far.
    staged: BTreeMap<String, (String, u64, Vec<u8>)>,
    /// Saved files by token, while remembered.
    saved: BTreeMap<String, String>,
    /// Every file saved, in order, with its bytes.
    names: Vec<(String, Vec<u8>)>,
    windows: usize,
    /// After this many windows, the app closes while the answer is on its
    /// way: the window arrived, the sender never hears.
    close_at: Option<usize>,
    closed: Option<oneshot::Sender<()>>,
    refuse: bool,
    /// The file changes under the send: what arrives does not match the
    /// SHA-256 the sender declared.
    spoiled: bool,
}
impl Inbox for Stand {
    async fn window(&mut self, request: &mut Request, file: &mut std::fs::File) -> Result<Outcome> {
        if self.refuse {
            bail!("This device isn't accepting files from you.");
        }
        let token = match &request.token {
            None => {
                assert_eq!(request.offset, 0);
                if let Some((token, (_, _, bytes))) =
                    self.staged.iter().find(|(_, (name, size, _))| {
                        *name == request.file_name && *size == request.size
                    })
                {
                    return Ok(Outcome::ContinueAt {
                        token: token.clone(),
                        at: bytes.len() as u64,
                    });
                }
                let token = uuid::Uuid::new_v4().to_string();
                self.staged.insert(
                    token.clone(),
                    (request.file_name.clone(), request.size, Vec::new()),
                );
                token
            }
            Some(token) => match self.staged.get(token) {
                Some((_, _, bytes)) if bytes.len() as u64 != request.offset => {
                    return Ok(Outcome::ContinueAt {
                        token: token.clone(),
                        at: bytes.len() as u64,
                    });
                }
                Some(_) => token.clone(),
                None => {
                    return Ok(match self.saved.get(token) {
                        Some(saved_as) => Outcome::Saved {
                            saved_as: saved_as.clone(),
                        },
                        None => Outcome::StartOver,
                    });
                }
            },
        };
        let count = u64::from(request.length).min(request.size - request.offset) as usize;
        let mut bytes = vec![0; count];
        file.seek(SeekFrom::Start(request.offset))?;
        file.read_exact(&mut bytes)?;
        let staged = self.staged.get_mut(&token).expect("staged");
        staged.2.extend_from_slice(&bytes);
        let done = staged.2.len() as u64 == request.size;
        let mut saved_as = None;
        if done && self.spoiled {
            // As the receiving device does: nothing saved, nothing kept.
            self.staged.remove(&token);
            self.windows += 1;
            return Err(connect_core::session::sharing::send::NotIntact.into());
        }
        if done {
            let (name, _, bytes) = self.staged.remove(&token).expect("staged");
            let digest: String = Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(digest, request.sha256, "Only a whole file is saved");
            let copies = self
                .names
                .iter()
                .filter(|(n, _)| *n == name || n.starts_with(&format!("{name} (")))
                .count();
            let name = if copies == 0 {
                name
            } else {
                format!("{name} ({})", copies + 1)
            };
            self.saved.insert(token.clone(), name.clone());
            self.names.push((name.clone(), bytes));
            saved_as = Some(name);
        }
        self.windows += 1;
        if self.close_at == Some(self.windows) {
            if let Some(closed) = self.closed.take() {
                let _ = closed.send(());
            }
            std::future::pending::<()>().await;
        }
        Ok(Outcome::Sent(Window {
            token,
            bytes: count,
            done,
            saved_as,
        }))
    }
    async fn reconnect(&mut self) {}
    fn pause(&self, _: u64) -> Duration {
        Duration::ZERO
    }
}
impl Stand {
    fn saved_names(&self) -> Vec<&str> {
        self.names.iter().map(|(n, _)| n.as_str()).collect()
    }
    /// A receiving device that restarted an hour later: unfinished files
    /// and what it saved are no longer known.
    fn forget(&mut self) {
        self.staged.clear();
        self.saved.clear();
    }
}

struct Device {
    _root: tempfile::TempDir,
    folder: PathBuf,
    picked: PathBuf,
    path: PathBuf,
}
fn device() -> Result<Device> {
    let root = tempfile::tempdir()?;
    let folder = root.path().join("files");
    let picked = root.path().join("connect-picked");
    let sends = root.path().join("connect-sends");
    for directory in [&folder, &picked, &sends] {
        std::fs::create_dir_all(directory)?;
    }
    Ok(Device {
        folder,
        picked,
        path: sends.join(RECORD),
        _root: root,
    })
}
fn bytes(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}
fn entry(folder: &Path, name: &str, content: &[u8], temporary: bool) -> Result<Entry> {
    let path = folder.join(name);
    std::fs::write(&path, content)?;
    Ok(Entry {
        path,
        name: name.into(),
        size: content.len() as u64,
        modified: nanos(std::fs::metadata(folder.join(name))?.modified().ok()),
        temporary,
        sha256: None,
        saved_as: None,
        unsure: false,
    })
}
fn record(files: Vec<Entry>) -> Record {
    Record {
        id: uuid::Uuid::new_v4().to_string(),
        space: "inbox".into(),
        files,
        index: 0,
        token: None,
        offset: 0,
        pending: None,
    }
}
/// What a send of `record` came to, run as the app runs it: from where the
/// record stands, with the files it names opened again.
async fn send(
    device: &Device,
    stand: &mut Stand,
    record: Record,
    cancel: bool,
) -> Result<(Option<Progress>, Option<Record>)> {
    let queue = record.files[record.index..]
        .iter()
        .map(reopen)
        .collect::<Result<Vec<_>>>()?;
    let mut progress = record.progress("checking", None);
    progress.kept = false;
    let (sender, canceled) = watch::channel(false);
    let jobs = Mutex::new(Some(Job {
        progress,
        cancel: sender,
    }));
    if cancel {
        jobs.lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .cancel
            .send_replace(true);
    }
    let _ = store(&device.path, &record);
    let records = Mutex::new(Some(record.clone()));
    let (closed, mut closing) = oneshot::channel();
    stand.closed = Some(closed);
    let running = run(
        stand,
        &jobs,
        &records,
        &device.path,
        record,
        queue,
        canceled,
    );
    let finished = tokio::select! {
        () = running => true,
        _ = &mut closing => false,
    };
    let progress = jobs.lock().unwrap().take().map(|j| j.progress);
    let kept = records.lock().unwrap().take();
    Ok((finished.then_some(progress).flatten(), kept))
}
/// The app opens again and finds what the closed one left.
fn restart(device: &Device) -> Option<Record> {
    let record = load(&device.path, &device.picked);
    tidy_picked(&device.picked, record.as_ref());
    record
}

#[tokio::test]
async fn a_send_the_app_closed_during_continues_where_it_stopped_and_sends_nothing_twice()
-> Result<()> {
    let device = device()?;
    let (a, b, c) = (bytes(100_000, 1), bytes(614_400, 2), bytes(10_000, 3));
    let files = vec![
        entry(&device.folder, "a.bin", &a, false)?,
        entry(&device.folder, "b.bin", &b, false)?,
        entry(&device.folder, "c.bin", &c, false)?,
    ];
    // a takes two windows; the app closes after b's second arrived.
    let mut stand = Stand {
        close_at: Some(4),
        ..Default::default()
    };
    let (finished, _) = send(&device, &mut stand, record(files), false).await?;
    assert!(finished.is_none(), "The app closed");
    assert_eq!(stand.saved_names(), ["a.bin"]);

    let left = restart(&device).expect("The send is kept");
    let shown = left.progress("interrupted", None);
    assert_eq!(
        (
            shown.index,
            shown.count,
            shown.name.as_str(),
            shown.saved.clone()
        ),
        (2, 3, "b.bin", vec!["a.bin".to_owned()]),
        "It says which files arrived and which one it was sending"
    );
    assert_eq!(
        (shown.sent, shown.total, shown.maybe_arrived, shown.kept),
        (65_536, 614_400, false, true),
        "At least what the receiving device confirmed, never more"
    );
    assert_eq!(shown.state, "interrupted");

    stand.close_at = None;
    let (finished, kept) = send(&device, &mut stand, left, false).await?;
    let finished = finished.expect("Finished");
    assert_eq!(finished.state, "complete");
    assert_eq!(finished.saved, ["a.bin", "b.bin", "c.bin"]);
    assert!(finished.unsure.is_empty() && !finished.kept);
    assert_eq!(
        stand.saved_names(),
        ["a.bin", "b.bin", "c.bin"],
        "Each file once"
    );
    assert_eq!(
        stand.names[1].1, b,
        "b continued from the bytes already there"
    );
    assert!(
        kept.is_none() && !device.path.exists(),
        "Nothing is left to continue"
    );
    assert!(restart(&device).is_none());
    Ok(())
}

#[tokio::test]
async fn a_file_whose_last_window_may_have_arrived_is_asked_about_not_sent_again() -> Result<()> {
    for forgotten in [false, true] {
        let device = device()?;
        let content = bytes(100_000, 4);
        let files = vec![entry(&device.folder, "report.pdf", &content, false)?];
        let mut stand = Stand {
            close_at: Some(2),
            ..Default::default()
        };
        send(&device, &mut stand, record(files), false).await?;
        assert_eq!(
            stand.saved_names(),
            ["report.pdf"],
            "It arrived; the sender never heard"
        );

        let left = restart(&device).expect("The send is kept");
        let shown = left.progress("interrupted", None);
        assert!(shown.maybe_arrived, "It may have arrived");
        assert!(shown.saved.is_empty() && shown.sent == 65_536);
        if forgotten {
            stand.forget();
        }
        stand.close_at = None;
        let (finished, _) = send(&device, &mut stand, left, false).await?;
        let finished = finished.expect("Finished");
        assert_eq!(finished.state, "complete");
        assert_eq!(stand.saved_names(), ["report.pdf"], "Never a second copy");
        if forgotten {
            assert_eq!(finished.unsure, ["report.pdf"], "It says it cannot tell");
            assert!(finished.saved.is_empty());
        } else {
            assert_eq!(
                finished.saved,
                ["report.pdf"],
                "The receiving device said where it went"
            );
            assert!(finished.unsure.is_empty());
        }
        assert!(!device.path.exists());
    }
    Ok(())
}

#[tokio::test]
async fn a_small_file_cut_off_in_its_first_window_is_not_sent_again() -> Result<()> {
    let device = device()?;
    let (small, next) = (bytes(10_000, 5), bytes(20_000, 6));
    let files = vec![
        entry(&device.folder, "note.txt", &small, false)?,
        entry(&device.folder, "photo.jpg", &next, false)?,
    ];
    let mut stand = Stand {
        close_at: Some(1),
        ..Default::default()
    };
    send(&device, &mut stand, record(files), false).await?;
    let left = restart(&device).expect("The send is kept");
    assert!(left.progress("interrupted", None).maybe_arrived);
    stand.close_at = None;
    let (finished, _) = send(&device, &mut stand, left, false).await?;
    let finished = finished.expect("Finished");
    assert_eq!(
        finished.unsure,
        ["note.txt"],
        "Only its sender's lost token could ask"
    );
    assert_eq!(finished.saved, ["photo.jpg"], "The rest still goes");
    assert_eq!(
        stand.saved_names(),
        ["note.txt", "photo.jpg"],
        "Never a second copy"
    );
    Ok(())
}

#[tokio::test]
async fn a_file_the_receiving_device_lost_partway_is_sent_again_from_the_start() -> Result<()> {
    let device = device()?;
    let content = bytes(614_400, 7);
    let files = vec![entry(&device.folder, "video.mp4", &content, false)?];
    let mut stand = Stand {
        close_at: Some(2),
        ..Default::default()
    };
    send(&device, &mut stand, record(files), false).await?;
    let left = restart(&device).expect("The send is kept");
    assert!(!left.progress("interrupted", None).maybe_arrived);
    stand.forget();
    stand.close_at = None;
    let (finished, _) = send(&device, &mut stand, left, false).await?;
    assert_eq!(finished.expect("Finished").saved, ["video.mp4"]);
    assert_eq!(stand.names, [("video.mp4".to_owned(), content)]);
    Ok(())
}

#[tokio::test]
async fn a_failed_send_stays_to_continue_and_a_canceled_one_goes() -> Result<()> {
    let device = device()?;
    let content = bytes(1_000, 8);
    let copy = entry(&device.picked, "copy.jpg", &content, true)?;
    let mut stand = Stand {
        refuse: true,
        ..Default::default()
    };
    let (failed, kept) = send(&device, &mut stand, record(vec![copy.clone()]), false).await?;
    let failed = failed.expect("Finished");
    assert_eq!(failed.state, "failed");
    assert!(
        failed.kept
            && failed
                .problem
                .as_deref()
                .is_some_and(|p| p.contains("isn't accepting"))
    );
    let kept = kept.expect("Kept to continue");
    assert!(
        !kept.progress("failed", None).maybe_arrived,
        "Refused before any byte: it did not arrive"
    );
    assert!(copy.path.exists(), "The phone's copy stays for continuing");
    assert_eq!(
        restart(&device).as_ref(),
        Some(&kept),
        "And after a restart"
    );

    stand.refuse = false;
    let (canceled, left) = send(&device, &mut stand, kept, true).await?;
    let canceled = canceled.expect("Finished");
    assert_eq!(canceled.state, "canceled");
    assert!(!canceled.kept && left.is_none() && !device.path.exists());
    assert!(!copy.path.exists(), "Its copy goes with it");
    assert!(stand.names.is_empty());
    Ok(())
}

/// A file whose bytes do not match what was declared used to be asked again,
/// sent a second time from the start, and then reported as "The other device
/// lost this file".
#[tokio::test]
async fn a_file_that_did_not_arrive_intact_is_refused_once_and_says_what_to_do() -> Result<()> {
    let device = device()?;
    let content = bytes(200_000, 21);
    let file = entry(&device.folder, "report.pdf", &content, false)?;
    let mut stand = Stand {
        spoiled: true,
        ..Default::default()
    };
    let (failed, kept) = send(&device, &mut stand, record(vec![file]), false).await?;
    let failed = failed.expect("Finished");
    assert_eq!(failed.state, "failed");
    assert_eq!(
        failed.problem.as_deref(),
        Some(
            "report.pdf did not arrive intact, so the other device did not save it. It may have changed while it was being sent. Discard this send and choose the file again."
        )
    );
    let once = content
        .len()
        .div_ceil(connect_core::session::sharing::send::MIN_WINDOW_BYTES as usize);
    assert!(
        stand.windows <= once,
        "Sent once, never again: {} windows for a file of at most {once}",
        stand.windows
    );
    assert!(
        stand.names.is_empty() && stand.staged.is_empty(),
        "Nothing saved or kept there"
    );
    let kept = kept.expect("Kept, for the person to discard");
    assert!(
        failed.kept && !kept.progress("failed", None).maybe_arrived,
        "It did not arrive: nothing says it may be there"
    );
    Ok(())
}

#[tokio::test]
async fn a_phone_copy_goes_once_its_file_arrived() -> Result<()> {
    let device = device()?;
    let first = entry(&device.picked, "first.jpg", &bytes(2_000, 9), true)?;
    let second = entry(&device.picked, "second.jpg", &bytes(200_000, 10), true)?;
    let mut stand = Stand {
        close_at: Some(2),
        ..Default::default()
    };
    send(
        &device,
        &mut stand,
        record(vec![first.clone(), second.clone()]),
        false,
    )
    .await?;
    assert!(!first.path.exists(), "It arrived: its copy went");
    assert!(second.path.exists(), "Still needed");
    // Left by a share the app closed during.
    std::fs::write(device.picked.join("orphan.jpg"), b"x")?;
    let left = restart(&device).expect("The send is kept");
    assert!(!device.picked.join("orphan.jpg").exists() && second.path.exists());
    stand.close_at = None;
    send(&device, &mut stand, left, false).await?;
    assert!(!second.path.exists());
    assert_eq!(stand.saved_names(), ["first.jpg", "second.jpg"]);
    Ok(())
}

#[test]
fn a_file_that_changed_or_went_is_not_continued() -> Result<()> {
    let device = device()?;
    let kept = entry(&device.folder, "plan.pdf", &bytes(5_000, 11), false)?;
    assert!(reopen(&kept).is_ok());
    std::fs::write(&kept.path, bytes(5_001, 11))?;
    let error = reopen(&kept).err().expect("Changed").to_string();
    assert!(
        error.contains("plan.pdf") && error.contains("choose the files again"),
        "{error}"
    );
    std::fs::remove_file(&kept.path)?;
    assert!(reopen(&kept).is_err(), "Gone");
    Ok(())
}

#[tokio::test]
async fn a_file_whose_bytes_changed_is_not_continued() -> Result<()> {
    let device = device()?;
    let content = bytes(614_400, 12);
    let files = vec![entry(&device.folder, "same-size.bin", &content, false)?];
    let mut stand = Stand {
        close_at: Some(2),
        ..Default::default()
    };
    send(&device, &mut stand, record(files), false).await?;
    let mut left = restart(&device).expect("Kept");
    assert!(left.files[0].sha256.is_some(), "Its digest was kept");
    // Same size and time, different bytes: only the digest shows it.
    left.files[0].sha256 = Some("0".repeat(64));
    stand.close_at = None;
    let (finished, kept) = send(&device, &mut stand, left, false).await?;
    let finished = finished.expect("Finished");
    assert_eq!(finished.state, "failed");
    assert!(
        finished
            .problem
            .unwrap()
            .contains("changed since it was chosen")
    );
    assert!(kept.is_some(), "Kept to discard");
    Ok(())
}

#[test]
fn only_a_record_that_makes_sense_is_continued() -> Result<()> {
    let device = device()?;
    let one = entry(&device.folder, "one.txt", b"one", false)?;
    let two = entry(&device.folder, "two.txt", b"two", false)?;
    let good = record(vec![one.clone(), two.clone()]);
    let mut wrong = Vec::new();
    let mut past = good.clone();
    past.index = 2;
    wrong.push(past);
    let mut skipped = good.clone();
    skipped.index = 1;
    wrong.push(skipped);
    let mut beyond = good.clone();
    beyond.offset = 4;
    wrong.push(beyond);
    let mut relative = good.clone();
    relative.files[0].path = PathBuf::from("one.txt");
    wrong.push(relative);
    // A copy outside the picked folder would never be removed by this app.
    let mut outside = good.clone();
    outside.files[1].temporary = true;
    wrong.push(outside);
    let mut name = good.clone();
    name.files[0].name = "../one.txt".into();
    wrong.push(name);
    for record in wrong {
        store(&device.path, &record)?;
        assert!(restart(&device).is_none(), "{record:?}");
        assert!(!device.path.exists(), "It goes");
        assert!(
            one.path.exists() && two.path.exists(),
            "Never a file it names"
        );
    }
    for junk in [b"{".to_vec(), vec![b' '; MAX_RECORD as usize + 1]] {
        std::fs::write(&device.path, junk)?;
        assert!(restart(&device).is_none() && !device.path.exists());
    }
    store(&device.path, &good)?;
    std::fs::File::options()
        .write(true)
        .open(&device.path)?
        .set_modified(SystemTime::now() - KEPT_FOR)?;
    assert!(restart(&device).is_none(), "Forgotten after a week");
    store(&device.path, &good)?;
    assert_eq!(restart(&device), Some(good));
    Ok(())
}

#[test]
fn a_send_waits_while_the_network_opens_but_not_without_one() {
    // Right after a restart the network computer's authority is still starting.
    assert!(waits_for("Authority unavailable"));
    assert!(waits_for("The other device did not respond"));
    assert!(!waits_for("Join your network first"));
    assert!(!waits_for("Add your other device first"));
    assert_eq!(REACH_FOR, Duration::from_secs(120), "As long as reads wait");
}
