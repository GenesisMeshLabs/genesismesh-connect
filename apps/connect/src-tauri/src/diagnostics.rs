//! A small local record of what Connect's background loops did, so a stall can be
//! explained after the fact. Only the phone owner test build turns it on. It holds
//! timestamps, states and short error text: never keys, tokens or file contents.
//! The file stays on the device; nothing sends it anywhere.

use std::{
    collections::HashMap,
    fmt::Display,
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

/// One file of about this size is kept, and one previous file.
const LIMIT: u64 = 256 * 1024;
const DETAIL: usize = 240;
/// Unchanged loops still say they are alive this often.
pub(crate) const HEARTBEAT: Duration = Duration::from_secs(600);

static FILE: OnceLock<PathBuf> = OnceLock::new();
static WRITING: Mutex<()> = Mutex::new(());

/// Start recording into `directory`, including any panic in any thread: a
/// panicking task otherwise ends without a trace while the process runs on.
#[cfg_attr(
    not(all(target_os = "android", feature = "android-owner-qualification")),
    allow(dead_code)
)]
pub(crate) fn start(directory: &Path) {
    if std::fs::create_dir_all(directory).is_err()
        || FILE.set(directory.join("events.log")).is_err()
    {
        return;
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let place = info
            .location()
            .map(|at| format!("{}:{}", at.file(), at.line()))
            .unwrap_or_default();
        let text = info
            .payload()
            .downcast_ref::<&str>()
            .map(|text| (*text).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        // A panic while writing must not wait for the lock it holds.
        if let Ok(_turn) = WRITING.try_lock()
            && let Some(path) = FILE.get()
        {
            append(path, &line("panic", format!("{place} {text}"), now()));
        }
        previous(info);
    }));
    note("start", format_args!("process {}", std::process::id()));
}

/// Record one event. Does nothing until [`start`] has run.
pub(crate) fn note(kind: &str, detail: impl Display) {
    let Some(path) = FILE.get() else {
        return;
    };
    let Ok(_turn) = WRITING.lock() else {
        return;
    };
    append(path, &line(kind, detail.to_string(), now()));
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn line(kind: &str, detail: String, at: String) -> String {
    let mut detail = detail.replace(['\n', '\r'], " ");
    if let Some((cut, _)) = detail.char_indices().nth(DETAIL) {
        detail.truncate(cut);
        detail.push('…');
    }
    format!("{at} {kind} {detail}\n")
}

fn append(path: &Path, line: &str) {
    if std::fs::metadata(path).is_ok_and(|file| file.len() > LIMIT) {
        let _ = std::fs::rename(path, path.with_extension("1.log"));
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = file.write_all(line.as_bytes());
    }
}

/// Remembers the last value of each state a loop reports, so only changes and
/// a periodic heartbeat are written.
pub(crate) struct Changes {
    loop_name: &'static str,
    last: HashMap<&'static str, String>,
    since: HashMap<&'static str, Instant>,
    beat: Option<Instant>,
}

impl Changes {
    pub(crate) fn new(loop_name: &'static str) -> Self {
        Self {
            loop_name,
            last: HashMap::new(),
            since: HashMap::new(),
            beat: None,
        }
    }

    /// Note each state whose value changed, and a heartbeat with every state and
    /// how long it has held when nothing changed for [`HEARTBEAT`].
    pub(crate) fn report(&mut self, states: &[(&'static str, String)], now: Instant) {
        for line in self.lines(states, now) {
            note(self.loop_name, line);
        }
    }

    fn lines(&mut self, states: &[(&'static str, String)], now: Instant) -> Vec<String> {
        let mut lines = Vec::new();
        for (key, value) in states {
            if self.last.get(key) != Some(value) {
                lines.push(format!("{key}={value}"));
                self.last.insert(key, value.clone());
                self.since.insert(key, now);
            }
        }
        if !lines.is_empty() {
            self.beat = Some(now);
        } else if self
            .beat
            .is_none_or(|at| now.duration_since(at) >= HEARTBEAT)
        {
            self.beat = Some(now);
            let held = states
                .iter()
                .map(|(key, value)| {
                    let age = self
                        .since
                        .get(key)
                        .map_or(0, |at| now.duration_since(*at).as_secs());
                    format!("{key}={value} ({age}s)")
                })
                .collect::<Vec<_>>()
                .join(" ");
            lines.push(format!("alive {held}"));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn states(controller: &str, refresh: &str) -> Vec<(&'static str, String)> {
        vec![
            ("controller", controller.into()),
            ("refresh", refresh.into()),
        ]
    }

    #[test]
    fn only_changes_and_a_heartbeat_are_written() {
        let start = Instant::now();
        let mut seen = Changes::new("maintenance");
        assert_eq!(
            seen.lines(&states("yes", "ok"), start),
            ["controller=yes", "refresh=ok"]
        );
        assert!(
            seen.lines(&states("yes", "ok"), start + Duration::from_secs(30))
                .is_empty()
        );
        assert_eq!(
            seen.lines(
                &states("yes", "failed: busy"),
                start + Duration::from_secs(60)
            ),
            ["refresh=failed: busy"]
        );
        assert!(
            seen.lines(
                &states("yes", "failed: busy"),
                start + Duration::from_secs(599)
            )
            .is_empty()
        );
        assert_eq!(
            seen.lines(
                &states("yes", "failed: busy"),
                start + Duration::from_secs(660)
            ),
            ["alive controller=yes (660s) refresh=failed: busy (600s)"]
        );
        assert!(
            seen.lines(
                &states("yes", "failed: busy"),
                start + Duration::from_secs(690)
            )
            .is_empty()
        );
    }

    #[test]
    fn a_line_is_one_line_and_bounded() {
        let long = format!("first\nsecond {}", "é".repeat(400));
        let written = line("refresh", long, "2026-11-08T00:00:00Z".into());
        assert_eq!(written.matches('\n').count(), 1);
        assert!(written.starts_with("2026-11-08T00:00:00Z refresh first second é"));
        assert!(written.trim_end().ends_with('…'));
        assert!(written.chars().count() < DETAIL + 50);
    }

    #[test]
    fn a_full_file_moves_aside_once() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("events.log");
        std::fs::write(&path, vec![b'x'; LIMIT as usize + 1]).unwrap();
        append(&path, "next\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "next\n");
        assert_eq!(
            std::fs::metadata(folder.path().join("events.1.log"))
                .unwrap()
                .len(),
            LIMIT + 1
        );
    }
}
