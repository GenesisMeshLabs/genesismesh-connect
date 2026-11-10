//! Access requests that devices and agents send to the network computer: what
//! they need and why, in their own words, for the owner to answer on screen.
//! A request grants nothing. The owner answers by sharing something with the
//! device, or declines it; either way it leaves the list. Waiting requests are
//! kept in a file beside the network, so they survive the app being ended in
//! the background or restarted, until answered or a day old.
use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// At most this many requests wait at once; one per device.
pub const MAX_WAITING: usize = 16;
/// The longest request, in characters.
pub const MAX_TEXT: usize = 280;
/// A request nobody answered is dropped after this long.
const KEPT_HOURS: i64 = 24;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ask {
    pub id: String,
    pub node: String,
    pub text: String,
    pub at: DateTime<Utc>,
}

/// A request's text: trimmed, 1 to 280 characters, no control characters.
pub fn text(value: &str) -> Result<String> {
    let value = value.trim();
    ensure!(
        (1..=MAX_TEXT).contains(&value.chars().count()) && !value.chars().any(char::is_control),
        "Describe what you need in 1 to 280 characters"
    );
    Ok(value.to_owned())
}

/// The largest request file read back: 16 requests of 280 characters.
const MAX_FILE: u64 = 64 * 1024;

#[derive(Default)]
pub struct Asks {
    waiting: Vec<Ask>,
    /// Where the waiting requests are kept; none keeps them in memory only.
    file: Option<PathBuf>,
}

impl Asks {
    /// The requests kept at `file`, without those older than a day. A missing,
    /// oversized or unreadable file starts an empty list; it is replaced at the
    /// next change.
    pub fn open(file: &Path) -> Self {
        let waiting = std::fs::File::open(file)
            .ok()
            .filter(|f| f.metadata().is_ok_and(|m| m.len() <= MAX_FILE))
            .and_then(|f| serde_json::from_reader::<_, Vec<Ask>>(f).ok())
            .unwrap_or_default()
            .into_iter()
            .filter(|ask| text(&ask.text).is_ok())
            .take(MAX_WAITING)
            .collect();
        let mut asks = Self {
            waiting,
            file: Some(file.to_owned()),
        };
        asks.expire(Utc::now());
        asks
    }

    /// Write the list beside its file and move it into place, so a crash
    /// leaves the previous list or the new one, never half of one.
    fn keep(&self) {
        let Some(file) = &self.file else { return };
        let written = (|| {
            let partial = file.with_extension("partial");
            std::fs::write(&partial, serde_json::to_vec(&self.waiting)?)?;
            std::fs::rename(&partial, file)?;
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(problem) = written {
            // Requests still work in memory; they would only be lost at a restart.
            eprintln!("Waiting requests were not saved: {problem:#}");
        }
    }

    /// Keep a device's request; a newer one replaces its earlier one.
    pub fn add(&mut self, node: &str, value: &str, now: DateTime<Utc>) -> Result<String> {
        let value = text(value)?;
        self.expire(now);
        self.waiting.retain(|ask| ask.node != node);
        ensure!(
            self.waiting.len() < MAX_WAITING,
            "Too many requests are waiting for the owner. Ask again later."
        );
        let id = uuid::Uuid::new_v4().to_string();
        self.waiting.push(Ask {
            id: id.clone(),
            node: node.to_owned(),
            text: value,
            at: now,
        });
        self.keep();
        Ok(id)
    }

    /// [`Asks::add`] at the current time.
    pub fn add_now(&mut self, node: &str, value: &str) -> Result<String> {
        self.add(node, value, Utc::now())
    }

    /// [`Asks::waiting`] at the current time.
    pub fn waiting_now(&mut self) -> Vec<Ask> {
        self.waiting(Utc::now())
    }

    /// The requests still waiting, oldest first.
    pub fn waiting(&mut self, now: DateTime<Utc>) -> Vec<Ask> {
        self.expire(now);
        self.waiting.clone()
    }

    /// Answer a request: it leaves the list. `None` if it already left.
    pub fn close(&mut self, id: &str) -> Option<Ask> {
        let index = self.waiting.iter().position(|ask| ask.id == id)?;
        let ask = self.waiting.remove(index);
        self.keep();
        Some(ask)
    }

    /// Drop the request of a device that left the network.
    pub fn forget(&mut self, node: &str) {
        let before = self.waiting.len();
        self.waiting.retain(|ask| ask.node != node);
        if self.waiting.len() != before {
            self.keep();
        }
    }

    fn expire(&mut self, now: DateTime<Utc>) {
        let before = self.waiting.len();
        self.waiting
            .retain(|ask| now - ask.at < Duration::hours(KEPT_HOURS));
        if self.waiting.len() != before {
            self.keep();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_waiting_request_per_device_bounded_and_dropped_after_a_day() {
        let now = Utc::now();
        let mut asks = Asks::default();
        let first = asks
            .add("agent", "  The 2025 tax papers, for the summary ", now)
            .unwrap();
        assert_eq!(
            asks.waiting(now)[0].text,
            "The 2025 tax papers, for the summary"
        );
        let second = asks.add("agent", "Only the receipts, please", now).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            asks.waiting(now).len(),
            1,
            "A newer request replaces the earlier one"
        );
        for n in 1..MAX_WAITING {
            asks.add(&format!("device {n}"), "Holiday photos", now)
                .unwrap();
        }
        assert!(asks.add("one more", "Anything", now).is_err());
        assert!(asks.close(&second).is_some());
        assert!(asks.close(&second).is_none(), "An answered request is gone");
        asks.forget("device 1");
        assert_eq!(asks.waiting(now).len(), MAX_WAITING - 2);
        let later = now + Duration::hours(KEPT_HOURS);
        assert!(asks.waiting(later).is_empty());
    }

    #[test]
    fn waiting_requests_survive_a_restart_until_answered_or_a_day_old() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("asks.json");
        let now = Utc::now();
        let mut asks = Asks::open(&file);
        assert!(asks.waiting(now).is_empty(), "No file yet: nothing waits");
        let kept = asks.add("agent", "The 2025 tax papers", now).unwrap();
        let answered = asks.add("tablet", "Holiday photos", now).unwrap();
        asks.close(&answered);
        // The app ends and starts again.
        let mut reopened = Asks::open(&file);
        let waiting = reopened.waiting(now);
        assert_eq!(waiting.len(), 1);
        assert_eq!(
            (waiting[0].id.as_str(), waiting[0].node.as_str()),
            (kept.as_str(), "agent")
        );
        // A request a day old is gone after the next start, and the file says so.
        let mut old = Asks::open(&file);
        old.waiting.push(Ask {
            id: "old".into(),
            node: "laptop".into(),
            text: "Something from yesterday".into(),
            at: now - Duration::hours(KEPT_HOURS + 1),
        });
        old.keep();
        assert_eq!(Asks::open(&file).waiting(now).len(), 1);
        // A device that left takes its request with it, also on disk.
        reopened.forget("agent");
        assert!(Asks::open(&file).waiting(now).is_empty());
        // A damaged file starts an empty list.
        std::fs::write(&file, b"{not json").unwrap();
        assert!(Asks::open(&file).waiting(now).is_empty());
    }

    #[test]
    fn request_text_is_bounded_and_plain() {
        assert!(text("").is_err());
        assert!(text("   ").is_err());
        assert!(text(&"x".repeat(MAX_TEXT + 1)).is_err());
        assert!(text("line one\nline two").is_err());
        assert_eq!(
            text(&"é".repeat(MAX_TEXT)).unwrap().chars().count(),
            MAX_TEXT
        );
    }
}
