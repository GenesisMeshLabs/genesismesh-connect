//! Access requests that devices and agents send to the network computer: what
//! they need and why, in their own words, for the owner to answer on screen.
//! A request grants nothing. The owner answers by sharing something with the
//! device, or declines it; either way it leaves the list.
use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

/// At most this many requests wait at once; one per device.
pub const MAX_WAITING: usize = 16;
/// The longest request, in characters.
pub const MAX_TEXT: usize = 280;
/// A request nobody answered is dropped after this long.
const KEPT_HOURS: i64 = 24;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
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

#[derive(Default)]
pub struct Asks {
    waiting: Vec<Ask>,
}

impl Asks {
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
        Some(self.waiting.remove(index))
    }

    /// Drop the request of a device that left the network.
    pub fn forget(&mut self, node: &str) {
        self.waiting.retain(|ask| ask.node != node);
    }

    fn expire(&mut self, now: DateTime<Utc>) {
        self.waiting
            .retain(|ask| now - ask.at < Duration::hours(KEPT_HOURS));
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
