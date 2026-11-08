//! When a phone that runs the network keeps its network open.
//!
//! Android blocks a background app's network, so while Connect is off screen no
//! other device can reach it and the network library only retries probes that
//! cannot work. After a grace period the network closes, and it reopens on return.
//! Short visits to another screen, such as a share sheet, stay within the grace
//! period, and a hold keeps it open while a file picker or an authentication
//! prompt is up.
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

const GRACE: Duration = Duration::from_secs(120);

#[derive(Default)]
struct State {
    suspended_at: Option<Instant>,
    holds: usize,
    closed: bool,
}

#[derive(Default)]
pub(crate) struct PhoneLifecycle {
    state: Mutex<State>,
    returned: Notify,
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) static LIFECYCLE: LazyLock<PhoneLifecycle> = LazyLock::new(Default::default);

impl PhoneLifecycle {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Connect left the screen; a repeat keeps the earlier time.
    pub(crate) fn suspended(&self, now: Instant) {
        self.state().suspended_at.get_or_insert(now);
    }
    /// Connect is back on screen.
    pub(crate) fn resumed(&self) {
        self.state().suspended_at = None;
        self.returned.notify_one();
    }
    pub(crate) async fn returned(&self) {
        self.returned.notified().await;
    }
    pub(crate) fn is_suspended(&self) -> bool {
        self.state().suspended_at.is_some()
    }
    /// Off screen for the whole grace period, with nothing holding it open.
    pub(crate) fn should_close(&self, now: Instant) -> bool {
        let state = self.state();
        state.holds == 0
            && state
                .suspended_at
                .is_some_and(|since| now.duration_since(since) >= GRACE)
    }
    /// The network is closed or reopening: the screen keeps what it last showed.
    pub(crate) fn set_closed(&self, closed: bool) {
        self.state().closed = closed;
    }
    pub(crate) fn is_closed(&self) -> bool {
        self.state().closed
    }
    /// Keeps the network open while another screen is part of what the person
    /// is doing. The grace period starts again when the last hold ends.
    pub(crate) fn hold(&'static self) -> Hold {
        self.state().holds += 1;
        Hold(self)
    }
}

pub(crate) struct Hold(&'static PhoneLifecycle);

impl Drop for Hold {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.holds -= 1;
        if state.holds == 0 && state.suspended_at.is_some() {
            state.suspended_at = Some(Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lifecycle() -> &'static PhoneLifecycle {
        Box::leak(Box::default())
    }

    #[test]
    fn stays_open_on_screen_and_through_short_visits() {
        let phone = lifecycle();
        let start = Instant::now();
        assert!(!phone.should_close(start + GRACE * 10), "Never on screen");
        phone.suspended(start);
        assert!(phone.is_suspended());
        assert!(!phone.should_close(start + GRACE - Duration::from_secs(1)));
        phone.resumed();
        assert!(!phone.is_suspended());
        assert!(!phone.should_close(start + GRACE * 10));
    }

    #[test]
    fn closes_after_the_whole_grace_period_counted_from_leaving() {
        let phone = lifecycle();
        let start = Instant::now();
        phone.suspended(start);
        phone.suspended(start + GRACE - Duration::from_secs(1));
        assert!(
            phone.should_close(start + GRACE),
            "A repeat does not restart it"
        );
    }

    #[test]
    fn a_return_restarts_the_count() {
        let phone = lifecycle();
        let start = Instant::now();
        phone.suspended(start);
        phone.resumed();
        phone.suspended(start + GRACE);
        assert!(!phone.should_close(start + GRACE + Duration::from_secs(1)));
    }

    #[test]
    fn a_hold_keeps_it_open_and_restarts_the_grace_period() {
        let phone = lifecycle();
        let start = Instant::now();
        phone.suspended(start);
        let first = phone.hold();
        let second = phone.hold();
        assert!(!phone.should_close(start + GRACE * 10));
        drop(first);
        assert!(!phone.should_close(start + GRACE * 10), "One hold remains");
        drop(second);
        let ended = Instant::now();
        assert!(!phone.should_close(ended + GRACE - Duration::from_secs(1)));
        assert!(phone.should_close(ended + GRACE + Duration::from_secs(1)));
    }

    #[test]
    fn closed_stays_until_the_network_is_open_again() {
        let phone = lifecycle();
        assert!(!phone.is_closed());
        phone.set_closed(true);
        phone.suspended(Instant::now());
        phone.resumed();
        assert!(phone.is_closed(), "Returning does not reopen it by itself");
        phone.set_closed(false);
        assert!(!phone.is_closed());
    }

    #[test]
    fn a_hold_on_screen_starts_no_count() {
        let phone = lifecycle();
        drop(phone.hold());
        assert!(!phone.is_suspended());
    }

    #[tokio::test]
    async fn a_return_wakes_the_keeper_even_if_it_was_not_yet_waiting() {
        let phone = lifecycle();
        phone.resumed();
        tokio::time::timeout(Duration::from_secs(1), phone.returned())
            .await
            .expect("The return is remembered");
    }
}
