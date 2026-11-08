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
/// How long an action waits for the network to open. Reopening took about 2
/// seconds on the test phone; after this the action runs anyway and says what
/// went wrong, as before.
pub(crate) const REOPEN_WAIT: Duration = Duration::from_secs(45);

/// Commands that run at once even while the network is closed or reopening: they
/// report state, cancel something, set up or leave a network, or work without it.
/// Every other command waits for the network first.
const NEVER_WAIT: &[&str] = &[
    "home_status",
    "network_status",
    "endpoint_status",
    "device_status",
    "send_status",
    "download_status",
    "access_workflow_status",
    "host_admin_status",
    "client_admin_status",
    "client_requests_status",
    "operation_registry",
    "pair_cancel",
    "cancel_send",
    "cancel_download",
    "cancel_access_review",
    "network_create",
    "network_reopen",
    "network_attach",
    "recovery_create",
    "recovery_restore",
    "disconnect_network",
    "reconnect_network",
    "leave_network",
];

/// Whether an action asked for while the network reopens should wait for it.
pub(crate) fn waits_for_network(command: &str) -> bool {
    !NEVER_WAIT.contains(&command)
}

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
    /// An attempt to open the network ended, opened or not.
    settled: Notify,
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
        if !closed {
            self.settled.notify_waiters();
        }
    }
    /// Opening failed: waiting actions run now and report it, instead of waiting
    /// out their limit. The next attempt follows as usual.
    pub(crate) fn open_failed(&self) {
        self.settled.notify_waiters();
    }
    /// Returns once the network is open or an attempt to open it failed, or after
    /// `limit` at the latest.
    pub(crate) async fn until_open(&self, limit: Duration) {
        // Registered before checking, so an opening in between is seen.
        let settled = self.settled.notified();
        tokio::pin!(settled);
        settled.as_mut().enable();
        if !self.is_closed() {
            return;
        }
        let _ = tokio::time::timeout(limit, settled).await;
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

/// Wraps the app's command handler: while the network is reopening after Connect
/// returned to the screen, an action waits for it, for at most [`REOPEN_WAIT`],
/// instead of failing because nothing is open yet. Then it runs as usual.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn waiting_for_reopen<R: tauri::Runtime>(
    handler: impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static,
) -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static {
    let handler = std::sync::Arc::new(handler);
    move |invoke| {
        if !LIFECYCLE.is_closed() || !waits_for_network(invoke.message.command()) {
            return handler(invoke);
        }
        let handler = handler.clone();
        tauri::async_runtime::spawn(async move {
            LIFECYCLE.until_open(REOPEN_WAIT).await;
            let resolver = invoke.resolver.clone();
            let command = invoke.message.command().to_owned();
            if !handler(invoke) {
                resolver.reject(format!("Command {command} not found"));
            }
        });
        true
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
    async fn an_action_waits_for_the_network_to_open_but_not_forever() {
        let phone = lifecycle();
        let limit = Duration::from_millis(800);
        let started = tokio::time::Instant::now();
        phone.until_open(limit).await;
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "Open: no wait"
        );

        phone.set_closed(true);
        let started = tokio::time::Instant::now();
        let opening = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            phone.set_closed(false);
        });
        phone.until_open(limit).await;
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(300) && waited < limit,
            "Waited {waited:?} for an opening after 300 ms"
        );
        opening.await.unwrap();

        phone.set_closed(true);
        let started = tokio::time::Instant::now();
        phone.until_open(limit).await;
        assert!(
            started.elapsed() >= limit,
            "No answer: the limit ends the wait"
        );
        assert!(phone.is_closed());

        let started = tokio::time::Instant::now();
        let failing = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            phone.open_failed();
        });
        phone.until_open(limit).await;
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(200) && waited < limit,
            "A failed opening ends the wait at once: {waited:?}"
        );
        assert!(phone.is_closed(), "Still closed; the next attempt follows");
        failing.await.unwrap();
    }

    #[test]
    fn status_cancel_and_setup_commands_never_wait() {
        for command in [
            "home_status",
            "pair_cancel",
            "network_reopen",
            "recovery_restore",
        ] {
            assert!(!waits_for_network(command), "{command}");
        }
        for command in ["pair_begin", "share_invitation", "open_file", "device_read"] {
            assert!(waits_for_network(command), "{command}");
        }
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
