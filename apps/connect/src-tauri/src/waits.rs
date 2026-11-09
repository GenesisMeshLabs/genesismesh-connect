//! Reads that may wait for a restarting device, for up to two minutes, can be
//! stopped by the person. Stopping only ends this device's wait: a read changes
//! nothing, so there is nothing to undo or to ask again.
use std::{
    collections::HashMap,
    future::Future,
    sync::{LazyLock, Mutex},
};
use tokio::sync::oneshot;

pub(crate) const STOPPED: &str = "Stopped waiting. Nothing was changed.";

static WAITS: LazyLock<Mutex<HashMap<String, oneshot::Sender<()>>>> =
    LazyLock::new(Default::default);

/// A wait the person can stop, known by the id the screen gave it.
pub(crate) struct Wait {
    id: Option<String>,
    stopped: oneshot::Receiver<()>,
}

impl Wait {
    /// Without an id the wait cannot be stopped, as for callers that never
    /// show a Cancel button.
    pub(crate) fn new(id: Option<String>) -> Self {
        let (stop, stopped) = oneshot::channel();
        if let Some(id) = &id {
            WAITS.lock().expect("waits").insert(id.clone(), stop);
        }
        Self { id, stopped }
    }

    /// Whether the person already asked to stop, as while trust was refreshed.
    /// Steps that may write, such as a renewal during that refresh, are never
    /// cut short; the wait ends after them.
    pub(crate) fn stopped(&mut self) -> bool {
        self.id.is_some() && self.stopped.try_recv().is_ok()
    }

    /// Run a read that is safe to drop, until it answers or the person stops.
    pub(crate) async fn until_stopped<T>(
        mut self,
        read: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        if self.stopped() {
            return Err(STOPPED.into());
        }
        if self.id.is_none() {
            return read.await;
        }
        tokio::select! {
            biased;
            Ok(()) = &mut self.stopped => Err(STOPPED.into()),
            outcome = read => outcome,
        }
    }
}

impl Drop for Wait {
    fn drop(&mut self) {
        if let Some(id) = &self.id {
            WAITS.lock().expect("waits").remove(id);
        }
    }
}

/// Stop the wait with this id. False when it already ended.
#[tauri::command]
pub fn cancel_wait(id: String) -> bool {
    WAITS
        .lock()
        .expect("waits")
        .remove(&id)
        .is_some_and(|stop| stop.send(()).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn id(name: &str) -> String {
        format!("{name}-{}", uuid::Uuid::new_v4())
    }

    #[tokio::test]
    async fn a_read_answers_unless_the_person_stops_waiting() {
        // It answers: the wait is forgotten, and stopping it later does nothing.
        let first = id("answers");
        let answered = Wait::new(Some(first.clone()))
            .until_stopped(async { Ok::<_, String>(7) })
            .await;
        assert_eq!(answered, Ok(7));
        assert!(!cancel_wait(first));

        // The person stops a read that is still waiting.
        let second = id("stopped");
        let wait = Wait::new(Some(second.clone()));
        let reading = tokio::spawn(wait.until_stopped(async {
            tokio::time::sleep(Duration::from_secs(120)).await;
            Ok::<_, String>(())
        }));
        tokio::task::yield_now().await;
        assert!(cancel_wait(second.clone()));
        let outcome = tokio::time::timeout(Duration::from_secs(5), reading)
            .await
            .expect("stopped promptly")
            .expect("task");
        assert_eq!(outcome, Err(STOPPED.into()));
        assert!(!cancel_wait(second), "Stopped once");

        // A refusal or other answer comes back as it is.
        let refused = Wait::new(Some(id("refused")))
            .until_stopped(async { Err::<(), _>("Access was not allowed".to_string()) })
            .await;
        assert_eq!(refused, Err("Access was not allowed".into()));
    }

    #[tokio::test]
    async fn stopping_during_a_refresh_ends_the_wait_after_it_without_reading() {
        let during = id("refresh");
        let mut wait = Wait::new(Some(during.clone()));
        assert!(!wait.stopped());
        // The person stops while trust is refreshed; the refresh finishes.
        assert!(cancel_wait(during));
        let read = std::cell::Cell::new(false);
        let outcome = wait
            .until_stopped(async {
                read.set(true);
                Ok::<_, String>(())
            })
            .await;
        assert_eq!(outcome, Err(STOPPED.into()));
        assert!(!read.get(), "No read starts after the person stopped");
    }

    #[tokio::test]
    async fn a_wait_without_an_id_cannot_be_stopped() {
        let mut wait = Wait::new(None);
        assert!(!wait.stopped());
        assert_eq!(
            wait.until_stopped(async { Ok::<_, String>(1) }).await,
            Ok(1)
        );
    }
}
