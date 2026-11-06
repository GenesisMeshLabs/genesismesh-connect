//! Qualification-only client command coordination over real embedded core/QUIC.
#![cfg(all(
    target_os = "linux",
    feature = "owner-requests-qualification",
    feature = "pairing-completion-recovery"
))]
#[path = "support/foreground_pairing.rs"]
mod pairing_support;
#[path = "support/foreground_resources.rs"]
#[allow(dead_code)]
mod resource_support;
#[path = "support/embedded_owner.rs"]
mod support;
use anyhow::{Context, Result};
use connect_core::{
    device::{AdministrativeBinding, AdministrativeKey, DeviceController},
    owner::{OwnerCall, OwnerRequest, foreground::ForegroundNetwork},
    owner_control::{
        ClientCommandPresence, ClientCommandStatus, ClientCommandView, ControlExchange,
        ControlResult, OwnerAction, PairingTarget, Permission, UnavailableCommandPresence,
    },
    session::pairing::{PairCard, PairClient, PairHost},
};
use pairing_support::{grant, joined, owner, request};
use resource_support::pair;
use std::{
    path::Path,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;

// Explicitly fixture-only: this is not a device-authentication provider or app IPC.
struct FixturePresence {
    digest: String,
    calls: usize,
    allow: bool,
}
impl FixturePresence {
    fn approve(view: &ClientCommandView) -> Self {
        Self {
            digest: view.digest.clone(),
            calls: 0,
            allow: true,
        }
    }
}
impl ClientCommandPresence for FixturePresence {
    fn available(&self) -> bool {
        true
    }
    fn confirm(&mut self, review: &ClientCommandView) -> Result<()> {
        self.calls += 1;
        anyhow::ensure!(
            self.allow && self.digest == review.digest,
            "Fixture presence denied or review changed"
        );
        Ok(())
    }
}
#[derive(Default)]
struct Observed {
    execute: AtomicUsize,
    result: AtomicUsize,
    loss: AtomicU8,
    commands: StdMutex<Vec<(String, String)>>,
    queries: StdMutex<Vec<(String, String)>>,
}
struct Fixture {
    host: Arc<Mutex<ForegroundNetwork>>,
    member: DeviceController,
    worker: tokio::task::JoinHandle<()>,
    observed: Arc<Observed>,
    grant_id: String,
    grant_ends: chrono::DateTime<chrono::Utc>,
}
impl Fixture {
    async fn new(root: &Path, short: bool) -> Result<Self> {
        let (mut host, _) = owner(root).await?;
        let member = pair(&mut host, &root.join("controller"), false).await?;
        host.device.enable_owner_requests()?;
        let (send, mut receive) = tokio::sync::mpsc::channel::<OwnerRequest>(8);
        host.device.serve_owner(send);
        let host = Arc::new(Mutex::new(host));
        let state = host.clone();
        let observed = Arc::new(Observed::default());
        let trace = observed.clone();
        let worker = tokio::spawn(async move {
            while let Some(message) = receive.recv().await {
                let mut drop_reply = false;
                let mut revoke_after = None;
                if let OwnerCall::Control { request, .. } = &message.call {
                    match &request.request {
                        ControlExchange::Execute { command } => {
                            trace.execute.fetch_add(1, Ordering::SeqCst);
                            trace
                                .commands
                                .lock()
                                .unwrap()
                                .push((command.intent.nonce.clone(), command.digest().unwrap()));
                            if trace
                                .loss
                                .compare_exchange(2, 0, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                            {
                                continue;
                            }
                            drop_reply = trace
                                .loss
                                .compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok();
                            if trace
                                .loss
                                .compare_exchange(4, 0, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                            {
                                revoke_after = Some(command.intent.grant_id.clone());
                            }
                        }
                        ControlExchange::Result { nonce, digest } => {
                            trace.result.fetch_add(1, Ordering::SeqCst);
                            trace
                                .queries
                                .lock()
                                .unwrap()
                                .push((nonce.clone(), digest.clone()));
                            drop_reply = trace
                                .loss
                                .compare_exchange(3, 0, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok();
                        }
                        _ => (),
                    }
                }
                let mut state = state.lock().await;
                let ForegroundNetwork {
                    runtime, device, ..
                } = &mut *state;
                let reply = match message.call {
                    OwnerCall::Control {
                        node,
                        certificate,
                        request,
                    } => {
                        device
                            .answer_owner_control(runtime, &node, &certificate, request)
                            .await
                    }
                    call => runtime.answer(call),
                };
                if let Some(id) = revoke_after {
                    device
                        .open_owner_requests()
                        .unwrap()
                        .revoke_locally(&id)
                        .unwrap();
                }
                if !drop_reply {
                    let _ = message.reply.send(reply);
                }
            }
        });
        let mut fixture = Self {
            host,
            member,
            worker,
            observed,
            grant_id: String::new(),
            grant_ends: chrono::Utc::now(),
        };
        let mut request = fixture
            .member
            .prepare_owner_enrollment(
                [
                    Permission::ListPairing,
                    Permission::ApprovePairing,
                    Permission::RejectPairing,
                ]
                .into_iter()
                .collect(),
                600,
            )
            .await?;
        if short {
            // Short lifetimes are only a signed disposable-fixture input. The
            // public native preparation contract and production clocks stay unchanged.
            let binding = AdministrativeBinding {
                scope: request.intent.scope.clone(),
                controller_node: request.intent.controller_node.clone(),
            };
            let key = AdministrativeKey::open(
                &root.join("controller/administrative-key.json"),
                &binding,
            )?;
            let now = chrono::Utc::now();
            let mut intent = request.intent;
            intent.created_at = now;
            intent.expires_at = now + chrono::Duration::seconds(12);
            intent.grant_expires_at = now + chrono::Duration::seconds(20);
            request = key.sign_enrollment(intent)?;
        }
        let digest = request.digest()?;
        fixture.grant_id = request.intent.id.clone();
        fixture.grant_ends = request.intent.grant_expires_at;
        fixture
            .member
            .retain_owner_enrollment(request, &digest)
            .await?;
        fixture.member.submit_owner_enrollment(&digest).await?;
        {
            let mut host = fixture.host.lock().await;
            let mut control = host.device.open_owner_requests()?;
            control
                .approve_locally(&mut host.device, &fixture.grant_id, &digest)
                .await?;
        }
        fixture.member.check_owner_enrollment().await?;
        Ok(fixture)
    }
    async fn candidate(
        &self,
        root: &Path,
        name: &str,
    ) -> Result<(
        DeviceController,
        Arc<PairHost>,
        PairCard,
        PairClient,
        PairingTarget,
    )> {
        let mut host = self.host.lock().await;
        let mut member = DeviceController::prepare_remote(&root.join(name), host.info.pin.clone())?;
        let (pair, card, client, target) = request(&mut host, &mut member, false).await?;
        Ok((member, pair, card, client, target))
    }
    async fn close(mut self) {
        self.member.stop().await;
        self.host.lock().await.device.stop().await;
        self.worker.abort();
        assert!(self.worker.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core foreground fixture"]
async fn list_then_exact_decline_require_review_presence_and_explicit_retirement() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut f = Fixture::new(root, false).await?;
    let (mut candidate, pair, _, mut client, target) = f.candidate(root, "candidate").await?;
    let review = f
        .member
        .review_owner_action(OwnerAction::ListPairing)
        .await?;
    assert_eq!(review.status, ClientCommandStatus::Reviewed);
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 0);
    assert!(
        f.member
            .submit_owner_action(&review.digest, &mut UnavailableCommandPresence)
            .await
            .is_err()
    );
    let mut presence = FixturePresence::approve(&review);
    presence.allow = false;
    assert!(
        f.member
            .submit_owner_action(&review.digest, &mut presence)
            .await
            .is_err()
    );
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 0);
    presence.allow = true;
    assert!(
        f.member
            .submit_owner_action("changed review", &mut presence)
            .await
            .is_err()
    );
    assert_eq!(presence.calls, 1);
    let observed = f
        .member
        .submit_owner_action(&review.digest, &mut presence)
        .await?;
    assert_eq!(
        observed.current_observation,
        Some(ControlResult::PairingList {
            request: Some(target.clone())
        })
    );
    assert_eq!(observed.status, ClientCommandStatus::Observed);
    assert!(
        f.member
            .review_owner_action(OwnerAction::RejectPairing(target.clone()))
            .await
            .is_err(),
        "Do not replace retained work"
    );
    f.member.archive_owner_action(&review.digest).await?;
    let reject = f
        .member
        .review_owner_action(OwnerAction::RejectPairing(target.clone()))
        .await?;
    assert_ne!(reject.nonce, review.nonce);
    let result = f
        .member
        .submit_owner_action(&reject.digest, &mut FixturePresence::approve(&reject))
        .await?;
    assert_eq!(
        result.current_observation,
        Some(ControlResult::Rejected { node: target.node })
    );
    assert!(client.grant().await.is_err());
    assert!(pair.pending().is_none());
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 2);
    assert_eq!(support::calls(root, "invite"), 2);
    client.close().await;
    pair.close().await;
    candidate.stop().await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core foreground fixture"]
async fn lost_approval_reply_reopens_with_same_command_and_only_reads_its_result() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut f = Fixture::new(root, false).await?;
    let (mut candidate, pair, card, mut client, target) = f.candidate(root, "candidate").await?;
    let review = f
        .member
        .review_owner_action(OwnerAction::ApprovePairing(target.clone()))
        .await?;
    let key_before = std::fs::read(root.join("controller/administrative-key.json"))?;
    let before = f.member.status()?;
    f.observed.loss.store(1, Ordering::SeqCst);
    let mut presence = FixturePresence::approve(&review);
    let approve = f.member.submit_owner_action(&review.digest, &mut presence);
    let join = async {
        let issued = grant(
            client
                .grant()
                .await
                .context("Candidate receiving original approved grant")?,
        )?;
        candidate
            .complete_approved_pairing(&mut client, &card, issued)
            .await
            .context("Candidate completing original approved pairing")
    };
    let (result, joined) = tokio::join!(approve, join);
    joined?;
    assert_eq!(result?.status, ClientCommandStatus::Uncertain);
    assert!(candidate.status()?.paired_device.is_some());
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 1);
    f.member.stop().await;
    drop(f.member);
    f.member = DeviceController::open(&root.join("controller"))?;
    let saved = f.member.saved_owner_action()?;
    assert_eq!(saved.nonce, review.nonce);
    assert_eq!(saved.digest, review.digest);
    assert_eq!(saved.status, ClientCommandStatus::Uncertain);
    assert!(
        f.member
            .review_owner_action(OwnerAction::ApprovePairing(target.clone()))
            .await
            .is_err()
    );
    assert!(
        f.member
            .submit_owner_action(&review.digest, &mut FixturePresence::approve(&review))
            .await
            .is_err()
    );
    f.observed.loss.store(3, Ordering::SeqCst);
    assert_eq!(
        f.member.check_owner_action().await?.status,
        ClientCommandStatus::Uncertain
    );
    let checked = f.member.check_owner_action().await?;
    assert_eq!(
        checked.current_observation,
        Some(ControlResult::Approved { node: target.node })
    );
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 1);
    assert!(
        f.observed
            .queries
            .lock()
            .unwrap()
            .iter()
            .all(|r| r == &(review.nonce.clone(), review.digest.clone()))
    );
    assert_eq!(before.node_public_key, f.member.status()?.node_public_key);
    assert_eq!(before.certificate_id, f.member.status()?.certificate_id);
    assert_eq!(
        std::fs::read(root.join("controller/administrative-key.json"))?,
        key_before
    );
    client.close().await;
    pair.close().await;
    candidate.stop().await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core foreground fixture"]
async fn matching_membership_from_another_local_approval_never_confirms_the_unobserved_command()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut f = Fixture::new(root, false).await?;
    let (mut candidate, pair, card, mut client, target) = f.candidate(root, "candidate").await?;
    let review = f
        .member
        .review_owner_action(OwnerAction::ApprovePairing(target.clone()))
        .await?;
    f.observed.loss.store(2, Ordering::SeqCst);
    assert_eq!(
        f.member
            .submit_owner_action(&review.digest, &mut FixturePresence::approve(&review))
            .await?
            .status,
        ClientCommandStatus::Uncertain
    );
    // A separate explicit local approval reaches the exact desired state. It is
    // not a retained Execute result for the lost client command's nonce/digest.
    let complete = {
        let mut host = f.host.lock().await;
        host.device.prepare_local_pairing(&target).await?;
        let ForegroundNetwork {
            runtime, device, ..
        } = &mut *host;
        device.issue_local_pairing(runtime, &target)?
    };
    let issued = grant(client.grant().await?)?;
    let join = candidate.complete_approved_pairing(&mut client, &card, issued);
    let commit = async {
        let joined = joined(complete).await?;
        f.host
            .lock()
            .await
            .device
            .commit_local_pairing(&target, joined)
            .await
    };
    let (a, b) = tokio::join!(join, commit);
    a?;
    b?;
    assert!(candidate.status()?.paired_device.is_some());
    let checked = f.member.check_owner_action().await?;
    assert_eq!(checked.status, ClientCommandStatus::Uncertain);
    assert!(checked.retained_outcome.is_none());
    assert!(checked.current_observation.is_none());
    assert!(
        f.member
            .review_owner_action(OwnerAction::ListPairing)
            .await
            .is_err()
    );
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 1);
    client.close().await;
    pair.close().await;
    candidate.stop().await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core foreground fixture"]
async fn changed_candidate_is_refused_under_host_gate_and_never_invited_or_replayed() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut f = Fixture::new(root, false).await?;
    let (mut original, old_pair, _, old_client, target) = f.candidate(root, "original").await?;
    let review = f
        .member
        .review_owner_action(OwnerAction::ApprovePairing(target))
        .await?;
    old_client.close().await;
    old_pair.close().await;
    original.stop().await;
    let (mut replacement, pair, _, mut client, _) = f.candidate(root, "replacement").await?;
    let result = f
        .member
        .submit_owner_action(&review.digest, &mut FixturePresence::approve(&review))
        .await?;
    assert_eq!(result.status, ClientCommandStatus::Uncertain);
    assert!(result.retained_outcome.is_none());
    let check = f.member.check_owner_action().await?;
    assert_eq!(check.current_observation, Some(ControlResult::Unconfirmed));
    assert!(pair.pending().is_some());
    assert_eq!(support::calls(root, "invite"), 2);
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 1);
    assert!(
        f.member
            .submit_owner_action(&review.digest, &mut FixturePresence::approve(&review))
            .await
            .is_err()
    );
    pair.close().await;
    assert!(client.grant().await.is_err());
    client.close().await;
    replacement.stop().await;
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core foreground fixture"]
async fn revoked_grant_blocks_dispatch_and_preserves_a_prior_terminal_result_as_history()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut f = Fixture::new(root, false).await?;
    let review = f
        .member
        .review_owner_action(OwnerAction::ListPairing)
        .await?;
    f.member
        .submit_owner_action(&review.digest, &mut FixturePresence::approve(&review))
        .await?;
    f.host
        .lock()
        .await
        .device
        .open_owner_requests()?
        .revoke_locally(&f.grant_id)?;
    let view = f.member.check_owner_action().await?;
    assert_eq!(view.status, ClientCommandStatus::Uncertain);
    assert!(view.current_observation.is_none());
    assert!(view.retained_outcome.is_some());
    assert_eq!(
        f.member.archive_owner_action(&review.digest).await?.status,
        ClientCommandStatus::Uncertain
    );
    assert!(
        f.member
            .review_owner_action(OwnerAction::ListPairing)
            .await
            .is_err()
    );
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 1);
    assert_eq!(f.observed.result.load(Ordering::SeqCst), 0);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core foreground fixture"]
async fn expired_grant_keeps_retained_outcome_but_allows_no_new_execute() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut f = Fixture::new(root, true).await?;
    let review = f
        .member
        .review_owner_action(OwnerAction::ListPairing)
        .await?;
    f.member
        .submit_owner_action(&review.digest, &mut FixturePresence::approve(&review))
        .await?;
    let wait = (f.grant_ends - chrono::Utc::now())
        .to_std()
        .unwrap_or_default()
        + Duration::from_millis(50);
    tokio::time::sleep(wait).await;
    let checked = f.member.check_owner_action().await?;
    assert_eq!(checked.status, ClientCommandStatus::Uncertain);
    assert!(checked.current_observation.is_none());
    assert!(checked.retained_outcome.is_some());
    assert!(
        f.member
            .submit_owner_action(&review.digest, &mut FixturePresence::approve(&review))
            .await
            .is_err()
    );
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 1);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core foreground fixture"]
async fn grant_revoked_after_dispatch_keeps_exact_result_as_history_without_current_confirmation()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut f = Fixture::new(dir.path(), false).await?;
    let review = f
        .member
        .review_owner_action(OwnerAction::ListPairing)
        .await?;
    f.observed.loss.store(4, Ordering::SeqCst);
    let result = f
        .member
        .submit_owner_action(&review.digest, &mut FixturePresence::approve(&review))
        .await?;
    assert_eq!(result.status, ClientCommandStatus::Uncertain);
    assert!(result.current_observation.is_none());
    assert_eq!(
        result.retained_outcome,
        Some(ControlResult::PairingList { request: None })
    );
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 1);
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires disposable pinned-core foreground fixture"]
async fn grant_revoked_after_review_refuses_before_presence_or_execute() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut f = Fixture::new(dir.path(), false).await?;
    let review = f
        .member
        .review_owner_action(OwnerAction::ListPairing)
        .await?;
    f.host
        .lock()
        .await
        .device
        .open_owner_requests()?
        .revoke_locally(&f.grant_id)?;
    let mut presence = FixturePresence::approve(&review);
    assert!(
        f.member
            .submit_owner_action(&review.digest, &mut presence)
            .await
            .is_err()
    );
    assert_eq!(presence.calls, 0);
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 0);
    assert_eq!(f.member.saved_owner_action()?.nonce, review.nonce);
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires disposable pinned-core foreground fixture"]
async fn fresh_core_revocation_of_controller_blocks_dispatch_without_replacing_native_key()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut f = Fixture::new(root, false).await?;
    let review = f
        .member
        .review_owner_action(OwnerAction::ListPairing)
        .await?;
    let before = std::fs::read(root.join("controller/administrative-key.json"))?;
    let node = f.member.status()?.node_public_key;
    assert!(f.host.lock().await.runtime.remove_device(&node)?.revoked > 0);
    assert!(
        f.member
            .submit_owner_action(&review.digest, &mut FixturePresence::approve(&review))
            .await
            .is_err()
    );
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read(root.join("controller/administrative-key.json"))?,
        before
    );
    assert_eq!(f.member.saved_owner_action()?.nonce, review.nonce);
    f.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires disposable pinned-core foreground fixture"]
async fn display_inspection_does_not_initialize_a_command_or_key_and_review_is_not_checkable()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut f = Fixture::new(root, false).await?;
    let key = std::fs::read(root.join("controller/administrative-key.json"))?;
    let overview = f.member.owner_requests_overview()?;
    assert!(overview.entry.is_none() && !overview.can_check && !overview.attention);
    assert!(!root.join("controller/owner-commands.json").exists());
    assert!(
        !root
            .join("controller/owner-commands.owner-commands-lock")
            .exists()
    );
    let review = f
        .member
        .review_owner_action(OwnerAction::ListPairing)
        .await?;
    let view = f.member.owner_requests_overview()?;
    assert_eq!(view.entry.as_ref().unwrap().nonce, review.nonce);
    assert!(!view.can_check);
    assert!(f.member.check_owner_requests_overview().await.is_err());
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 0);
    assert_eq!(f.observed.result.load(Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read(root.join("controller/administrative-key.json"))?,
        key
    );
    f.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires disposable pinned-core foreground fixture"]
async fn display_readback_projects_the_same_result_without_execute_and_does_not_promote_history()
-> Result<()> {
    use connect_core::device::RequestResultKind;
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut f = Fixture::new(root, false).await?;
    let review = f
        .member
        .review_owner_action(OwnerAction::ListPairing)
        .await?;
    f.observed.loss.store(1, Ordering::SeqCst);
    f.member
        .submit_owner_action(&review.digest, &mut FixturePresence::approve(&review))
        .await?;
    let saved = f.member.owner_requests_overview()?;
    assert_eq!(
        saved.entry.as_ref().unwrap().status,
        ClientCommandStatus::Uncertain
    );
    assert!(saved.entry.as_ref().unwrap().current_result.is_none());
    let checked = f.member.check_owner_requests_overview().await?;
    assert_eq!(checked.context, saved.context);
    let entry = checked.entry.unwrap();
    assert_eq!(entry.nonce, review.nonce);
    assert_eq!(entry.digest, review.digest);
    assert_eq!(
        entry.current_result.as_ref().unwrap().state,
        RequestResultKind::QueueSnapshot
    );
    let again = f.member.owner_requests_overview()?.entry.unwrap();
    assert!(again.current_result.is_none());
    assert!(again.retained_result.is_some());
    assert_eq!(f.observed.execute.load(Ordering::SeqCst), 1);
    f.close().await;
    Ok(())
}
