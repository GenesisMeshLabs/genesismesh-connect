//! Qualification-only disposable core/QUIC fixtures. No phone/app acceptance.
#![cfg(all(target_os = "linux", feature = "pairing-completion-recovery"))]
#[path = "support/foreground_pairing.rs"]
mod pairing_support;
#[path = "support/embedded_owner.rs"]
mod support;
use anyhow::{Context, Result};
use connect_core::{
    device::{DeviceController, PairedDevice},
    owner::{
        OwnerCall, OwnerRequest,
        foreground::{ForegroundNetwork, SetupChoice},
    },
};
use pairing_support::*;
use std::{path::Path, sync::Arc};
use tokio::sync::Mutex;

/// Drop only the observation future, while retaining original host approval,
/// enrollment and the eventual host commit as distinct facts.
async fn interrupted(
    root: &Path,
    recoverable: bool,
    committed: bool,
) -> Result<(ForegroundNetwork, DeviceController)> {
    let (mut owner, _) = owner(root).await?;
    let mut member = candidate(root, &owner)?;
    let (pair, card, mut client, target) = request(&mut owner, &mut member, recoverable).await?;
    owner.device.prepare_local_pairing(&target).await?;
    let completion = owner
        .device
        .issue_local_pairing(&mut owner.runtime, &target)?;
    let issued = grant(client.grant().await?)?;
    let mut joining = Box::pin(member.complete_approved_pairing(&mut client, &card, issued));
    let joined = tokio::select! {
        result=joined(completion)=>result?,
        result=&mut joining=> {result?; anyhow::bail!("Client completed before original host commit")}
    };
    drop(joining);
    assert!(member.status()?.certificate_id.is_some());
    assert!(member.status()?.paired_device.is_none());
    if committed {
        owner.device.commit_local_pairing(&target, joined).await?;
    } else {
        // Even an exact matching relationship written later by another local
        // action is not evidence that this original approval finished.
        owner.device.remember_pairing(PairedDevice {
            name: target.name,
            node: target.node,
            ticket: joined.ticket,
        })?;
        let _ = joined.confirm.send(false);
    }
    client.close().await;
    pair.close().await;
    member.stop().await;
    let before = member.status()?;
    drop(member);
    let member = DeviceController::open(&root.join("candidate"))?;
    assert_eq!(member.status()?.node_public_key, before.node_public_key);
    assert_eq!(member.status()?.certificate_id, before.certificate_id);
    assert!(member.status()?.paired_device.is_none());
    Ok((owner, member))
}
fn readbacks(
    mut owner: ForegroundNetwork,
) -> (Arc<Mutex<ForegroundNetwork>>, tokio::task::JoinHandle<()>) {
    let (send, mut receive) = tokio::sync::mpsc::channel::<OwnerRequest>(8);
    owner.device.serve_owner(send);
    let owner = Arc::new(Mutex::new(owner));
    let host = owner.clone();
    let task = tokio::spawn(async move {
        while let Some(request) = receive.recv().await {
            let mut host = host.lock().await;
            let result = match request.call {
                OwnerCall::PairingCompletion {
                    node,
                    certificate,
                    query,
                } => host
                    .device
                    .answer_pairing_completion(&node, &certificate, query)
                    .await
                    .and_then(|a| Ok(serde_json::to_value(a)?)),
                _ => panic!("Unexpected fixture operation"),
            };
            let _ = request.reply.send(result);
        }
    });
    (owner, task)
}
async fn close(
    owner: Arc<Mutex<ForegroundNetwork>>,
    task: tokio::task::JoinHandle<()>,
    member: &mut DeviceController,
) {
    member.stop().await;
    owner.lock().await.device.stop().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}
fn counts(root: &Path) -> (usize, usize, usize) {
    (
        support::calls(root, "invite"),
        support::core_calls(root, "/join"),
        support::core_calls(root, "/renew"),
    )
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn explicit_finish_after_both_profiles_reopen_uses_original_evidence_and_no_new_issuance()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (mut owner, mut member) = interrupted(root, true, true).await?;
    let before = member.status()?;
    let original_host = owner.device.status()?;
    let expected = counts(root);
    // Explicit native Open, not reconstruction from membership or an invite.
    owner.device.stop().await;
    drop(owner);
    let mut setup = support::begin(root, SetupChoice::Open, None)?;
    setup.open_authority()?;
    setup.prepare_device()?;
    setup.request_invitation()?;
    setup.enroll_device().await?;
    let mut owner = setup.finish()?;
    assert_eq!(
        original_host.node_public_key,
        owner.device.status()?.node_public_key
    );
    assert_eq!(
        original_host.certificate_id,
        owner.device.status()?.certificate_id
    );
    owner.device.start(&before.node_public_key).await?;
    assert_eq!(counts(root), expected);
    let (owner, task) = readbacks(owner);
    member.inspect_pairing_completion().await?;
    assert!(
        member.status()?.paired_device.is_none(),
        "Inspection cannot finish pairing"
    );
    member.finish_pairing_completion().await?;
    let after = member.status()?;
    assert_eq!(after.node_public_key, before.node_public_key);
    assert_eq!(after.certificate_id, before.certificate_id);
    assert_eq!(
        after
            .paired_device
            .as_ref()
            .context("Explicit finish did not save relationship")?
            .node,
        original_host.node_public_key
    );
    member.finish_pairing_completion().await?; // Freshly checked idempotent local outcome.
    assert_eq!(counts(root), expected);
    close(owner, task, &mut member).await;
    drop(member);
    let member = DeviceController::open(&root.join("candidate"))?;
    assert_eq!(member.status()?.certificate_id, before.certificate_id);
    assert!(member.status()?.paired_device.is_some());
    Ok(())
}
#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn reserved_approval_plus_matching_membership_and_graph_never_finishes_the_original_pairing()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (owner, mut member) = interrupted(root, true, false).await?;
    assert!(
        owner
            .device
            .status()?
            .devices
            .iter()
            .any(|d| d.node == member.status().unwrap().node_public_key)
    );
    let expected = counts(root);
    let before = member.status()?;
    let (owner, task) = readbacks(owner);
    assert!(member.inspect_pairing_completion().await.is_err());
    assert!(member.finish_pairing_completion().await.is_err());
    assert!(member.status()?.paired_device.is_none());
    assert_eq!(member.status()?.certificate_id, before.certificate_id);
    assert_eq!(counts(root), expected);
    close(owner, task, &mut member).await;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn legacy_pairing_without_original_reference_is_not_recoverable_from_matching_state()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (owner, mut member) = interrupted(root, false, true).await?;
    let expected = counts(root);
    let (owner, task) = readbacks(owner);
    let error = member.inspect_pairing_completion().await.unwrap_err();
    assert!(
        error.to_string().contains("reference is missing"),
        "{error:#}"
    );
    assert!(member.finish_pairing_completion().await.is_err());
    assert!(member.status()?.paired_device.is_none());
    assert_eq!(counts(root), expected);
    close(owner, task, &mut member).await;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn later_matching_relationship_cannot_be_attributed_to_old_completion() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (owner, mut member) = interrupted(root, true, true).await?;
    let expected = counts(root);
    let node = member.status()?.node_public_key;
    let (owner, task) = readbacks(owner);
    member.inspect_pairing_completion().await?;
    {
        let mut host = owner.lock().await;
        let peer = host
            .device
            .status()?
            .devices
            .into_iter()
            .find(|d| d.node == node)
            .context("Missing paired member")?;
        host.device.remember_pairing(peer)?; // Supersedes causal binding, even with identical graph.
    }
    assert!(member.inspect_pairing_completion().await.is_err());
    assert!(member.finish_pairing_completion().await.is_err());
    assert!(member.status()?.paired_device.is_none());
    assert_eq!(counts(root), expected);
    close(owner, task, &mut member).await;
    Ok(())
}
#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn revocation_after_eligible_inspection_refuses_explicit_finish_with_fresh_trust()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (owner, mut member) = interrupted(root, true, true).await?;
    let expected = counts(root);
    let before = member.status()?;
    let (owner, task) = readbacks(owner);
    member.inspect_pairing_completion().await?;
    owner
        .lock()
        .await
        .runtime
        .remove_device(&before.node_public_key)?;
    let error = member.finish_pairing_completion().await.unwrap_err();
    assert!(format!("{error:#}").contains("revoked"), "{error:#}");
    assert!(member.status()?.paired_device.is_none());
    assert_eq!(member.status()?.certificate_id, before.certificate_id);
    assert_eq!(counts(root), expected);
    close(owner, task, &mut member).await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn unavailable_readback_preserves_enrollment_until_an_explicit_retry() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (owner, mut member) = interrupted(root, true, true).await?;
    let expected = counts(root);
    let before = member.status()?;
    // No native host responder has been attached yet. Membership and the
    // committed peer alone cannot cause the client to manufacture a reply.
    assert!(member.inspect_pairing_completion().await.is_err());
    assert!(member.finish_pairing_completion().await.is_err());
    assert!(member.status()?.paired_device.is_none());
    assert_eq!(member.status()?.certificate_id, before.certificate_id);
    let (owner, task) = readbacks(owner);
    assert!(
        member.status()?.paired_device.is_none(),
        "Attaching the responder is not an automatic finish"
    );
    member.finish_pairing_completion().await?;
    assert_eq!(counts(root), expected);
    close(owner, task, &mut member).await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn host_revocation_also_refuses_recovery_with_existing_client_membership() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (owner, mut member) = interrupted(root, true, true).await?;
    let host_node = owner.device.status()?.node_public_key;
    let expected = counts(root);
    let before = member.status()?;
    let (owner, task) = readbacks(owner);
    member.inspect_pairing_completion().await?;
    let removed = owner.lock().await.runtime.remove_device(&host_node)?;
    assert!(removed.revoked > 0);
    assert!(member.inspect_pairing_completion().await.is_err());
    assert!(member.finish_pairing_completion().await.is_err());
    assert!(member.status()?.paired_device.is_none());
    assert_eq!(member.status()?.certificate_id, before.certificate_id);
    assert_eq!(counts(root), expected);
    close(owner, task, &mut member).await;
    Ok(())
}
