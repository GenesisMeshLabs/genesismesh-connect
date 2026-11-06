//! Embedded ForegroundNetwork + independent device, genuine core/QUIC only.
//! Explicit disposable host fixtures, not a phone/UI or full-app qualification.
#![cfg(target_os = "linux")]
#[path = "support/embedded_owner.rs"]
mod support;
use anyhow::{Context, Result};
use connect_core::device::DeviceController;
use std::time::Duration;
use support::{calls, core_calls};

#[path = "support/foreground_pairing.rs"]
mod pairing_support;
use pairing_support::*;

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn embedded_owner_pairs_exact_candidate_then_core_revocation_refuses_refreshed_quic()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (mut owner, _) = owner(root).await?;
    let baseline = core_calls(root, "/join");
    let mut member = candidate(root, &owner)?;
    let (pair, card, mut client, target) = request(&mut owner, &mut member, false).await?;
    for field in ["node", "code", "name", "id"] {
        let mut wrong = target.clone();
        match field {
            "node" => wrong.node = card.host_node.clone(),
            "code" => {
                wrong.comparison_code = if target.comparison_code == "000000" {
                    "000001".into()
                } else {
                    "000000".into()
                }
            }
            "name" => wrong.name = "Other candidate".into(),
            _ => wrong.request_id = uuid::Uuid::new_v4().to_string(),
        }
        assert!(owner.device.prepare_local_pairing(&wrong).await.is_err());
        assert!(
            owner
                .device
                .issue_local_pairing(&mut owner.runtime, &wrong)
                .is_err()
        );
    }
    assert_eq!(
        calls(root, "invite"),
        1,
        "No invitation precedes exact approval"
    );
    owner.device.prepare_local_pairing(&target).await?;
    let completion = owner
        .device
        .issue_local_pairing(&mut owner.runtime, &target)?;
    let issued = grant(client.grant().await?)?;
    let client_flow = member.complete_approved_pairing(&mut client, &card, issued);
    let host_flow = async {
        owner
            .device
            .commit_local_pairing(&target, joined(completion).await?)
            .await
    };
    let (a, b) = tokio::join!(client_flow, host_flow);
    a?;
    b?;
    let own = owner.device.status()?;
    let other = member.status()?;
    assert!(other.authority.is_none() && other.authority_via_bridge && other.sharing_host);
    assert!(own.devices.iter().any(|d| d.node == target.node));
    assert!(other.paired_device.is_some());
    assert_eq!(core_calls(root, "/join"), baseline + 1);
    let other_ticket = ticket(other.ticket.context("Missing member session")?)?;
    let own_ticket = ticket(own.ticket.context("Missing owner session")?)?;
    owner
        .device
        .send(&other_ticket, "Owner to member over real QUIC")
        .await?;
    member
        .send(&own_ticket, "Member to embedded owner over real QUIC")
        .await?;
    let removal = owner.runtime.remove_device(&target.node)?;
    assert!(removal.revoked > 0);
    owner.device.refresh().await?;
    assert!(
        member.refresh().await.is_err(),
        "Refreshed signed core trust refuses revoked membership"
    );
    assert!(
        owner
            .device
            .send(&other_ticket, "Must be refused")
            .await
            .is_err()
    );
    assert!(member.send(&own_ticket, "Must be refused").await.is_err());
    assert_eq!(
        core_calls(root, "/join"),
        baseline + 1,
        "Revocation does not cause re-enrollment"
    );
    stop(&mut owner, &mut member, &pair, &client).await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn decline_never_invites_or_enrolls_and_preserves_the_prepared_identity() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (mut owner, _) = owner(root).await?;
    let baseline = core_calls(root, "/join");
    let mut member = candidate(root, &owner)?;
    let node = member.status()?.node_public_key;
    let (pair, _, mut client, target) = request(&mut owner, &mut member, false).await?;
    owner.device.decline_local_pairing(&target)?;
    assert!(client.grant().await.is_err());
    assert!(pair.pending().is_none());
    assert!(owner.device.decline_local_pairing(&target).is_err());
    assert_eq!(calls(root, "invite"), 1);
    assert_eq!(core_calls(root, "/join"), baseline);
    assert!(member.status()?.certificate_id.is_none());
    stop(&mut owner, &mut member, &pair, &client).await;
    drop(member);
    assert_eq!(
        node,
        DeviceController::open(&root.join("candidate"))?
            .status()?
            .node_public_key
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn lost_native_invitation_reply_fences_the_same_exact_approval_before_another_core_call()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (mut owner, loss) = owner(root).await?;
    let baseline = core_calls(root, "/join");
    let mut member = candidate(root, &owner)?;
    let (pair, _, mut client, target) = request(&mut owner, &mut member, false).await?;
    owner.device.prepare_local_pairing(&target).await?;
    *loss.lock().unwrap() = Some("invite");
    assert!(
        owner
            .device
            .issue_local_pairing(&mut owner.runtime, &target)
            .is_err()
    );
    let mut retried = 0;
    assert!(
        pair.approve_reviewed(&target, || {
            retried += 1;
            anyhow::bail!("Must not dispatch another invitation")
        })
        .is_err()
    );
    assert_eq!(
        retried, 0,
        "An uncertain approval must be consumed before its native/core call"
    );
    assert_eq!(calls(root, "invite"), 2);
    assert_eq!(core_calls(root, "/join"), baseline);
    pair.close().await;
    assert!(client.grant().await.is_err());
    stop(&mut owner, &mut member, &pair, &client).await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn core_revocation_during_join_is_rechecked_before_trusting_or_confirming_candidate()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (mut owner, _) = owner(root).await?;
    let mut member = candidate(root, &owner)?;
    let (pair, card, mut client, target) = request(&mut owner, &mut member, false).await?;
    owner.device.prepare_local_pairing(&target).await?;
    let completion = owner
        .device
        .issue_local_pairing(&mut owner.runtime, &target)?;
    let issued = grant(client.grant().await?)?;
    let own_ticket = member.prepare_approved_pairing(&card, &issued).await?;
    let removed = owner.runtime.remove_device(&target.node)?;
    assert!(removed.revoked > 0);
    member
        .send(
            &issued.session_ticket,
            "Earlier session trust still authenticates before refresh",
        )
        .await?;
    // Both session endpoints still have earlier trust; commit must fetch fresh core state.
    let host = async {
        owner
            .device
            .commit_local_pairing(&target, joined(completion).await?)
            .await
    };
    let (a, b) = tokio::join!(client.finish(ticket(own_ticket)?), host);
    assert!(a.is_err());
    assert!(b.is_err());
    assert!(
        format!("{:#}", b.unwrap_err())
            .to_lowercase()
            .contains("revoked"),
        "Commit must fail on fresh revocation evidence"
    );
    assert!(
        !owner
            .device
            .status()?
            .devices
            .iter()
            .any(|d| d.node == target.node)
    );
    assert!(member.status()?.paired_device.is_none());
    assert_eq!(calls(root, "invite"), 2);
    stop(&mut owner, &mut member, &pair, &client).await;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn unobserved_final_reply_keeps_enrollment_but_does_not_claim_pairing_or_repeat_it()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (mut owner, _) = owner(root).await?;
    let baseline = core_calls(root, "/join");
    let mut member = candidate(root, &owner)?;
    let (pair, card, mut client, target) = request(&mut owner, &mut member, false).await?;
    owner.device.prepare_local_pairing(&target).await?;
    let completion = owner
        .device
        .issue_local_pairing(&mut owner.runtime, &target)?;
    let issued = grant(client.grant().await?)?;
    let mut joining = Box::pin(member.complete_approved_pairing(&mut client, &card, issued));
    let joined = tokio::select! {
        result=joined(completion)=>result?,
        result=&mut joining=> { result?; anyhow::bail!("Pairing completed before host verification") }
    };
    drop(joining); // Application loses the completion response, not its saved credential.
    assert!(member.status()?.certificate_id.is_some());
    assert!(
        member.status()?.paired_device.is_none(),
        "Do not persist a confirmed pair before observing confirmation"
    );
    owner.device.commit_local_pairing(&target, joined).await?;
    stop(&mut owner, &mut member, &pair, &client).await;
    let before = member.status()?;
    drop(member);
    let mut member = DeviceController::open(&root.join("candidate"))?;
    assert_eq!(before.node_public_key, member.status()?.node_public_key);
    assert_eq!(before.certificate_id, member.status()?.certificate_id);
    assert!(member.request_pairing(card, "Retry".into()).await.is_err());
    assert!(member.enroll_host("must-not-be-used").await.is_err());
    assert_eq!(calls(root, "invite"), 2);
    assert_eq!(core_calls(root, "/join"), baseline + 1);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires the disposable pinned-core foreground fixture"]
async fn interrupted_enrollment_blocks_a_fresh_ceremony_until_the_saved_outcome_is_reviewed()
-> Result<()> {
    use std::{future::Future, task::Poll};
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let (mut owner, _) = owner(root).await?;
    let mut member = candidate(root, &owner)?;
    let node = member.status()?.node_public_key;
    let (pair, _, client, target) = request(&mut owner, &mut member, false).await?;
    owner.device.prepare_local_pairing(&target).await?;
    let _completion = owner
        .device
        .issue_local_pairing(&mut owner.runtime, &target)?;
    let mut client = client;
    let issued = grant(client.grant().await?)?;
    member.use_bridge(issued.route).await?;
    {
        let mut enrollment = Box::pin(member.enroll_host(&issued.invitation));
        std::future::poll_fn(|context| {
            assert!(matches!(enrollment.as_mut().poll(context), Poll::Pending));
            Poll::Ready(())
        })
        .await;
    }
    assert!(member.status()?.enrollment_pending);
    let joins_before_retry = core_calls(root, "/join");
    client.close().await;
    pair.close().await;
    let next = owner.device.create_pairing("Fresh ceremony".into()).await?;
    let card = serde_json::from_value(loopback(serde_json::to_value(next.card())?)?)?;
    assert!(
        member
            .request_pairing(card, "Retry uncertain device".into())
            .await
            .is_err()
    );
    assert_eq!(node, member.status()?.node_public_key);
    assert!(member.enroll_host("must-not-be-used").await.is_err());
    assert_eq!(
        core_calls(root, "/join"),
        joins_before_retry,
        "Pending enrollment blocks another core join attempt"
    );
    assert_eq!(calls(root, "invite"), 2);
    next.close().await;
    member.stop().await;
    owner.device.stop().await;
    Ok(())
}
