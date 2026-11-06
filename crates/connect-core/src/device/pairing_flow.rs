//! Shared native local-owner and joining-device ceremony; no administrative delegation.
use super::{DeviceController, PairedDevice};
use crate::{
    owner::OwnerRuntime,
    owner_control::{OwnerAction, PairingTarget},
    session::{
        bridge::BridgeRoute,
        pairing::{Joined, PairCard, PairClient, PairGrant},
    },
};
use anyhow::{Context, Result, ensure};

impl DeviceController {
    pub async fn prepare_local_pairing(&mut self, target: &PairingTarget) -> Result<()> {
        ensure!(
            self.network_computer(),
            "Approve devices from their authority host"
        );
        let pair = self.pairing().context("No open pairing")?;
        OwnerAction::ApprovePairing(target.clone())
            .require_pending(&pair.pending().context("No pending device")?)?;
        self.start(&target.node).await
    }

    /// Blocking native owner call; callers use a worker thread. Approval applies
    /// to the exact reviewed ID, key, name and comparison code under the gate.
    pub fn issue_local_pairing(
        &mut self,
        owner: &mut OwnerRuntime,
        target: &PairingTarget,
    ) -> Result<tokio::sync::oneshot::Receiver<Joined>> {
        ensure!(
            self.network_computer(),
            "Approve devices from their authority host"
        );
        let status = self.status()?;
        let pair = self.pairing().context("No open pairing")?;
        let recoverable = pair.completion_requested(target)?;
        pair.approve_reviewed(target, || {
            owner.pairing_ready(self.vault.pin())?;
            self.make_pairing_grant(
                owner,
                target,
                BridgeRoute {
                    host_node: status.node_public_key,
                    ticket: status.bridge_ticket.context("Missing authority bridge")?,
                },
                status.ticket.context("Missing host session")?,
                recoverable,
            )
        })
    }
    pub(crate) fn make_pairing_grant(
        &mut self,
        owner: &mut OwnerRuntime,
        target: &PairingTarget,
        route: BridgeRoute,
        session_ticket: String,
        recoverable: bool,
    ) -> Result<PairGrant> {
        let completion = if recoverable {
            let reference = super::pairing_completion::CompletionReference::issue(
                self.vault.pin().clone(),
                target.clone(),
                &session_ticket,
                &self.vault.key(),
            )?;
            // Durable reservation precedes invitation. A lost invite reply never
            // upgrades this reservation into a committed relationship.
            self.vault.reserve_completion(reference.clone())?;
            Some(reference)
        } else {
            None
        };
        Ok(PairGrant {
            invitation: owner.invite(&target.node, true)?,
            route,
            session_ticket,
            completion,
        })
    }
    pub(crate) fn remember_approved_pairing(
        &mut self,
        target: &PairingTarget,
        digest: Option<&str>,
        peer: PairedDevice,
    ) -> Result<()> {
        if let Some(digest) = digest {
            let evidence = self.vault.host_completion(digest)?;
            ensure!(
                &evidence.reference.target == target
                    && peer.node == target.node
                    && peer.name == target.name,
                "Completion evidence belongs to another original pairing"
            );
            ensure!(
                self.vault.peer() == Some(target.node.as_str()),
                "Pairing does not match the selected identity"
            );
            self.vault
                .save_completed_pairing(peer, Some(digest), true)?;
            self.publish_members();
            Ok(())
        } else {
            self.remember_pairing(peer)
        }
    }

    pub fn decline_local_pairing(&self, target: &PairingTarget) -> Result<()> {
        ensure!(
            self.network_computer(),
            "Decline devices from their authority host"
        );
        self.pairing()
            .context("No open pairing")?
            .reject_reviewed(target)
    }

    pub async fn commit_local_pairing(
        &mut self,
        target: &PairingTarget,
        joined: Joined,
    ) -> Result<()> {
        let verified = async {
            let proof = self
                .session()?
                .prove_pairing_to(&target.node, &joined.ticket)
                .await?;
            self.current_pairing_trust(&proof, &target.node).await?;
            // No await between the fresh trust check and the native commit.
            self.remember_approved_pairing(
                target,
                joined.completion_digest.as_deref(),
                PairedDevice {
                    name: target.name.clone(),
                    node: target.node.clone(),
                    ticket: joined.ticket.clone(),
                },
            )
        }
        .await;
        if let Err(error) = verified {
            let _ = joined.confirm.send(false);
            return Err(error);
        }
        joined
            .confirm
            .send(true)
            .map_err(|_| anyhow::anyhow!("Joining confirmation was lost"))
    }

    /// Save enrollment before network proof. A failed final reply must never
    /// become a reason to generate another identity or repeat enrollment.
    pub async fn prepare_approved_pairing(
        &mut self,
        card: &PairCard,
        grant: &PairGrant,
    ) -> Result<String> {
        ensure!(
            self.device.is_none() && !self.vault.pending(),
            "Existing or uncertain enrollment must not be repeated"
        );
        ensure!(
            self.vault.pin() == &card.pin && grant.route.host_node == card.host_node,
            "Pairing grant belongs to another authority host"
        );
        if let Some(reference) = &grant.completion {
            super::pairing_completion::qualified()?;
            let node = self.status()?.node_public_key;
            reference.require_scope(self.vault.pin(), &card.host_node, &node)?;
            ensure!(
                crate::session::ticket_endpoint(&grant.session_ticket)?.to_string()
                    == reference.host_endpoint,
                "Original host endpoint changed"
            );
            self.vault
                .save_client_completion(reference.clone(), card.host_name.clone())?;
        }
        self.use_bridge(grant.route.clone()).await?;
        self.enroll_host(&grant.invitation).await?;
        self.start(&card.host_node).await?;
        self.send(&grant.session_ticket, "Connect pairing verification")
            .await?;
        self.status()?
            .ticket
            .context("Device connection is unavailable")
    }

    pub async fn complete_approved_pairing(
        &mut self,
        pairing: &mut PairClient,
        card: &PairCard,
        grant: PairGrant,
    ) -> Result<()> {
        pairing.require_grant(&grant)?;
        let ticket = self.prepare_approved_pairing(card, &grant).await?;
        let peer = PairedDevice {
            name: card.host_name.clone(),
            node: card.host_node.clone(),
            ticket: grant.session_ticket,
        };
        if let Some(reference) = &grant.completion {
            pairing.finish(ticket).await?;
            self.vault
                .save_completed_pairing(peer, Some(&reference.digest()?), false)?;
            self.publish_members();
            Ok(())
        } else {
            // Legacy peers have no exact completion readback. Retain the
            // approved host's connection before sending Finished, as on the
            // compatible ordinary path. It is a reconnect route, not proof that
            // the host received Finished. The final reply still decides this
            // ceremony's result; later traffic rechecks current core trust.
            let proof = self
                .session()?
                .prove_pairing_to(&card.host_node, &peer.ticket)
                .await?;
            let trust = self
                .bridge_client
                .as_ref()
                .context("Missing original authority bridge")?
                .refresh(&mut self.trust)
                .await?;
            let own = self
                .device
                .as_ref()
                .context("Missing original membership")?;
            trust.certificate(own.certificate(), &own.public_key(), chrono::Utc::now())?;
            proof.require_current(&trust, &card.host_node)?;
            self.remember_pairing(peer)?;
            pairing.finish(ticket).await.context(
                "The connection was saved but final pairing confirmation was not received. Reconnect the saved device; do not enroll again",
            )
        }
    }
}
