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
        &self,
        owner: &mut OwnerRuntime,
        target: &PairingTarget,
    ) -> Result<tokio::sync::oneshot::Receiver<Joined>> {
        ensure!(
            self.network_computer(),
            "Approve devices from their authority host"
        );
        let status = self.status()?;
        let pair = self.pairing().context("No open pairing")?;
        pair.approve_reviewed(target, || {
            owner.pairing_ready(self.vault.pin())?;
            Ok(PairGrant {
                invitation: owner.invite(&target.node, true)?,
                route: BridgeRoute {
                    host_node: status.node_public_key,
                    ticket: status.bridge_ticket.context("Missing authority bridge")?,
                },
                session_ticket: status.ticket.context("Missing host session")?,
            })
        })
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
            self.remember_pairing(PairedDevice {
                name: target.name.clone(),
                node: target.node.clone(),
                ticket: joined.ticket.clone(),
            })
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
        let ticket = self.prepare_approved_pairing(card, &grant).await?;
        pairing.finish(ticket).await?;
        self.remember_pairing(PairedDevice {
            name: card.host_name.clone(),
            node: card.host_node.clone(),
            ticket: grant.session_ticket,
        })
    }
}
