//! Native host coordinator. There is no generic admin proxy or remote local-approval route.
use super::*;
use crate::{
    device::{DeviceController, PairedDevice},
    owner::OwnerRuntime,
    session::{bridge::BridgeRoute, pairing::PairGrant},
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use serde_json::Value;
use std::path::Path;

pub struct HostControl {
    store: ControlStore,
    scope: ControlScope,
}
impl HostControl {
    /// Explicit native opt-in. Opening/receiving remote requests never creates state.
    pub fn create(path: &Path, scope: ControlScope) -> Result<Self> {
        Ok(Self {
            store: ControlStore::create(path, scope.clone(), Utc::now())?,
            scope,
        })
    }
    pub fn open(path: &Path, scope: ControlScope) -> Result<Self> {
        // ControlStore's exclusive-lock marker fences loss after initialization.
        // A remote probe must never create that marker on an unconfigured host.
        ensure!(
            path.try_exists()?,
            "Enable pairing Requests locally on the authority host first"
        );
        Ok(Self {
            store: ControlStore::open(path, &scope)?,
            scope,
        })
    }
    pub fn pending_locally(&self) -> Vec<PendingEnrollment> {
        self.store.pending_enrollments(Utc::now())
    }
    pub fn grants_locally(&self) -> &[Grant] {
        self.store.grants()
    }
    pub async fn approve_locally(
        &mut self,
        device: &mut DeviceController,
        id: &str,
        reviewed_digest: &str,
    ) -> Result<Grant> {
        let pending = self
            .pending_locally()
            .into_iter()
            .find(|p| p.request.intent.id == id)
            .context("Enrollment is no longer waiting")?;
        ensure!(
            pending.request.digest()? == reviewed_digest,
            "Enrollment changed after review"
        );
        let peer = device
            .verify_owner_controller(
                &pending.certificate,
                &pending.request.intent.controller_node,
            )
            .await?;
        self.store.check_peer(&peer, Utc::now())?;
        self.store
            .enroll_locally(pending.request, reviewed_digest, &peer, Utc::now())
    }
    pub fn decline_locally(&mut self, id: &str, reviewed_digest: &str) -> Result<()> {
        self.store.decline_locally(id, reviewed_digest, Utc::now())
    }
    pub fn revoke_locally(&mut self, id: &str) -> Result<()> {
        self.store.revoke_locally(id, Utc::now())
    }
    /// Called with identities from the authenticated bridge, not deserialized
    /// request identities. The host's outer lock serializes local and remote
    /// operations; this store's exclusive native lock lasts through dispatch.
    pub async fn answer(
        &mut self,
        owner: &mut OwnerRuntime,
        device: &mut DeviceController,
        node: &str,
        certificate: &Value,
        envelope: ControlEnvelope,
    ) -> Result<ControlReply> {
        ensure!(
            envelope.version == 1 && serde_json::to_vec(&envelope)?.len() <= 16 * 1024,
            "Unsupported or oversized owner Requests envelope"
        );
        let peer = device.verify_owner_controller(certificate, node).await?;
        self.store.check_peer(&peer, Utc::now())?;
        match envelope.request {
            ControlExchange::Enroll { request } => Ok(ControlReply::Enrollment(
                self.store
                    .request_enrollment(request, certificate.clone(), &peer, Utc::now())?,
            )),
            ControlExchange::EnrollmentStatus { id } => {
                super::protocol::uuid_id(&id)?;
                Ok(ControlReply::Enrollment(self.store.enrollment_state(
                    node,
                    &id,
                    Utc::now(),
                )))
            }
            ControlExchange::Result { nonce, digest } => {
                super::protocol::uuid_id(&nonce)?;
                ensure!(digest.len() <= 128, "Invalid request digest");
                Ok(ControlReply::Result(self.store.checked_result(
                    &peer,
                    &nonce,
                    &digest,
                    Utc::now(),
                )?))
            }
            ControlExchange::Execute { command } => {
                let reserved = self.store.reserve(&command, &peer, Utc::now())?;
                let result = self
                    .dispatch(owner, device, node, certificate, &command, &reserved)
                    .await?;
                self.store.record_result(
                    reserved.nonce(),
                    reserved.digest(),
                    result.clone(),
                    Utc::now(),
                )?;
                Ok(ControlReply::Result(result))
            }
        }
    }
    async fn dispatch(
        &mut self,
        owner: &mut OwnerRuntime,
        device: &mut DeviceController,
        node: &str,
        certificate: &Value,
        command: &OwnerCommand,
        reserved: &Reservation,
    ) -> Result<ControlResult> {
        match reserved.action() {
            OwnerAction::ListPairing => {
                owner.pairing_ready(&self.scope.pin)?;
                let peer = device.verify_owner_controller(certificate, node).await?;
                self.require_dispatch(&peer, command)?;
                let request = device
                    .pairing()
                    .and_then(|p| p.pending())
                    .map(|r| PairingTarget::from_pending(&r));
                Ok(ControlResult::PairingList { request })
            }
            action @ (OwnerAction::ApprovePairing(target) | OwnerAction::RejectPairing(target)) => {
                let pair = device.pairing().context("No join request is open")?;
                // Refuse an old PairHost before preparing a transport or calling core.
                action.require_pending(&pair.pending().context("No device is waiting")?)?;
                let approve = matches!(action, OwnerAction::ApprovePairing(_));
                let route = if approve {
                    device.start(&target.node).await?;
                    let status = device.status()?;
                    Some((
                        BridgeRoute {
                            host_node: status.node_public_key,
                            ticket: status
                                .bridge_ticket
                                .context("Authority connection is unavailable")?,
                        },
                        status.ticket.context("Device connection is unavailable")?,
                    ))
                } else {
                    None
                };
                let peer = device.verify_owner_controller(certificate, node).await?;
                let completion = pair.control_dispatch(action, || {
                    owner.pairing_ready(&self.scope.pin)?;
                    self.require_dispatch(&peer, command)?;
                    let grant = if let Some((route, session_ticket)) = route {
                        Some(PairGrant {
                            invitation: owner.invite(&target.node, true)?,
                            route,
                            session_ticket,
                        })
                    } else {
                        None
                    };
                    self.require_dispatch(&peer, command)?;
                    Ok(grant)
                })?;
                let Some(completion) = completion else {
                    return Ok(ControlResult::Rejected {
                        node: target.node.clone(),
                    });
                };
                self.store.record_result(
                    reserved.nonce(),
                    reserved.digest(),
                    ControlResult::Started,
                    Utc::now(),
                )?;
                let joined = tokio::time::timeout(std::time::Duration::from_secs(80), completion)
                    .await
                    .context("Joining is unconfirmed; read its result without resending")?
                    .context("The joining device disconnected; do not resend approval")?;
                let commit = async {
                    let proof = device
                        .session()?
                        .prove_pairing_to(&target.node, &joined.ticket)
                        .await?;
                    // Enrollment may have taken time. Verify the exact peer
                    // certificate against fresh core state, along with the host
                    // and controller, immediately before synchronous commit.
                    let peer = device
                        .verify_pairing_commit(certificate, node, &proof, &target.node)
                        .await?;
                    self.store.checked_result(
                        &peer,
                        reserved.nonce(),
                        reserved.digest(),
                        Utc::now(),
                    )?;
                    device.remember_pairing(PairedDevice {
                        name: target.name.clone(),
                        node: target.node.clone(),
                        ticket: joined.ticket.clone(),
                    })
                }
                .await;
                if let Err(error) = commit {
                    let _ = joined.confirm.send(false);
                    self.store.record_result(
                        reserved.nonce(),
                        reserved.digest(),
                        ControlResult::Unconfirmed,
                        Utc::now(),
                    )?;
                    return Err(error);
                }
                joined
                    .confirm
                    .send(true)
                    .map_err(|_| anyhow::anyhow!("Joining confirmation was lost"))?;
                // Delivery grace matches the existing local pairing ceremony.
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    pair.close().await;
                });
                Ok(ControlResult::Approved {
                    node: target.node.clone(),
                })
            }
        }
    }
    fn require_dispatch(&self, peer: &VerifiedController, command: &OwnerCommand) -> Result<()> {
        let now = Utc::now();
        super::protocol::live(command.intent.created_at, command.intent.expires_at, now)?;
        self.store
            .checked_result(peer, &command.intent.nonce, &command.digest()?, now)?;
        Ok(())
    }
}
