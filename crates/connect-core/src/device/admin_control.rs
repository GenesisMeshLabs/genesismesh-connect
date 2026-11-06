//! Native preparation only; neither a UI signing oracle nor a remote grant.
use super::{AdministrativeBinding, AdministrativeKey, DeviceController, admin_vault};
use crate::owner_control::{
    CommandIntent, ControlScope, EnrollmentIntent, EnrollmentRequest, Grant, OwnerAction,
    OwnerCommand, Permission,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use std::collections::BTreeSet;

impl DeviceController {
    pub(crate) async fn local_admin_scope(&mut self) -> Result<ControlScope> {
        self.current_owner_trust().await?;
        Ok(self.host_control_path()?.1)
    }
    pub(crate) fn local_admin_enabled(&self) -> Result<bool> {
        let (path, _) = self.host_control_path()?;
        if path.try_exists()? || path.with_extension("owner-control-lock").try_exists()? {
            self.open_owner_requests()?; // Missing initialized/corrupt state is never "off".
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn host_control_path(&self) -> Result<(std::path::PathBuf, ControlScope)> {
        ensure!(
            self.network_computer(),
            "Use Requests on the authority host"
        );
        Ok((
            self.state_directory.join("owner-control.json"),
            self.administrative_binding()?.scope,
        ))
    }
    /// Explicit local enablement. No request or reopen may initialize this registry.
    pub fn enable_owner_requests(&self) -> Result<()> {
        let (path, scope) = self.host_control_path()?;
        crate::owner_control::HostControl::create(&path, scope)?;
        Ok(())
    }
    /// Local native review surface; never offered on the member transport.
    pub fn open_owner_requests(&self) -> Result<crate::owner_control::HostControl> {
        let (path, scope) = self.host_control_path()?;
        crate::owner_control::HostControl::open(&path, scope)
    }
    pub async fn answer_owner_control(
        &mut self,
        owner: &mut crate::owner::OwnerRuntime,
        node: &str,
        certificate: &serde_json::Value,
        request: crate::owner_control::ControlEnvelope,
    ) -> Result<serde_json::Value> {
        let mut control = self.open_owner_requests()?;
        Ok(serde_json::to_value(
            control
                .answer(owner, self, node, certificate, request)
                .await?,
        )?)
    }
    pub async fn owner_control_exchange(
        &mut self,
        request: &crate::owner_control::ControlEnvelope,
    ) -> Result<crate::owner_control::ControlReply> {
        self.require_connected()?;
        let trust = self.refresh_inner(false).await?;
        let identity = self
            .device
            .as_ref()
            .context("Join this device first")?
            .session_identity()?;
        self.bridge_client
            .as_ref()
            .context("Use Requests locally on the network computer")?
            .owner_control(identity, trust, request)
            .await
    }
    pub async fn verify_owner_controller(
        &mut self,
        certificate: &serde_json::Value,
        node: &str,
    ) -> Result<crate::owner_control::VerifiedController> {
        let trust = self.current_owner_trust().await?;
        crate::owner_control::VerifiedController::from_session(
            &self.administrative_binding()?.scope,
            &trust,
            certificate,
            node,
            Utc::now(),
        )
    }
    pub(crate) async fn verify_pairing_commit(
        &mut self,
        certificate: &serde_json::Value,
        controller: &str,
        candidate: &crate::session::AuthenticatedPeer,
        candidate_node: &str,
    ) -> Result<crate::owner_control::VerifiedController> {
        // The same newly fetched snapshot covers host, controller and the exact
        // authenticated candidate. No retained session snapshot authorizes commit.
        let trust = self.current_owner_trust().await?;
        candidate.require_current(&trust, candidate_node)?;
        crate::owner_control::VerifiedController::from_session(
            &self.administrative_binding()?.scope,
            &trust,
            certificate,
            controller,
            Utc::now(),
        )
    }
    async fn current_owner_trust(&mut self) -> Result<crate::session::TrustSnapshot> {
        self.require_connected()?;
        ensure!(
            self.network_computer(),
            "This device is not the authority host"
        );
        // Validate against the current authority without republishing bridge
        // credentials: republishing cancels the very QUIC request being checked.
        // Periodic lifecycle maintenance still renews and publishes separately.
        let trust = self
            .authority
            .as_ref()
            .context("Authority host is unavailable")?
            .refresh(&mut self.trust)
            .await?;
        let own = self
            .device
            .as_ref()
            .context("Enroll the authority host first")?;
        trust.certificate(own.certificate(), &own.public_key(), Utc::now())?;
        Ok(trust)
    }
    pub(super) fn administrative_binding(&self) -> Result<AdministrativeBinding> {
        let node = STANDARD.encode(self.vault.key().verifying_key().to_bytes());
        let host = if self.network_computer() {
            node.clone()
        } else {
            self.vault
                .bridge_route()
                .context(
                    "Pair this device with its network computer before requesting administration",
                )?
                .host_node
                .clone()
        };
        Ok(AdministrativeBinding {
            scope: ControlScope {
                pin: self.vault.pin().clone(),
                host_node: host,
            },
            controller_node: node,
        })
    }
    /// Explicit enrollment preparation, not approval. This is the only native
    /// path that may create the separate key; no raw identity overrides.
    pub async fn prepare_owner_enrollment(
        &mut self,
        permissions: BTreeSet<Permission>,
        validity_seconds: u32,
    ) -> Result<EnrollmentRequest> {
        ensure!(
            !permissions.is_empty() && validity_seconds > 120 && validity_seconds <= 30 * 24 * 3600,
            "Choose pairing permissions and administrative access of at most 30 days"
        );
        ensure!(
            !crate::owner_control::ClientEnrollment::initialized(
                &self
                    .state_directory
                    .join(crate::owner_control::CLIENT_ENROLLMENT_FILE)
            )?,
            "Resume the saved administrative enrollment; no replacement request or key was created"
        );
        self.require_connected()?;
        self.check_network().await?;
        ensure!(
            self.device.is_some(),
            "Join this device to its network before requesting administration"
        );
        let binding = self.administrative_binding()?;
        let path = self.state_directory.join(admin_vault::FILE);
        let key = if path.try_exists()? {
            AdministrativeKey::open(&path, &binding)?
        } else {
            AdministrativeKey::create(&path, binding.clone())?
        };
        let now = Utc::now();
        key.sign_enrollment(EnrollmentIntent {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            scope: binding.scope,
            controller_node: binding.controller_node,
            administrative_key: key.public_key().into(),
            permissions,
            created_at: now,
            expires_at: now + Duration::seconds(120),
            grant_expires_at: now + Duration::seconds(validity_seconds.into()),
        })
    }
    /// Preparation after exact user review belongs in the eventual trusted
    /// workflow adapter. The host must independently check its real grant,
    /// current membership, target and core rights. This method dispatches nothing.
    pub async fn prepare_owner_command(
        &mut self,
        grant: &Grant,
        action: OwnerAction,
    ) -> Result<OwnerCommand> {
        self.require_connected()?;
        self.check_network().await?;
        ensure!(
            self.device.is_some(),
            "Join this device to its network before requesting administration"
        );
        let binding = self.administrative_binding()?;
        let enrollment = &grant.enrollment.intent;
        ensure!(
            enrollment.scope == binding.scope
                && enrollment.controller_node == binding.controller_node
                && grant.approval_digest == grant.enrollment.digest()?,
            "Administrative enrollment belongs to a different network, host or device"
        );
        let now = Utc::now();
        ensure!(
            grant.revoked_at.is_none()
                && grant.approved_at <= now
                && now < enrollment.grant_expires_at,
            "Administrative access expired or was revoked"
        );
        ensure!(
            enrollment.permissions.contains(&action.permission()),
            "This enrollment does not allow that pairing operation"
        );
        let key = AdministrativeKey::open(&self.state_directory.join(admin_vault::FILE), &binding)?;
        ensure!(
            key.public_key() == enrollment.administrative_key,
            "Administrative key changed; enroll this device again on its network computer"
        );
        key.sign_command(CommandIntent {
            version: 1,
            grant_id: enrollment.id.clone(),
            nonce: uuid::Uuid::new_v4().to_string(),
            scope: binding.scope,
            controller_node: binding.controller_node,
            action,
            created_at: now,
            expires_at: std::cmp::min(now + Duration::seconds(120), enrollment.grant_expires_at),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority::{LocalAuthority, TrustStore},
        owner::OwnerRuntime,
        owner_control::{ControlStore, VerifiedController},
    };
    #[tokio::test]
    #[ignore = "Requires pinned CONNECT_NA_PYTHON and isolated native credential store"]
    async fn real_controller_prepares_scoped_native_signatures_and_preserves_identity_across_restart()
    -> Result<()> {
        let dir = tempfile::tempdir()?;
        let profile = dir.path().join("device");
        let python = std::env::var_os("CONNECT_NA_PYTHON").context("Set CONNECT_NA_PYTHON")?;
        let mut owner = OwnerRuntime::start_python(
            std::path::Path::new(&python),
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../apps/connect/authority/main.py"),
            &dir.path().join("owner"),
        )?;
        let info = owner.create("Native owner preparation")?;
        let mut device = DeviceController::prepare(&profile, info.url.clone(), info.pin.clone())?;
        device.enable_managed_connectivity()?;
        assert!(
            device
                .prepare_owner_enrollment([Permission::ListPairing].into_iter().collect(), 600)
                .await
                .is_err()
        );
        assert!(!profile.join(admin_vault::FILE).exists());
        let node = device.status()?.node_public_key;
        device.enroll_host(&owner.invite(&node, true)?).await?;
        let enrollment = device
            .prepare_owner_enrollment([Permission::ListPairing].into_iter().collect(), 600)
            .await?;
        assert_eq!(enrollment.intent.controller_node, node);
        assert_eq!(enrollment.intent.scope.pin, info.pin);
        assert_eq!(enrollment.intent.scope.host_node, node);
        assert_ne!(enrollment.intent.administrative_key, node);
        let admin_public = enrollment.intent.administrative_key.clone();
        let recovery = device.recovery_identity()?;
        assert!(!std::str::from_utf8(&recovery.vault)?.contains("administrative-key"));
        assert!(!std::str::from_utf8(&recovery.vault)?.contains(&admin_public));
        let authority = LocalAuthority::new(&info.url)?;
        let mut trust = TrustStore::create(&dir.path().join("host-trust.json"), info.pin)?;
        let snapshot = authority.refresh(&mut trust).await?;
        let now = Utc::now();
        let peer = VerifiedController::from_session(
            &enrollment.intent.scope,
            &snapshot,
            device
                .device
                .as_ref()
                .context("Missing device")?
                .certificate(),
            &node,
            now,
        )?;
        let mut registry = ControlStore::create(
            &dir.path().join("controls.json"),
            enrollment.intent.scope.clone(),
            now,
        )?;
        let digest = enrollment.digest()?;
        let grant = registry.enroll_locally(enrollment, &digest, &peer, now)?;
        let command = device
            .prepare_owner_command(&grant, OwnerAction::ListPairing)
            .await?;
        let current_snapshot = authority.refresh(&mut trust).await?;
        let now = Utc::now();
        let peer = VerifiedController::from_session(
            &grant.enrollment.intent.scope,
            &current_snapshot,
            device
                .device
                .as_ref()
                .context("Missing device")?
                .certificate(),
            &node,
            now,
        )?;
        registry.reserve(&command, &peer, now)?;
        let before = std::fs::read(profile.join(admin_vault::FILE))?;
        drop(device);
        let mut device = DeviceController::open(&profile)?;
        assert_eq!(device.status()?.node_public_key, node);
        let again = device
            .prepare_owner_enrollment([Permission::ListPairing].into_iter().collect(), 600)
            .await?;
        assert_eq!(again.intent.administrative_key, admin_public);
        assert_eq!(std::fs::read(profile.join(admin_vault::FILE))?, before);
        device.disconnect().await?;
        assert!(
            device
                .prepare_owner_command(&grant, OwnerAction::ListPairing)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(profile.join(admin_vault::FILE))?, before);
        device.discard()?;
        assert!(!profile.exists());
        Ok(())
    }
}
