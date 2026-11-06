//! Native client workflow. No mutation IPC, presence bypass or pairing dispatch.
use super::{AdministrativeKey, DeviceController, admin_vault};
use crate::owner_control::{
    CLIENT_ENROLLMENT_FILE, ClientEnrollment, ClientEnrollmentView, EnrollmentBinding,
    EnrollmentRequest,
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;

impl DeviceController {
    /// An absent request is not initialized by inspection. An existing marker,
    /// missing key or invalid journal remains a recovery error, never "empty".
    pub fn retained_owner_enrollment(&self) -> Result<Option<ClientEnrollmentView>> {
        self.require_connected()?;
        ensure!(
            self.device.is_some() && self.bridge_client.is_some() && !self.network_computer(),
            "Use Requests on a joined device connected through its network computer"
        );
        if !ClientEnrollment::initialized(&self.state_directory.join(CLIENT_ENROLLMENT_FILE))? {
            return Ok(None);
        }
        self.saved_owner_enrollment().map(Some)
    }
    async fn current_enrollment_binding(&mut self) -> Result<EnrollmentBinding> {
        let expected = self.enrollment_binding()?;
        let trust = self.refresh_inner(false).await?;
        let own = self.device.as_ref().context("Join this device first")?;
        // No endpoint is required after restart, so validate the actual member
        // explicitly rather than relying on an endpoint refresh to do it.
        trust.certificate(own.certificate(), &own.public_key(), Utc::now())?;
        ensure!(
            self.enrollment_binding()? == expected,
            "Native enrollment context changed during membership refresh"
        );
        Ok(expected)
    }
    fn enrollment_binding(&self) -> Result<EnrollmentBinding> {
        self.require_connected()?;
        ensure!(
            self.device.is_some() && self.bridge_client.is_some() && !self.network_computer(),
            "Use client enrollment on an already joined device with its paired network computer"
        );
        let binding = self.administrative_binding()?;
        // Opening validates the current native credential. Resume never creates it.
        let key = AdministrativeKey::open(&self.state_directory.join(admin_vault::FILE), &binding)?;
        Ok(EnrollmentBinding {
            scope: binding.scope,
            controller_node: binding.controller_node,
            administrative_key: key.public_key().into(),
        })
    }
    /// Retain the exact native-prepared request after review, before any send.
    /// Trusted application entrypoints must still supply qualified native user
    /// presence. This library method is deliberately not registered as app IPC.
    pub async fn retain_owner_enrollment(
        &mut self,
        request: EnrollmentRequest,
        reviewed_digest: &str,
    ) -> Result<ClientEnrollmentView> {
        let binding = self.current_enrollment_binding().await?;
        Ok(ClientEnrollment::create(
            &self.state_directory.join(CLIENT_ENROLLMENT_FILE),
            binding,
            request,
            reviewed_digest,
            Utc::now(),
        )?
        .view())
    }
    /// Inspect retained native work without creating a key, ID or enrollment.
    /// Submitted work reopens as uncertain until an authenticated status check.
    pub fn saved_owner_enrollment(&self) -> Result<ClientEnrollmentView> {
        let binding = self.enrollment_binding()?;
        Ok(ClientEnrollment::open(
            &self.state_directory.join(CLIENT_ENROLLMENT_FILE),
            &binding,
            Utc::now(),
        )?
        .view())
    }
    /// One explicitly reviewed initial send. Reservation precedes the transport;
    /// a lost reply or restart permits status checks only, never a second send.
    pub async fn submit_owner_enrollment(
        &mut self,
        reviewed_digest: &str,
    ) -> Result<ClientEnrollmentView> {
        self.enrollment_exchange(Some(reviewed_digest)).await
    }
    pub async fn check_owner_enrollment(&mut self) -> Result<ClientEnrollmentView> {
        self.enrollment_exchange(None).await
    }
    async fn enrollment_exchange(
        &mut self,
        reviewed_digest: Option<&str>,
    ) -> Result<ClientEnrollmentView> {
        let binding = self.current_enrollment_binding().await?;
        let mut workflow = ClientEnrollment::open(
            &self.state_directory.join(CLIENT_ENROLLMENT_FILE),
            &binding,
            Utc::now(),
        )?;
        let call = if let Some(digest) = reviewed_digest {
            workflow.reserve_submission(digest, Utc::now())?
        } else {
            workflow.status_query(Utc::now())?
        };
        let reply = self.owner_control_exchange(call.envelope()).await;
        ensure!(
            self.current_enrollment_binding().await? == binding,
            "Native enrollment context changed during the exchange; saved work was preserved"
        );
        match reply {
            Ok(value) => workflow.record_reply(call, value, Utc::now()),
            Err(_) => Ok(workflow.view()), // Durable uncertainty, not a claimed refusal or implicit retry.
        }
    }
}
