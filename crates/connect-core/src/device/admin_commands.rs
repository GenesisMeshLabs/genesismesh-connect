//! Native qualification coordinator. No command registration or generic signing IPC.
use super::DeviceController;
use crate::owner_control::{
    CLIENT_COMMAND_FILE, ClientCommandPresence, ClientCommandStatus, ClientCommandView,
    ClientCommands, CommandBinding, ControlEnvelope, ControlExchange, ControlReply,
    EnrollmentState, Grant, OwnerAction, commands_qualified, same_active_grant,
};
use anyhow::{Result, ensure};
use chrono::Utc;
impl DeviceController {
    async fn command_binding(&mut self) -> Result<CommandBinding> {
        commands_qualified()?;
        Ok(CommandBinding {
            profile_id: self.vault.storage_id().into(),
            enrollment: self.current_enrollment_binding().await?,
        })
    }
    async fn command_grant(&mut self, binding: &CommandBinding) -> Result<Grant> {
        let saved = self.saved_owner_enrollment()?;
        let reply = self
            .owner_control_exchange(&ControlEnvelope {
                version: 1,
                request: ControlExchange::EnrollmentStatus {
                    id: saved.request.intent.id.clone(),
                },
            })
            .await?;
        let ControlReply::Enrollment(EnrollmentState::Active { grant }) = reply else {
            anyhow::bail!("Administrative grant is not currently active")
        };
        ensure!(
            grant.enrollment.digest()? == saved.request.digest()?
                && grant.enrollment.intent.scope == binding.enrollment.scope
                && grant.enrollment.intent.controller_node == binding.enrollment.controller_node
                && grant.enrollment.intent.administrative_key
                    == binding.enrollment.administrative_key,
            "Host returned another administrative enrollment"
        );
        same_active_grant(&grant, &grant, Utc::now())?;
        Ok(grant)
    }
    /// One explicit native review. Unresolved work is checked, never replaced.
    pub async fn review_owner_action(&mut self, action: OwnerAction) -> Result<ClientCommandView> {
        let binding = self.command_binding().await?;
        let mut saved = ClientCommands::open(
            &self.state_directory.join(CLIENT_COMMAND_FILE),
            &binding,
            true,
            Utc::now(),
        )?;
        saved.require_new()?;
        let grant = self.command_grant(&binding).await?;
        let command = self.prepare_owner_command(&grant, action).await?;
        ensure!(
            self.command_binding().await? == binding,
            "Native command context changed during preparation"
        );
        saved.retain(grant, command, Utc::now())
    }
    pub fn saved_owner_action(&self) -> Result<ClientCommandView> {
        commands_qualified()?;
        let binding = CommandBinding {
            profile_id: self.vault.storage_id().into(),
            enrollment: self.enrollment_binding()?,
        };
        ClientCommands::open(
            &self.state_directory.join(CLIENT_COMMAND_FILE),
            &binding,
            false,
            Utc::now(),
        )?
        .view()
    }
    /// Production has no qualified implementation or mutation IPC for this seam.
    pub async fn submit_owner_action(
        &mut self,
        digest: &str,
        presence: &mut dyn ClientCommandPresence,
    ) -> Result<ClientCommandView> {
        commands_qualified()?;
        ensure!(
            presence.available(),
            "Qualified native presence is unavailable for pairing Requests"
        );
        let binding = self.command_binding().await?;
        let mut saved = ClientCommands::open(
            &self.state_directory.join(CLIENT_COMMAND_FILE),
            &binding,
            false,
            Utc::now(),
        )?;
        let review = saved.review(digest, Utc::now())?;
        let grant = self.command_grant(&binding).await?;
        same_active_grant(saved.grant()?, &grant, Utc::now())?;
        presence.confirm(&review)?;
        let grant = self.command_grant(&binding).await?;
        same_active_grant(saved.grant()?, &grant, Utc::now())?;
        ensure!(
            self.command_binding().await? == binding,
            "Native command context changed during presence confirmation"
        );
        let exchange = saved.reserve(Some(digest), Utc::now())?;
        let reply = self.owner_control_exchange(exchange.envelope()).await;
        if let Ok(reply) = reply {
            saved.reply(exchange, reply, Utc::now())?;
        } else {
            return saved.view();
        }
        self.current_command_observation(&binding, &mut saved).await
    }
    async fn current_command_observation(
        &mut self,
        binding: &CommandBinding,
        saved: &mut ClientCommands,
    ) -> Result<ClientCommandView> {
        // A received exact result may be retained as history even if a later
        // refresh fails. It must not appear to be currently confirmed then.
        match self.command_binding().await {
            Ok(actual) => ensure!(
                &actual == binding,
                "Native command context changed; saved operation was preserved"
            ),
            Err(_) => return saved.uncertain_view(),
        }
        if self
            .command_grant(binding)
            .await
            .and_then(|g| same_active_grant(saved.grant()?, &g, Utc::now()))
            .is_err()
        {
            return saved.uncertain_view();
        }
        saved.view()
    }
    pub async fn check_owner_action(&mut self) -> Result<ClientCommandView> {
        self.read_owner_action(None).await
    }
    pub async fn archive_owner_action(&mut self, digest: &str) -> Result<ClientCommandView> {
        self.read_owner_action(Some(digest)).await
    }
    async fn read_owner_action(&mut self, archive: Option<&str>) -> Result<ClientCommandView> {
        let binding = self.command_binding().await?;
        let mut saved = ClientCommands::open(
            &self.state_directory.join(CLIENT_COMMAND_FILE),
            &binding,
            false,
            Utc::now(),
        )?;
        ensure!(
            saved.view()?.status != ClientCommandStatus::Archived,
            "This operation was already retired; no request was sent"
        );
        if let Some(digest) = archive {
            ensure!(saved.view()?.digest == digest, "Reviewed operation changed");
        }
        let exchange = saved.reserve(None, Utc::now())?;
        // Refusal, including expiry/revocation, is uncertainty about execution;
        // it must not erase an older exact retained outcome or authorize replay.
        if self
            .command_grant(&binding)
            .await
            .and_then(|g| same_active_grant(saved.grant()?, &g, Utc::now()))
            .is_err()
        {
            return saved.view();
        }
        let reply = self.owner_control_exchange(exchange.envelope()).await;
        if let Ok(reply) = reply {
            saved.reply(exchange, reply, Utc::now())?;
        } else {
            return saved.view();
        }
        let view = self
            .current_command_observation(&binding, &mut saved)
            .await?;
        if let Some(digest) = archive {
            if view.status != ClientCommandStatus::Observed {
                return Ok(view);
            }
            saved.archive(digest, Utc::now())
        } else {
            Ok(view)
        }
    }
}
