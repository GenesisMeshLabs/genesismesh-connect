//! An AI agent's own identity on a Genesis Mesh Connect network.
//!
//! The agent joins like any device: it asks with an invitation link, the
//! owner compares the code and approves it, and it gets its own key and
//! membership. It reaches only the Spaces other devices share with it, and
//! removing it from the network revokes it alone, even when several agents run
//! on one machine. `mcp` serves that view to the agent's tools over stdio.
mod mcp;

use anyhow::{Context, Result, bail};
use connect_core::{
    device::{DeviceController, PairedDevice},
    session::{pairing::PairCard, sharing::ReadRequest},
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const USAGE: &str =
    "Usage: genesismesh-connect-agent <profile> (join <invitation link> [name] | status | mcp)";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let profile = PathBuf::from(args.first().context(USAGE)?);
    match args.get(1).map(String::as_str) {
        Some("join") => {
            let link = args.get(2).context(USAGE)?;
            join(
                &profile,
                link,
                args.get(3).map_or("AI agent", String::as_str),
            )
            .await
        }
        Some("status") => {
            let mut agent = Agent::open(&profile).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&mcp::Shared::list(&mut agent).await?)?
            );
            Ok(())
        }
        Some("mcp") => {
            let mut agent = Agent::open(&profile).await?;
            let input = tokio::io::BufReader::new(tokio::io::stdin());
            mcp::serve(&mut agent, input, tokio::io::stdout()).await
        }
        _ => bail!(USAGE),
    }
}

/// Ask to join, show the comparison code, then wait for the owner's decision.
async fn join(profile: &Path, link: &str, name: &str) -> Result<()> {
    let card = PairCard::parse(link)?;
    anyhow::ensure!(
        !profile.exists(),
        "This agent profile already has an identity. Use another profile for another agent."
    );
    let mut device = DeviceController::prepare_remote(profile, card.pin.clone())?;
    let mut pairing = device.request_pairing(card.clone(), name.into()).await?;
    eprintln!(
        "Waiting for approval on {}. The owner checks that this code matches: {}",
        card.host_name, pairing.code
    );
    let result = async {
        let grant = pairing.grant().await?;
        device
            .complete_approved_pairing(&mut pairing, &card, grant)
            .await
    }
    .await;
    pairing.close().await;
    result?;
    let status = device.status()?;
    eprintln!(
        "{name} joined {}. Share a folder with it from one of your devices.",
        status.network
    );
    Ok(())
}

struct Agent {
    device: DeviceController,
}

impl Agent {
    async fn open(profile: &Path) -> Result<Self> {
        let device = DeviceController::open(profile)
            .context("This agent has not joined a network yet. Run `join` first.")?;
        Ok(Self { device })
    }

    async fn refreshed(&mut self) -> Result<()> {
        self.device.reconnect_saved().await?;
        self.device.refresh().await
    }

    /// The device sharing `space` with this agent.
    fn host(&self, space: &str) -> Result<PairedDevice> {
        let status = self.device.status()?;
        let host = status
            .spaces
            .iter()
            .find(|s| s.collection == space)
            .map(|s| s.host.clone())
            .context("This space is not shared with this agent")?;
        status
            .devices
            .iter()
            .chain(&status.members)
            .find(|d| d.node == host)
            .cloned()
            .context("The device sharing this space is not on the network right now")
    }
}

impl mcp::Shared for Agent {
    async fn list(&mut self) -> Result<Value> {
        self.refreshed().await?;
        let status = self.device.status()?;
        let name_of = |node: &str| {
            status
                .devices
                .iter()
                .chain(&status.members)
                .find(|d| d.node == node)
                .map_or("Unknown device".to_owned(), |d| d.name.clone())
        };
        Ok(json!({
            "network": status.network,
            "spaces": status.spaces.iter().map(|space| json!({
                "space": space.collection,
                "name": space.name,
                "kind": space.kind,
                "shared_by": name_of(&space.host),
            })).collect::<Vec<_>>(),
        }))
    }

    async fn browse(&mut self, space: String, folder: Vec<String>) -> Result<Value> {
        self.refreshed().await?;
        let peer = self.host(&space)?;
        let page = self
            .device
            .session()?
            .browse_from(&peer.node, &peer.ticket, None, folder, Some(space))
            .await?;
        Ok(serde_json::to_value(page)?)
    }

    async fn read(&mut self, space: String, name: String) -> Result<Value> {
        self.refreshed().await?;
        let peer = self.host(&space)?;
        let report = self
            .device
            .session()?
            .read_file_from(
                Some(&peer.node),
                &peer.ticket,
                ReadRequest {
                    request_id: uuid::Uuid::new_v4().to_string(),
                    collection_id: space,
                    file_name: name,
                    expected_sha256: None,
                },
            )
            .await?;
        Ok(json!({
            "name": report.file_name,
            "bytes": report.bytes,
            "sha256": report.sha256,
            "text": report.text,
            "receipt": report.receipt_id,
        }))
    }

    async fn ask(&mut self, text: String) -> Result<Value> {
        self.refreshed().await?;
        self.device.ask_access(&text).await?;
        Ok(json!({
            "sent": true,
            "next": "The owner answers on their device. Anything they share with this agent appears in list_shared.",
        }))
    }
}
