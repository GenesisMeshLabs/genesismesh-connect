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

/// Windows gives the main thread 1 MiB of stack, Linux 8 MiB, and joining a
/// network overflowed it on Windows. The program runs on a runtime worker
/// thread with the stack Linux gives instead.
const STACK: usize = 8 << 20;

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(STACK)
        .build()
}

fn main() -> Result<()> {
    runtime()?.block_on(async { tokio::spawn(run()).await? })
}

async fn run() -> Result<()> {
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

    /// Each tool call checks trust first. While the phone that runs the network
    /// restarts, the call waits for it for up to two minutes, as long as a
    /// running device waits for its host, instead of failing. An MCP client
    /// whose own request timeout is shorter gives up first.
    async fn refreshed(&mut self) -> Result<()> {
        self.device.connect_when_reachable().await
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

#[cfg(test)]
mod stack {
    /// Joining a network overflowed the 1 MiB main-thread stack on Windows.
    /// The program's tasks run with 8 MiB. This task needs more than 4 MiB in
    /// the debug builds tests use (32 frames, each holding 64 KiB twice): it
    /// overflows with 1, 2 or 4 MiB, as the main thread on Windows or a default
    /// runtime worker would give it, and finishes with the program's 8 MiB.
    #[test]
    fn the_agent_has_room_to_join_from_windows() {
        fn deep(depth: u8) -> u64 {
            let frame = std::hint::black_box([depth; 64 * 1024]);
            if depth == 0 {
                0
            } else {
                deep(depth - 1) + u64::from(frame[1])
            }
        }
        let reached = super::runtime()
            .unwrap()
            .block_on(async { tokio::spawn(async { deep(32) }).await.unwrap() });
        assert_eq!(reached, (1..=32).sum::<u64>());
    }
}
