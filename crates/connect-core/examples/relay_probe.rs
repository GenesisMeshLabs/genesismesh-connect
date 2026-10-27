//! Connect transport diagnostic with no direct IP transport on the client.
//! This verifies relay traffic without changing system network settings.
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};
use serde::Deserialize;
use tokio::time::timeout;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    version: u8,
    endpoint: EndpointAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    let input = std::env::args()
        .nth(1)
        .context("Usage: relay_probe '<Connect ticket JSON>'")?;
    ensure!(input.len() <= 16 * 1024, "Ticket is too large");
    let ticket: Ticket = serde_json::from_str(&input)?;
    ensure!(ticket.version == 1, "Unsupported ticket version");
    ensure!(
        ticket.endpoint.relay_urls().next().is_some(),
        "Ticket needs a relay"
    );

    let endpoint = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .relay_mode(RelayMode::Default)
        .bind()
        .await?;
    let deadline = Duration::from_secs(20);
    let result = timeout(deadline, async {
        endpoint.online().await;
        let started = Instant::now();
        let connection = endpoint
            .connect(ticket.endpoint, b"genesismesh-connect/probe/0")
            .await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        let message = b"Connect hello";
        send.write_all(message).await?;
        send.finish()?;
        let reply = recv.read_to_end(1024).await?;
        ensure!(reply == message, "Reply differs from request");
        let paths = connection.paths();
        ensure!(!paths.is_empty(), "No observed path");
        ensure!(paths.iter().all(|p| p.is_relay()), "Unexpected direct path");
        ensure!(paths.iter().any(|p| p.is_selected()), "No selected path");
        let path_report = paths
            .iter()
            .map(|p| {
                if p.is_selected() {
                    "relay (selected)"
                } else {
                    "relay"
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let report = serde_json::json!({
            "peer_id": connection.remote_id().to_string(),
            "bytes": reply.len(),
            "elapsed_ms": started.elapsed().as_millis(),
            "paths": path_report,
            "client_mode": "relay_only_no_ip_transport",
            "genesis_mesh_authenticated": false
        });
        connection.close(0u32.into(), b"probe complete");
        Ok::<_, anyhow::Error>(report)
    })
    .await;
    endpoint.close().await;
    let report = result.context("Relay probe timed out")??;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
