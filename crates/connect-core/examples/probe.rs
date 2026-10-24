use anyhow::{Context, Result, bail};
use connect_core::{NetworkMode, ProbeEndpoint};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mode = if args.iter().any(|a| a == "--public-relay") {
        NetworkMode::PublicRelay
    } else {
        NetworkMode::Local
    };
    let endpoint = ProbeEndpoint::bind(mode).await?;
    let result = match args.first().map(String::as_str) {
        Some("listen") => {
            println!("Transport diagnostic only; Genesis Mesh authentication is not implemented.");
            println!("{}", serde_json::to_string_pretty(&endpoint.status()?)?);
            println!("Press Ctrl+C to stop.");
            tokio::signal::ctrl_c()
                .await
                .context("Cannot wait for Ctrl+C")
        }
        Some("send") => {
            let ticket = args
                .get(1)
                .context("Usage: probe send '<ticket JSON>' [--public-relay]")?;
            match endpoint.round_trip(ticket, "Connect hello").await {
                Ok(report) => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }
        Some("self-test") => {
            let client = ProbeEndpoint::bind(mode).await?;
            let mut ticket: serde_json::Value = serde_json::from_str(&endpoint.status()?.ticket)?;
            if mode == NetworkMode::PublicRelay {
                let addr: iroh::EndpointAddr = serde_json::from_value(ticket["endpoint"].take())?;
                let relay = addr
                    .relay_urls()
                    .next()
                    .context("No relay address")?
                    .clone();
                ticket["endpoint"] =
                    serde_json::to_value(iroh::EndpointAddr::new(addr.id).with_relay_url(relay))?;
            }
            let result = client
                .round_trip(&serde_json::to_string(&ticket)?, "Connect hello")
                .await;
            client.close().await;
            match result {
                Ok(report) => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }
        _ => {
            endpoint.close().await;
            bail!("Usage: probe listen|self-test|send '<ticket JSON>' [--public-relay]")
        }
    };
    endpoint.close().await;
    result
}
