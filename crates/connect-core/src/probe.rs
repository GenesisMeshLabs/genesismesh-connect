use std::{
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::timeout,
};

const ALPN: &[u8] = b"genesismesh-connect/probe/0";
const MAX_MESSAGE: usize = 1024;
const MAX_TICKET: usize = 16 * 1024;
const DEADLINE: Duration = Duration::from_secs(20);
const MAX_CONNECTIONS: usize = 8;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    #[default]
    Local,
    PublicRelay,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeTicket {
    version: u8,
    endpoint: EndpointAddr,
}

impl ProbeTicket {
    fn parse(input: &str) -> Result<Self> {
        ensure!(input.len() <= MAX_TICKET, "Endpoint ticket is too large");
        let ticket: Self = serde_json::from_str(input).context("Invalid endpoint ticket JSON")?;
        ensure!(ticket.version == 1, "Unsupported endpoint ticket version");
        ensure!(
            !ticket.endpoint.is_empty(),
            "Ticket has no reachable addresses"
        );
        Ok(ticket)
    }
}

#[derive(Debug, Serialize)]
pub struct EndpointStatus {
    pub endpoint_id: String,
    pub mode: NetworkMode,
    pub ticket: String,
    pub received_probes: u64,
}

#[derive(Debug, Serialize)]
pub struct RoundTripReport {
    pub peer_id: String,
    pub bytes: usize,
    pub elapsed_ms: u128,
    pub paths: String,
    pub genesis_mesh_authenticated: bool,
}

/// An ephemeral Iroh endpoint serving one bounded echo per connection.
/// It exposes neither files nor authority routes. Its key is never sent to the UI.
pub struct ProbeEndpoint {
    endpoint: Endpoint,
    mode: NetworkMode,
    received: std::sync::Arc<AtomicU64>,
    accept_task: Mutex<Option<JoinHandle<()>>>,
    outgoing: Semaphore,
}

impl ProbeEndpoint {
    pub async fn bind(mode: NetworkMode) -> Result<Self> {
        // No public address lookup/publishing and no router port mapping:
        // peers exchange explicit tickets.
        let relay_mode = match mode {
            NetworkMode::Local => RelayMode::Disabled,
            NetworkMode::PublicRelay => RelayMode::Default,
        };
        let endpoint = Endpoint::builder(presets::Minimal)
            .relay_mode(relay_mode)
            .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .context("Cannot bind Iroh endpoint")?;
        if mode == NetworkMode::PublicRelay && timeout(DEADLINE, endpoint.online()).await.is_err() {
            endpoint.close().await;
            anyhow::bail!("Public relay did not become ready within 20 seconds");
        }
        let received = std::sync::Arc::new(AtomicU64::new(0));
        let accept_task = tokio::spawn(accept_probes(endpoint.clone(), received.clone()));
        Ok(Self {
            endpoint,
            mode,
            received,
            accept_task: Mutex::new(Some(accept_task)),
            outgoing: Semaphore::new(2),
        })
    }

    pub fn status(&self) -> Result<EndpointStatus> {
        Ok(EndpointStatus {
            endpoint_id: self.endpoint.id().to_string(),
            mode: self.mode,
            ticket: serde_json::to_string(&ProbeTicket {
                version: 1,
                endpoint: self.endpoint.addr(),
            })?,
            received_probes: self.received.load(Ordering::Relaxed),
        })
    }

    pub async fn round_trip(&self, ticket: &str, message: &str) -> Result<RoundTripReport> {
        ensure!(!message.is_empty(), "Enter a diagnostic message");
        ensure!(
            message.len() <= MAX_MESSAGE,
            "Message exceeds 1024 UTF-8 bytes"
        );
        let ticket = ProbeTicket::parse(ticket)?;
        ensure!(
            ticket.endpoint.id != self.endpoint.id(),
            "Use the other device's ticket"
        );
        let _permit = self
            .outgoing
            .try_acquire()
            .context("A probe is already running")?;
        let start = Instant::now();
        let connection = timeout(DEADLINE, self.endpoint.connect(ticket.endpoint, ALPN))
            .await
            .context("Connection timed out")?
            .context("Iroh connection failed")?;
        let result = timeout(DEADLINE, async {
            let (mut send, mut recv) = connection.open_bi().await?;
            send.write_all(message.as_bytes()).await?;
            send.finish()?;
            let reply = recv.read_to_end(MAX_MESSAGE).await?;
            ensure!(
                reply == message.as_bytes(),
                "Diagnostic reply differs from request"
            );
            Ok::<_, anyhow::Error>(RoundTripReport {
                peer_id: connection.remote_id().to_string(),
                bytes: reply.len(),
                elapsed_ms: start.elapsed().as_millis(),
                paths: connection
                    .paths()
                    .iter()
                    .map(|path| {
                        format!(
                            "{}{}",
                            if path.is_relay() { "relay" } else { "direct" },
                            if path.is_selected() {
                                " (selected)"
                            } else {
                                ""
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
                genesis_mesh_authenticated: false,
            })
        })
        .await
        .context("Diagnostic exchange timed out");
        connection.close(0u32.into(), b"probe complete");
        result?
    }

    pub async fn close(&self) {
        self.endpoint.close().await;
        let task = self.accept_task.lock().expect("task mutex poisoned").take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

impl Drop for ProbeEndpoint {
    fn drop(&mut self) {
        if let Some(task) = self
            .accept_task
            .get_mut()
            .expect("task mutex poisoned")
            .take()
        {
            task.abort();
        }
    }
}

async fn accept_probes(endpoint: Endpoint, received: std::sync::Arc<AtomicU64>) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                if tasks.len() >= MAX_CONNECTIONS {
                    incoming.refuse();
                    continue;
                }
                let received = received.clone();
                tasks.spawn(async move {
                    let _ = timeout(DEADLINE, async {
                        let connection = incoming.await?;
                        let outcome = async {
                            let (mut send, mut recv) = connection.accept_bi().await?;
                            let data = recv.read_to_end(MAX_MESSAGE).await?;
                            ensure!(!data.is_empty(), "Empty probe");
                            send.write_all(&data).await?;
                            send.finish()?;
                            received.fetch_add(1, Ordering::Relaxed);
                            // Keep the response alive until the client acknowledges receipt by closing.
                            connection.closed().await;
                            Ok::<_, anyhow::Error>(())
                        }.await;
                        connection.close(0u32.into(), b"probe finished");
                        outcome
                    }).await;
                });
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    tasks.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn real_round_trip_then_reconnect_and_reject_bad_input() -> Result<()> {
        let server = ProbeEndpoint::bind(NetworkMode::Local).await?;
        // Explicit loopback avoids depending on OS interface address discovery in this test.
        let port = server
            .endpoint
            .bound_sockets()
            .iter()
            .find(|a| a.is_ipv4())
            .context("No IPv4 listener")?
            .port();
        let ticket = serde_json::to_string(&ProbeTicket {
            version: 1,
            endpoint: EndpointAddr::new(server.endpoint.id())
                .with_ip_addr(([127, 0, 0, 1], port).into()),
        })?;
        for _ in 0..2 {
            let client = ProbeEndpoint::bind(NetworkMode::Local).await?;
            let report = client.round_trip(&ticket, "Connect hello").await?;
            assert_eq!(report.peer_id, server.endpoint.id().to_string());
            assert_eq!(report.bytes, 13);
            assert!(!report.genesis_mesh_authenticated);
            assert!(client.round_trip(&ticket, &"x".repeat(1025)).await.is_err());
            assert!(client.round_trip("{}", "hello").await.is_err());
            client.close().await;
        }
        assert_eq!(server.status()?.received_probes, 2);
        server.close().await;
        Ok(())
    }

    #[test]
    fn rejects_oversized_and_unsupported_tickets() {
        assert!(ProbeTicket::parse(&"x".repeat(MAX_TICKET + 1)).is_err());
        let endpoint = EndpointAddr::new(iroh::SecretKey::generate().public())
            .with_ip_addr(([127, 0, 0, 1], 12345).into());
        let unsupported = serde_json::to_string(&ProbeTicket {
            version: 255,
            endpoint,
        })
        .unwrap();
        assert!(
            ProbeTicket::parse(&unsupported)
                .unwrap_err()
                .to_string()
                .contains("Unsupported")
        );
    }

    #[tokio::test]
    async fn receiver_refuses_oversized_data_and_unknown_protocol() -> Result<()> {
        let server = ProbeEndpoint::bind(NetworkMode::Local).await?;
        let port = server
            .endpoint
            .bound_sockets()
            .iter()
            .find(|a| a.is_ipv4())
            .context("No IPv4 listener")?
            .port();
        let address =
            EndpointAddr::new(server.endpoint.id()).with_ip_addr(([127, 0, 0, 1], port).into());
        let client = Endpoint::bind(presets::Minimal).await?;
        assert!(
            timeout(
                DEADLINE,
                client.connect(address.clone(), b"unsupported/protocol")
            )
            .await?
            .is_err()
        );
        let connection = timeout(DEADLINE, client.connect(address, ALPN)).await??;
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(&vec![b'x'; MAX_MESSAGE + 1]).await?;
        send.finish()?;
        assert!(
            timeout(DEADLINE, recv.read_to_end(MAX_MESSAGE))
                .await?
                .is_err()
        );
        assert_eq!(server.status()?.received_probes, 0);
        client.close().await;
        server.close().await;
        Ok(())
    }
}
