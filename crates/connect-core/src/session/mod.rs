//! Spike B: mutually authenticated, one-message diagnostics on local Iroh.
//! Authority control has a separate ALPN and grants no service permission.

pub mod bridge;
pub mod pairing;
pub mod sharing;

#[cfg(test)]
mod tests;
mod trust;
mod wire;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, EndpointAddr, endpoint::Connection};
#[cfg(test)]
use iroh::{RelayMode, endpoint::presets};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Semaphore, watch},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

pub use trust::{TrustPolicy, TrustSnapshot};
use wire::{ALPN, Role, authenticate, read_frame, write_frame};

const DEADLINE: Duration = Duration::from_secs(10);
const MAX_MESSAGE: usize = 1024;
const MAX_CONNECTIONS: usize = 8;

/// Node key is separate from Iroh's ephemeral transport key; never serialized.
#[derive(Clone)]
pub struct SessionIdentity {
    pub(crate) key: SigningKey,
    pub(crate) certificate: Value,
}

impl SessionIdentity {
    pub fn new(key: SigningKey, certificate: Value) -> Result<Self> {
        ensure!(
            serde_json::to_vec(&certificate)?.len() <= 8 * 1024,
            "Certificate too large"
        );
        let identity = Self { key, certificate };
        ensure!(
            identity.certificate["node_public_key"] == identity.public_key(),
            "Certificate does not name the local node key"
        );
        Ok(identity)
    }

    pub fn public_key(&self) -> String {
        STANDARD.encode(self.key.verifying_key().to_bytes())
    }
}

#[derive(Clone)]
struct Credentials {
    identity: SessionIdentity,
    trust: TrustSnapshot,
    expected_node: String,
    allowed_nodes: BTreeSet<String>,
}

impl Credentials {
    fn permits(&self, node: &str) -> bool {
        if self.allowed_nodes.is_empty() {
            node == self.expected_node
        } else {
            self.allowed_nodes.contains(node)
        }
    }

    fn for_node(&self, node: &str) -> Result<Self> {
        ensure!(self.permits(node), "This device has not been approved");
        Ok(Self {
            expected_node: node.to_owned(),
            ..self.clone()
        })
    }

    /// Called only after certificate and session proof verification. Rebind
    /// authorization and receipts to this connection's authenticated peer.
    fn for_authenticated(&self, certificate: &Value) -> Result<Self> {
        self.for_node(
            certificate["node_public_key"]
                .as_str()
                .context("Missing peer identity")?,
        )
    }
}

#[derive(Clone)]
struct Peers {
    selected: String,
    allowed: BTreeSet<String>,
}

impl Peers {
    fn new(
        local: &str,
        selected: String,
        allowed: impl IntoIterator<Item = String>,
    ) -> Result<Self> {
        let allowed: BTreeSet<_> = allowed.into_iter().collect();
        ensure!(
            !allowed.is_empty() && allowed.len() <= 32,
            "Choose up to 32 approved devices"
        );
        ensure!(allowed.contains(&selected), "Select an approved device");
        for node in &allowed {
            ensure!(
                STANDARD
                    .decode(node)
                    .is_ok_and(|k| k.len() == 32 && STANDARD.encode(k) == *node)
                    && node != local,
                "Invalid approved device identity"
            );
        }
        Ok(Self { selected, allowed })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionTicket {
    version: u8,
    endpoint: EndpointAddr,
}

pub(crate) fn validate_ticket(ticket: &str) -> Result<()> {
    ticket_endpoint(ticket).map(|_| ())
}

/// The endpoint a valid session ticket names. Fresh addresses may replace a
/// saved ticket only for this same endpoint.
pub(crate) fn ticket_endpoint(ticket: &str) -> Result<iroh::EndpointId> {
    let ticket: SessionTicket = wire::decode(ticket.as_bytes())?;
    ensure!(
        ticket.version == 1 && !ticket.endpoint.is_empty(),
        "Invalid saved device address"
    );
    Ok(ticket.endpoint.id)
}

#[derive(Debug, Serialize)]
pub struct SessionReport {
    pub peer_endpoint: String,
    pub peer_node: String,
    pub peer_certificate: String,
    pub bytes: usize,
    pub genesis_mesh_authenticated: bool,
}

/// A local-network diagnostic endpoint. One authentication and one bounded echo
/// per connection; raw connections are not exposed to callers or the frontend.
pub struct SessionEndpoint {
    endpoint: Endpoint,
    credentials: watch::Sender<Option<Arc<Credentials>>>,
    node_public_key: String,
    peers: Mutex<Peers>,
    accepted: Arc<AtomicU64>,
    accept_task: Mutex<Option<JoinHandle<()>>>,
    outgoing: Semaphore,
}

impl SessionEndpoint {
    pub async fn bind(
        identity: SessionIdentity,
        trust: TrustSnapshot,
        expected_node: String,
    ) -> Result<Self> {
        Self::bind_with_share(identity, trust, expected_node, None).await
    }

    pub async fn bind_with_share(
        identity: SessionIdentity,
        trust: TrustSnapshot,
        expected_node: String,
        share: Option<Arc<sharing::Share>>,
    ) -> Result<Self> {
        Self::bind_with_transport(
            identity,
            trust,
            expected_node,
            share,
            None,
            crate::Connectivity::LocalNetwork,
        )
        .await
    }

    pub async fn bind_with_transport(
        identity: SessionIdentity,
        trust: TrustSnapshot,
        expected_node: String,
        share: Option<Arc<sharing::Share>>,
        transport: Option<crate::connectivity::Transport>,
        connectivity: crate::Connectivity,
    ) -> Result<Self> {
        ensure!(
            STANDARD
                .decode(&expected_node)
                .is_ok_and(|key| key.len() == 32),
            "Expected peer must be a node public key"
        );
        ensure!(
            expected_node != identity.public_key(),
            "Peer must be a different node"
        );
        trust.certificate(&identity.certificate, &identity.public_key(), Utc::now())?;
        let mut protocols = vec![ALPN.to_vec()];
        if share.is_some() {
            protocols.push(wire::Protocol::Read.alpn().to_vec());
            protocols.push(wire::Protocol::List.alpn().to_vec());
            protocols.push(wire::Protocol::Catalog.alpn().to_vec());
            protocols.push(wire::Protocol::Download.alpn().to_vec());
            protocols.push(wire::Protocol::Browse.alpn().to_vec());
            protocols.push(wire::Protocol::NestedDownload.alpn().to_vec());
        }
        let (key, port) = transport.map_or((None, None), |t| (Some(t.key), t.port));
        let endpoint = connectivity
            .bind(port, |builder| {
                let builder = builder.alpns(protocols.clone());
                match &key {
                    Some(key) => builder.secret_key(key.clone()),
                    None => builder,
                }
            })
            .await?;
        let endpoint = connectivity
            .ready(
                endpoint,
                true,
                DEADLINE,
                "Connection relay did not become ready",
            )
            .await?;
        let node_public_key = identity.public_key();
        let peers = Peers::new(
            &node_public_key,
            expected_node.clone(),
            [expected_node.clone()],
        )?;
        let credentials = watch::channel(Some(Arc::new(Credentials {
            identity,
            trust,
            expected_node: expected_node.clone(),
            allowed_nodes: peers.allowed.clone(),
        })))
        .0;
        let accepted = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn(accept_sessions(
            endpoint.clone(),
            credentials.clone(),
            accepted.clone(),
            share,
        ));
        Ok(Self {
            endpoint,
            credentials,
            node_public_key,
            peers: Mutex::new(peers),
            accepted,
            accept_task: Mutex::new(Some(task)),
            outgoing: Semaphore::new(2),
        })
    }

    pub fn ticket(&self) -> Result<String> {
        Ok(serde_json::to_string(&SessionTicket {
            version: 1,
            endpoint: self.endpoint.addr(),
        })?)
    }

    /// The IPv4 port to reuse after a restart.
    pub fn port(&self) -> Option<u16> {
        crate::connectivity::ipv4_port(&self.endpoint)
    }

    pub fn received_messages(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// Cancel in-flight operations and reject new sessions while retaining the
    /// transport identity/ticket. No stale-credential fallback is possible.
    pub fn suspend(&self) {
        self.credentials.send_replace(None);
    }

    pub fn refresh(&self, identity: SessionIdentity, trust: TrustSnapshot) -> Result<()> {
        let peers = self.peers.lock().expect("peer mutex poisoned");
        self.suspend();
        ensure!(
            identity.public_key() == self.node_public_key,
            "Cannot change the running node identity"
        );
        trust.certificate(&identity.certificate, &identity.public_key(), Utc::now())?;
        self.credentials.send_replace(Some(Arc::new(Credentials {
            identity,
            trust,
            expected_node: peers.selected.clone(),
            allowed_nodes: peers.allowed.clone(),
        })));
        Ok(())
    }

    /// Replace the explicitly approved set without replacing the endpoint.
    /// Every membership/selection change cancels in-flight operations.
    pub fn set_peers(&self, selected: String, allowed: Vec<String>) -> Result<()> {
        let next = Peers::new(&self.node_public_key, selected, allowed)?;
        let mut peers = self.peers.lock().expect("peer mutex poisoned");
        let credentials = self.credentials.borrow().clone();
        self.suspend();
        if let Some(credentials) = credentials {
            self.credentials.send_replace(Some(Arc::new(Credentials {
                expected_node: next.selected.clone(),
                allowed_nodes: next.allowed.clone(),
                ..(*credentials).clone()
            })));
        }
        *peers = next;
        Ok(())
    }

    fn selected_credentials(
        &self,
        node: Option<&str>,
        changes: &mut watch::Receiver<Option<Arc<Credentials>>>,
    ) -> Result<Credentials> {
        let current = changes
            .borrow_and_update()
            .clone()
            .context("Connection is suspended")?;
        current.for_node(node.unwrap_or(&current.expected_node))
    }

    pub fn ready(&self) -> bool {
        self.credentials.borrow().as_ref().is_some_and(|c| {
            c.trust
                .certificate(&c.identity.certificate, &self.node_public_key, Utc::now())
                .is_ok()
        })
    }

    pub async fn round_trip(&self, ticket: &str, message: &str) -> Result<SessionReport> {
        self.round_trip_to(None, ticket, message).await
    }

    pub async fn round_trip_to(
        &self,
        node: Option<&str>,
        ticket: &str,
        message: &str,
    ) -> Result<SessionReport> {
        ensure!(
            !message.is_empty() && message.len() <= MAX_MESSAGE,
            "Diagnostic message must contain 1 to 1024 UTF-8 bytes"
        );
        let ticket: SessionTicket = wire::decode(ticket.as_bytes())?;
        ensure!(ticket.version == 1, "Unsupported ticket version");
        ensure!(
            !ticket.endpoint.is_empty() && ticket.endpoint.id != self.endpoint.id(),
            "Invalid destination"
        );
        let _permit = self
            .outgoing
            .try_acquire()
            .context("Too many outgoing sessions")?;
        let mut changes = self.credentials.subscribe();
        let credentials = self.selected_credentials(node, &mut changes)?;
        let connection = timeout(DEADLINE, self.endpoint.connect(ticket.endpoint, ALPN))
            .await
            .context("Connection timed out")??;
        limit_streams(&connection);
        let exchange = timeout(DEADLINE, async {
            let (mut send, mut recv) = connection.open_bi().await?;
            let peer_certificate = authenticate(
                &connection,
                self.endpoint.id(),
                Role::Client,
                &credentials,
                &mut send,
                &mut recv,
            )
            .await?;
            write_frame(&mut send, &message).await?;
            send.finish()?;
            let reply: String = read_frame(&mut recv).await?;
            ensure!(reply == message, "Diagnostic reply differs");
            ensure!(
                recv.read_to_end(0).await?.is_empty(),
                "Unexpected response data"
            );
            credentials.trust.certificate(
                &peer_certificate,
                &credentials.expected_node,
                Utc::now(),
            )?;
            credentials.trust.certificate(
                &credentials.identity.certificate,
                &self.node_public_key,
                Utc::now(),
            )?;
            Ok(SessionReport {
                peer_endpoint: connection.remote_id().to_string(),
                peer_node: credentials.expected_node.clone(),
                peer_certificate: peer_certificate["cert_id"]
                    .as_str()
                    .context("Missing certificate ID")?
                    .to_owned(),
                bytes: reply.len(),
                genesis_mesh_authenticated: true,
            })
        });
        let result = tokio::select! {
            biased;
            _ = changes.changed() => Err(anyhow::anyhow!("Trust changed; reconnect with current credentials")),
            outcome = exchange => outcome.context("Authenticated diagnostic timed out").and_then(|value| value),
        };
        connection.close(0u32.into(), b"diagnostic finished");
        result
    }

    pub async fn close(&self) {
        self.suspend();
        self.endpoint.close().await;
        let task = self.accept_task.lock().expect("task mutex poisoned").take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    pub async fn read_file(
        &self,
        ticket: &str,
        request: sharing::ReadRequest,
    ) -> Result<sharing::ReadReport> {
        self.read_file_from(None, ticket, request).await
    }

    pub async fn read_file_from(
        &self,
        node: Option<&str>,
        ticket: &str,
        request: sharing::ReadRequest,
    ) -> Result<sharing::ReadReport> {
        let ticket: SessionTicket = wire::decode(ticket.as_bytes())?;
        ensure!(
            ticket.version == 1
                && !ticket.endpoint.is_empty()
                && ticket.endpoint.id != self.endpoint.id(),
            "Invalid read destination"
        );
        let _permit = self
            .outgoing
            .try_acquire()
            .context("Too many outgoing operations")?;
        let mut changes = self.credentials.subscribe();
        let credentials = self.selected_credentials(node, &mut changes)?;
        let connection = timeout(
            DEADLINE,
            self.endpoint
                .connect(ticket.endpoint, wire::Protocol::Read.alpn()),
        )
        .await
        .context("Read connection timed out")??;
        limit_streams(&connection);
        let result = tokio::select! {biased;
            _=changes.changed()=>Err(anyhow::anyhow!("Trust changed during read")),
            result=timeout(Duration::from_secs(20),sharing::receive(&connection,self.endpoint.id(),&credentials,&request))=>result.context("Read timed out").and_then(|r|r),
        };
        connection.close(0u32.into(), b"read finished");
        result
    }
    pub async fn list_files(
        &self,
        ticket: &str,
        after: Option<String>,
    ) -> Result<sharing::listing::FilePage> {
        self.list_files_from(None, ticket, after).await
    }

    pub async fn list_files_from(
        &self,
        node: Option<&str>,
        ticket: &str,
        after: Option<String>,
    ) -> Result<sharing::listing::FilePage> {
        let ticket: SessionTicket = wire::decode(ticket.as_bytes())?;
        ensure!(
            ticket.version == 1
                && !ticket.endpoint.is_empty()
                && ticket.endpoint.id != self.endpoint.id(),
            "Invalid file destination"
        );
        let _permit = self
            .outgoing
            .try_acquire()
            .context("Another operation is running")?;
        let mut changes = self.credentials.subscribe();
        let credentials = self.selected_credentials(node, &mut changes)?;
        let connection = timeout(
            DEADLINE,
            self.endpoint
                .connect(ticket.endpoint, wire::Protocol::List.alpn()),
        )
        .await
        .context("Computer did not respond")??;
        limit_streams(&connection);
        let request = sharing::listing::ListRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            after,
            directory: Vec::new(),
        };
        let result = tokio::select! {biased;_=changes.changed()=>Err(anyhow::anyhow!("Trust changed during file listing")),result=timeout(Duration::from_secs(20),sharing::listing::receive(&connection,self.endpoint.id(),&credentials,&request))=>result.context("File listing timed out").and_then(|r|r)};
        connection.close(0u32.into(), b"file list complete");
        result
    }

    pub async fn catalog_from(
        &self,
        node: &str,
        ticket: &str,
        after: Option<String>,
    ) -> Result<sharing::catalog::Page> {
        let ticket: SessionTicket = wire::decode(ticket.as_bytes())?;
        ensure!(
            ticket.version == 1
                && !ticket.endpoint.is_empty()
                && ticket.endpoint.id != self.endpoint.id(),
            "Invalid file destination"
        );
        let _permit = self
            .outgoing
            .try_acquire()
            .context("Another operation is running")?;
        let mut changes = self.credentials.subscribe();
        let credentials = self.selected_credentials(Some(node), &mut changes)?;
        let connection = timeout(
            DEADLINE,
            self.endpoint
                .connect(ticket.endpoint, wire::Protocol::Catalog.alpn()),
        )
        .await
        .context("Computer did not respond")??;
        limit_streams(&connection);
        let request = sharing::listing::ListRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            after,
            directory: Vec::new(),
        };
        let result = tokio::select! { biased;
            _=changes.changed()=>Err(anyhow::anyhow!("Trust changed during file listing")),
            result=timeout(Duration::from_secs(20),sharing::listing::receive_catalog(&connection,self.endpoint.id(),&credentials,&request))=>result.context("File listing timed out").and_then(|r|r),
        };
        connection.close(0u32.into(), b"catalog complete");
        result
    }

    pub async fn browse_from(
        &self,
        node: &str,
        ticket: &str,
        after: Option<String>,
        directory: Vec<String>,
    ) -> Result<sharing::browse::Page> {
        let ticket: SessionTicket = wire::decode(ticket.as_bytes())?;
        ensure!(
            ticket.version == 1
                && !ticket.endpoint.is_empty()
                && ticket.endpoint.id != self.endpoint.id(),
            "Invalid file destination"
        );
        let _permit = self
            .outgoing
            .try_acquire()
            .context("Another operation is running")?;
        let mut changes = self.credentials.subscribe();
        let credentials = self.selected_credentials(Some(node), &mut changes)?;
        let connection = timeout(
            DEADLINE,
            self.endpoint
                .connect(ticket.endpoint, wire::Protocol::Browse.alpn()),
        )
        .await
        .context("Computer did not respond")??;
        limit_streams(&connection);
        let request = sharing::listing::ListRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            after,
            directory,
        };
        let result = tokio::select! { biased;
            _=changes.changed()=>Err(anyhow::anyhow!("Trust changed during file listing")),
            result=timeout(Duration::from_secs(20),sharing::listing::receive_browse(&connection,self.endpoint.id(),&credentials,&request))=>result.context("File listing timed out").and_then(|r|r),
        };
        connection.close(0u32.into(), b"catalog complete");
        result
    }

    pub async fn download_window_from(
        &self,
        node: &str,
        ticket: &str,
        request: sharing::download::Request,
        output: &mut std::fs::File,
    ) -> Result<sharing::download::Window> {
        use std::io::{Seek, SeekFrom};
        ensure!(
            output.metadata()?.len() == request.offset,
            "Download staging position differs"
        );
        let ticket: SessionTicket = wire::decode(ticket.as_bytes())?;
        ensure!(
            ticket.version == 1
                && !ticket.endpoint.is_empty()
                && ticket.endpoint.id != self.endpoint.id(),
            "Invalid file destination"
        );
        let _permit = self
            .outgoing
            .try_acquire()
            .context("Another operation is running")?;
        let mut changes = self.credentials.subscribe();
        let credentials = self.selected_credentials(Some(node), &mut changes)?;
        let connection = timeout(
            DEADLINE,
            self.endpoint.connect(
                ticket.endpoint,
                sharing::download::protocol(&request).alpn(),
            ),
        )
        .await
        .context("Computer did not respond")??;
        struct CloseOnDrop(iroh::endpoint::Connection);
        impl Drop for CloseOnDrop {
            fn drop(&mut self) {
                self.0.close(0u32.into(), b"download ended");
            }
        }
        let _close = CloseOnDrop(connection.clone());
        limit_streams(&connection);
        let result = tokio::select! { biased;
            _=changes.changed()=>Err(anyhow::anyhow!("Trust changed during download")),
            result=timeout(Duration::from_secs(120),sharing::download::receive(&connection,self.endpoint.id(),&credentials,&request,output))=>result.context("Download timed out").and_then(|r|r),
        };
        connection.close(0u32.into(), b"download window complete");
        if result.is_err() {
            output.set_len(request.offset)?;
            output.seek(SeekFrom::Start(request.offset))?;
        }
        result
    }
}

impl Drop for SessionEndpoint {
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

fn limit_streams(connection: &Connection) {
    connection.set_max_concurrent_uni_streams(0u32.into());
    connection.set_max_concurrent_bi_streams(1u32.into());
}

async fn accept_sessions(
    endpoint: Endpoint,
    state: watch::Sender<Option<Arc<Credentials>>>,
    accepted: Arc<AtomicU64>,
    share: Option<Arc<sharing::Share>>,
) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                if tasks.len() >= MAX_CONNECTIONS { incoming.refuse(); continue; }
                let mut changes = state.subscribe();
                let Some(credentials) = changes.borrow_and_update().clone() else { incoming.refuse(); continue };
                let accepted = accepted.clone();
                let local_id = endpoint.id();
                let share=share.clone();
                tasks.spawn(async move {
                    let Ok(Ok(connection)) = timeout(DEADLINE, incoming).await else { return };
                    limit_streams(&connection);
                    let deadline=if connection.alpn()==wire::Protocol::Download.alpn() || connection.alpn()==wire::Protocol::NestedDownload.alpn(){Duration::from_secs(120)}else if connection.alpn()==wire::Protocol::Read.alpn(){Duration::from_secs(20)}else{DEADLINE};
                    let exchange = timeout(deadline, async {
                        if connection.alpn()==wire::Protocol::Read.alpn(){
                            return sharing::serve(&connection,local_id,&credentials,share.as_deref().context("Sharing disabled")?).await;
                        }
                        if connection.alpn()==wire::Protocol::List.alpn(){return sharing::listing::serve(&connection,local_id,&credentials,share.as_deref().context("Sharing disabled")?).await;}
                        if connection.alpn()==wire::Protocol::Browse.alpn(){return sharing::listing::serve_for(&connection,local_id,&credentials,share.as_deref().context("Sharing disabled")?,wire::Protocol::Browse).await;}
                        if connection.alpn()==wire::Protocol::Catalog.alpn(){return sharing::listing::serve_for(&connection,local_id,&credentials,share.as_deref().context("Sharing disabled")?,wire::Protocol::Catalog).await;}
                        if connection.alpn()==wire::Protocol::Download.alpn() || connection.alpn()==wire::Protocol::NestedDownload.alpn(){return sharing::download::serve(&connection,local_id,&credentials,share.as_deref().context("Sharing disabled")?).await;}
                        let (mut send, mut recv) = connection.accept_bi().await?;
                        let peer_certificate = authenticate(&connection, local_id, Role::Server, &credentials, &mut send, &mut recv).await?;
                        let credentials = credentials.for_authenticated(&peer_certificate)?;
                        let message: String = read_frame(&mut recv).await?;
                        ensure!(!message.is_empty() && message.len() <= MAX_MESSAGE, "Invalid diagnostic size");
                        ensure!(recv.read_to_end(0).await?.is_empty(), "Unexpected request data");
                        // An expired trust snapshot or certificate cannot authorize even a late echo.
                        credentials.trust.certificate(&peer_certificate, &credentials.expected_node, Utc::now())?;
                        credentials.trust.certificate(&credentials.identity.certificate, &credentials.identity.public_key(), Utc::now())?;
                        write_frame(&mut send, &message).await?;
                        send.finish()?;
                        accepted.fetch_add(1, Ordering::Relaxed);
                        connection.closed().await;
                        Ok::<_, anyhow::Error>(())
                    });
                    tokio::select! {
                        biased;
                        _ = changes.changed() => {},
                        _ = exchange => {},
                    }
                    connection.close(0u32.into(), b"session ended");
                });
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    tasks.shutdown().await;
}
