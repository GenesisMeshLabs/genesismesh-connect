//! Authenticated, policy-bound TCP streams to an explicitly configured local
//! service. Targets never arrive from the peer. No filesystem protocol can
//! address these resources; raw application bytes never enter a WebView IPC.
use super::*;
use crate::session::wire::{Protocol, Role, authenticate_for};
use iroh::endpoint::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub const MAX_SECONDS: u32 = 3600;
const HEADER_LIMIT: usize = 512 * 1024;
const HANDSHAKE: Duration = Duration::from_secs(20);
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub port: u16,
    pub max_bytes: u64,
    pub max_seconds: u32,
}
impl Target {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.port > 0, "Choose a service port from 1 to 65535");
        ensure!(
            (1..=crate::transfer_limits::MAX_FILE_BYTES).contains(&self.max_bytes),
            "Invalid service byte limit"
        );
        ensure!(
            (1..=MAX_SECONDS).contains(&self.max_seconds),
            "Choose a session duration up to one hour"
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    collection_id: String,
    request_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Permission {
    intent: Value,
    decision: Value,
    attestation: Value,
    receipt: Value,
}
async fn write_permission(send: &mut SendStream, value: &Permission) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= HEADER_LIMIT, "Service permission too large");
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}
async fn read_permission(recv: &mut RecvStream) -> Result<Permission> {
    let mut size = [0; 4];
    recv.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(
        size > 0 && size <= HEADER_LIMIT,
        "Invalid service permission size"
    );
    let mut bytes = vec![0; size];
    recv.read_exact(&mut bytes).await?;
    Ok(serde_json::from_value(
        genesis_mesh_sdk::parse_strict_json(std::str::from_utf8(&bytes)?)?,
    )?)
}
fn signed_receipt(identity: &SessionIdentity, intent: &Value, decision: &Value) -> Result<Value> {
    let mut receipt = json!({"domain":"genesismesh-connect/service-authorization/v1","receipt_id":uuid::Uuid::new_v4().to_string(),
        "host_node":identity.public_key(),"intent_digest":genesis_mesh_sdk::canonical_digest(intent)?,
        "decision_digest":genesis_mesh_sdk::canonical_digest(decision)?,"created_at":genesis_mesh_sdk::canonical::python_timestamp(Utc::now())});
    receipt["signature"] = genesis_mesh_sdk::sign_canonical(
        &genesis_mesh_sdk::canonical_json(&receipt)?,
        "connect-node",
        &identity.key,
    );
    Ok(receipt)
}
fn check_receipt(p: &Permission, node: &str) -> Result<()> {
    let mut body = p.receipt.clone();
    let sig = body
        .as_object_mut()
        .and_then(|b| b.remove("signature"))
        .context("Missing service receipt signature")?;
    ensure!(
        body["domain"] == "genesismesh-connect/service-authorization/v1"
            && body["host_node"] == node
            && body["intent_digest"] == genesis_mesh_sdk::canonical_digest(&p.intent)?
            && body["decision_digest"] == genesis_mesh_sdk::canonical_digest(&p.decision)?
            && genesis_mesh_sdk::verify_canonical(
                &genesis_mesh_sdk::canonical_json(&body)?,
                sig["sig"].as_str().context("Invalid signature")?,
                &[node.to_owned()]
            ),
        "Invalid service receipt"
    );
    Ok(())
}
impl Share {
    async fn authorize_service(
        &self,
        credentials: &Credentials,
        peer: &Value,
        request: &Request,
    ) -> Result<(Permission, Duration)> {
        let target = self.config.service.as_ref().context("Not a service")?;
        ensure!(
            self.config.recipients.contains(&credentials.expected_node),
            "Service not shared with this device"
        );
        self.authority.check_service_port(target.port)?;
        let mut store = self.trust.lock().await;
        let trust = self.authority.refresh(&mut store).await?;
        drop(store);
        trust.certificate(peer, &credentials.expected_node, Utc::now())?;
        trust.certificate(
            &credentials.identity.certificate,
            &credentials.identity.public_key(),
            Utc::now(),
        )?;
        let intent = json!({"domain":"genesismesh-connect/service/v1","request":request,"kind":self.config.kind,
            "host_node":credentials.identity.public_key(),"peer_node":credentials.expected_node,
            "nonce":uuid::Uuid::new_v4().to_string(),"max_bytes":target.max_bytes,"max_seconds":target.max_seconds,
            "policy_id":self.config.policy_id});
        let context = format!(
            "connect-service:{}",
            genesis_mesh_sdk::canonical_digest(&intent)?
        );
        let attestation_id = self.attestation_id();
        let attestation = self
            .authority
            .attestation(&credentials.identity, &trust, &attestation_id)
            .await?["attestation"]
            .clone();
        let decision=self.authority.evaluate(&credentials.identity,&trust,&attestation_id,&context,
            json!({"collection_id":request.collection_id,"peer_node":credentials.expected_node,"size":target.max_bytes,"duration_seconds":target.max_seconds}),
            "connect.service.connect").await?["decision"].clone();
        trust.read_decision(
            &decision,
            &attestation,
            &context,
            &self.config.policy_id,
            &credentials.identity.public_key(),
        )?;
        let until = chrono::DateTime::parse_from_rfc3339(
            decision["decision_valid_until"]
                .as_str()
                .context("No decision expiry")?,
        )?;
        let lease = (until.with_timezone(&Utc) - Utc::now())
            .to_std()?
            .min(Duration::from_secs(10));
        ensure!(
            lease > Duration::from_millis(100),
            "Service decision expired"
        );
        let receipt = signed_receipt(&credentials.identity, &intent, &decision)?;
        self.persist(
            &json!({"receipt":receipt,"intent":intent,"decision":decision,"attestation":attestation,
            "host_certificate":credentials.identity.certificate,"peer_certificate":peer}),
        )?;
        Ok((
            Permission {
                intent,
                decision,
                attestation,
                receipt,
            },
            lease,
        ))
    }
}
/// Two bounded buffers; one combined byte budget for both directions. Reserve
/// bytes before writing so simultaneous directions cannot exceed the limit.
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut read: R,
    mut write: W,
    remaining: Arc<AtomicU64>,
) -> Result<()> {
    let mut buffer = [0; 64 * 1024];
    loop {
        let available = remaining.load(Ordering::Relaxed);
        ensure!(available > 0, "Service byte limit reached");
        let amount = buffer
            .len()
            .min(usize::try_from(available).unwrap_or(usize::MAX));
        let n = read.read(&mut buffer[..amount]).await?;
        if n == 0 {
            write.shutdown().await?;
            return Ok(());
        }
        remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(n as u64)
            })
            .map_err(|_| anyhow::anyhow!("Service byte limit reached"))?;
        write.write_all(&buffer[..n]).await?;
    }
}
async fn stream(tcp: TcpStream, send: SendStream, recv: RecvStream, budget: u64) -> Result<()> {
    let remaining = Arc::new(AtomicU64::new(budget));
    let (read, write) = tcp.into_split();
    tokio::try_join!(
        pump(read, send, remaining.clone()),
        pump(recv, write, remaining)
    )?;
    Ok(())
}
pub(in crate::session) async fn serve(
    connection: &Connection,
    local: iroh::EndpointId,
    initial: &Credentials,
    shares: &Shares,
    mut changes: watch::Receiver<Option<Arc<Credentials>>>,
) -> Result<()> {
    let (share, mut credentials, peer, request, send, recv, lease) = timeout(HANDSHAKE, async {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let peer = authenticate_for(
            connection,
            local,
            Role::Server,
            initial,
            &mut send,
            &mut recv,
            Protocol::Service,
        )
        .await?;
        let credentials = initial.for_authenticated(&peer)?;
        let request: Request = read_frame(&mut recv).await?;
        uuid::Uuid::parse_str(&request.request_id)?;
        uuid::Uuid::parse_str(&request.collection_id)?;
        let share = shares
            .iter()
            .find(|s| s.config.collection_id == request.collection_id && s.config.kind.is_service())
            .context("Unknown service")?;
        let (permission, lease) = share
            .authorize_service(&credentials, &peer, &request)
            .await?;
        write_permission(&mut send, &permission).await?;
        let ack: String = read_frame(&mut recv).await?;
        ensure!(
            ack == genesis_mesh_sdk::canonical_digest(&permission.intent)?,
            "Service acknowledgement differs"
        );
        Ok::<_, anyhow::Error>((share, credentials, peer, request, send, recv, lease))
    })
    .await??;
    let target = share
        .config
        .service
        .as_ref()
        .context("Missing service target")?;
    // Only the host's saved port is dialed, after the signed allow decision.
    let tcp = timeout(
        Duration::from_secs(5),
        TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, target.port)),
    )
    .await??;
    let forwarding = stream(tcp, send, recv, target.max_bytes);
    tokio::pin!(forwarding);
    let expiry = tokio::time::sleep(Duration::from_secs(u64::from(target.max_seconds)));
    tokio::pin!(expiry);
    let mut check_at = tokio::time::Instant::now() + lease;
    loop {
        tokio::select! { biased;
            _=&mut expiry => anyhow::bail!("Service session time limit reached"),
            changed=changes.changed()=>{
                changed?;
                let next=current_credentials(&mut changes).await?;
                credentials=next.for_node(&credentials.expected_node)?;
                check_at=tokio::time::Instant::now();
            },
            _=tokio::time::sleep_until(check_at)=>{
                // Forwarding is paused while authorization is refreshed.
                let (_,lease)=timeout(HANDSHAKE,share.authorize_service(&credentials,&peer,&request)).await??;
                check_at=tokio::time::Instant::now()+lease;
            },
            result=&mut forwarding=>return result,
        }
    }
}
async fn current_credentials(
    changes: &mut watch::Receiver<Option<Arc<Credentials>>>,
) -> Result<Arc<Credentials>> {
    if let Some(current) = changes.borrow_and_update().clone() {
        return Ok(current);
    }
    timeout(
        Duration::from_secs(5),
        changes.wait_for(|current| current.is_some()),
    )
    .await??
    .clone()
    .context("Connection suspended")
}
impl SessionEndpoint {
    /// Each local TCP connection opens a new mutually authenticated stream and
    /// obtains a fresh authority decision. Dropping this future closes QUIC.
    pub async fn forward_service(
        &self,
        node: &str,
        ticket: &str,
        collection: &str,
        kind: SpaceKind,
        tcp: TcpStream,
    ) -> Result<()> {
        ensure!(kind.is_service(), "Not a service");
        let ticket: SessionTicket = wire::decode(ticket.as_bytes())?;
        ensure!(
            ticket.version == 1
                && !ticket.endpoint.is_empty()
                && ticket.endpoint.id != self.endpoint.id(),
            "Invalid service destination"
        );
        let mut changes = self.credentials.subscribe();
        let mut credentials = self.selected_credentials(Some(node), &mut changes)?;
        let connection = timeout(
            DEADLINE,
            self.endpoint
                .connect(ticket.endpoint, Protocol::Service.alpn()),
        )
        .await??;
        struct Close(Connection);
        impl Drop for Close {
            fn drop(&mut self) {
                self.0.close(0u32.into(), b"service closed");
            }
        }
        let _close = Close(connection.clone());
        limit_streams(&connection);
        let (send, recv, budget, seconds) = timeout(HANDSHAKE, async {
            let (mut send, mut recv) = connection.open_bi().await?;
            authenticate_for(
                &connection,
                self.endpoint.id(),
                Role::Client,
                &credentials,
                &mut send,
                &mut recv,
                Protocol::Service,
            )
            .await?;
            let request = Request {
                collection_id: collection.into(),
                request_id: uuid::Uuid::new_v4().to_string(),
            };
            write_frame(&mut send, &request).await?;
            let permission = read_permission(&mut recv).await?;
            let intent = &permission.intent;
            ensure!(
                intent["domain"] == "genesismesh-connect/service/v1"
                    && intent["request"] == serde_json::to_value(&request)?
                    && intent["host_node"] == node
                    && intent["peer_node"] == self.node_public_key
                    && intent["kind"] == serde_json::to_value(kind)?
                    && intent["policy_id"] == format!("connect-{collection}"),
                "Wrong service permission"
            );
            let budget = intent["max_bytes"]
                .as_u64()
                .context("Invalid service budget")?;
            let seconds = intent["max_seconds"]
                .as_u64()
                .context("Invalid service duration")?;
            ensure!(
                (1..=crate::transfer_limits::MAX_FILE_BYTES).contains(&budget)
                    && (1..=u64::from(MAX_SECONDS)).contains(&seconds),
                "Invalid service limits"
            );
            credentials.trust.read_decision(
                &permission.decision,
                &permission.attestation,
                &format!(
                    "connect-service:{}",
                    genesis_mesh_sdk::canonical_digest(intent)?
                ),
                &format!("connect-{collection}"),
                node,
            )?;
            check_receipt(&permission, node)?;
            write_frame(&mut send, &genesis_mesh_sdk::canonical_digest(intent)?).await?;
            Ok::<_, anyhow::Error>((send, recv, budget, seconds))
        })
        .await??;
        let forwarding = timeout(
            Duration::from_secs(seconds),
            stream(tcp, send, recv, budget),
        );
        tokio::pin!(forwarding);
        loop {
            tokio::select! { biased;
                changed=changes.changed()=>{
                    changed?; let next=current_credentials(&mut changes).await?;
                    credentials=next.for_node(node)?;
                    ensure!(credentials.identity.public_key()==self.node_public_key,"Identity changed");
                },
                outcome=&mut forwarding=>return outcome.context("Service session expired")?,
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_limits_are_bounded() {
        let mut target = Target {
            port: 8080,
            max_bytes: 1024,
            max_seconds: 60,
        };
        assert!(target.validate().is_ok());
        target.port = 0;
        assert!(target.validate().is_err());
        target.port = 8080;
        target.max_seconds = 3601;
        assert!(target.validate().is_err());
    }
    #[tokio::test]
    async fn combined_stream_budget_stops_excess_bytes() -> Result<()> {
        let (mut producer, reader) = tokio::io::duplex(64);
        let (writer, mut consumer) = tokio::io::duplex(64);
        producer.write_all(b"abcdefgh").await?;
        producer.shutdown().await?;
        let remaining = Arc::new(AtomicU64::new(4));
        assert!(pump(reader, writer, remaining.clone()).await.is_err());
        let mut bytes = Vec::new();
        consumer.read_to_end(&mut bytes).await?;
        assert_eq!(bytes, b"abcd");
        assert_eq!(remaining.load(Ordering::Relaxed), 0);
        Ok(())
    }
}
