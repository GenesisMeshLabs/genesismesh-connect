//! Owner-approved, single-use pairing. No invitation is sent before the owner
//! proves the node identity pinned by the locally displayed join link.
use super::{
    wire::{self, Hello, Proof, Protocol, Role, read_frame, write_frame},
    *,
};
use crate::authority::{LocalAuthority, TrustDocuments, TrustPin, TrustStore};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use genesis_mesh_sdk::{canonical_digest, canonical_json};
use iroh::endpoint::{RecvStream, SendStream};
use tokio::sync::oneshot;

const PREFIX: &str = "genesismesh://join/";
const WINDOW: Duration = Duration::from_secs(300);
const APPROVAL: Duration = Duration::from_secs(120);
const MAX_DOCUMENTS: usize = 512 * 1024 + 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairCard {
    version: u8,
    pub pin: TrustPin,
    pub host_node: String,
    pub host_name: String,
    endpoint: EndpointAddr,
    token: String,
    pub expires_at: i64,
}
impl PairCard {
    pub fn parse(link: &str) -> Result<Self> {
        ensure!(link.len() <= 8192, "Join link is too long");
        let bytes = URL_SAFE_NO_PAD.decode(
            link.trim()
                .strip_prefix(PREFIX)
                .context("Choose a Genesis Mesh join link")?,
        )?;
        let card: Self = wire::decode(&bytes)?;
        card.validate()?;
        Ok(card)
    }
    fn validate(&self) -> Result<()> {
        // The network computer dated the link by its own clock, which may run
        // ahead of this device's.
        let remaining = self.expires_at - Utc::now().timestamp();
        ensure!(
            self.version == 1
                && remaining > 0
                && remaining <= 300 + super::trust::CLOCK_SKEW.num_seconds(),
            "This join link has expired. Create a new one on your computer."
        );
        ensure!(
            !self.endpoint.is_empty()
                && STANDARD
                    .decode(&self.host_node)
                    .is_ok_and(|b| b.len() == 32)
                && URL_SAFE_NO_PAD
                    .decode(&self.token)
                    .is_ok_and(|b| b.len() == 32),
            "Invalid join link"
        );
        valid_name(&self.host_name)?;
        Ok(())
    }
    /// The network's connection setting when this card was created. The
    /// network computer's later answers keep a device up to date.
    pub fn connectivity(&self) -> crate::Connectivity {
        crate::Connectivity::of_destination(&self.endpoint)
    }
    pub fn link(&self) -> Result<String> {
        Ok(format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?)
        ))
    }
}
pub fn valid_name(name: &str) -> Result<()> {
    ensure!(
        !name.trim().is_empty()
            && name.chars().count() <= 64
            && !name.chars().any(char::is_control),
        "Use a device name of up to 64 characters"
    );
    Ok(())
}
#[derive(Clone, Serialize)]
pub struct PairRequest {
    pub id: String,
    pub name: String,
    pub node: String,
    pub code: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairGrant {
    pub invitation: String,
    pub route: bridge::BridgeRoute,
    pub session_ticket: String,
}
pub struct Joined {
    pub ticket: String,
    pub confirm: oneshot::Sender<bool>,
}
struct Pending {
    info: PairRequest,
    grant: oneshot::Sender<PairGrant>,
    joined: oneshot::Receiver<Joined>,
}
struct Gate {
    pending: Option<Pending>,
    used: bool,
    attempts: u8,
}
pub struct PairHost {
    endpoint: Endpoint,
    card: PairCard,
    state: watch::Sender<Option<Arc<Credentials>>>,
    gate: Arc<Mutex<Gate>>,
    task: Mutex<Option<JoinHandle<()>>>,
    created: std::time::Instant,
}
impl PairHost {
    pub async fn bind(
        identity: SessionIdentity,
        trust: TrustSnapshot,
        authority: LocalAuthority,
        name: String,
        connectivity: crate::Connectivity,
    ) -> Result<Arc<Self>> {
        valid_name(&name)?;
        trust.certificate(&identity.certificate, &identity.public_key(), Utc::now())?;
        // The temporary pairing endpoint is never published for lookup.
        let endpoint = connectivity
            .ready(
                connectivity
                    .builder(crate::connectivity::Role::Plain)
                    .alpns(vec![Protocol::Pair.alpn().to_vec()])
                    .bind()
                    .await?,
                crate::connectivity::Role::Plain,
                DEADLINE,
                "Pairing relay is unavailable; try again",
            )
            .await?;
        let mut secret = [0; 32];
        getrandom::fill(&mut secret)?;
        let addr = endpoint.addr();
        // A relay-only join card fits a QR code. Direct paths are learned by Iroh.
        let addr = match addr.relay_urls().next().cloned() {
            Some(relay) => EndpointAddr::new(endpoint.id()).with_relay_url(relay),
            None => addr.clone(),
        };
        let card = PairCard {
            version: 1,
            pin: TrustPin {
                network_name: trust.network().into(),
                root_public_key: trust.root().into(),
            },
            host_node: identity.public_key(),
            host_name: name,
            endpoint: addr,
            token: URL_SAFE_NO_PAD.encode(secret),
            expires_at: Utc::now().timestamp() + 300,
        };
        let state = watch::channel(Some(Arc::new(Credentials {
            identity,
            trust,
            expected_node: String::new(),
            allowed_nodes: Default::default(),
        })))
        .0;
        let gate = Arc::new(Mutex::new(Gate {
            pending: None,
            used: false,
            attempts: 0,
        }));
        let task = tokio::spawn(accept(
            endpoint.clone(),
            state.clone(),
            gate.clone(),
            card.clone(),
            authority,
        ));
        Ok(Arc::new(Self {
            endpoint,
            card,
            state,
            gate,
            task: Mutex::new(Some(task)),
            created: std::time::Instant::now(),
        }))
    }
    pub fn card(&self) -> &PairCard {
        &self.card
    }
    pub fn pending(&self) -> Option<PairRequest> {
        if self.created.elapsed() >= WINDOW {
            return None;
        }
        self.gate
            .lock()
            .expect("pair gate")
            .pending
            .as_ref()
            .filter(|p| !p.grant.is_closed())
            .map(|p| p.info.clone())
    }
    pub fn approve(&self, id: &str, grant: PairGrant) -> Result<oneshot::Receiver<Joined>> {
        ensure!(self.created.elapsed() < WINDOW, "Pairing expired");
        let mut gate = self.gate.lock().expect("pair gate");
        ensure!(
            gate.pending
                .as_ref()
                .is_some_and(|p| p.info.id == id && !p.grant.is_closed()),
            "This request is no longer waiting"
        );
        let pending = gate.pending.take().context("No pending device")?;
        pending
            .grant
            .send(grant)
            .map_err(|_| anyhow::anyhow!("The device disconnected"))?;
        Ok(pending.joined)
    }
    pub fn reject(&self, id: &str) -> Result<()> {
        let mut gate = self.gate.lock().expect("pair gate");
        ensure!(
            gate.pending.as_ref().is_some_and(|p| p.info.id == id),
            "Request no longer waiting"
        );
        gate.pending.take(); // Dropping the sender refuses the request.
        Ok(())
    }
    pub fn refresh(&self, identity: SessionIdentity, trust: TrustSnapshot) -> Result<()> {
        self.suspend();
        ensure!(
            identity.public_key() == self.card.host_node,
            "Pairing owner changed"
        );
        trust.certificate(&identity.certificate, &identity.public_key(), Utc::now())?;
        self.state.send_replace(Some(Arc::new(Credentials {
            identity,
            trust,
            expected_node: String::new(),
            allowed_nodes: Default::default(),
        })));
        Ok(())
    }
    pub fn suspend(&self) {
        self.state.send_replace(None);
    }
    pub async fn close(&self) {
        self.suspend();
        self.endpoint.close().await;
        let task = self.task.lock().expect("pair task").take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}
impl Drop for PairHost {
    fn drop(&mut self) {
        if let Some(task) = self.task.get_mut().expect("pair task").take() {
            task.abort();
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClientHello {
    version: u8,
    node: String,
    endpoint: iroh::EndpointId,
    network: String,
    root: String,
    nonce: [u8; 32],
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ask {
    token: String,
    name: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Finished {
    ticket: String,
}
fn transcript(
    client: &ClientHello,
    server: &Hello,
    binding: &[u8; 32],
    signer: Role,
) -> Result<String> {
    Ok(canonical_json(
        &serde_json::json!({"domain":Protocol::Pair.domain(),"alpn":std::str::from_utf8(Protocol::Pair.alpn())?,"version":1,"client":client,"server":{"endpoint":server.endpoint,"nonce":server.nonce,"network":server.network,"root":server.root,"certificate_digest":canonical_digest(&server.certificate)?},"tls_exporter":STANDARD.encode(binding),"signer":signer}),
    )?)
}
fn comparison(binding: &[u8; 32]) -> String {
    format!(
        "{:06}",
        u32::from_be_bytes(binding[..4].try_into().expect("four bytes")) % 1_000_000
    )
}
async fn docs_send(send: &mut SendStream, docs: &TrustDocuments) -> Result<()> {
    let bytes = serde_json::to_vec(docs)?;
    ensure!(bytes.len() <= MAX_DOCUMENTS, "Trust response too large");
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}
async fn docs_read(recv: &mut RecvStream) -> Result<TrustDocuments> {
    let mut size = [0; 4];
    recv.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(
        size > 0 && size <= MAX_DOCUMENTS,
        "Invalid trust response size"
    );
    let mut bytes = vec![0; size];
    recv.read_exact(&mut bytes).await?;
    Ok(serde_json::from_value(
        genesis_mesh_sdk::parse_strict_json(std::str::from_utf8(&bytes)?)?,
    )?)
}
async fn serve(
    connection: &Connection,
    local: iroh::EndpointId,
    credentials: &Credentials,
    gate: &Mutex<Gate>,
    card: &PairCard,
    authority: &LocalAuthority,
    state: &watch::Sender<Option<Arc<Credentials>>>,
) -> Result<()> {
    card.validate()?;
    current_owner(state, card)?;
    let (mut send, mut recv) = connection.accept_bi().await?;
    let peer: ClientHello = read_frame(&mut recv).await?;
    ensure!(
        peer.version == 1
            && peer.endpoint == connection.remote_id()
            && peer.network == card.pin.network_name
            && peer.root == card.pin.root_public_key
            && STANDARD.decode(&peer.node).is_ok_and(|b| b.len() == 32)
            && peer.node != card.host_node,
        "Invalid pairing device"
    );
    let ours = wire::hello(
        Role::Server,
        local,
        &credentials.identity,
        &credentials.trust,
    )?;
    docs_send(&mut send, &authority.documents().await?).await?;
    write_frame(&mut send, &ours).await?;
    let binding = wire::exporter_for(connection, Protocol::Pair)?;
    write_frame(
        &mut send,
        &wire::sign(
            &credentials.identity,
            &transcript(&peer, &ours, &binding, Role::Server)?,
        ),
    )
    .await?;
    let proof: Proof = read_frame(&mut recv).await?;
    wire::verify(
        &proof,
        &transcript(&peer, &ours, &binding, Role::Client)?,
        &peer.node,
    )?;
    let ask: Ask = read_frame(&mut recv).await?;
    valid_name(&ask.name)?;
    // Compare a digest to avoid leaking a progressively matched secret prefix.
    ensure!(
        canonical_digest(&serde_json::json!(ask.token))?
            == canonical_digest(&serde_json::json!(card.token))?,
        "Wrong join secret"
    );
    card.validate()?;
    let (grant_tx, grant_rx) = oneshot::channel();
    let (joined_tx, joined_rx) = oneshot::channel();
    let id = uuid::Uuid::new_v4().to_string();
    {
        let mut gate = gate.lock().expect("pair gate");
        ensure!(!gate.used, "This join link was already used");
        gate.used = true;
        gate.pending = Some(Pending {
            info: PairRequest {
                id,
                name: ask.name,
                node: peer.node,
                code: comparison(&binding),
            },
            grant: grant_tx,
            joined: joined_rx,
        });
    }
    write_frame(
        &mut send,
        &serde_json::json!({"waiting":true,"code":comparison(&binding)}),
    )
    .await?;
    let grant = timeout(APPROVAL, grant_rx)
        .await
        .context("Approval expired")?
        .context("Owner declined")?;
    card.validate()?;
    current_owner(state, card)?;
    write_frame(&mut send, &grant).await?;
    let finished: Finished = timeout(Duration::from_secs(75), read_frame(&mut recv)).await??;
    let _: super::SessionTicket = wire::decode(finished.ticket.as_bytes())?;
    let (confirm_tx, confirm_rx) = oneshot::channel();
    joined_tx
        .send(Joined {
            ticket: finished.ticket,
            confirm: confirm_tx,
        })
        .map_err(|_| anyhow::anyhow!("Pairing cancelled"))?;
    ensure!(
        timeout(Duration::from_secs(20), confirm_rx).await??,
        "Device verification failed"
    );
    current_owner(state, card)?;
    write_frame(&mut send, &serde_json::json!({"paired":true})).await?;
    send.finish()?;
    connection.closed().await;
    Ok(())
}
fn current_owner(state: &watch::Sender<Option<Arc<Credentials>>>, card: &PairCard) -> Result<()> {
    let snapshot = state
        .borrow()
        .clone()
        .context("Owner trust is unavailable")?;
    snapshot
        .trust
        .certificate(&snapshot.identity.certificate, &card.host_node, Utc::now())
}
async fn accept(
    endpoint: Endpoint,
    state: watch::Sender<Option<Arc<Credentials>>>,
    gate: Arc<Mutex<Gate>>,
    card: PairCard,
    authority: LocalAuthority,
) {
    let mut tasks = JoinSet::new();
    let expires = tokio::time::sleep(WINDOW);
    tokio::pin!(expires);
    loop {
        tokio::select! {
            _=&mut expires=>break,
            incoming=endpoint.accept()=>{let Some(incoming)=incoming else{break};
                let allowed={let mut g=gate.lock().expect("pair gate");if g.used||g.attempts>=12{false}else{g.attempts+=1;true}};
                if !allowed||tasks.len()>=2{incoming.refuse();continue}
                let mut changes=state.subscribe();let Some(credentials)=changes.borrow_and_update().clone()else{incoming.refuse();continue};
                let(gate,card,authority,local,state)=(gate.clone(),card.clone(),authority.clone(),endpoint.id(),state.clone());
                tasks.spawn(async move{let Ok(Ok(connection))=timeout(DEADLINE,incoming).await else{return};super::limit_streams(&connection);
                    // Recheck the current refreshed owner snapshot at approval
                    // and completion, including after renewal while waiting.
                    let _=timeout(Duration::from_secs(240),serve(&connection,local,&credentials,&gate,&card,&authority,&state)).await;
                    connection.close(0u32.into(),b"pairing ended");});
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{},
        }
    }
    tasks.shutdown().await;
    endpoint.close().await;
}

pub struct PairClient {
    endpoint: Endpoint,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    pub card: PairCard,
    pub code: String,
}
impl PairClient {
    pub async fn request(
        card: PairCard,
        key: &SigningKey,
        store: &mut TrustStore,
        name: String,
    ) -> Result<Self> {
        card.validate()?;
        valid_name(&name)?;
        let endpoint = crate::Connectivity::of_destination(&card.endpoint)
            .builder(crate::connectivity::Role::Plain)
            .bind()
            .await?;
        let outcome = timeout(Duration::from_secs(25), async {
            let connection = endpoint
                .connect(card.endpoint.clone(), Protocol::Pair.alpn())
                .await?;
            super::limit_streams(&connection);
            let (mut send, mut recv) = connection.open_bi().await?;
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce)?;
            let ours = ClientHello {
                version: 1,
                node: STANDARD.encode(key.verifying_key().to_bytes()),
                endpoint: endpoint.id(),
                network: card.pin.network_name.clone(),
                root: card.pin.root_public_key.clone(),
                nonce,
            };
            write_frame(&mut send, &ours).await?;
            let docs = docs_read(&mut recv).await?;
            let trust = store.accept(&docs.history, docs.crl, Utc::now())?;
            let host: Hello = read_frame(&mut recv).await?;
            ensure!(
                host.version == 1
                    && host.role == Role::Server
                    && host.endpoint == connection.remote_id()
                    && host.network == card.pin.network_name
                    && host.root == card.pin.root_public_key,
                "Unexpected pairing host"
            );
            trust.certificate(&host.certificate, &card.host_node, Utc::now())?;
            let binding = wire::exporter_for(&connection, Protocol::Pair)?;
            let proof: Proof = read_frame(&mut recv).await?;
            wire::verify(
                &proof,
                &transcript(&ours, &host, &binding, Role::Server)?,
                &card.host_node,
            )?;
            write_frame(
                &mut send,
                &wire::sign_key(key, &transcript(&ours, &host, &binding, Role::Client)?),
            )
            .await?;
            // Secret is sent only to the verified host on this exact TLS session.
            write_frame(
                &mut send,
                &Ask {
                    token: card.token.clone(),
                    name,
                },
            )
            .await?;
            let waiting: Value = read_frame(&mut recv).await?;
            let code = comparison(&binding);
            ensure!(
                waiting == serde_json::json!({"waiting":true,"code":code}),
                "Pairing request refused"
            );
            Ok::<_, anyhow::Error>((connection, send, recv, code))
        })
        .await;
        match outcome {
            Ok(Ok((connection, send, recv, code))) => Ok(Self {
                endpoint,
                connection,
                send,
                recv,
                card,
                code,
            }),
            other => {
                endpoint.close().await;
                match other {
                    Ok(Err(e)) => Err(e),
                    _ => anyhow::bail!(
                        "The computer did not respond. Keep Connect open on both devices."
                    ),
                }
            }
        }
    }
    pub async fn grant(&mut self) -> Result<PairGrant> {
        let grant: PairGrant = timeout(APPROVAL, read_frame(&mut self.recv))
            .await
            .context("Approval timed out")??;
        ensure!(
            grant.route.host_node == self.card.host_node,
            "Approval named another owner"
        );
        Ok(grant)
    }
    pub async fn finish(&mut self, ticket: String) -> Result<()> {
        write_frame(&mut self.send, &Finished { ticket }).await?;
        self.send.finish()?;
        let paired: Value = timeout(Duration::from_secs(25), read_frame(&mut self.recv)).await??;
        ensure!(
            paired == serde_json::json!({"paired":true}),
            "Pairing was not confirmed"
        );
        Ok(())
    }
    pub async fn close(&self) {
        self.connection.close(0u32.into(), b"pairing complete");
        self.endpoint.close().await;
    }
}
impl Drop for PairClient {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"pairing closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::tests::support::{Fixture, key, public};
    #[test]
    fn join_links_refuse_expiry_unknown_fields_and_bad_secrets() -> Result<()> {
        let f = Fixture::new();
        let endpoint = EndpointAddr::new(iroh::SecretKey::from([7; 32]).public())
            .with_ip_addr(([127, 0, 0, 1], 1234).into());
        let card = PairCard {
            version: 1,
            pin: TrustPin {
                network_name: "connect-spike".into(),
                root_public_key: public(&f.root),
            },
            host_node: public(&f.server),
            host_name: "Home".into(),
            endpoint,
            token: URL_SAFE_NO_PAD.encode([8; 32]),
            expires_at: Utc::now().timestamp() + 299,
        };
        assert_eq!(PairCard::parse(&card.link()?)?.host_node, card.host_node);
        // Made by a computer whose clock runs a minute ahead of this one.
        let mut ahead = card.clone();
        ahead.expires_at = Utc::now().timestamp() + 360;
        PairCard::parse(&ahead.link()?)?;
        let mut expired = card.clone();
        expired.expires_at = Utc::now().timestamp();
        assert!(PairCard::parse(&expired.link()?).is_err());
        let mut too_far = card.clone();
        too_far.expires_at = Utc::now().timestamp() + 300 + 310;
        assert!(PairCard::parse(&too_far.link()?).is_err());
        let mut changed = serde_json::to_value(&card)?;
        changed["admin_key"] = serde_json::json!("unexpected");
        assert!(
            PairCard::parse(&format!(
                "{PREFIX}{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed)?)
            ))
            .is_err()
        );
        for name in ["", "  ", "Device\nAllow me"] {
            assert!(valid_name(name).is_err());
        }
        Ok(())
    }
    #[test]
    fn pairing_proof_cannot_be_reused_for_another_node_role_endpoint_or_tls_session() -> Result<()>
    {
        let f = Fixture::new();
        let identity = SessionIdentity::new(f.server.clone(), f.server_cert.clone())?;
        let host = wire::hello(
            Role::Server,
            iroh::SecretKey::from([2; 32]).public(),
            &identity,
            &f.trust()?,
        )?;
        let client = ClientHello {
            version: 1,
            node: public(&f.client),
            endpoint: iroh::SecretKey::from([3; 32]).public(),
            network: "connect-spike".into(),
            root: public(&f.root),
            nonce: [4; 32],
        };
        let original = transcript(&client, &host, &[5; 32], Role::Client)?;
        let proof = wire::sign_key(&f.client, &original);
        wire::verify(&proof, &original, &public(&f.client))?;
        assert!(
            wire::verify(
                &proof,
                &transcript(&client, &host, &[6; 32], Role::Client)?,
                &public(&f.client)
            )
            .is_err()
        );
        assert!(
            wire::verify(
                &proof,
                &transcript(&client, &host, &[5; 32], Role::Server)?,
                &public(&f.client)
            )
            .is_err()
        );
        assert!(wire::verify(&proof, &original, &public(&key())).is_err());
        let mut changed = client;
        changed.endpoint = iroh::SecretKey::from([9; 32]).public();
        assert!(
            wire::verify(
                &proof,
                &transcript(&changed, &host, &[5; 32], Role::Client)?,
                &public(&f.client)
            )
            .is_err()
        );
        assert_ne!(Protocol::Pair.domain(), Protocol::Enrollment.domain());
        assert_ne!(Protocol::List.domain(), Protocol::Read.domain());
        Ok(())
    }
}
