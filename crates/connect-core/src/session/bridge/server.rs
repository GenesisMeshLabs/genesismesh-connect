use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use genesis_mesh_sdk::{node_auth::node_signing_payload, verify_canonical};

/// Serves one explicitly selected node. Node renewal signatures pass unchanged
/// to the configured local authority; there is no URL/method/path input.
pub struct AuthorityBridge {
    endpoint: Endpoint,
    credentials: watch::Sender<Option<Arc<Credentials>>>,
    node: String,
    peers: Mutex<super::super::Peers>,
    forwarded: Arc<AtomicU64>,
    published: Arc<Published>,
    task: Mutex<Option<JoinHandle<()>>>,
}

/// The connection setting and session address devices receive from `Settings`,
/// and the saved devices they receive from `Members`.
struct Published {
    connectivity: crate::Connectivity,
    session_ticket: Mutex<Option<String>>,
    /// None until the network computer publishes its saved devices.
    members: Mutex<Option<Vec<crate::device::PairedDevice>>>,
    /// Session addresses members reported for their own paired endpoint, until
    /// the network computer saves them.
    reported: Mutex<std::collections::BTreeMap<String, String>>,
    /// The owner runtime, where this computer runs one.
    owner: Mutex<Option<crate::owner::OwnerHandle>>,
    /// The Space registry as the network computer last published it, so
    /// listing never waits for the owner runtime.
    spaces: Mutex<Option<Vec<crate::owner::Space>>>,
}

impl AuthorityBridge {
    pub async fn bind(
        identity: SessionIdentity,
        trust: TrustSnapshot,
        peer: String,
        authority: LocalAuthority,
    ) -> Result<Self> {
        Self::bind_with_transport(
            identity,
            trust,
            peer,
            authority,
            None,
            crate::Connectivity::LocalNetwork,
        )
        .await
    }
    pub async fn bind_with_transport(
        identity: SessionIdentity,
        trust: TrustSnapshot,
        peer: String,
        authority: LocalAuthority,
        transport: Option<crate::connectivity::Transport>,
        connectivity: crate::Connectivity,
    ) -> Result<Self> {
        ensure!(
            STANDARD.decode(&peer).is_ok_and(|key| key.len() == 32)
                && peer != identity.public_key(),
            "Choose another node for the authority bridge"
        );
        let node = identity.public_key();
        let peers = super::super::Peers::new(&node, peer.clone(), [peer.clone()])?;
        let credentials = Credentials {
            identity,
            trust,
            expected_node: peer.clone(),
            allowed_nodes: peers.allowed.clone(),
        };
        own_credential(&credentials)?;
        let state = watch::channel(Some(Arc::new(credentials))).0;
        // Only a guided device's saved transport is announced and port-mapped.
        let role = if transport.is_some() {
            crate::connectivity::Role::Host
        } else {
            crate::connectivity::Role::Plain
        };
        let (key, port) = transport.map_or((None, None), |t| (Some(t.key), t.port));
        let endpoint = connectivity
            .bind(role, port, |builder| {
                let builder = builder.alpns(vec![
                    Protocol::Authority.alpn().to_vec(),
                    Protocol::Enrollment.alpn().to_vec(),
                ]);
                match &key {
                    Some(key) => builder.secret_key(key.clone()),
                    None => builder,
                }
            })
            .await?;
        let endpoint = connectivity
            .ready(
                endpoint,
                role,
                DEADLINE,
                "Authority relay did not become ready",
            )
            .await?;
        let forwarded = Arc::new(AtomicU64::new(0));
        let published = Arc::new(Published {
            connectivity,
            session_ticket: Mutex::new(None),
            members: Mutex::new(None),
            reported: Mutex::new(Default::default()),
            owner: Mutex::new(None),
            spaces: Mutex::new(None),
        });
        let task = tokio::spawn(accept(
            endpoint.clone(),
            state.clone(),
            authority,
            forwarded.clone(),
            published.clone(),
        ));
        Ok(Self {
            endpoint,
            credentials: state,
            node,
            peers: Mutex::new(peers),
            forwarded,
            published,
            task: Mutex::new(Some(task)),
        })
    }
    /// The session address devices receive with the connection setting, so a
    /// saved address can follow this computer after it changes networks.
    pub fn publish_session(&self, ticket: Option<String>) -> Result<()> {
        if let Some(ticket) = &ticket {
            crate::session::validate_ticket(ticket)?;
        }
        *self
            .published
            .session_ticket
            .lock()
            .expect("bridge publication mutex poisoned") = ticket;
        Ok(())
    }
    /// The saved devices members receive. Each sees the others, never itself.
    pub fn publish_members(&self, members: Vec<crate::device::PairedDevice>) {
        *self
            .published
            .members
            .lock()
            .expect("bridge publication mutex poisoned") = Some(members);
    }
    /// The Space registry devices list from; the network computer publishes it
    /// at least every 30 seconds.
    pub fn publish_spaces(&self, spaces: Vec<crate::owner::Space>) {
        *self
            .published
            .spaces
            .lock()
            .expect("bridge publication mutex poisoned") = Some(spaces);
    }
    /// Answer devices' Space requests through this owner runtime.
    pub fn serve_owner(&self, owner: crate::owner::OwnerHandle) {
        *self
            .published
            .owner
            .lock()
            .expect("bridge publication mutex poisoned") = Some(owner);
    }
    /// Session addresses members reported since the last call, by node.
    pub fn take_reported(&self) -> std::collections::BTreeMap<String, String> {
        std::mem::take(
            &mut *self
                .published
                .reported
                .lock()
                .expect("bridge publication mutex poisoned"),
        )
    }
    pub fn ticket(&self) -> Result<String> {
        Ok(serde_json::to_string(&Ticket {
            version: 1,
            service: Service::Authority,
            endpoint: self.endpoint.addr(),
        })?)
    }
    #[cfg(test)]
    pub(super) fn loopback_ticket(&self) -> Result<String> {
        // Same-host unit tests must not depend on routability of a LAN address.
        let port = self
            .endpoint
            .bound_sockets()
            .iter()
            .find(|address| address.is_ipv4())
            .context("No IPv4 test socket")?
            .port();
        Ok(serde_json::to_string(&Ticket {
            version: 1,
            service: Service::Authority,
            endpoint: EndpointAddr::new(self.endpoint.id())
                .with_ip_addr(([127, 0, 0, 1], port).into()),
        })?)
    }
    pub fn suspend(&self) {
        self.credentials.send_replace(None);
    }
    pub fn refresh(&self, identity: SessionIdentity, trust: TrustSnapshot) -> Result<()> {
        let peers = self.peers.lock().expect("bridge peer mutex poisoned");
        self.suspend();
        ensure!(
            identity.public_key() == self.node,
            "Cannot change the bridge host identity"
        );
        let credentials = Credentials {
            identity,
            trust,
            expected_node: peers.selected.clone(),
            allowed_nodes: peers.allowed.clone(),
        };
        own_credential(&credentials)?;
        self.credentials.send_replace(Some(Arc::new(credentials)));
        Ok(())
    }
    pub fn set_peers(&self, selected: String, allowed: Vec<String>) -> Result<()> {
        let next = super::super::Peers::new(&self.node, selected, allowed)?;
        let mut peers = self.peers.lock().expect("bridge peer mutex poisoned");
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
    /// The IPv4 port to reuse after a restart.
    pub fn port(&self) -> Option<u16> {
        crate::connectivity::ipv4_port(&self.endpoint)
    }
    pub fn forwarded_renewals(&self) -> u64 {
        self.forwarded.load(Ordering::Relaxed)
    }
    pub async fn close(&self) {
        self.suspend();
        self.endpoint.close().await;
        let task = self.task.lock().expect("bridge task mutex poisoned").take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}
impl Drop for AuthorityBridge {
    fn drop(&mut self) {
        if let Some(task) = self
            .task
            .get_mut()
            .expect("bridge task mutex poisoned")
            .take()
        {
            task.abort();
        }
    }
}

pub(super) fn check_renewal(
    body: &Value,
    peer_certificate: &Value,
    expected_node: &str,
) -> Result<()> {
    let object = body.as_object().context("Invalid renewal request")?;
    let fields = [
        "cert_id",
        "node_public_key",
        "validity_hours",
        "timestamp",
        "nonce",
        "signature",
    ];
    ensure!(
        object.len() == fields.len() && object.keys().all(|key| fields.contains(&key.as_str())),
        "Unsupported renewal fields"
    );
    ensure!(
        body["cert_id"] == peer_certificate["cert_id"] && body["node_public_key"] == expected_node,
        "Renewal must name the authenticated credential"
    );
    ensure!(
        body["validity_hours"]
            .as_u64()
            .is_some_and(|n| (1..=24).contains(&n)),
        "Invalid renewal validity"
    );
    check_request_signature(body, expected_node)
}

pub(super) fn check_request_signature(body: &Value, expected_node: &str) -> Result<()> {
    let timestamp = chrono::DateTime::parse_from_rfc3339(
        body["timestamp"]
            .as_str()
            .context("Missing renewal timestamp")?,
    )?;
    ensure!(
        (Utc::now() - timestamp.with_timezone(&Utc))
            .num_seconds()
            .unsigned_abs()
            < 300,
        "Renewal timestamp out of range"
    );
    let nonce = uuid::Uuid::parse_str(body["nonce"].as_str().context("Missing renewal nonce")?)?;
    ensure!(nonce.get_version_num() == 4, "Invalid renewal nonce");
    ensure!(
        verify_canonical(
            &node_signing_payload(body)?,
            body["signature"]
                .as_str()
                .context("Missing renewal signature")?,
            &[expected_node.to_owned()]
        ),
        "Invalid node renewal signature"
    );
    Ok(())
}

struct Budgets {
    renewals: Mutex<Budget>,
    collections: Mutex<Budget>,
    enrollments: Mutex<Budget>,
    settings: Mutex<Budget>,
    members: Mutex<Budget>,
    spaces: Mutex<Budget>,
    space_changes: Mutex<Budget>,
}
async fn exchange(
    connection: &Connection,
    endpoint: &Endpoint,
    credentials: &Credentials,
    authority: &LocalAuthority,
    budgets: &Budgets,
    forwarded: &AtomicU64,
    published: &Published,
) -> Result<()> {
    let local_id = endpoint.id();
    own_credential(credentials)?;
    if connection.alpn() == Protocol::Enrollment.alpn() {
        return enrollment::serve(
            connection,
            local_id,
            credentials,
            authority,
            &budgets.enrollments,
        )
        .await;
    }
    ensure!(
        connection.alpn() == Protocol::Authority.alpn(),
        "Unsupported bridge protocol"
    );
    let (mut send, mut recv) = connection.accept_bi().await?;
    let request: Request = read_frame(&mut recv).await?;
    ensure!(request.version == 1, "Unsupported authority protocol");
    let result = match request.operation {
        Operation::Trust => {
            ensure!(
                recv.read_to_end(0).await?.is_empty(),
                "Unexpected authority request data"
            );
            authority
                .documents()
                .await
                .and_then(|docs| Ok(serde_json::to_value(docs)?))
        }
        Operation::Renew
        | Operation::Evaluate
        | Operation::Attestation
        | Operation::Settings
        | Operation::Members
        | Operation::Spaces
        | Operation::ShareSpace
        | Operation::UnshareSpace => {
            let peer = authenticate_for(
                connection,
                local_id,
                Role::Server,
                credentials,
                &mut send,
                &mut recv,
                Protocol::Authority,
            )
            .await?;
            let selected = credentials.for_authenticated(&peer)?;
            let credentials = &selected;
            let signed: Value = read_frame(&mut recv).await?;
            ensure!(
                recv.read_to_end(0).await?.is_empty(),
                "Unexpected renewal request data"
            );
            own_credential(credentials)?;
            credentials.trust.renewable_certificate(
                &peer,
                &credentials.expected_node,
                Utc::now(),
            )?;
            ensure!(
                (match request.operation {
                    Operation::Renew => &budgets.renewals,
                    Operation::Settings => &budgets.settings,
                    Operation::Members => &budgets.members,
                    Operation::Spaces => &budgets.spaces,
                    Operation::ShareSpace | Operation::UnshareSpace => &budgets.space_changes,
                    _ => &budgets.collections,
                })
                .lock()
                .expect("bridge budget mutex poisoned")
                .allow(),
                "Authority renewal budget exhausted"
            );
            match request.operation {
                Operation::Renew => {
                    check_renewal(&signed, &peer, &credentials.expected_node)?;
                    forwarded.fetch_add(1, Ordering::Relaxed);
                    authority.forward_renewal(&signed).await
                }
                Operation::Evaluate => {
                    credentials
                        .trust
                        .certificate(&peer, &credentials.expected_node, Utc::now())?;
                    check_collection_decision(&signed, &peer, &credentials.trust)?;
                    authority.forward_collection_decision(&signed).await
                }
                Operation::Attestation => {
                    credentials
                        .trust
                        .certificate(&peer, &credentials.expected_node, Utc::now())?;
                    ensure!(
                        signed.as_object().is_some_and(|o| o.len() == 1),
                        "Unsupported attestation fields"
                    );
                    authority
                        .read_attestation(
                            signed["attestation_id"]
                                .as_str()
                                .context("Missing attestation")?,
                        )
                        .await
                }
                Operation::Settings => {
                    credentials
                        .trust
                        .certificate(&peer, &credentials.expected_node, Utc::now())?;
                    ensure!(
                        signed.as_object().is_some_and(|o| o.is_empty()),
                        "Unsupported settings fields"
                    );
                    let session_ticket = published
                        .session_ticket
                        .lock()
                        .expect("bridge publication mutex poisoned")
                        .clone();
                    Ok(serde_json::to_value(super::NetworkSettings {
                        connectivity: published.connectivity,
                        authority_ticket: serde_json::to_string(&Ticket {
                            version: 1,
                            service: Service::Authority,
                            endpoint: endpoint.addr(),
                        })?,
                        session_ticket,
                    })?)
                }
                Operation::Members => {
                    credentials
                        .trust
                        .certificate(&peer, &credentials.expected_node, Utc::now())?;
                    members(signed, &credentials.expected_node, published)
                }
                Operation::Spaces | Operation::ShareSpace | Operation::UnshareSpace => {
                    credentials
                        .trust
                        .certificate(&peer, &credentials.expected_node, Utc::now())?;
                    spaces(
                        request.operation,
                        signed,
                        &credentials.expected_node,
                        &credentials.identity.public_key(),
                        published,
                    )
                    .await
                }
                Operation::Trust => unreachable!(),
            }
        }
    };
    own_credential(credentials)?;
    respond(&mut send, result).await?;
    connection.closed().await;
    Ok(())
}

/// Answer one saved device with the others, and keep the session address it
/// reported if it names the endpoint it paired with. Until the network
/// computer has published its devices, and for a device it has not saved,
/// there is no answer: an empty list would read as "nobody else".
fn members(request: Value, node: &str, published: &Published) -> Result<Value> {
    let request: MembersRequest = serde_json::from_value(request)?;
    let members = published
        .members
        .lock()
        .expect("bridge publication mutex poisoned")
        .clone()
        .context("The device list is not ready")?;
    let paired = members
        .iter()
        .find(|m| m.node == node)
        .context("Only saved devices receive the device list")?;
    // An address too long to pass on is not kept; the answer still comes.
    if let Some(ticket) = request.session_ticket {
        let ticket = crate::session::canonical_ticket(&ticket)?;
        if ticket.len() <= MAX_MEMBER_TICKET
            && crate::session::canonical_ticket(&paired.ticket).ok() != Some(ticket.clone())
            && crate::session::ticket_endpoint(&paired.ticket).ok()
                == Some(crate::session::ticket_endpoint(&ticket)?)
        {
            published
                .reported
                .lock()
                .expect("bridge publication mutex poisoned")
                .insert(node.to_owned(), ticket);
        }
    }
    Ok(serde_json::to_value(MembersAnswer {
        members: members
            .into_iter()
            .filter(|m| m.node != node)
            .filter_map(|mut m| {
                m.ticket = crate::session::canonical_ticket(&m.ticket).ok()?;
                (m.ticket.len() <= MAX_MEMBER_TICKET).then_some(m)
            })
            .collect(),
    })?)
}

/// One request to the owner runtime, answered by whoever holds it.
async fn ask(owner: &crate::owner::OwnerHandle, call: crate::owner::OwnerCall) -> Result<Value> {
    let (reply, answer) = tokio::sync::oneshot::channel();
    owner
        .send(crate::owner::OwnerRequest { call, reply })
        .await
        .map_err(|_| anyhow::anyhow!("The owner runtime stopped"))?;
    timeout(Duration::from_secs(10), answer)
        .await
        .context("The owner runtime did not answer")?
        .context("The owner runtime stopped")?
}

/// One Space operation for an authenticated, saved device. Lists come from
/// the published registry; changes go through the owner runtime. The device
/// can only act as the host of its own Spaces, share with devices this
/// computer saved (or this computer), and see the Spaces that it hosts or
/// that name it.
async fn spaces(
    operation: Operation,
    request: Value,
    node: &str,
    computer: &str,
    published: &Published,
) -> Result<Value> {
    let owner = published
        .owner
        .lock()
        .expect("bridge publication mutex poisoned")
        .clone()
        .context("This network computer does not share folders for devices")?;
    let saved: Vec<String> = published
        .members
        .lock()
        .expect("bridge publication mutex poisoned")
        .as_ref()
        .context("The device list is not ready")?
        .iter()
        .map(|m| m.node.clone())
        .collect();
    ensure!(
        saved.iter().any(|n| n == node),
        "Only saved devices share folders"
    );
    match operation {
        Operation::Spaces => {
            ensure!(
                request.as_object().is_some_and(|o| o.is_empty()),
                "Unsupported spaces fields"
            );
            let list = published
                .spaces
                .lock()
                .expect("bridge publication mutex poisoned")
                .clone()
                .context("The shared folders are not ready")?;
            Ok(serde_json::to_value(SpacesAnswer {
                spaces: list
                    .into_iter()
                    .filter_map(|space| SpaceView::of(space, node))
                    .collect(),
            })?)
        }
        Operation::ShareSpace => {
            let request: ShareSpaceRequest = serde_json::from_value(request)?;
            uuid::Uuid::parse_str(&request.collection)?;
            ensure!(
                !request.recipients.is_empty()
                    && request.recipients.len() <= 31
                    && request
                        .recipients
                        .iter()
                        .all(|r| r != node && (r == computer || saved.contains(r))),
                "Share only with devices of this network"
            );
            let space: crate::owner::Space = serde_json::from_value(
                ask(
                    &owner,
                    crate::owner::OwnerCall::Share {
                        host: node.to_owned(),
                        collection: request.collection,
                        name: request.name,
                        recipients: request.recipients,
                    },
                )
                .await?,
            )?;
            // The registry as of this change, until the next publication.
            if let Some(list) = published
                .spaces
                .lock()
                .expect("bridge publication mutex poisoned")
                .as_mut()
            {
                list.retain(|s| s.collection != space.collection);
                list.push(space.clone());
            }
            Ok(serde_json::to_value(
                SpaceView::of(space, node).context("Unexpected shared folder")?,
            )?)
        }
        Operation::UnshareSpace => {
            let request: UnshareSpaceRequest = serde_json::from_value(request)?;
            let removed = ask(
                &owner,
                crate::owner::OwnerCall::Remove {
                    host: node.to_owned(),
                    collection: request.collection.clone(),
                },
            )
            .await?;
            if let Some(list) = published
                .spaces
                .lock()
                .expect("bridge publication mutex poisoned")
                .as_mut()
            {
                list.retain(|s| s.collection != request.collection || s.host != node);
            }
            Ok(removed)
        }
        _ => anyhow::bail!("Unsupported spaces operation"),
    }
}

pub(super) fn check_collection_decision(
    body: &Value,
    peer: &Value,
    trust: &TrustSnapshot,
) -> Result<()> {
    let fields = [
        "cert_id",
        "node_public_key",
        "purpose",
        "audience",
        "attestation_id",
        "requested_capability",
        "context",
        "timestamp",
        "nonce",
        "signature",
    ];
    let object = body.as_object().context("Invalid collection decision")?;
    ensure!(
        object.len() == fields.len() && object.keys().all(|k| fields.contains(&k.as_str())),
        "Unsupported collection fields"
    );
    let node = peer["node_public_key"]
        .as_str()
        .context("Missing peer identity")?;
    ensure!(
        body["cert_id"] == peer["cert_id"]
            && body["node_public_key"] == node
            && body["purpose"] == "node_boundary_evaluate"
            && body["audience"] == trust.audience()?,
        "Decision must name this authenticated node and authority"
    );
    uuid::Uuid::parse_str(
        body["attestation_id"]
            .as_str()
            .context("Missing attestation")?,
    )?;
    let context = body["context"]
        .as_object()
        .context("Missing collection context")?;
    ensure!(
        context.len() == 2
            && context.contains_key("context_id")
            && context.contains_key("request_parameters"),
        "Unsupported collection context"
    );
    let id = body["context"]["context_id"]
        .as_str()
        .context("Missing context ID")?;
    ensure!(!id.is_empty() && id.len() <= 128, "Invalid context ID");
    let parameters = body["context"]["request_parameters"]
        .as_object()
        .context("Invalid collection parameters")?;
    let allowed: &[&str] = match body["requested_capability"].as_str() {
        Some("connect.collection.read") => {
            &["collection_id", "file_name", "peer_node", "sha256", "size"]
        }
        Some("connect.collection.list") if id.starts_with("connect-browse:") => &[
            "collection_id",
            "peer_node",
            "size",
            "page_digest",
            "directory",
        ],
        Some("connect.collection.list") => &["collection_id", "peer_node", "size", "page_digest"],
        _ => anyhow::bail!("Unsupported collection action"),
    };
    ensure!(
        parameters.len() == allowed.len()
            && parameters.keys().all(|k| allowed.contains(&k.as_str())),
        "Unsupported collection parameters"
    );
    if body["requested_capability"] == "connect.collection.list"
        && id.starts_with("connect-browse:")
    {
        let directory = parameters["directory"]
            .as_str()
            .context("Invalid folder parameter")?;
        ensure!(directory.len() <= 2048, "Folder parameter too long");
    }
    ensure!(
        parameters["collection_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 128)
            && parameters["peer_node"]
                .as_str()
                .is_some_and(|s| STANDARD.decode(s).is_ok_and(|k| k.len() == 32))
            && parameters["size"].as_u64().is_some_and(|n| n
                <= if id.starts_with("connect-download:") {
                    crate::session::sharing::download::MAX_FILE_BYTES
                } else {
                    65536
                }),
        "Invalid collection request limits"
    );
    check_request_signature(body, node)
}

async fn accept(
    endpoint: Endpoint,
    state: watch::Sender<Option<Arc<Credentials>>>,
    authority: LocalAuthority,
    forwarded: Arc<AtomicU64>,
    published: Arc<Published>,
) {
    let mut tasks = JoinSet::new();
    // Each short download window obtains fresh authority documents and a live
    // decision. Keep concurrency bounded while allowing those signed calls.
    let mut arrivals = Budget::new(1024);
    let budgets = Arc::new(Budgets {
        renewals: Mutex::new(Budget::new(8)),
        collections: Mutex::new(Budget::new(480)),
        enrollments: Mutex::new(Budget::new(3)),
        // Each device asks once per trust refresh (every 30 seconds).
        settings: Mutex::new(Budget::new(120)),
        members: Mutex::new(Budget::new(120)),
        // Each device asks once per refresh; changes come from people.
        spaces: Mutex::new(Budget::new(120)),
        space_changes: Mutex::new(Budget::new(16)),
    });
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                if tasks.len() >= 4 || !arrivals.allow() { incoming.refuse(); continue; }
                let mut changes = state.subscribe();
                let Some(credentials) = changes.borrow_and_update().clone() else { incoming.refuse(); continue };
                let (authority, forwarded, budgets, local, published) = (authority.clone(), forwarded.clone(), budgets.clone(), endpoint.clone(), published.clone());
                tasks.spawn(async move {
                    let incoming = timeout(DEADLINE, incoming);
                    let connection = tokio::select! { biased; _ = changes.changed() => return, result = incoming => match result { Ok(Ok(c)) => c, _ => return } };
                    limit_streams(&connection);
                    tokio::select! { biased;
                        _ = changes.changed() => {},
                        _ = timeout(DEADLINE, exchange(&connection, &local, &credentials, &authority, &budgets, &forwarded, &published)) => {},
                    }
                    connection.close(0u32.into(), b"authority operation ended");
                });
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
    tasks.shutdown().await;
}
