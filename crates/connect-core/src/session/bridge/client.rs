use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Provision the host node key independently from its reachability ticket.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeRoute {
    pub ticket: String,
    pub host_node: String,
}

/// The endpoint a valid authority ticket names.
pub(crate) fn endpoint_of(ticket: &str) -> Result<iroh::EndpointId> {
    let ticket: Ticket = wire::decode(ticket.as_bytes())?;
    ensure!(
        ticket.version == 1 && !ticket.endpoint.is_empty(),
        "Invalid desktop authority ticket"
    );
    Ok(ticket.endpoint.id)
}

#[derive(Clone)]
pub struct BridgeAuthority {
    route: BridgeRoute,
    pub(super) destination: EndpointAddr,
    connectivity: crate::Connectivity,
    /// Guided devices look their network computer up on the local network.
    guided: bool,
    endpoint: Arc<OnceCell<Endpoint>>,
    pub(super) outgoing: Arc<Semaphore>,
}

impl BridgeAuthority {
    /// Reaches the desktop the way its ticket was created; a device that knows
    /// its own setting uses `with_connectivity`.
    pub fn new(route: BridgeRoute) -> Result<Self> {
        let ticket: Ticket = wire::decode(route.ticket.as_bytes())?;
        ensure!(
            ticket.version == 1 && !ticket.endpoint.is_empty(),
            "Invalid desktop authority ticket"
        );
        ensure!(
            STANDARD
                .decode(&route.host_node)
                .is_ok_and(|key| key.len() == 32),
            "Enter the desktop's node public key"
        );
        Ok(Self {
            route,
            connectivity: crate::Connectivity::of_destination(&ticket.endpoint),
            destination: ticket.endpoint,
            guided: false,
            endpoint: Arc::new(OnceCell::new()),
            outgoing: Arc::new(Semaphore::new(2)),
        })
    }

    /// A guided device's client: the device's own setting, and local
    /// network lookups of its network computer.
    pub fn with_connectivity(self, connectivity: crate::Connectivity) -> Self {
        Self {
            connectivity,
            guided: true,
            endpoint: Arc::new(OnceCell::new()),
            ..self
        }
    }

    /// Close this client's endpoint, shared with its clones, before a
    /// replacement takes over.
    pub async fn close(&self) {
        if let Some(endpoint) = self.endpoint.get() {
            endpoint.close().await;
        }
    }

    pub fn route(&self) -> &BridgeRoute {
        &self.route
    }

    pub(super) async fn endpoint(&self) -> Result<&Endpoint> {
        self.endpoint
            .get_or_try_init(|| async {
                let role = crate::connectivity::Role::Client;
                let endpoint = self.connectivity.builder(role).bind().await?;
                if self.guided {
                    crate::connectivity::discover(&endpoint, role);
                }
                Ok(endpoint)
            })
            .await
    }

    /// The network computer's current connection setting and addresses. The
    /// answer must name the same endpoints this device already trusts.
    pub async fn settings(
        &self,
        identity: SessionIdentity,
        trust: TrustSnapshot,
    ) -> Result<super::NetworkSettings> {
        let value = self
            .authenticated(identity, trust, Operation::Settings, &serde_json::json!({}))
            .await?;
        let settings: super::NetworkSettings = serde_json::from_value(value)?;
        ensure!(
            settings.authority_ticket.len() <= 16 * 1024
                && endpoint_of(&settings.authority_ticket)? == self.destination.id,
            "The network computer answered for another endpoint"
        );
        if let Some(ticket) = &settings.session_ticket {
            ensure!(ticket.len() <= 16 * 1024, "Session address too long");
            crate::session::ticket_endpoint(ticket)?;
        }
        Ok(settings)
    }

    /// The network's other devices, reporting this device's own current
    /// session address. Entries are checked as saved devices are; the caller
    /// decides which to keep.
    pub async fn members(
        &self,
        identity: SessionIdentity,
        trust: TrustSnapshot,
        session_ticket: Option<String>,
    ) -> Result<Vec<crate::device::PairedDevice>> {
        let value = self
            .authenticated(
                identity,
                trust,
                Operation::Members,
                &serde_json::to_value(super::MembersRequest { session_ticket })?,
            )
            .await?;
        let answer: super::MembersAnswer = serde_json::from_value(value)?;
        ensure!(answer.members.len() <= 32, "Too many network devices");
        for member in &answer.members {
            ensure!(
                member.ticket.len() <= super::MAX_MEMBER_TICKET,
                "Device address too long"
            );
            crate::device::validate_peer(member)?;
        }
        Ok(answer.members)
    }

    /// The Spaces this device hosts or that name it.
    pub async fn spaces(
        &self,
        identity: SessionIdentity,
        trust: TrustSnapshot,
    ) -> Result<Vec<super::SpaceView>> {
        let (mut spaces, inboxes) = self.listing(identity, trust).await?;
        spaces.extend(inboxes.unwrap_or_default());
        Ok(spaces)
    }
    /// The shared folders, and the inboxes when the network computer could
    /// list them: none from one that predates inboxes or did not answer.
    pub async fn listing(
        &self,
        identity: SessionIdentity,
        trust: TrustSnapshot,
    ) -> Result<(Vec<super::SpaceView>, Option<Vec<super::SpaceView>>)> {
        let spaces = self
            .listed(identity.clone(), trust.clone(), Operation::Spaces)
            .await?;
        let inboxes = self.listed(identity, trust, Operation::Inboxes).await.ok();
        Ok((spaces, inboxes))
    }
    async fn listed(
        &self,
        identity: SessionIdentity,
        trust: TrustSnapshot,
        operation: Operation,
    ) -> Result<Vec<super::SpaceView>> {
        let value = self
            .authenticated(identity, trust, operation, &serde_json::json!({}))
            .await?;
        let answer: super::SpacesAnswer = serde_json::from_value(value)?;
        ensure!(answer.spaces.len() <= 64, "Too many shared folders");
        // One entry this device cannot use never hides the others.
        Ok(answer
            .spaces
            .into_iter()
            .filter(|space| space.check().is_ok())
            .collect())
    }

    /// Ask the network computer for a Space on one of this device's folders,
    /// or to change its name and devices.
    pub async fn share_space(
        &self,
        identity: SessionIdentity,
        trust: TrustSnapshot,
        collection: String,
        name: String,
        recipients: Vec<String>,
        kind: crate::session::sharing::SpaceKind,
    ) -> Result<super::SpaceView> {
        let node = identity.public_key();
        let value = self
            .authenticated(
                identity,
                trust,
                Operation::ShareSpace,
                &serde_json::to_value(super::ShareSpaceRequest {
                    collection: collection.clone(),
                    name,
                    recipients,
                    kind,
                })?,
            )
            .await?;
        let space: super::SpaceView = serde_json::from_value(value)?;
        space.check()?;
        ensure!(
            space.collection == collection
                && space.host == node
                && space.kind == kind
                && space.grant.is_some(),
            "The network computer answered for another folder"
        );
        Ok(space)
    }

    /// Stop one of this device's Spaces. False if the computer had none.
    pub async fn unshare_space(
        &self,
        identity: SessionIdentity,
        trust: TrustSnapshot,
        collection: String,
    ) -> Result<bool> {
        let value = self
            .authenticated(
                identity,
                trust,
                Operation::UnshareSpace,
                &serde_json::to_value(super::UnshareSpaceRequest { collection })?,
            )
            .await?;
        Ok(serde_json::from_value(value)?)
    }

    /// Public, signed documents solve trust bootstrap after suspension. The
    /// locally pinned store verifies them before any credential is used.
    pub async fn refresh(&self, store: &mut TrustStore) -> Result<TrustSnapshot> {
        let _permit = self
            .outgoing
            .try_acquire()
            .context("Too many authority operations")?;
        let observed = Utc::now();
        let endpoint = self.endpoint().await?;
        timeout(DEADLINE, async {
            let connection = endpoint
                .connect(self.destination.clone(), Protocol::Authority.alpn())
                .await?;
            limit_streams(&connection);
            let result = async {
                let (mut send, mut recv) = connection.open_bi().await?;
                write_frame(
                    &mut send,
                    &Request {
                        version: 1,
                        operation: Operation::Trust,
                    },
                )
                .await?;
                send.finish()?;
                let documents: TrustDocuments = serde_json::from_value(response(&mut recv).await?)?;
                store.accept(&documents.history, documents.crl, observed)
            }
            .await;
            connection.close(0u32.into(), b"authority trust complete");
            result
        })
        .await
        .context("Desktop authority timed out")?
    }

    pub async fn renew(&self, device: &mut EnrolledDevice, store: &mut TrustStore) -> Result<()> {
        let trust = self.refresh(store).await?;
        let signed = device.renewal_request(&trust)?;
        let mut certificate = self
            .renew_signed(device.session_identity()?, trust.clone(), &signed)
            .await?;
        if let Some(object) = certificate.as_object_mut() {
            object.remove("edge");
        }
        device.accept_renewal(certificate, &trust)
    }

    pub(super) async fn renew_signed(
        &self,
        identity: SessionIdentity,
        trust: TrustSnapshot,
        signed: &Value,
    ) -> Result<Value> {
        self.authenticated(identity, trust, Operation::Renew, signed)
            .await
    }

    pub(crate) async fn attestation(
        &self,
        identity: SessionIdentity,
        trust: TrustSnapshot,
        id: &str,
    ) -> Result<Value> {
        uuid::Uuid::parse_str(id)?;
        self.authenticated(
            identity,
            trust,
            Operation::Attestation,
            &serde_json::json!({"attestation_id":id}),
        )
        .await
    }

    pub(crate) async fn evaluate(
        &self,
        identity: &SessionIdentity,
        trust: &TrustSnapshot,
        attestation: &str,
        context: &str,
        parameters: Value,
        capability: &str,
    ) -> Result<Value> {
        ensure!(
            [
                "connect.collection.read",
                "connect.collection.list",
                "connect.inbox.write"
            ]
            .contains(&capability),
            "Unsupported collection action"
        );
        let signed = crate::authority::request(
            &identity.key,
            serde_json::json!({"cert_id":identity.certificate["cert_id"],"node_public_key":identity.public_key(),"purpose":"node_boundary_evaluate","audience":trust.audience()?,"attestation_id":attestation,"requested_capability":capability,"context":{"context_id":context,"request_parameters":parameters}}),
        )?;
        self.authenticated(
            identity.clone(),
            trust.clone(),
            Operation::Evaluate,
            &signed,
        )
        .await
    }

    async fn authenticated(
        &self,
        identity: SessionIdentity,
        trust: TrustSnapshot,
        operation: Operation,
        signed: &Value,
    ) -> Result<Value> {
        let _permit = self
            .outgoing
            .try_acquire()
            .context("Too many authority operations")?;
        let credentials = Credentials {
            identity,
            trust,
            expected_node: self.route.host_node.clone(),
            allowed_nodes: Default::default(),
        };
        own_credential(&credentials)?;
        let endpoint = self.endpoint().await?;
        timeout(DEADLINE, async {
            let connection = endpoint
                .connect(self.destination.clone(), Protocol::Authority.alpn())
                .await?;
            limit_streams(&connection);
            let result = async {
                let (mut send, mut recv) = connection.open_bi().await?;
                write_frame(
                    &mut send,
                    &Request {
                        version: 1,
                        operation,
                    },
                )
                .await?;
                let peer = authenticate_for(
                    &connection,
                    endpoint.id(),
                    Role::Client,
                    &credentials,
                    &mut send,
                    &mut recv,
                    Protocol::Authority,
                )
                .await?;
                if !matches!(operation, Operation::Renew) {
                    credentials.trust.certificate(
                        &credentials.identity.certificate,
                        &credentials.identity.public_key(),
                        Utc::now(),
                    )?;
                    credentials
                        .trust
                        .certificate(&peer, &credentials.expected_node, Utc::now())?;
                }
                write_frame(&mut send, signed).await?;
                send.finish()?;
                let certificate = response(&mut recv).await?;
                if !matches!(operation, Operation::Renew) {
                    credentials.trust.certificate(
                        &credentials.identity.certificate,
                        &credentials.identity.public_key(),
                        Utc::now(),
                    )?;
                    credentials
                        .trust
                        .certificate(&peer, &credentials.expected_node, Utc::now())?;
                }
                own_credential(&credentials)?;
                credentials.trust.renewable_certificate(
                    &peer,
                    &credentials.expected_node,
                    Utc::now(),
                )?;
                Ok(certificate)
            }
            .await;
            connection.close(0u32.into(), b"authority renewal complete");
            result
        })
        .await
        .context("Desktop authority timed out")?
    }
}
