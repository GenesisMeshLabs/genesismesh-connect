use super::*;
use crate::session::tests::support;
use crate::{authority::TrustPin, session::SessionEndpoint};
use genesis_mesh_sdk::{
    canonical::python_timestamp,
    node_auth::{node_timestamp, sign_node_request},
};
use serde_json::json;
use support::{Fixture, public, signed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct HttpFixture {
    url: String,
    task: JoinHandle<()>,
    requests: Arc<Mutex<Vec<(String, Value)>>>,
}

#[test]
fn collection_forwarding_only_accepts_bound_read_or_list_requests() -> Result<()> {
    let f = Fixture::new();
    let body = crate::authority::request(
        &f.client,
        json!({
            "cert_id":f.client_cert["cert_id"],"node_public_key":public(&f.client),
            "purpose":"node_boundary_evaluate","audience":f.trust()?.audience()?,
            "attestation_id":uuid::Uuid::new_v4().to_string(),"requested_capability":"connect.collection.read",
            "context":{"context_id":"connect-read:test","request_parameters":{"collection_id":"family","file_name":"note.txt","peer_node":public(&f.server),"sha256":"0".repeat(64),"size":12}}
        }),
    )?;
    server::check_collection_decision(&body, &f.client_cert, &f.trust()?)?;
    for (field, value) in [
        ("node_public_key", json!(public(&f.server))),
        ("cert_id", json!("another-cert")),
        ("purpose", json!("admin")),
        ("audience", json!(public(&f.root))),
        ("requested_capability", json!("connect.collection.write")),
        ("url", json!("http://127.0.0.1/admin")),
        ("signature", json!("bad")),
    ] {
        let mut invalid = body.clone();
        invalid[field] = value;
        assert!(
            server::check_collection_decision(&invalid, &f.client_cert, &f.trust()?).is_err(),
            "{field}"
        );
    }
    Ok(())
}
impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn authority(f: &Fixture) -> Result<HttpFixture> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let documents = json!({"genesis": f.genesis, "successions": [], "vouching_grace_seconds": 0});
    let (crl, certificate) = (f.crl.clone(), f.client_cert.clone());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut bytes = Vec::new();
            let mut chunk = [0; 2048];
            let head = loop {
                let Ok(n) = stream.read(&mut chunk).await else {
                    return;
                };
                if n == 0 || bytes.len() + n > 32768 {
                    return;
                }
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(index) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = String::from_utf8_lossy(&bytes[..head]);
            let first = headers.lines().next().unwrap().to_owned();
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|n| n.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            while bytes.len() < head + length {
                let n = stream.read(&mut chunk).await.unwrap();
                if n == 0 || bytes.len() + n > 32768 {
                    return;
                }
                bytes.extend_from_slice(&chunk[..n]);
            }
            let body = if length == 0 {
                Value::Null
            } else {
                serde_json::from_slice(&bytes[head..head + length]).unwrap()
            };
            log.lock().unwrap().push((first.clone(), body));
            let value = match first.as_str() {
                "GET /na/key-history HTTP/1.1" => &documents,
                "GET /crl HTTP/1.1" => &crl,
                "POST /renew HTTP/1.1" | "POST /join HTTP/1.1" => &certificate,
                _ => panic!("unexpected forwarded route: {first}"),
            };
            let body = serde_json::to_vec(value).unwrap();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
        }
    });
    Ok(HttpFixture {
        url,
        task,
        requests,
    })
}
fn pin(f: &Fixture) -> TrustPin {
    TrustPin {
        root_public_key: public(&f.root),
        network_name: "connect-spike".into(),
    }
}
fn identity(f: &Fixture) -> SessionIdentity {
    SessionIdentity::new(f.client.clone(), f.client_cert.clone()).unwrap()
}
fn route(bridge: &AuthorityBridge, f: &Fixture) -> BridgeRoute {
    BridgeRoute {
        ticket: bridge.loopback_ticket().unwrap(),
        host_node: public(&f.server),
    }
}
async fn host(f: &Fixture, http: &HttpFixture) -> Result<AuthorityBridge> {
    AuthorityBridge::bind(
        SessionIdentity::new(f.server.clone(), f.server_cert.clone())?,
        f.trust()?,
        public(&f.client),
        LocalAuthority::new(&http.url)?,
    )
    .await
}

#[tokio::test]
async fn public_trust_is_root_verified_and_old_valid_identity_can_only_renew() -> Result<()> {
    let f = Fixture::new();
    let http = authority(&f).await?;
    let bridge = host(&f, &http).await?;
    let client = BridgeAuthority::new(route(&bridge, &f))?;
    let dir = tempfile::tempdir()?;
    let mut store = TrustStore::create(&dir.path().join("trust.json"), pin(&f))?;
    let trust = client.refresh(&mut store).await?;
    let mut old = f.client_cert.clone();
    old["cert_id"] = json!("pre-suspension-cert");
    old["issued_at"] = json!(python_timestamp(f.now - chrono::Duration::minutes(10)));
    old = signed(old, &[&f.authority]);
    assert!(
        SessionEndpoint::bind(
            SessionIdentity::new(f.client.clone(), old.clone())?,
            trust.clone(),
            public(&f.server)
        )
        .await
        .is_err()
    );
    let mut device = EnrolledDevice::restore(f.client.clone(), old)?;
    client.renew(&mut device, &mut store).await?;
    assert_eq!(device.certificate(), &f.client_cert);
    assert_eq!(bridge.forwarded_renewals(), 1);
    let request = http
        .requests
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.0.starts_with("POST"))
        .unwrap()
        .1
        .clone();
    assert_eq!(request["cert_id"], "pre-suspension-cert");
    server::check_renewal(
        &request,
        &json!({"cert_id":"pre-suspension-cert"}),
        &public(&f.client),
    )?;
    let mut wrong = pin(&f);
    wrong.root_public_key = public(&support::key());
    let path = dir.path().join("wrong.json");
    let mut wrong_store = TrustStore::create(&path, wrong)?;
    let baseline = std::fs::read(&path)?;
    assert!(client.refresh(&mut wrong_store).await.is_err());
    assert_eq!(std::fs::read(&path)?, baseline);
    bridge.close().await;
    Ok(())
}

#[tokio::test]
async fn wire_refuses_routes_methods_unknown_fields_and_huge_frames_before_http() -> Result<()> {
    let f = Fixture::new();
    let http = authority(&f).await?;
    let bridge = host(&f, &http).await?;
    let ticket: Ticket = wire::decode(bridge.loopback_ticket()?.as_bytes())?;
    let raw = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    for value in [
        json!({"version":1,"operation":"admin"}),
        json!({"version":1,"operation":"trust","url":"http://127.0.0.1/admin"}),
        json!({"version":1,"operation":"trust","method":"POST"}),
        json!({"version":2,"operation":"trust"}),
    ] {
        let conn = raw
            .connect(ticket.endpoint.clone(), Protocol::Authority.alpn())
            .await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        write_frame(&mut send, &value).await?;
        send.finish()?;
        assert!(
            timeout(Duration::from_secs(2), response(&mut recv))
                .await?
                .is_err()
        );
        conn.close(0u32.into(), b"done");
    }
    let conn = raw
        .connect(ticket.endpoint, Protocol::Authority.alpn())
        .await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&u32::MAX.to_be_bytes()).await?;
    assert!(
        timeout(Duration::from_secs(2), response(&mut recv))
            .await?
            .is_err()
    );
    assert!(http.requests.lock().unwrap().is_empty());
    raw.close().await;
    bridge.close().await;
    Ok(())
}

#[tokio::test]
async fn renewal_is_bound_to_the_authenticated_peer_and_its_exact_credential() -> Result<()> {
    let f = Fixture::new();
    let http = authority(&f).await?;
    let bridge = host(&f, &http).await?;
    let client = BridgeAuthority::new(route(&bridge, &f))?;
    let body =
        json!({"cert_id":"client-cert","node_public_key":public(&f.client),"validity_hours":24});
    let good = sign_node_request(
        body,
        &f.client,
        &node_timestamp(Utc::now()),
        &uuid::Uuid::new_v4().to_string(),
    )?;
    for (field, value) in [
        ("cert_id", json!("another-cert")),
        ("node_public_key", json!(public(&f.server))),
        ("roles", json!(["role:operator"])),
        ("signature", json!("forged")),
        ("validity_hours", json!(25)),
    ] {
        let mut signed = good.clone();
        signed[field] = value;
        assert!(
            client
                .renew_signed(identity(&f), f.trust()?, &signed)
                .await
                .is_err(),
            "{field}"
        );
    }
    assert_eq!(bridge.forwarded_renewals(), 0);
    assert!(http.requests.lock().unwrap().is_empty());
    let mut wrong_route = route(&bridge, &f);
    wrong_route.host_node = public(&support::key());
    let wrong = BridgeAuthority::new(wrong_route)?;
    assert!(
        wrong
            .renew_signed(identity(&f), f.trust()?, &good)
            .await
            .is_err()
    );
    let wrong_identity = SessionIdentity::new(f.server.clone(), f.server_cert.clone())?;
    assert!(
        client
            .renew_signed(wrong_identity, f.trust()?, &good)
            .await
            .is_err()
    );
    assert_eq!(bridge.forwarded_renewals(), 0);
    bridge.close().await;
    Ok(())
}

#[test]
fn control_proof_has_a_separate_domain_and_budgets_do_not_grow_unbounded() -> Result<()> {
    let f = Fixture::new();
    let trust = f.trust()?;
    let client = wire::hello(
        Role::Client,
        iroh::SecretKey::generate().public(),
        &identity(&f),
        &trust,
    )?;
    let server = wire::hello(
        Role::Server,
        iroh::SecretKey::generate().public(),
        &SessionIdentity::new(f.server.clone(), f.server_cert.clone())?,
        &trust,
    )?;
    let payload = wire::transcript(&client, &server, &[1; 32], Role::Client)?;
    let proof = wire::sign(&identity(&f), &payload);
    let control = wire::transcript_for(
        &client,
        &server,
        &[1; 32],
        Role::Client,
        Protocol::Authority,
    )?;
    assert!(wire::verify(&proof, &control, &public(&f.client)).is_err());
    let mut budget = Budget::new(8);
    for _ in 0..8 {
        assert!(budget.allow());
    }
    assert!(!budget.allow());
    assert!(!budget.allow());
    budget.since = Instant::now() - Duration::from_secs(61);
    assert!(budget.allow());
    assert_eq!(budget.used, 1);
    Ok(())
}

#[tokio::test]
async fn bridge_renewal_budget_is_enforced_before_another_http_call() -> Result<()> {
    let f = Fixture::new();
    let http = authority(&f).await?;
    let bridge = host(&f, &http).await?;
    let client = BridgeAuthority::new(route(&bridge, &f))?;
    for n in 0..9 {
        let signed = sign_node_request(
            json!({"cert_id":"client-cert","node_public_key":public(&f.client),"validity_hours":24}),
            &f.client,
            &node_timestamp(Utc::now()),
            &uuid::Uuid::new_v4().to_string(),
        )?;
        let result = client.renew_signed(identity(&f), f.trust()?, &signed).await;
        assert_eq!(result.is_ok(), n < 8);
    }
    assert_eq!(bridge.forwarded_renewals(), 8);
    assert_eq!(http.requests.lock().unwrap().len(), 8);
    bridge.close().await;
    Ok(())
}

#[tokio::test]
async fn refreshed_bridge_refuses_revoked_peer_and_suspension_cancels_handshake() -> Result<()> {
    let mut f = Fixture::new();
    let http = authority(&f).await?;
    let bridge = host(&f, &http).await?;
    let client = BridgeAuthority::new(route(&bridge, &f))?;
    let old_trust = f.trust()?;
    let signed_body = sign_node_request(
        json!({"cert_id":"client-cert","node_public_key":public(&f.client),"validity_hours":24}),
        &f.client,
        &node_timestamp(Utc::now()),
        &uuid::Uuid::new_v4().to_string(),
    )?;
    f.crl["revoked_certificates"] = json!([{"certificate_id":"client-cert"}]);
    f.crl = signed(f.crl, &[&f.authority]);
    bridge.refresh(
        SessionIdentity::new(f.server.clone(), f.server_cert.clone())?,
        f.trust()?,
    )?;
    assert!(
        client
            .renew_signed(identity(&f), old_trust, &signed_body)
            .await
            .is_err()
    );
    f.crl["revoked_certificates"] = json!([]);
    f.crl = signed(f.crl, &[&f.authority]);
    bridge.refresh(
        SessionIdentity::new(f.server.clone(), f.server_cert.clone())?,
        f.trust()?,
    )?;
    let ticket: Ticket = wire::decode(bridge.loopback_ticket()?.as_bytes())?;
    let raw = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let conn = raw
        .connect(ticket.endpoint, Protocol::Authority.alpn())
        .await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(
        &mut send,
        &Request {
            version: 1,
            operation: Operation::Renew,
        },
    )
    .await?;
    let _: wire::Hello = read_frame(&mut recv).await?;
    // The remote stops before sending its proof; suspension closes it promptly.
    bridge.suspend();
    timeout(Duration::from_secs(2), conn.closed()).await?;
    assert_eq!(bridge.forwarded_renewals(), 0);
    assert!(http.requests.lock().unwrap().is_empty());
    raw.close().await;
    bridge.close().await;
    Ok(())
}

#[tokio::test]
async fn enrollment_checks_the_host_and_selected_node_before_forwarding_an_invite() -> Result<()> {
    let f = Fixture::new();
    let http = authority(&f).await?;
    let bridge = host(&f, &http).await?;
    let directory = tempfile::tempdir()?;
    let mut store = TrustStore::create(&directory.path().join("trust.json"), pin(&f))?;
    let mut wrong = route(&bridge, &f);
    wrong.host_node = public(&support::key());
    let bad_host = BridgeAuthority::new(wrong)?;
    assert!(
        bad_host
            .enroll(f.client.clone(), "must-not-reach-authority", &mut store)
            .await
            .is_err()
    );
    assert!(
        http.requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.0.starts_with("GET"))
    );
    let client = BridgeAuthority::new(route(&bridge, &f))?;
    assert!(
        client
            .enroll(support::key(), "wrong-device", &mut store)
            .await
            .is_err()
    );
    assert!(
        http.requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.0.starts_with("GET"))
    );
    let enrolled = client
        .enroll(f.client.clone(), "selected-device-invite", &mut store)
        .await?;
    assert_eq!(enrolled.public_key(), public(&f.client));
    {
        let requests = http.requests.lock().unwrap();
        let joins: Vec<_> = requests
            .iter()
            .filter(|r| r.0 == "POST /join HTTP/1.1")
            .collect();
        assert_eq!(joins.len(), 1);
        assert_eq!(joins[0].1["invite_token"], "selected-device-invite");
        assert_eq!(joins[0].1["node_public_key"], public(&f.client));
    }
    bridge.close().await;
    Ok(())
}

#[tokio::test]
async fn members_see_the_others_and_report_only_their_own_endpoint() -> Result<()> {
    let f = Fixture::new();
    let http = authority(&f).await?;
    let bridge = host(&f, &http).await?;
    let client = BridgeAuthority::new(route(&bridge, &f))?;
    // Tickets as the network computer saves and passes them on.
    let ticket = |id: iroh::EndpointId, port: u16| {
        crate::session::canonical_ticket(
            &json!({
                "version": 1,
                "endpoint": EndpointAddr::new(id).with_ip_addr(([192, 0, 2, 9], port).into()),
            })
            .to_string(),
        )
        .unwrap()
    };
    let (own, other, laptop_endpoint) = (
        iroh::SecretKey::generate().public(),
        iroh::SecretKey::generate().public(),
        iroh::SecretKey::generate().public(),
    );
    let device = |name: &str, node: String, ticket: String| crate::device::PairedDevice {
        name: name.into(),
        node,
        ticket,
    };
    // A second saved device the bridge lets in, though it is not selected.
    let laptop_key = support::key();
    let laptop_cert = signed(
        json!({
            "cert_id": "laptop-cert", "node_public_key": public(&laptop_key),
            "network_name": "connect-spike", "roles": ["role:client"],
            "issued_at": python_timestamp(f.now - chrono::Duration::seconds(1)),
            "expires_at": python_timestamp(f.now + chrono::Duration::hours(1)),
            "issued_by": "spike-only"
        }),
        &[&f.authority],
    );
    let laptop_identity = || SessionIdentity::new(laptop_key.clone(), laptop_cert.clone());
    let me = device("Phone", public(&f.client), ticket(own, 7000));
    let tablet = device("Tablet", public(&support::key()), ticket(other, 7001));
    let laptop = device("Laptop", public(&laptop_key), ticket(laptop_endpoint, 7002));
    let huge = device(
        "Huge",
        public(&support::key()),
        serde_json::to_string(&json!({
            "version": 1,
            "endpoint": (0..120u16).fold(
                EndpointAddr::new(iroh::SecretKey::generate().public()),
                |addr, port| addr.with_ip_addr(([192, 0, 2, 10], port + 1).into()),
            ),
        }))?,
    );
    assert!(huge.ticket.len() > MAX_MEMBER_TICKET);

    assert!(
        client
            .members(identity(&f), f.trust()?, None)
            .await
            .is_err(),
        "Before the computer publishes its devices there is no answer, not an empty one"
    );
    bridge.publish_members(vec![tablet.clone()]);
    assert!(
        client
            .members(identity(&f), f.trust()?, None)
            .await
            .is_err(),
        "A device the computer has not saved receives nothing, even when selected"
    );

    bridge.publish_members(vec![me.clone(), tablet.clone(), laptop.clone(), huge]);
    bridge.set_peers(
        public(&f.client),
        vec![public(&f.client), public(&laptop_key)],
    )?;
    let members = client
        .members(identity(&f), f.trust()?, Some(ticket(own, 7100)))
        .await?;
    assert_eq!(
        members,
        vec![tablet.clone(), laptop.clone()],
        "A device sees the others, never itself or an oversized address"
    );
    assert_eq!(
        bridge.take_reported(),
        std::collections::BTreeMap::from([(public(&f.client), ticket(own, 7100))]),
        "A fresh address for the device's own endpoint is kept"
    );
    assert!(bridge.take_reported().is_empty());

    // The list and the report follow the caller, not the selected device.
    let seen = client
        .members(
            laptop_identity()?,
            f.trust()?,
            Some(ticket(laptop_endpoint, 7300)),
        )
        .await?;
    assert_eq!(seen, vec![me.clone(), tablet.clone()]);
    assert_eq!(
        bridge.take_reported(),
        std::collections::BTreeMap::from([(public(&laptop_key), ticket(laptop_endpoint, 7300))])
    );

    client
        .members(identity(&f), f.trust()?, Some(ticket(other, 7200)))
        .await?;
    client
        .members(identity(&f), f.trust()?, Some(me.ticket.clone()))
        .await?;
    // The same address spelled with padding is the same address.
    let padded = me.ticket.replace(',', " ,\n ");
    assert_ne!(padded, me.ticket);
    client
        .members(identity(&f), f.trust()?, Some(padded))
        .await?;
    assert!(
        bridge.take_reported().is_empty(),
        "Another endpoint's address, an unchanged one, or a respelled one is not kept"
    );
    // An address too long to pass on is dropped; the device still gets its list.
    let long = serde_json::to_string(&json!({
        "version": 1,
        "endpoint": (0..120u16).fold(EndpointAddr::new(own), |addr, port| {
            addr.with_ip_addr(([192, 0, 2, 11], port + 1).into())
        }),
    }))?;
    assert!(long.len() > MAX_MEMBER_TICKET);
    assert_eq!(
        client.members(identity(&f), f.trust()?, Some(long)).await?,
        vec![tablet.clone(), laptop.clone()]
    );
    assert!(bridge.take_reported().is_empty());
    assert!(
        client
            .members(identity(&f), f.trust()?, Some("not a ticket".into()))
            .await
            .is_err()
    );
    let wrong_identity = SessionIdentity::new(f.server.clone(), f.server_cert.clone())?;
    assert!(
        client
            .members(wrong_identity, f.trust()?, None)
            .await
            .is_err(),
        "The host's own identity is not an approved device"
    );
    assert!(http.requests.lock().unwrap().is_empty());
    bridge.close().await;
    Ok(())
}

#[tokio::test]
async fn settings_come_only_from_the_authenticated_host_and_name_its_endpoints() -> Result<()> {
    let f = Fixture::new();
    let http = authority(&f).await?;
    let bridge = host(&f, &http).await?;
    let client = BridgeAuthority::new(route(&bridge, &f))?;
    let settings = client.settings(identity(&f), f.trust()?).await?;
    assert_eq!(settings.connectivity, crate::Connectivity::LocalNetwork);
    assert_eq!(
        endpoint_of(&settings.authority_ticket)?,
        endpoint_of(&bridge.ticket()?)?
    );
    assert_eq!(settings.session_ticket, None);
    let session = serde_json::to_string(&json!({
        "version": 1,
        "endpoint": EndpointAddr::new(iroh::SecretKey::generate().public())
            .with_ip_addr(([192, 0, 2, 7], 7000).into()),
    }))?;
    bridge.publish_session(Some(session.clone()))?;
    assert!(bridge.publish_session(Some("not a ticket".into())).is_err());
    let settings = client.settings(identity(&f), f.trust()?).await?;
    assert_eq!(settings.session_ticket, Some(session));
    let mut wrong_route = route(&bridge, &f);
    wrong_route.host_node = public(&support::key());
    assert!(
        BridgeAuthority::new(wrong_route)?
            .settings(identity(&f), f.trust()?)
            .await
            .is_err(),
        "Another host key must not be trusted for settings"
    );
    let wrong_identity = SessionIdentity::new(f.server.clone(), f.server_cert.clone())?;
    assert!(
        client.settings(wrong_identity, f.trust()?).await.is_err(),
        "The host's own identity is not an approved device and receives nothing"
    );
    assert!(http.requests.lock().unwrap().is_empty());
    bridge.close().await;
    Ok(())
}

#[tokio::test]
async fn spaces_act_for_the_caller_name_only_saved_devices_and_show_only_its_own() -> Result<()> {
    let f = Fixture::new();
    let http = authority(&f).await?;
    let bridge = host(&f, &http).await?;
    let client = BridgeAuthority::new(route(&bridge, &f))?;
    let ticket = |port: u16| {
        crate::session::canonical_ticket(
            &json!({
                "version": 1,
                "endpoint": EndpointAddr::new(iroh::SecretKey::generate().public())
                    .with_ip_addr(([192, 0, 2, 20], port).into()),
            })
            .to_string(),
        )
        .unwrap()
    };
    let (me, tablet, stranger) = (
        public(&f.client),
        public(&support::key()),
        public(&support::key()),
    );
    let computer = public(&f.server);
    let collection = uuid::Uuid::new_v4().to_string();

    assert!(
        client.spaces(identity(&f), f.trust()?).await.is_err(),
        "A computer without an owner runtime shares nothing for devices"
    );
    // A stand-in owner runtime that keeps the calls it receives.
    let (owner, mut requests) = tokio::sync::mpsc::channel::<crate::owner::OwnerRequest>(8);
    bridge.serve_owner(owner);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let log = calls.clone();
    let space = |collection: &str, host: &str, recipients: Vec<String>| crate::owner::Space {
        collection: collection.into(),
        name: "Photos".into(),
        host: host.into(),
        subject: "connect-device-test".into(),
        recipients,
        created_at: "2026-10-27T00:00:00+00:00".into(),
        policy_id: format!("connect-{collection}"),
        policy_version: 1,
        attestation_id: uuid::Uuid::new_v4().to_string(),
        valid_until: "2027-01-25T00:00:00+00:00".into(),
    };
    let listed = vec![
        space(&collection, &me, vec![tablet.clone()]),
        space(&uuid::Uuid::new_v4().to_string(), &tablet, vec![me.clone()]),
        space(
            &uuid::Uuid::new_v4().to_string(),
            &tablet,
            vec![computer.clone()],
        ),
    ];
    let answers = listed.clone();
    let runtime = tokio::spawn(async move {
        while let Some(request) = requests.recv().await {
            let result = match &request.call {
                crate::owner::OwnerCall::List => Ok(serde_json::to_value(&answers).unwrap()),
                crate::owner::OwnerCall::Share {
                    host,
                    collection,
                    recipients,
                    ..
                } => Ok(serde_json::to_value(space(collection, host, recipients.clone())).unwrap()),
                crate::owner::OwnerCall::Remove { .. } => Ok(json!(true)),
            };
            log.lock().unwrap().push(format!("{:?}", request.call));
            let _ = request.reply.send(result);
        }
    });

    assert!(
        client.spaces(identity(&f), f.trust()?).await.is_err(),
        "No answer before the computer has published its devices"
    );
    let saved = |node: &str, port: u16| crate::device::PairedDevice {
        name: "Device".into(),
        node: node.into(),
        ticket: ticket(port),
    };
    bridge.publish_members(vec![saved(&me, 7000), saved(&tablet, 7001)]);

    let spaces = client.spaces(identity(&f), f.trust()?).await?;
    assert_eq!(spaces.len(), 2, "Its own Space and the one naming it");
    assert!(spaces[0].host == me && spaces[0].grant.is_some());
    assert!(spaces[1].host == tablet && spaces[1].grant.is_none());

    // The caller is always the host, and names only saved devices or the
    // computer itself.
    let shared = client
        .share_space(
            identity(&f),
            f.trust()?,
            collection.clone(),
            "Photos".into(),
            vec![tablet.clone(), computer.clone()],
        )
        .await?;
    assert_eq!(shared.host, me);
    for recipients in [vec![stranger.clone()], vec![me.clone()], vec![]] {
        assert!(
            client
                .share_space(
                    identity(&f),
                    f.trust()?,
                    uuid::Uuid::new_v4().to_string(),
                    "Photos".into(),
                    recipients,
                )
                .await
                .is_err()
        );
    }
    assert!(
        client
            .unshare_space(identity(&f), f.trust()?, collection.clone())
            .await?
    );
    let calls = calls.lock().unwrap().clone();
    assert_eq!(
        calls.len(),
        3,
        "Refused requests never reach the owner: {calls:?}"
    );
    assert!(calls[1].contains(&format!("host: \"{me}\"")));
    assert!(calls[2].starts_with("Remove") && calls[2].contains(&format!("host: \"{me}\"")));

    // A device the computer has not saved gets nothing, even when selected.
    bridge.publish_members(vec![saved(&tablet, 7001)]);
    assert!(client.spaces(identity(&f), f.trust()?).await.is_err());
    assert!(http.requests.lock().unwrap().is_empty());
    bridge.close().await;
    runtime.abort();
    Ok(())
}
