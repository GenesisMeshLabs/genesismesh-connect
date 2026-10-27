use super::wire::{Hello, Proof, exporter, hello, sign, transcript, verify};
use super::*;
use genesis_mesh_sdk::canonical::python_timestamp;
use serde_json::json;

#[path = "../../tests/support/mod.rs"]
pub(super) mod support;
use support::{Fixture, key, public, signed};

fn identity(key: &SigningKey, cert: &Value) -> SessionIdentity {
    SessionIdentity::new(key.clone(), cert.clone()).unwrap()
}

#[test]
fn renewed_device_policy_accepts_daily_crls_but_requires_recent_certificates() -> Result<()> {
    let mut f = Fixture::new();
    f.crl["issued_at"] = json!(python_timestamp(f.now - chrono::Duration::hours(10)));
    f.crl["next_update"] = json!(python_timestamp(f.now + chrono::Duration::hours(14)));
    f.crl = signed(f.crl, &[&f.authority]);
    let snapshot = |crl: Value| {
        let mut policy = f.policy();
        policy.max_age = Duration::from_secs(60);
        TrustSnapshot::for_renewed_devices(policy, &f.genesis, &[], crl, f.now)
    };
    let trust = snapshot(f.crl.clone())?;
    trust.certificate(&f.client_cert, &public(&f.client), f.now)?;
    // A certificate just renewed by a network computer whose clock runs ahead.
    let mut renewed = f.client_cert.clone();
    renewed["issued_at"] = json!(python_timestamp(f.now + chrono::Duration::seconds(2)));
    trust.certificate(&signed(renewed, &[&f.authority]), &public(&f.client), f.now)?;
    let mut older = f.client_cert.clone();
    older["issued_at"] = json!(python_timestamp(f.now - chrono::Duration::seconds(300)));
    older = signed(older, &[&f.authority]);
    assert!(
        trust
            .certificate(&older, &public(&f.client), f.now)
            .is_err()
    );
    // A still-valid credential may authenticate renewal after app suspension.
    trust.renewable_certificate(&older, &public(&f.client), f.now)?;
    assert!(
        trust
            .check_fresh(f.now + chrono::Duration::seconds(60))
            .is_err()
    );
    // A network computer whose clock runs ahead of this device's.
    let mut ahead = f.crl.clone();
    ahead["issued_at"] = json!(python_timestamp(f.now + chrono::Duration::seconds(2)));
    snapshot(signed(ahead, &[&f.authority]))?;
    for (field, value) in [
        ("issued_at", f.now - chrono::Duration::hours(25)),
        (
            "issued_at",
            f.now + trust::CLOCK_SKEW + chrono::Duration::seconds(10),
        ),
        ("next_update", f.now),
        ("next_update", f.now + chrono::Duration::hours(15)),
    ] {
        let mut crl = f.crl.clone();
        crl[field] = json!(python_timestamp(value));
        assert!(snapshot(signed(crl, &[&f.authority])).is_err(), "{field}");
    }
    Ok(())
}

#[tokio::test]
async fn trust_refresh_keeps_endpoint_and_failed_update_suspends_it() -> Result<()> {
    let mut f = Fixture::new();
    let server = server(&f).await?;
    let endpoint_id = server.endpoint.id();
    server.refresh(identity(&f.server, &f.server_cert), f.trust()?)?;
    assert_eq!(endpoint_id, server.endpoint.id());
    assert!(server.ready());
    // A certificate for another identity cannot replace this running node.
    assert!(
        server
            .refresh(identity(&f.client, &f.client_cert), f.trust()?)
            .is_err()
    );
    assert!(!server.ready());
    server.refresh(identity(&f.server, &f.server_cert), f.trust()?)?;
    f.crl["revoked_certificates"] = json!([{"certificate_id": "server-cert"}]);
    f.crl = signed(f.crl, &[&f.authority]);
    assert!(
        server
            .refresh(identity(&f.server, &f.server_cert), f.trust()?)
            .is_err()
    );
    assert!(!server.ready());
    server.close().await;
    Ok(())
}

#[tokio::test]
async fn suspension_cancels_an_inflight_handshake_and_blocks_new_messages() -> Result<()> {
    let f = Fixture::new();
    let server = server(&f).await?;
    let raw = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let conn = raw.connect(address(&server), ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let ours = hello(
        Role::Client,
        raw.id(),
        &identity(&f.client, &f.client_cert),
        &f.trust()?,
    )?;
    write_frame(&mut send, &ours).await?;
    let _: Hello = read_frame(&mut recv).await?;
    let _: Proof = read_frame(&mut recv).await?;
    server.suspend();
    timeout(Duration::from_secs(2), conn.closed()).await?;
    assert!(!server.ready());
    assert_eq!(server.received_messages(), 0);
    let client = SessionEndpoint::bind(
        identity(&f.client, &f.client_cert),
        f.trust()?,
        public(&f.server),
    )
    .await?;
    assert!(
        client
            .round_trip(&server.ticket()?, "blocked")
            .await
            .is_err()
    );
    client.close().await;
    raw.close().await;
    server.close().await;
    Ok(())
}

async fn server(f: &Fixture) -> Result<SessionEndpoint> {
    SessionEndpoint::bind(
        identity(&f.server, &f.server_cert),
        f.trust()?,
        public(&f.client),
    )
    .await
}

fn address(server: &SessionEndpoint) -> EndpointAddr {
    let port = server
        .endpoint
        .bound_sockets()
        .iter()
        .find(|a| a.is_ipv4())
        .unwrap()
        .port();
    EndpointAddr::new(server.endpoint.id()).with_ip_addr(([127, 0, 0, 1], port).into())
}

#[tokio::test]
async fn authenticates_real_quic_echo_and_fresh_reconnect() -> Result<()> {
    let f = Fixture::new();
    let server = server(&f).await?;
    let ticket = serde_json::to_string(&SessionTicket {
        version: 1,
        endpoint: address(&server),
    })?;
    for _ in 0..2 {
        let client = SessionEndpoint::bind(
            identity(&f.client, &f.client_cert),
            f.trust()?,
            public(&f.server),
        )
        .await?;
        let report = client.round_trip(&ticket, "authenticated hello").await?;
        assert!(report.genesis_mesh_authenticated);
        assert_eq!(report.peer_node, public(&f.server));
        assert_eq!(report.peer_certificate, "server-cert");
        assert_eq!(report.bytes, 19);
        assert!(client.round_trip(&ticket, &"x".repeat(1025)).await.is_err());
        client.close().await;
    }
    assert_eq!(server.received_messages(), 2);
    server.close().await;
    Ok(())
}

#[tokio::test]
async fn three_devices_route_by_verified_identity_and_removed_device_cannot_reconnect() -> Result<()>
{
    let f = Fixture::new();
    let third_key = key();
    let mut third_cert = f.client_cert.clone();
    third_cert["node_public_key"] = json!(public(&third_key));
    third_cert["cert_id"] = json!("third-cert");
    third_cert = signed(third_cert, &[&f.authority]);
    let server = server(&f).await?;
    let original_ticket = server.endpoint.id();
    let client = SessionEndpoint::bind(
        identity(&f.client, &f.client_cert),
        f.trust()?,
        public(&f.server),
    )
    .await?;
    let third = SessionEndpoint::bind(
        identity(&third_key, &third_cert),
        f.trust()?,
        public(&f.server),
    )
    .await?;
    server.set_peers(
        public(&f.client),
        vec![public(&f.client), public(&third_key)],
    )?;
    let ticket = |e: &SessionEndpoint| {
        serde_json::to_string(&SessionTicket {
            version: 1,
            endpoint: address(e),
        })
    };
    client
        .round_trip(&ticket(&server)?, "first still works")
        .await?;
    third
        .round_trip(&ticket(&server)?, "second also works")
        .await?;
    // Explicit destination pins matter even for a different approved peer.
    assert!(
        server
            .round_trip_to(Some(&public(&f.client)), &ticket(&third)?, "wrong device")
            .await
            .is_err()
    );
    server
        .round_trip_to(
            Some(&public(&third_key)),
            &ticket(&third)?,
            "selected second",
        )
        .await?;
    server.set_peers(public(&f.client), vec![public(&f.client)])?;
    assert_eq!(server.endpoint.id(), original_ticket);
    assert!(
        third
            .round_trip(&ticket(&server)?, "removed")
            .await
            .is_err()
    );
    assert!(
        server
            .round_trip_to(Some(&public(&third_key)), &ticket(&third)?, "removed")
            .await
            .is_err()
    );
    // An invalid replacement must preserve the current approved peer set.
    assert!(
        server
            .set_peers(public(&f.server), vec![public(&f.server)])
            .is_err()
    );
    client
        .round_trip(&ticket(&server)?, "first retained")
        .await?;
    server.close().await;
    client.close().await;
    third.close().await;
    Ok(())
}

#[tokio::test]
async fn removing_a_peer_cancels_its_inflight_proof_exchange() -> Result<()> {
    let f = Fixture::new();
    let server = server(&f).await?;
    let replacement = key();
    let raw = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let conn = raw.connect(address(&server), ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(
        &mut send,
        &hello(
            Role::Client,
            raw.id(),
            &identity(&f.client, &f.client_cert),
            &f.trust()?,
        )?,
    )
    .await?;
    let _: Hello = read_frame(&mut recv).await?;
    let _: Proof = read_frame(&mut recv).await?;
    server.set_peers(public(&replacement), vec![public(&replacement)])?;
    timeout(Duration::from_secs(2), conn.closed()).await?;
    assert_eq!(server.received_messages(), 0);
    server.close().await;
    raw.close().await;
    Ok(())
}

#[test]
fn certificates_refuse_tampering_wrong_node_network_time_and_revocation() -> Result<()> {
    let mut f = Fixture::new();
    let trust = f.trust()?;
    trust.certificate(&f.client_cert, &public(&f.client), f.now)?;
    assert!(
        trust
            .certificate(&f.client_cert, &public(&f.server), f.now)
            .is_err()
    );
    assert!(SessionIdentity::new(f.server.clone(), f.client_cert.clone()).is_err());
    for (field, value) in [
        ("roles", json!(["role:operator"])),
        ("node_public_key", json!(public(&f.server))),
        ("signatures", json!([])),
    ] {
        let mut cert = f.client_cert.clone();
        cert[field] = value;
        assert!(
            trust.certificate(&cert, &public(&f.client), f.now).is_err(),
            "{field}"
        );
    }
    // Issued a moment ago by an authority whose clock runs ahead of this one.
    let mut ahead = f.client_cert.clone();
    ahead["issued_at"] = json!(python_timestamp(f.now + chrono::Duration::seconds(2)));
    trust.certificate(&signed(ahead, &[&f.authority]), &public(&f.client), f.now)?;
    let mut edge = f.client_cert.clone();
    edge["issued_at"] = json!(python_timestamp(f.now + trust::CLOCK_SKEW));
    trust.certificate(&signed(edge, &[&f.authority]), &public(&f.client), f.now)?;
    for (field, value) in [
        ("network_name", json!("other-network")),
        ("expires_at", json!(python_timestamp(f.now))),
        (
            "issued_at",
            json!(python_timestamp(
                f.now + trust::CLOCK_SKEW + chrono::Duration::seconds(1)
            )),
        ),
    ] {
        let mut cert = f.client_cert.clone();
        cert[field] = value;
        cert = signed(cert, &[&f.authority]);
        assert!(
            trust.certificate(&cert, &public(&f.client), f.now).is_err(),
            "{field}"
        );
    }
    f.crl["revoked_certificates"] = json!([{"certificate_id": "client-cert", "revoked_at": python_timestamp(f.now), "reason": "test", "issuer": "spike-only"}]);
    f.crl = signed(f.crl, &[&f.authority]);
    assert!(
        f.trust()?
            .certificate(&f.client_cert, &public(&f.client), f.now)
            .is_err()
    );
    Ok(())
}

#[test]
fn trust_refuses_wrong_root_network_signature_staleness_and_rollbacks() -> Result<()> {
    let f = Fixture::new();
    for variation in 0..5 {
        let mut policy = f.policy();
        match variation {
            0 => policy.root_public_key = public(&key()),
            1 => policy.network_name = "other".into(),
            2 => policy.minimum_crl_sequence = 2,
            3 => policy.minimum_key_sequence = 2,
            _ => policy.max_age = Duration::ZERO,
        }
        assert!(
            TrustSnapshot::from_records(policy, &f.genesis, &[], f.crl.clone(), f.now).is_err()
        );
    }
    for (field, value) in [
        (
            "issued_at",
            json!(python_timestamp(f.now - chrono::Duration::minutes(6))),
        ),
        (
            "issued_at",
            json!(python_timestamp(f.now + chrono::Duration::minutes(6))),
        ),
        ("next_update", json!(python_timestamp(f.now))),
        ("revoked_certificates", json!([{}])),
    ] {
        let mut crl = f.crl.clone();
        crl[field] = value;
        crl = signed(crl, &[&f.authority]);
        assert!(
            TrustSnapshot::from_records(f.policy(), &f.genesis, &[], crl, f.now).is_err(),
            "{field}"
        );
    }
    let forged = signed(f.crl.clone(), &[&key()]);
    assert!(TrustSnapshot::from_records(f.policy(), &f.genesis, &[], forged, f.now).is_err());
    assert!(
        TrustSnapshot::from_records(
            f.policy(),
            &f.genesis,
            &[],
            f.crl.clone(),
            f.now - chrono::Duration::minutes(6)
        )
        .is_err()
    );
    assert!(
        f.trust()?
            .check_fresh(f.now + chrono::Duration::minutes(6))
            .is_err()
    );
    Ok(())
}

#[test]
fn ended_authority_cannot_vouch_for_a_long_lived_certificate() -> Result<()> {
    let f = Fixture::new();
    let next = key();
    let effective = f.now - chrono::Duration::seconds(301);
    let succession = signed(
        json!({
            "succession_id": "spike-succession", "sovereign_id": "connect-spike", "key_sequence": 2,
        "previous_key_id": "spike-only", "previous_public_key": public(&f.authority),
            "new_key_id": "next", "new_public_key": public(&next), "effective_at": python_timestamp(effective),
            "new_valid_to": python_timestamp(f.now + chrono::Duration::hours(1)), "issued_at": python_timestamp(effective),
        }),
        &[&f.root, &f.authority, &next],
    );
    let crl = signed(f.crl.clone(), &[&next]);
    let trust = TrustSnapshot::from_records(f.policy(), &f.genesis, &[succession], crl, f.now)?;
    let mut old = f.client_cert.clone();
    old["issued_at"] = json!(python_timestamp(effective - chrono::Duration::seconds(1)));
    old = signed(old, &[&f.authority]);
    let error = trust
        .certificate(&old, &public(&f.client), f.now)
        .unwrap_err();
    assert!(error.to_string().contains("horizon"));
    let current = signed(f.client_cert.clone(), &[&next]);
    trust.certificate(&current, &public(&f.client), f.now)?;
    Ok(())
}

#[test]
fn proofs_bind_roles_challenges_both_endpoints_credentials_network_and_tls() -> Result<()> {
    let f = Fixture::new();
    let trust = f.trust()?;
    let client_identity = identity(&f.client, &f.client_cert);
    let client = hello(
        Role::Client,
        iroh::SecretKey::generate().public(),
        &client_identity,
        &trust,
    )?;
    let server = hello(
        Role::Server,
        iroh::SecretKey::generate().public(),
        &identity(&f.server, &f.server_cert),
        &trust,
    )?;
    let binding = [1; 32];
    let payload = transcript(&client, &server, &binding, Role::Client)?;
    let proof = sign(&client_identity, &payload);
    verify(&proof, &payload, &public(&f.client))?;
    assert!(verify(&proof, &payload, &public(&f.server)).is_err());
    for variation in 0..10 {
        let mut c = client.clone();
        let mut s = server.clone();
        let mut b = binding;
        let mut role = Role::Client;
        match variation {
            0 => c.nonce[0] ^= 1,
            1 => s.nonce[0] ^= 1,
            2 => c.endpoint = iroh::SecretKey::generate().public(),
            3 => s.endpoint = iroh::SecretKey::generate().public(),
            4 => c.certificate = f.server_cert.clone(),
            5 => s.certificate = f.client_cert.clone(),
            6 => c.network = "other".into(),
            7 => c.root = public(&key()),
            8 => b[0] ^= 1,
            _ => role = Role::Server,
        }
        assert!(
            verify(&proof, &transcript(&c, &s, &b, role)?, &public(&f.client)).is_err(),
            "mutation {variation}"
        );
    }
    Ok(())
}

#[test]
fn frames_refuse_duplicate_fields_unknown_fields_and_oversized_input() {
    assert!(wire::decode::<Proof>(br#"{"signature":"a","signature":"b"}"#).is_err());
    assert!(wire::decode::<Proof>(br#"{"signature":"a","extra":true}"#).is_err());
    assert!(wire::decode::<Proof>(&vec![b'x'; wire::MAX_FRAME + 1]).is_err());
    assert!(wire::decode::<Proof>(b"").is_err());
}

#[tokio::test]
async fn live_session_refuses_wrong_hello_and_proof_before_any_echo() -> Result<()> {
    let f = Fixture::new();
    let server = server(&f).await?;
    let raw = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let local = identity(&f.client, &f.client_cert);
    let trust = f.trust()?;
    for variant in 0..7 {
        let conn = raw.connect(address(&server), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let mut ours = hello(Role::Client, raw.id(), &local, &trust)?;
        match variant {
            0 => ours.version = 2,
            1 => ours.role = Role::Server,
            2 => ours.endpoint = iroh::SecretKey::generate().public(),
            3 => ours.network = "other".into(),
            4 => ours.root = public(&key()),
            5 => ours.certificate = f.server_cert.clone(),
            _ => {}
        }
        let outcome = timeout(Duration::from_secs(3), async {
            write_frame(&mut send, &ours).await?;
            let theirs: Hello = read_frame(&mut recv).await?;
            let _: Proof = read_frame(&mut recv).await?;
            assert_eq!(variant, 6, "invalid hello must not receive a proof");
            let wrong_role = sign(
                &local,
                &transcript(&ours, &theirs, &exporter(&conn)?, Role::Server)?,
            );
            write_frame(&mut send, &wrong_role).await?;
            read_frame::<Value>(&mut recv).await
        })
        .await?;
        assert!(outcome.is_err(), "variant {variant}");
        conn.close(0u32.into(), b"test done");
    }
    assert_eq!(server.received_messages(), 0);
    raw.close().await;
    server.close().await;
    Ok(())
}

#[tokio::test]
async fn live_tls_exporter_changes_and_captured_proof_cannot_be_replayed() -> Result<()> {
    let f = Fixture::new();
    let server = server(&f).await?;
    let raw = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let local = identity(&f.client, &f.client_cert);
    let trust = f.trust()?;
    let mut captured = None;
    let mut first_binding = None;
    for attempt in 0..2 {
        let conn = raw.connect(address(&server), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let ours = hello(Role::Client, raw.id(), &local, &trust)?;
        write_frame(&mut send, &ours).await?;
        let theirs: Hello = read_frame(&mut recv).await?;
        let _: Proof = read_frame(&mut recv).await?;
        let binding = exporter(&conn)?;
        if attempt == 0 {
            let proof = sign(&local, &transcript(&ours, &theirs, &binding, Role::Client)?);
            write_frame(&mut send, &proof).await?;
            let _: Value = read_frame(&mut recv).await?;
            captured = Some(proof);
            first_binding = Some(binding);
        } else {
            assert_ne!(Some(binding), first_binding);
            write_frame(&mut send, captured.as_ref().unwrap()).await?;
            assert!(
                timeout(Duration::from_secs(3), read_frame::<Value>(&mut recv))
                    .await?
                    .is_err()
            );
        }
        conn.close(0u32.into(), b"test done");
        conn.closed().await;
    }
    assert_eq!(server.received_messages(), 0);
    raw.close().await;
    server.close().await;
    Ok(())
}

#[tokio::test]
async fn receiver_rejects_huge_frame_length_without_allocating_the_body() -> Result<()> {
    let f = Fixture::new();
    let server = server(&f).await?;
    let raw = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let conn = raw.connect(address(&server), ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&u32::MAX.to_be_bytes()).await?;
    let outcome = timeout(Duration::from_secs(3), async {
        let _: Hello = read_frame(&mut recv).await?;
        read_frame::<Proof>(&mut recv).await
    })
    .await?;
    assert!(outcome.is_err());
    assert_eq!(server.received_messages(), 0);
    raw.close().await;
    server.close().await;
    Ok(())
}

#[tokio::test]
async fn authenticated_peer_still_cannot_send_oversized_or_extra_messages() -> Result<()> {
    let f = Fixture::new();
    let server = server(&f).await?;
    let raw = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let credentials = Credentials {
        identity: identity(&f.client, &f.client_cert),
        trust: f.trust()?,
        expected_node: public(&f.server),
        allowed_nodes: Default::default(),
    };
    for extra in [false, true] {
        let conn = raw.connect(address(&server), ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        authenticate(
            &conn,
            raw.id(),
            Role::Client,
            &credentials,
            &mut send,
            &mut recv,
        )
        .await?;
        if extra {
            write_frame(&mut send, &"first").await?;
            write_frame(&mut send, &"second").await?;
        } else {
            write_frame(&mut send, &"x".repeat(1025)).await?;
        }
        send.finish()?;
        assert!(
            timeout(Duration::from_secs(3), read_frame::<String>(&mut recv))
                .await?
                .is_err()
        );
        conn.close(0u32.into(), b"test done");
    }
    assert_eq!(server.received_messages(), 0);
    raw.close().await;
    server.close().await;
    Ok(())
}

#[tokio::test]
async fn incomplete_authentication_has_a_deadline_and_never_echoes() -> Result<()> {
    let f = Fixture::new();
    let server = server(&f).await?;
    let raw = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let conn = raw.connect(address(&server), ALPN).await?;
    let (mut send, _recv) = conn.open_bi().await?;
    // A valid frame size with no body must not retain a slot indefinitely.
    send.write_all(&100u32.to_be_bytes()).await?;
    timeout(DEADLINE + Duration::from_secs(3), conn.closed()).await?;
    assert_eq!(server.received_messages(), 0);
    raw.close().await;
    server.close().await;
    Ok(())
}
