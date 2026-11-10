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

/// Seconds since `start` at which each attempt began, on tokio's paused clock.
fn attempts_at(start: tokio::time::Instant, calls: &std::cell::RefCell<Vec<u64>>) -> u64 {
    let at = start.elapsed().as_secs();
    calls.borrow_mut().push(at);
    at
}

#[tokio::test(start_paused = true)]
async fn a_running_device_waits_out_a_restart_as_long_as_those_measured() {
    // The phone that runs the network was out of reach for 42 to 88 s after a
    // restart. A host that cannot be reached until then is asked again, with
    // waits of 1, 2, 4 and then 8 s, and the read answers once it is back.
    for outage in [42, 62, 88] {
        let start = tokio::time::Instant::now();
        let calls = std::cell::RefCell::new(Vec::new());
        let answered = asking_again(ASK_AGAIN_FOR, || {
            let at = attempts_at(start, &calls);
            let reply = if at < outage {
                Err(unreached(anyhow::anyhow!("no route to the device")))
            } else {
                Ok(at)
            };
            async move { reply }
        })
        .await;
        let at = answered.unwrap();
        assert!(
            at >= outage && at < outage + 8,
            "{outage} s outage answered at {at} s"
        );
        assert_eq!(calls.borrow()[..5], [0, 1, 3, 7, 15]);
    }

    // The same when each attempt takes the 10 s connection deadline to fail.
    let start = tokio::time::Instant::now();
    let calls = std::cell::RefCell::new(Vec::new());
    let answered = asking_again(ASK_AGAIN_FOR, || {
        let at = attempts_at(start, &calls);
        async move {
            if at < 88 {
                tokio::time::sleep(DEADLINE).await;
                Err(unreached(anyhow::anyhow!("Read connection timed out")))
            } else {
                Ok(at)
            }
        }
    })
    .await;
    assert_eq!(answered.unwrap(), 91);
    assert_eq!(*calls.borrow(), [0, 11, 23, 37, 55, 73, 91]);

    // A host that answers busy while it cannot ask its network computer.
    let start = tokio::time::Instant::now();
    let answered = asking_again(ASK_AGAIN_FOR, || {
        let reply = if start.elapsed() < Duration::from_secs(70) {
            Err(anyhow::Error::new(sharing::Busy("Not yet")))
        } else {
            Ok(())
        };
        async move { reply }
    })
    .await;
    assert!(answered.is_ok());
}

/// The 30-second trust refresh used to fail a pairing whose final proof it
/// landed on: the device had enrolled, and the owner's side gave up.
#[tokio::test(start_paused = true)]
async fn a_pairing_proof_a_trust_refresh_ended_is_asked_again() {
    for ended in [
        "Trust changed; reconnect with current credentials",
        "connection lost: closed by peer: session ended (code 0)",
    ] {
        let attempts = std::cell::Cell::new(0);
        let proved = proving_again(PAIRING_PROOF, || {
            attempts.set(attempts.get() + 1);
            let reply = if attempts.get() == 1 {
                Err(anyhow::anyhow!(ended))
            } else {
                Ok("proved")
            };
            async move { reply }
        })
        .await;
        assert_eq!(proved.unwrap(), "proved", "{ended}");
        assert_eq!(attempts.get(), 2, "{ended}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_refused_pairing_proof_is_final_and_a_lasting_refresh_gives_up() {
    // A refusal is never asked again: a revoked or wrong device stays out.
    for refusal in [
        "Certificate revoked",
        "Peer certificate does not match the expected node",
        "Signature verification failed",
    ] {
        let attempts = std::cell::Cell::new(0);
        let proved: Result<()> = proving_again(PAIRING_PROOF, || {
            attempts.set(attempts.get() + 1);
            async move { Err(anyhow::anyhow!(refusal)) }
        })
        .await;
        assert_eq!(proved.unwrap_err().to_string(), refusal);
        assert_eq!(attempts.get(), 1, "{refusal}");
    }
    // Trust that keeps changing ends within the time the device waits.
    let start = tokio::time::Instant::now();
    let attempts = std::cell::Cell::new(0);
    let proved: Result<()> = proving_again(PAIRING_PROOF, || {
        attempts.set(attempts.get() + 1);
        async move {
            Err(anyhow::anyhow!(
                "Trust changed; reconnect with current credentials"
            ))
        }
    })
    .await;
    assert!(proved.is_err());
    assert_eq!(attempts.get(), 4, "at 0, 1, 3 and 7 seconds");
    assert!(start.elapsed() < Duration::from_secs(20));
}

#[tokio::test(start_paused = true)]
async fn asking_again_stops_after_two_minutes_with_the_last_answer() {
    // Fast failures: attempts at 0, 1, 3, 7 and every 8 s after, the last
    // starting before the two minutes are up.
    let start = tokio::time::Instant::now();
    let calls = std::cell::RefCell::new(Vec::new());
    let given_up: Result<()> = asking_again(ASK_AGAIN_FOR, || {
        attempts_at(start, &calls);
        let reply = Err(unreached(anyhow::anyhow!("no route to the device")));
        async move { reply }
    })
    .await;
    let error = given_up.unwrap_err();
    assert!(error.is::<sharing::Busy>());
    assert!(error.to_string().contains("Keep Connect open"), "{error:#}");
    let mut expected = vec![0, 1, 3];
    expected.extend((7..120).step_by(8));
    assert_eq!(*calls.borrow(), expected);
    assert_eq!(start.elapsed(), Duration::from_secs(119));

    // Slow failures stop within the budget too, attempt time included.
    let start = tokio::time::Instant::now();
    let calls = std::cell::RefCell::new(Vec::new());
    let given_up: Result<()> = asking_again(ASK_AGAIN_FOR, || {
        attempts_at(start, &calls);
        async move {
            tokio::time::sleep(DEADLINE).await;
            Err(unreached(anyhow::anyhow!("Read connection timed out")))
        }
    })
    .await;
    assert!(given_up.unwrap_err().is::<sharing::Busy>());
    assert_eq!(*calls.borrow(), [0, 11, 23, 37, 55, 73, 91, 109]);
    assert!(start.elapsed() <= ASK_AGAIN_FOR);

    // This device's own connection still suspended when time runs out: said
    // plainly as busy, with the last answer kept underneath.
    let given_up: Result<()> = asking_again(ASK_AGAIN_FOR, || async {
        Err(anyhow::anyhow!("Connection is suspended"))
    })
    .await;
    let error = given_up.unwrap_err();
    assert!(error.is::<sharing::Busy>());
    assert!(
        error.to_string().starts_with("No answer in time"),
        "{error:#}"
    );
    assert!(format!("{error:#}").ends_with("Connection is suspended"));
}

#[tokio::test(start_paused = true)]
async fn a_refusal_is_final_even_during_an_outage() {
    let start = tokio::time::Instant::now();
    let calls = std::cell::RefCell::new(Vec::new());
    let refused: Result<()> = asking_again(ASK_AGAIN_FOR, || {
        let at = attempts_at(start, &calls);
        let reply = if at < 3 {
            Err(unreached(anyhow::anyhow!("no route to the device")))
        } else {
            Err(anyhow::anyhow!("Read unavailable or denied"))
        };
        async move { reply }
    })
    .await;
    assert_eq!(
        refused.unwrap_err().to_string(),
        "Read unavailable or denied"
    );
    assert_eq!(*calls.borrow(), [0, 1, 3], "A refusal is never asked again");

    let calls = std::cell::RefCell::new(Vec::new());
    let start = tokio::time::Instant::now();
    let refused: Result<()> = asking_again(ASK_AGAIN_FOR, || {
        attempts_at(start, &calls);
        let reply = Err(anyhow::anyhow!(
            "This folder is unavailable or access was not allowed"
        ));
        async move { reply }
    })
    .await;
    assert!(refused.is_err());
    assert_eq!(*calls.borrow(), [0]);
}

#[test]
fn only_outcomes_that_clear_by_themselves_are_asked_again() {
    let cut = anyhow::anyhow!("closed by peer: session ended (code 0)").context("connection lost");
    assert!(clears_by_itself(&cut), "A trust refresh on the host");
    assert!(clears_by_itself(&anyhow::anyhow!(
        "Trust snapshot stale or future dated"
    )));
    let down = unreached(anyhow::anyhow!("no route to the device"));
    assert!(clears_by_itself(&down), "A host that may be restarting");
    assert!(down.to_string().contains("could not be reached"));
    let refused = unreached(anyhow::anyhow!(
        "aborted by peer: the server refused to accept a new connection"
    ));
    assert!(clears_by_itself(&refused), "A host still starting");
    let no_share = unreached(anyhow::anyhow!("peer doesn't support any known protocol"));
    assert!(!clears_by_itself(&no_share), "A host that shares nothing");
    assert!(no_share.to_string().contains("support any known protocol"));
    assert!(clears_by_itself(&anyhow::anyhow!(
        "Connection is suspended"
    )));
    assert!(clears_by_itself(&anyhow::anyhow!(
        "Trust changed during read"
    )));
    assert!(clears_by_itself(&anyhow::Error::new(sharing::Busy(
        "Not yet"
    ))));
    for final_answer in [
        "Read unavailable or denied",
        "This folder is unavailable or access was not allowed",
        "closed by peer: authority operation ended (code 0)",
        "Read timed out",
    ] {
        assert!(!clears_by_itself(&anyhow::anyhow!(final_answer)));
    }
}
