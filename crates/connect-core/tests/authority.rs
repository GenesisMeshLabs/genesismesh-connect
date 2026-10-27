#[allow(dead_code)]
mod support;
use anyhow::Result;
use chrono::Utc;
use connect_core::authority::{LocalAuthority, TrustPin, TrustStore};
use serde_json::json;
use support::{Fixture, public, signed};

fn pin(f: &Fixture) -> TrustPin {
    TrustPin {
        root_public_key: public(&f.root),
        network_name: "connect-spike".into(),
    }
}
fn view(f: &Fixture) -> serde_json::Value {
    json!({"genesis": f.genesis, "successions": [], "vouching_grace_seconds": 86400})
}

#[test]
fn trust_watermarks_survive_restart_and_refuse_rollback_or_equivocation() -> Result<()> {
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("trust.json");
    let mut store = TrustStore::create(&path, pin(&f))?;
    assert!(store.status().observed_at.is_none());
    assert!(store.status().crl_sequence.is_none());
    store.accept(&view(&f), f.crl.clone(), f.now)?;
    assert_eq!(store.status().observed_at, Some(f.now));
    assert_eq!(store.status().key_sequence, Some(1));
    assert!(TrustStore::open(&path, &pin(&f)).is_err()); // one writer
    let mut newer = f.crl.clone();
    newer["sequence"] = json!(2);
    newer = signed(newer, &[&f.authority]);
    store.accept(&view(&f), newer.clone(), Utc::now())?;
    drop(store);
    let bytes = std::fs::read(&path)?;
    let mut store = TrustStore::open(&path, &pin(&f))?;
    assert_eq!(store.status().crl_sequence, Some(2));
    let last_observed = store.status().observed_at;
    assert!(store.accept(&view(&f), f.crl.clone(), Utc::now()).is_err());
    assert_eq!(store.status().observed_at, last_observed);
    let mut fork = newer.clone();
    fork["crl_id"] = json!("different");
    fork = signed(fork, &[&f.authority]);
    assert!(store.accept(&view(&f), fork, Utc::now()).is_err());
    let mut history = view(&f);
    history["genesis"]["network_version"] = json!("v2");
    history["genesis"] = signed(history["genesis"].clone(), &[&f.root]);
    assert!(store.accept(&history, newer.clone(), Utc::now()).is_err());
    assert_eq!(
        std::fs::read(&path)?,
        bytes,
        "refusals must not change disk state"
    );
    store.accept(&view(&f), newer, Utc::now())?;
    drop(store);
    assert!(TrustStore::create(&path, pin(&f)).is_err());
    Ok(())
}

#[test]
fn missing_corrupt_or_wrong_network_checkpoint_never_resets() -> Result<()> {
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("trust.json");
    assert!(TrustStore::open(&path, &pin(&f)).is_err());
    drop(TrustStore::create(&path, pin(&f))?);
    let mut wrong = pin(&f);
    wrong.network_name = "other".into();
    assert!(TrustStore::open(&path, &wrong).is_err());
    std::fs::write(&path, b"{broken")?;
    assert!(TrustStore::open(&path, &pin(&f)).is_err());
    assert!(TrustStore::create(&path, pin(&f)).is_err());
    Ok(())
}

#[test]
fn forged_or_stale_refresh_does_not_advance_the_checkpoint() -> Result<()> {
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("trust.json");
    let mut store = TrustStore::create(&path, pin(&f))?;
    store.accept(&view(&f), f.crl.clone(), f.now)?;
    let prior = std::fs::read(&path)?;
    let mut invalid = f.crl.clone();
    invalid["sequence"] = json!(9999);
    assert!(store.accept(&view(&f), invalid, Utc::now()).is_err());
    assert!(
        store
            .accept(
                &view(&f),
                f.crl.clone(),
                f.now - chrono::Duration::seconds(1)
            )
            .is_err()
    );
    let mut stale = f.crl.clone();
    stale["sequence"] = json!(2);
    stale["issued_at"] = json!(genesis_mesh_sdk::canonical::python_timestamp(
        f.now - chrono::Duration::hours(25)
    ));
    stale = signed(stale, &[&f.authority]);
    assert!(store.accept(&view(&f), stale, Utc::now()).is_err());
    assert_eq!(std::fs::read(path)?, prior);
    Ok(())
}

#[test]
fn initial_signed_crl_zero_is_distinct_from_an_uninitialized_checkpoint() -> Result<()> {
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("trust.json");
    let mut store = TrustStore::create(&path, pin(&f))?;
    let mut zero = f.crl.clone();
    zero["sequence"] = json!(0);
    zero = signed(zero, &[&f.authority]);
    store.accept(&view(&f), zero.clone(), f.now)?;
    drop(store);
    let mut store = TrustStore::open(&path, &pin(&f))?;
    store.accept(&view(&f), zero.clone(), Utc::now())?;
    let mut fork = zero.clone();
    fork["crl_id"] = json!("different-zero");
    fork = signed(fork, &[&f.authority]);
    assert!(store.accept(&view(&f), fork, Utc::now()).is_err());
    store.accept(&view(&f), f.crl.clone(), Utc::now())?;
    assert!(store.accept(&view(&f), zero, Utc::now()).is_err());
    Ok(())
}

#[test]
fn signed_key_history_must_extend_the_exact_persisted_chain() -> Result<()> {
    use genesis_mesh_sdk::canonical::python_timestamp;
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("trust.json");
    let mut store = TrustStore::create(&path, pin(&f))?;
    store.accept(&view(&f), f.crl.clone(), f.now)?;
    let next = support::key();
    let effective = f.now - chrono::Duration::seconds(1);
    let successor = signed(
        json!({
            "succession_id": "connect-test-succession", "sovereign_id": "connect-spike", "key_sequence": 2,
            "previous_key_id": "spike-only", "previous_public_key": public(&f.authority),
            "new_key_id": "next", "new_public_key": public(&next), "effective_at": python_timestamp(effective),
            "new_valid_to": python_timestamp(f.now + chrono::Duration::hours(1)), "issued_at": python_timestamp(effective),
        }),
        &[&f.root, &f.authority, &next],
    );
    let mut history = view(&f);
    history["successions"] = json!([successor.clone()]);
    let mut crl = f.crl.clone();
    crl["sequence"] = json!(2);
    crl = signed(crl, &[&next]);
    store.accept(&history, crl.clone(), Utc::now())?;
    drop(store);
    let mut store = TrustStore::open(&path, &pin(&f))?;
    let before = std::fs::read(&path)?;
    assert!(
        store
            .accept(&view(&f), signed(crl.clone(), &[&f.authority]), Utc::now())
            .is_err()
    );
    let mut fork = successor;
    fork["new_key_id"] = json!("different-name");
    history["successions"] = json!([signed(fork, &[&f.root, &f.authority, &next])]);
    assert!(store.accept(&history, crl, Utc::now()).is_err());
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

#[tokio::test]
async fn a_stalled_authority_response_times_out_without_changing_trust() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("trust.json");
    let mut store = TrustStore::create(&path, pin(&f))?;
    let before = std::fs::read(&path)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 2048];
        let _ = stream.read(&mut request).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
            .await;
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        LocalAuthority::new(&url)?.refresh(&mut store),
    )
    .await;
    task.abort();
    let _ = task.await;
    assert!(result?.is_err());
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

#[test]
fn disk_failure_returns_no_snapshot_and_poisoned_store_cannot_continue() -> Result<()> {
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("trust.json");
    let mut store = TrustStore::create(&path, pin(&f))?;
    // A directory in place of the destination makes atomic replacement fail.
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;
    assert!(store.accept(&view(&f), f.crl.clone(), f.now).is_err());
    std::fs::remove_dir(&path)?;
    assert!(
        store
            .accept(&view(&f), f.crl.clone(), f.now)
            .err()
            .expect("persistence failure must poison the store")
            .to_string()
            .contains("previously failed")
    );
    Ok(())
}

async fn response_server(response: Vec<u8>) -> Result<(String, tokio::task::JoinHandle<()>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = [0; 2048];
        let _ = stream.read(&mut head).await;
        let _ = stream.write_all(&response).await;
    });
    Ok((url, task))
}

#[tokio::test]
async fn redirects_large_bodies_duplicate_json_and_unavailable_authority_fail_closed() -> Result<()>
{
    let f = Fixture::new();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("trust.json");
    let mut store = TrustStore::create(&path, pin(&f))?;
    let baseline = std::fs::read(&path)?;
    let body = "x".repeat(256 * 1024 + 1);
    let responses = [
        b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1/admin\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"a\":1,\"a\":2}".to_vec(),
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        )
        .into_bytes(),
        b"HTTP/1.1 500 Error\r\nContent-Length: 12\r\n\r\nsecret-token".to_vec(),
    ];
    for response in responses {
        let (url, task) = response_server(response).await?;
        let error = LocalAuthority::new(&url)?
            .refresh(&mut store)
            .await
            .err()
            .expect("must reject");
        assert!(!format!("{error:#}").contains("secret-token"));
        task.await?;
        assert_eq!(std::fs::read(&path)?, baseline);
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    drop(listener);
    assert!(
        LocalAuthority::new(&url)?
            .refresh(&mut store)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path)?, baseline);
    Ok(())
}
