//! In-memory synthetic authority; this does not enroll devices in a real mesh.
#[path = "../tests/support/mod.rs"]
mod support;

use anyhow::{Result, ensure};
use connect_core::session::{SessionEndpoint, SessionIdentity};
use support::{Fixture, public};

#[tokio::main]
async fn main() -> Result<()> {
    ensure!(
        std::env::args().nth(1).as_deref() == Some("self-test"),
        "Usage: session self-test"
    );
    let f = Fixture::new();
    let server = SessionEndpoint::bind(
        SessionIdentity::new(f.server.clone(), f.server_cert.clone())?,
        f.trust()?,
        public(&f.client),
    )
    .await?;
    let ticket = server.ticket()?;
    for attempt in 1..=2 {
        let client = SessionEndpoint::bind(
            SessionIdentity::new(f.client.clone(), f.client_cert.clone())?,
            f.trust()?,
            public(&f.server),
        )
        .await?;
        let report = client
            .round_trip(&ticket, "Connect authenticated hello")
            .await?;
        println!("Attempt {attempt}: {}", serde_json::to_string(&report)?);
        client.close().await;
    }
    ensure!(
        server.received_messages() == 2,
        "Missing authenticated echoes"
    );
    server.close().await;
    println!(
        "Synthetic same-host session and reconnect passed; no device enrollment or file permission is implied."
    );
    Ok(())
}
