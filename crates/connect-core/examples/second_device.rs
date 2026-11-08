//! A headless member device for acceptance tests against a real network. It
//! joins with an invitation link and the comparison code, then lists and reads
//! what other devices share with it, through the same controller as the app.
//!
//! Its key lives in the OS credential store. On Linux, run it inside a Secret
//! Service session, for example:
//!
//! ```text
//! dbus-run-session -- sh -c 'printf test | gnome-keyring-daemon --unlock --components=secrets >/dev/null;
//!   cargo run --example second_device -- <profile> join "<invitation link>" "Test laptop"'
//! ```
use anyhow::{Context, Result, bail};
use connect_core::{
    device::{DeviceController, PairedDevice},
    session::{pairing::PairCard, sharing::ReadRequest},
};
use std::path::Path;

const USAGE: &str = "Usage: second_device <profile> (join <link> [name] | status | browse [space] [folder/...] | read <space> <name> [sha256] | watch <space> <name> <reads>)";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let profile = Path::new(args.first().context(USAGE)?);
    match args.get(1).map(String::as_str) {
        Some("join") => {
            let link = args.get(2).context(USAGE)?;
            let name = args.get(3).map_or("Second device", String::as_str);
            join(profile, link, name).await
        }
        Some("status") => {
            let device = connected(profile).await?;
            println!("{}", serde_json::to_string_pretty(&device.status()?)?);
            Ok(())
        }
        Some("browse") => {
            let space = args.get(2).cloned();
            let folder = args.iter().skip(3).cloned().collect();
            let mut device = connected(profile).await?;
            let peer = host(&mut device, space.as_deref())?;
            let page = device
                .session()?
                .browse_from(&peer.node, &peer.ticket, None, folder, space)
                .await?;
            println!("Space {} /{}", page.collection_id, page.directory.join("/"));
            for entry in page.files {
                println!(
                    "  {:?} {} ({} bytes, {})",
                    entry.kind, entry.name, entry.bytes, entry.version
                );
            }
            Ok(())
        }
        Some("read") => {
            let space = args.get(2).context(USAGE)?.clone();
            let name = args.get(3).context(USAGE)?.clone();
            let mut device = connected(profile).await?;
            let peer = host(&mut device, Some(&space))?;
            let report = device
                .session()?
                .read_file_from(
                    Some(&peer.node),
                    &peer.ticket,
                    ReadRequest {
                        request_id: uuid::Uuid::new_v4().to_string(),
                        collection_id: space,
                        file_name: name,
                        expected_sha256: args.get(4).cloned(),
                    },
                )
                .await?;
            println!(
                "Read {} ({} bytes, sha256 {}, receipt {})",
                report.file_name, report.bytes, report.sha256, report.receipt_id
            );
            if let Some(text) = report.text {
                println!("{text}");
            }
            Ok(())
        }
        // One running device reading again and again, as an open app does while
        // its host restarts. Refreshes trust during reads too, like the app's
        // background task.
        Some("watch") => {
            let space = args.get(2).context(USAGE)?.clone();
            let name = args.get(3).context(USAGE)?.clone();
            let reads: u32 = args.get(4).context(USAGE)?.parse()?;
            let mut device = connected(profile).await?;
            let peer = host(&mut device, Some(&space))?;
            let start = std::time::Instant::now();
            let mut refresh = tokio::time::interval(std::time::Duration::from_secs(30));
            refresh.tick().await;
            for read in 1..=reads {
                let asked = start.elapsed().as_secs();
                let session = device.session()?;
                let reading = session.read_file_from(
                    Some(&peer.node),
                    &peer.ticket,
                    ReadRequest {
                        request_id: uuid::Uuid::new_v4().to_string(),
                        collection_id: space.clone(),
                        file_name: name.clone(),
                        expected_sha256: None,
                    },
                );
                tokio::pin!(reading);
                let outcome = loop {
                    tokio::select! {
                        outcome = &mut reading => break outcome,
                        _ = refresh.tick() => {
                            if let Err(error) = device.refresh().await {
                                println!("refresh at {}s: {error:#}", start.elapsed().as_secs());
                            }
                        }
                    }
                };
                let answered = start.elapsed().as_secs();
                match outcome {
                    Ok(report) => println!(
                        "read {read} asked at {asked}s answered at {answered}s: ok, receipt {}",
                        report.receipt_id
                    ),
                    Err(error) => {
                        println!("read {read} asked at {asked}s answered at {answered}s: {error:#}")
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Ok(())
        }
        _ => bail!(USAGE),
    }
}

/// Ask to join, show the comparison code, then wait for the owner's decision.
async fn join(profile: &Path, link: &str, name: &str) -> Result<()> {
    let card = PairCard::parse(link)?;
    let mut device = if profile.exists() {
        DeviceController::open(profile)?
    } else {
        DeviceController::prepare_remote(profile, card.pin.clone())?
    };
    let mut pairing = device.request_pairing(card.clone(), name.into()).await?;
    println!(
        "Waiting for approval on {}. Compare code {}.",
        card.host_name, pairing.code
    );
    let result = async {
        let grant = pairing.grant().await?;
        println!("Approved. Finishing the secure connection…");
        device
            .complete_approved_pairing(&mut pairing, &card, grant)
            .await
    }
    .await;
    pairing.close().await;
    result?;
    let status = device.status()?;
    println!(
        "Joined {} as {} (certificate {}).",
        status.network,
        status.node_public_key,
        status.certificate_id.as_deref().unwrap_or("-")
    );
    Ok(())
}

async fn connected(profile: &Path) -> Result<DeviceController> {
    let mut device = DeviceController::open(profile)?;
    device.connect_when_reachable().await?;
    Ok(device)
}

/// The device sharing `space` when this device knows it, else the selected one.
fn host(device: &mut DeviceController, space: Option<&str>) -> Result<PairedDevice> {
    let status = device.status()?;
    let host = space
        .and_then(|id| status.spaces.iter().find(|s| s.collection == id))
        .map(|s| s.host.clone());
    match host {
        Some(host) => status
            .devices
            .iter()
            .chain(&status.members)
            .find(|d| d.node == host)
            .cloned()
            .context("The device sharing this Space is not on the network right now"),
        None => device
            .paired_device()
            .cloned()
            .context("No other device is paired yet"),
    }
}
