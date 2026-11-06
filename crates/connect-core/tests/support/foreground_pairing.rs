#![allow(dead_code)]
use super::support;
use anyhow::{Context, Result};
use connect_core::{
    Connectivity,
    device::DeviceController,
    owner::foreground::{ForegroundNetwork, ForegroundSetup, NativeSetupConfig},
    owner_control::PairingTarget,
    session::pairing::{Joined, PairCard, PairClient, PairGrant, PairHost},
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc, time::Duration};
pub(crate) fn loopback(mut value: Value) -> Result<Value> {
    let address = value["endpoint"]["addrs"]
        .as_array()
        .context("Missing fixture addresses")?
        .iter()
        .filter_map(|a| a["Ip"].as_str()?.parse::<std::net::SocketAddr>().ok())
        .find(|a| a.is_ipv4())
        .context("Missing IPv4 fixture socket")?;
    value["endpoint"]["addrs"] = json!([{"Ip":format!("127.0.0.1:{}",address.port())}]);
    Ok(value)
}
pub(crate) fn ticket(text: String) -> Result<String> {
    Ok(serde_json::to_string(&loopback(serde_json::from_str(
        &text,
    )?)?)?)
}
pub(crate) fn grant(mut value: PairGrant) -> Result<PairGrant> {
    value.route.ticket = ticket(value.route.ticket)?;
    value.session_ticket = ticket(value.session_ticket)?;
    Ok(value)
}
pub(crate) async fn owner(root: &Path) -> Result<(ForegroundNetwork, support::Loss)> {
    support::sealed_store();
    std::fs::create_dir(root.join("native"))?;
    let (runtime, _, loss) = support::controlled_backend(&root.join("backend"), None)?;
    let mut setup = ForegroundSetup::begin(
        runtime,
        NativeSetupConfig::new(root.join("native"))?,
        support::create(),
    )?;
    setup.open_authority()?;
    setup.prepare_device()?;
    setup.request_invitation()?;
    setup.enroll_device().await?;
    let mut owner = setup.finish()?;
    owner
        .device
        .set_network_connectivity(Connectivity::LocalNetwork)
        .await?;
    Ok((owner, loss))
}
pub(crate) async fn request(
    owner: &mut ForegroundNetwork,
    member: &mut DeviceController,
    recoverable: bool,
) -> Result<(Arc<PairHost>, PairCard, PairClient, PairingTarget)> {
    let pair = owner.device.create_pairing("Fixture home".into()).await?;
    let card: PairCard = serde_json::from_value(loopback(serde_json::to_value(pair.card())?)?)?;
    let client = if recoverable {
        member
            .request_recoverable_pairing(card.clone(), "Second device".into())
            .await?
    } else {
        member
            .request_pairing(card.clone(), "Second device".into())
            .await?
    };
    let target =
        PairingTarget::from_pending(&pair.pending().context("No actual pending candidate")?);
    assert_eq!(target.node, member.status()?.node_public_key);
    assert_eq!(target.comparison_code, client.code);
    assert_eq!(target.comparison_code.len(), 6);
    Ok((pair, card, client, target))
}
pub(crate) fn candidate(root: &Path, owner: &ForegroundNetwork) -> Result<DeviceController> {
    DeviceController::prepare_remote(&root.join("candidate"), owner.info.pin.clone())
}
pub(crate) async fn joined(completion: tokio::sync::oneshot::Receiver<Joined>) -> Result<Joined> {
    Ok(tokio::time::timeout(Duration::from_secs(20), completion).await??)
}
pub(crate) async fn stop(
    owner: &mut ForegroundNetwork,
    member: &mut DeviceController,
    pair: &PairHost,
    client: &PairClient,
) {
    client.close().await;
    pair.close().await;
    member.stop().await;
    owner.device.stop().await;
}
