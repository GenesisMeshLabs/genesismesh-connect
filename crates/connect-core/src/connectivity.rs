//! How devices find and reach each other. This never decides what they may do:
//! Genesis Mesh still authenticates every node and authorizes every operation.
use anyhow::Result;
use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

/// Ordered from least to most strict, so the stricter of two settings is the
/// larger one.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Connectivity {
    /// n0's public Iroh relays and address lookup help devices find each other
    /// from anywhere. Relays see connection metadata, never file contents.
    #[default]
    PublicRelays,
    /// No relay and no address publication: only devices on the same local
    /// network, found through saved addresses and, where the platform allows
    /// it, local network discovery.
    LocalNetwork,
}

impl Connectivity {
    /// A device may be stricter than its network's setting, never looser.
    pub fn effective(network: Self, own: Option<Self>) -> Self {
        own.map_or(network, |own| network.max(own))
    }

    pub fn uses_relays(self) -> bool {
        self == Self::PublicRelays
    }

    /// The setting a join card or authority ticket was created under.
    pub fn of_destination(destination: &EndpointAddr) -> Self {
        if destination.relay_urls().next().is_some() {
            Self::PublicRelays
        } else {
            Self::LocalNetwork
        }
    }

    /// `findable` endpoints publish their addresses (n0 address lookup, or
    /// local network discovery) so saved devices can reach them after an
    /// address change. Temporary pairing endpoints are never published.
    pub(crate) fn builder(self, findable: bool) -> iroh::endpoint::Builder {
        let base = Endpoint::builder(presets::Minimal);
        match self {
            Self::PublicRelays if findable => {
                base.preset(presets::N0).relay_mode(RelayMode::Default)
            }
            Self::PublicRelays => base.relay_mode(RelayMode::Default),
            Self::LocalNetwork => base.relay_mode(RelayMode::Disabled),
        }
    }

    /// Bind a findable endpoint, on its previous IPv4 port when one is saved,
    /// so devices that only know saved addresses still reach it after a
    /// restart. A port now taken by another program falls back to a new one.
    pub(crate) async fn bind(
        self,
        port: Option<u16>,
        configure: impl Fn(iroh::endpoint::Builder) -> iroh::endpoint::Builder,
    ) -> Result<Endpoint> {
        if let Some(port) = port.filter(|port| *port != 0)
            && let Ok(builder) = configure(self.builder(true))
                .bind_addr(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
            && let Ok(endpoint) = builder.bind().await
        {
            return Ok(endpoint);
        }
        Ok(configure(self.builder(true)).bind().await?)
    }

    /// Wait for a relay when one is used, and add local network discovery to a
    /// findable endpoint where the platform allows it. Discovery is best
    /// effort: saved addresses still work without it.
    pub(crate) async fn ready(
        self,
        endpoint: Endpoint,
        findable: bool,
        deadline: Duration,
        unavailable: &'static str,
    ) -> Result<Endpoint> {
        if self.uses_relays() {
            if timeout(deadline, endpoint.online()).await.is_err() {
                endpoint.close().await;
                anyhow::bail!(unavailable);
            }
        } else if findable {
            self.discover_locally(&endpoint);
        }
        Ok(endpoint)
    }

    /// Find (and be found by) devices on the local network, for the private
    /// setting. Public relays use n0 address lookup instead.
    pub(crate) fn discover_locally(self, endpoint: &Endpoint) {
        if self == Self::LocalNetwork {
            add_local_discovery(endpoint);
        }
    }
}

/// The IPv4 port an endpoint listens on, to reuse after a restart.
pub(crate) fn ipv4_port(endpoint: &Endpoint) -> Option<u16> {
    endpoint
        .bound_sockets()
        .iter()
        .find(|address| address.is_ipv4())
        .map(|address| address.port())
}

/// A saved transport identity and the port it listened on last time.
pub struct Transport {
    pub key: iroh::SecretKey,
    pub port: Option<u16>,
}

#[cfg(any(
    windows,
    target_os = "macos",
    target_os = "linux",
    target_os = "android"
))]
fn add_local_discovery(endpoint: &Endpoint) {
    // iOS needs Apple's multicast entitlement first, so it relies on saved
    // addresses. A network without multicast leaves the endpoint unchanged.
    if let (Ok(lookup), Ok(services)) = (
        iroh_mdns_address_lookup::MdnsAddressLookup::builder()
            .service_name("gmconnect1")
            .build(endpoint.id()),
        endpoint.address_lookup(),
    ) {
        services.add(lookup);
    }
}

#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "linux",
    target_os = "android"
)))]
fn add_local_discovery(_: &Endpoint) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_can_only_be_stricter_than_its_network() {
        use Connectivity::*;
        assert_eq!(Connectivity::effective(PublicRelays, None), PublicRelays);
        assert_eq!(Connectivity::effective(LocalNetwork, None), LocalNetwork);
        assert_eq!(
            Connectivity::effective(PublicRelays, Some(LocalNetwork)),
            LocalNetwork
        );
        assert_eq!(
            Connectivity::effective(LocalNetwork, Some(PublicRelays)),
            LocalNetwork,
            "A looser device preference must not widen a private network"
        );
    }

    #[test]
    fn saved_names_are_stable_and_unknown_values_are_refused() {
        assert_eq!(
            serde_json::to_string(&Connectivity::PublicRelays).unwrap(),
            "\"public_relays\""
        );
        assert_eq!(
            serde_json::to_string(&Connectivity::LocalNetwork).unwrap(),
            "\"local_network\""
        );
        assert!(serde_json::from_str::<Connectivity>("\"anywhere\"").is_err());
        assert_eq!(Connectivity::default(), Connectivity::PublicRelays);
    }

    #[test]
    fn a_destination_names_the_setting_it_was_created_under() {
        let id = iroh::SecretKey::from([3; 32]).public();
        let direct = EndpointAddr::new(id).with_ip_addr(([192, 0, 2, 1], 7000).into());
        assert_eq!(
            Connectivity::of_destination(&direct),
            Connectivity::LocalNetwork
        );
        let relayed =
            EndpointAddr::new(id).with_relay_url("https://relay.example.org./".parse().unwrap());
        assert_eq!(
            Connectivity::of_destination(&relayed),
            Connectivity::PublicRelays
        );
    }
}
