//! How devices find and reach each other. This never decides what they may do:
//! Genesis Mesh still authenticates every node and authorizes every operation.
use anyhow::Result;
use iroh::{
    Endpoint, EndpointAddr, RelayMode,
    endpoint::{PortmapperConfig, presets},
};
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

    /// Relays only under public relays. n0 address lookup only for endpoints
    /// that reach or are reached by saved devices. A router port mapping only
    /// for a guided device's own endpoints under public relays: private mode
    /// never opens an internet-facing port.
    pub(crate) fn builder(self, role: Role) -> iroh::endpoint::Builder {
        let base = Endpoint::builder(presets::Minimal);
        let base = if self.uses_relays() && role != Role::Plain {
            base.preset(presets::N0)
        } else {
            base
        };
        base.relay_mode(if self.uses_relays() {
            RelayMode::Default
        } else {
            RelayMode::Disabled
        })
        .portmapper_config(if self.uses_relays() && role == Role::Host {
            PortmapperConfig::default()
        } else {
            PortmapperConfig::Disabled
        })
    }

    /// Bind on the previous IPv4 port when one is saved, so devices that only
    /// know saved addresses still reach it after a restart. A port now taken
    /// by another program falls back to a new one.
    pub(crate) async fn bind(
        self,
        role: Role,
        port: Option<u16>,
        configure: impl Fn(iroh::endpoint::Builder) -> iroh::endpoint::Builder,
    ) -> Result<Endpoint> {
        if let Some(port) = port.filter(|port| *port != 0)
            && let Ok(builder) = configure(self.builder(role))
                .bind_addr(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
            && let Ok(endpoint) = builder.bind().await
        {
            return Ok(endpoint);
        }
        Ok(configure(self.builder(role)).bind().await?)
    }

    /// Wait for a relay when one is used, then add local network discovery.
    pub(crate) async fn ready(
        self,
        endpoint: Endpoint,
        role: Role,
        deadline: Duration,
        unavailable: &'static str,
    ) -> Result<Endpoint> {
        if self.uses_relays() && timeout(deadline, endpoint.online()).await.is_err() {
            endpoint.close().await;
            anyhow::bail!(unavailable);
        }
        discover(&endpoint, role);
        Ok(endpoint)
    }
}

/// What an endpoint is for, which decides what it publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// A guided device's own session or bridge endpoint, which saved devices
    /// dial: announced on the local network under either setting.
    Host,
    /// A guided device dialing its network computer: looks it up on the local
    /// network under either setting, without announcing itself.
    Client,
    /// Pairing, advanced profiles and tests: no lookup or discovery.
    Plain,
}

/// Local network discovery runs under both settings, so a device that has not
/// yet learned of a switch to private still finds its network computer.
/// Discovery is best effort: saved addresses still work without it.
pub(crate) fn discover(endpoint: &Endpoint, role: Role) {
    match role {
        Role::Host => add_local_discovery(endpoint, true),
        Role::Client => add_local_discovery(endpoint, false),
        Role::Plain => {}
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
fn add_local_discovery(endpoint: &Endpoint, advertise: bool) {
    // iOS needs Apple's multicast entitlement first, so it relies on saved
    // addresses. A network without multicast leaves the endpoint unchanged.
    if let (Ok(lookup), Ok(services)) = (
        iroh_mdns_address_lookup::MdnsAddressLookup::builder()
            .service_name("gmconnect1")
            .advertise(advertise)
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
fn add_local_discovery(_: &Endpoint, _: bool) {}

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

    #[tokio::test]
    async fn only_a_guided_public_host_maps_a_router_port_or_uses_relays() -> Result<()> {
        // Private mode never relays or asks the router to open a port; the
        // builder must not even configure them.
        for role in [Role::Host, Role::Client, Role::Plain] {
            let endpoint = Connectivity::LocalNetwork.builder(role).bind().await?;
            assert!(endpoint.addr().relay_urls().next().is_none(), "{role:?}");
            endpoint.close().await;
        }
        let builder = format!("{:?}", Connectivity::LocalNetwork.builder(Role::Host));
        assert!(builder.contains("portmapper_config: Disabled"), "{builder}");
        let builder = format!("{:?}", Connectivity::PublicRelays.builder(Role::Client));
        assert!(builder.contains("portmapper_config: Disabled"), "{builder}");
        let builder = format!("{:?}", Connectivity::PublicRelays.builder(Role::Plain));
        assert!(builder.contains("portmapper_config: Disabled"), "{builder}");
        let builder = format!("{:?}", Connectivity::PublicRelays.builder(Role::Host));
        assert!(
            !builder.contains("portmapper_config: Disabled"),
            "{builder}"
        );
        Ok(())
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
