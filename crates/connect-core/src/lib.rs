//! Portable Connect logic. Spike A exposes diagnostics only, with no GM authorization.

mod probe;

pub use probe::{EndpointStatus, NetworkMode, ProbeEndpoint, RoundTripReport};
