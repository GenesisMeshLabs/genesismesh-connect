//! Portable Connect diagnostics. Authentication does not grant service permission.

#[cfg(test)]
extern crate self as connect_core;

pub mod authority;
pub mod connectivity;
pub mod device;
pub mod owner;
mod probe;
pub mod session;

pub use connectivity::Connectivity;
pub use probe::{EndpointStatus, NetworkMode, ProbeEndpoint, RoundTripReport};
