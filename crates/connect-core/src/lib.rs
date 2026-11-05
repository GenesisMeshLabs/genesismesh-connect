//! Portable Connect diagnostics. Authentication does not grant service permission.

#[cfg(test)]
extern crate self as connect_core;

pub mod access_workflow;
pub mod authority;
pub mod connectivity;
pub mod device;
pub mod operations;
pub mod owner;
pub mod owner_control;
mod probe;
pub mod recovery;
pub mod session;
pub mod transfer_limits;

pub use connectivity::Connectivity;
pub use probe::{EndpointStatus, NetworkMode, ProbeEndpoint, RoundTripReport};

/// Validate a selected filename before creating a private sharing snapshot.
pub fn validate_shared_file_name(name: &str) -> anyhow::Result<()> {
    session::sharing::validate_file_name(name)
}
