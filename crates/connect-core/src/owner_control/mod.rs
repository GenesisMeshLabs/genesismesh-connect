//! Separately enrolled, pairing-only owner control over the authenticated bridge.
//! Local approval, current membership and an administrative signature remain
//! independent prerequisites. Only the native host adapter calls the authority.
mod client;
mod exchange;
mod host;
mod local;
mod protocol;
mod store;

pub use client::*;
pub use exchange::*;
pub use host::HostControl;
pub use local::*;
pub use protocol::*;
pub use store::{ControlStore, Grant, Observation, Reservation};
