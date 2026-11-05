//! Separately enrolled, pairing-only owner control. Not exposed on the member
//! bridge. Local approval, current membership and an administrative signature
//! are independent prerequisites. This module never calls an authority.
mod protocol;
mod store;

pub use protocol::*;
pub use store::{ControlStore, Grant, Observation, Reservation};
