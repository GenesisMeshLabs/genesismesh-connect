//! Fixed authority control operations over Iroh. No administrative or file APIs.
mod client;
mod enrollment;
mod server;
#[cfg(test)]
mod tests;

pub(crate) use client::endpoint_of;
pub use client::{BridgeAuthority, BridgeRoute};
pub use server::AuthorityBridge;

use super::{Credentials, SessionIdentity, TrustSnapshot, limit_streams, wire};
use crate::authority::{EnrolledDevice, LocalAuthority, TrustDocuments, TrustStore};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, RecvStream, SendStream},
};
#[cfg(test)]
use iroh::{RelayMode, endpoint::presets};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{OnceCell, Semaphore, watch},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use wire::{Protocol, Role, authenticate_for, read_frame, write_frame};

const DEADLINE: Duration = Duration::from_secs(15);
// Two authority responses of at most 256 KiB, plus a small envelope.
const MAX_RESPONSE: usize = 512 * 1024 + 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    version: u8,
    service: Service,
    endpoint: EndpointAddr,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Service {
    Authority,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    operation: Operation,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[derive(Clone, Copy)]
enum Operation {
    Trust,
    Renew,
    Evaluate,
    Attestation,
    Settings,
    Members,
    Spaces,
    ShareSpace,
    UnshareSpace,
}

/// A Space as a device learns it from its network computer: another device's
/// with its name and host only; its own with the grant it shares under.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpaceView {
    pub collection: String,
    pub name: String,
    pub host: String,
    #[serde(default)]
    pub kind: crate::session::sharing::SpaceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<SpaceGrant>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpaceGrant {
    pub policy_id: String,
    pub attestation_id: String,
    pub recipients: Vec<String>,
    pub valid_until: String,
}
impl SpaceView {
    /// What `node` may learn about `space`: nothing unless it hosts the Space
    /// or the Space names it.
    pub fn of(space: crate::owner::Space, node: &str) -> Option<Self> {
        let own = space.host == node;
        if !own && !space.recipients.iter().any(|r| r == node) {
            return None;
        }
        Some(Self {
            grant: own.then_some(SpaceGrant {
                policy_id: space.policy_id,
                attestation_id: space.attestation_id,
                recipients: space.recipients,
                valid_until: space.valid_until,
            }),
            collection: space.collection,
            name: space.name,
            host: space.host,
            kind: space.kind,
        })
    }
    pub(crate) fn check(&self) -> Result<()> {
        uuid::Uuid::parse_str(&self.collection)?;
        let key = |node: &str| {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            STANDARD.decode(node).is_ok_and(|k| k.len() == 32)
        };
        ensure!(
            !self.name.trim().is_empty()
                && self.name.chars().count() <= 64
                && !self.name.chars().any(char::is_control)
                && key(&self.host),
            "Invalid shared folder"
        );
        if let Some(grant) = &self.grant {
            uuid::Uuid::parse_str(&grant.attestation_id)?;
            ensure!(
                grant.policy_id == format!("connect-{}", self.collection)
                    && (1..=31).contains(&grant.recipients.len())
                    && grant.recipients.iter().all(|r| key(r))
                    && grant.valid_until.len() <= 64,
                "Invalid shared folder grant"
            );
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ShareSpaceRequest {
    collection: String,
    name: String,
    recipients: Vec<String>,
    #[serde(default)]
    kind: crate::session::sharing::SpaceKind,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnshareSpaceRequest {
    collection: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SpacesAnswer {
    spaces: Vec<SpaceView>,
}

/// The longest session address a member list carries. Real addresses are a
/// few hundred bytes; the bound keeps 32 of them within one response and a
/// device's saved profile.
pub(crate) const MAX_MEMBER_TICKET: usize = 2048;

/// What a device tells its network computer when it asks for the members:
/// its own current session address, so the others can reach it after its
/// addresses change. Accepted only for the endpoint it paired with.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MembersRequest {
    session_ticket: Option<String>,
}

/// The other devices of the network, from the network computer's saved
/// devices. It is only sent over a mutually authenticated bridge connection.
/// Knowing a member grants no file access: every operation still needs the
/// authority's decision.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MembersAnswer {
    members: Vec<crate::device::PairedDevice>,
}

/// What a network computer tells its devices about reaching it. It is only
/// sent over a mutually authenticated bridge connection, so a device can treat
/// it as its own network computer's choice. It never grants permission.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct NetworkSettings {
    pub connectivity: crate::Connectivity,
    /// The bridge's current ticket: the same endpoint, with fresh addresses.
    pub authority_ticket: String,
    /// The network computer's current session ticket, while its session runs.
    pub session_ticket: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Ok { value: Value },
    Refused,
}

async fn respond(send: &mut SendStream, result: Result<Value>) -> Result<()> {
    // Errors are deliberately static; never reflect a signed request or NA body.
    let response = match result {
        Ok(value) => Response::Ok { value },
        Err(_) => Response::Refused,
    };
    let bytes = serde_json::to_vec(&response)?;
    ensure!(bytes.len() <= MAX_RESPONSE, "Bridge response too large");
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    send.finish()?;
    Ok(())
}

async fn response(recv: &mut RecvStream) -> Result<Value> {
    let mut size = [0; 4];
    recv.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(
        size > 0 && size <= MAX_RESPONSE,
        "Invalid bridge response length"
    );
    let mut bytes = vec![0; size];
    recv.read_exact(&mut bytes).await?;
    ensure!(
        recv.read_to_end(0).await?.is_empty(),
        "Unexpected bridge response data"
    );
    let value = genesis_mesh_sdk::parse_strict_json(std::str::from_utf8(&bytes)?)?;
    match serde_json::from_value(value)? {
        Response::Ok { value } => Ok(value),
        Response::Refused => anyhow::bail!("Desktop authority request refused or unavailable"),
    }
}

fn own_credential(credentials: &Credentials) -> Result<()> {
    credentials.trust.renewable_certificate(
        &credentials.identity.certificate,
        &credentials.identity.public_key(),
        Utc::now(),
    )
}

struct Budget {
    since: Instant,
    used: u32,
    maximum: u32,
}
impl Budget {
    fn new(maximum: u32) -> Self {
        Self {
            since: Instant::now(),
            used: 0,
            maximum,
        }
    }
    fn allow(&mut self) -> bool {
        if self.since.elapsed() >= Duration::from_secs(60) {
            self.since = Instant::now();
            self.used = 0;
        }
        if self.used >= self.maximum {
            return false;
        }
        self.used += 1;
        true
    }
}
