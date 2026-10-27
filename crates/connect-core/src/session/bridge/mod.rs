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
