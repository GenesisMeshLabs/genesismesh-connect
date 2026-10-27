use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use genesis_mesh_sdk::{
    canonical::{key_succession_digest, received_canonical},
    canonical_digest,
    key_history::vouching_grace,
    parse_strict_json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use crate::session::{TrustPolicy, TrustSnapshot};

/// Provisioned out of band. Never construct this from an untrusted HTTP reply.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustPin {
    pub root_public_key: String,
    pub network_name: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u8,
    pin: TrustPin,
    // A whole verified history prefix prevents a signed same-sequence fork.
    genesis_digest: Option<String>,
    succession_digests: Vec<String>,
    crl_sequence: Option<u64>,
    crl_digest: Option<String>,
    crl_issued_at: Option<DateTime<Utc>>,
    observed_at: Option<DateTime<Utc>>,
    grace_seconds: i64,
}

/// Single writer with atomic checkpoint replacement in a caller-owned directory.
/// Stores public trust metadata only. Missing/corrupt files never auto-reset.
pub struct TrustStore {
    path: PathBuf,
    checkpoint: Checkpoint,
    _lock: File,
    usable: bool,
}

const MAX_CHECKPOINT: u64 = 256 * 1024;

/// Public checkpoint metadata for display; it does not assert current validity.
#[derive(Serialize)]
pub struct TrustCheckpointStatus {
    pub observed_at: Option<DateTime<Utc>>,
    pub crl_sequence: Option<u64>,
    pub key_sequence: Option<usize>,
}

impl TrustStore {
    pub fn status(&self) -> TrustCheckpointStatus {
        TrustCheckpointStatus {
            observed_at: self.checkpoint.observed_at,
            crl_sequence: self.checkpoint.crl_sequence,
            key_sequence: self
                .checkpoint
                .genesis_digest
                .as_ref()
                .map(|_| self.checkpoint.succession_digests.len() + 1),
        }
    }
    /// Explicit first-time bootstrap. Refuses to overwrite any existing state.
    pub fn create(path: &Path, pin: TrustPin) -> Result<Self> {
        validate_pin(&pin)?;
        let lock = lock(path)?;
        let checkpoint = Checkpoint {
            version: 1,
            pin,
            genesis_digest: None,
            succession_digests: vec![],
            crl_sequence: None,
            crl_digest: None,
            crl_issued_at: None,
            observed_at: None,
            grace_seconds: 0,
        };
        persist(path, &checkpoint, true)?;
        Ok(Self {
            path: path.to_owned(),
            checkpoint,
            _lock: lock,
            usable: true,
        })
    }

    pub fn open(path: &Path, pin: &TrustPin) -> Result<Self> {
        validate_pin(pin)?;
        let lock = lock(path)?;
        let mut bytes = Vec::new();
        File::open(path)
            .context("Trust checkpoint missing; restore it rather than silently re-enrolling")?
            .take(MAX_CHECKPOINT + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_CHECKPOINT,
            "Trust checkpoint too large"
        );
        let checkpoint: Checkpoint =
            serde_json::from_value(parse_strict_json(std::str::from_utf8(&bytes)?)?)?;
        ensure!(
            checkpoint.version == 1 && &checkpoint.pin == pin,
            "Trust checkpoint pin/version mismatch"
        );
        let empty = checkpoint.crl_sequence.is_none();
        ensure!(
            empty == checkpoint.genesis_digest.is_none()
                && empty == checkpoint.crl_digest.is_none()
                && empty == checkpoint.crl_issued_at.is_none()
                && empty == checkpoint.observed_at.is_none()
                && (!empty || checkpoint.succession_digests.is_empty())
                && checkpoint.grace_seconds == 0,
            "Inconsistent trust checkpoint"
        );
        Ok(Self {
            path: path.to_owned(),
            checkpoint,
            _lock: lock,
            usable: true,
        })
    }

    /// The entire response is untrusted until SDK verification succeeds. Public
    /// `keys`, `signing_key_sequence`, and `handover_seconds` are not trust inputs.
    pub fn accept(
        &mut self,
        view: &Value,
        crl: Value,
        observed_at: DateTime<Utc>,
    ) -> Result<TrustSnapshot> {
        ensure!(
            self.usable,
            "Trust persistence previously failed; reopen the checkpoint"
        );
        ensure!(
            serde_json::to_vec(view)?.len() <= super::http::MAX_RESPONSE
                && serde_json::to_vec(&crl)?.len() <= super::http::MAX_RESPONSE,
            "Trust response too large"
        );
        let genesis = &view["genesis"];
        let successions = view["successions"]
            .as_array()
            .context("Missing key successions")?;
        let prior = &self.checkpoint;
        ensure!(
            prior.observed_at.is_none_or(|old| observed_at >= old),
            "Trust observation moved backwards"
        );
        // Unsigned policy may only shorten the locally chosen zero grace.
        let grace = prior
            .grace_seconds
            .min(vouching_grace(view["vouching_grace_seconds"].as_i64()));
        let snapshot = TrustSnapshot::for_renewed_devices(
            TrustPolicy {
                root_public_key: prior.pin.root_public_key.clone(),
                network_name: prior.pin.network_name.clone(),
                minimum_crl_sequence: prior.crl_sequence.unwrap_or(0),
                minimum_key_sequence: prior.succession_digests.len() as i64 + 1,
                max_age: Duration::from_secs(60),
                vouching_grace_seconds: grace,
            },
            genesis,
            successions,
            crl.clone(),
            observed_at,
        )?;
        // Hash canonical signed bodies, so signature-list ordering is irrelevant.
        let genesis_digest = canonical_digest(&parse_strict_json(&received_canonical(
            "GenesisBlock",
            genesis,
        )?)?)?;
        let digests: Vec<String> = successions
            .iter()
            .map(key_succession_digest)
            .collect::<Result<_, _>>()?;
        ensure!(
            prior
                .genesis_digest
                .as_ref()
                .is_none_or(|old| old == &genesis_digest),
            "Genesis equivocation"
        );
        ensure!(
            digests.starts_with(&prior.succession_digests),
            "Key history rollback or equivocation"
        );
        let mut crl_body = crl.clone();
        crl_body
            .as_object_mut()
            .context("Malformed CRL")?
            .remove("signatures");
        let digest = canonical_digest(&crl_body)?;
        let sequence = crl["sequence"].as_u64().context("Missing CRL sequence")?;
        ensure!(
            Some(sequence) != prior.crl_sequence || prior.crl_digest.as_ref() == Some(&digest),
            "CRL equivocation"
        );
        let issued =
            DateTime::parse_from_rfc3339(crl["issued_at"].as_str().context("Missing CRL time")?)?
                .with_timezone(&Utc);
        ensure!(
            prior.crl_issued_at.is_none_or(|old| issued >= old),
            "CRL time moved backwards"
        );
        let next = Checkpoint {
            version: 1,
            pin: prior.pin.clone(),
            genesis_digest: Some(genesis_digest),
            succession_digests: digests,
            crl_sequence: Some(sequence),
            crl_digest: Some(digest),
            crl_issued_at: Some(issued),
            observed_at: Some(observed_at),
            grace_seconds: grace,
        };
        self.usable = false;
        persist(&self.path, &next, false)?;
        self.checkpoint = next;
        self.usable = true;
        Ok(snapshot)
    }
}

fn validate_pin(pin: &TrustPin) -> Result<()> {
    ensure!(
        STANDARD
            .decode(&pin.root_public_key)
            .is_ok_and(|key| key.len() == 32)
            && !pin.network_name.is_empty()
            && pin.network_name.len() <= 256,
        "Invalid network trust pin"
    );
    Ok(())
}

fn lock(path: &Path) -> Result<File> {
    ensure!(path.is_absolute(), "Trust checkpoint path must be absolute");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path.with_extension("lock"))?;
    lock.try_lock()
        .context("Trust checkpoint already in use or cannot be locked")?;
    Ok(lock)
}

fn persist(path: &Path, checkpoint: &Checkpoint, new: bool) -> Result<()> {
    let bytes = serde_json::to_vec(checkpoint)?;
    ensure!(
        bytes.len() as u64 <= MAX_CHECKPOINT,
        "Trust checkpoint too large"
    );
    let parent = path.parent().context("Missing trust directory")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    if new {
        file.persist_noclobber(path)?;
    } else {
        file.persist(path)?;
    }
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}
