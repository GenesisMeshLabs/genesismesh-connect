//! Exact, expiring access intents and a device-local crash journal.
//! These records are NOT signed core evidence or independent human approval.
use crate::{authority::TrustPin, owner::AccessPolicy};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use genesis_mesh_sdk::{canonical_digest, parse_strict_json};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub mod history;

pub const OPERATION: &str = "connect.access.update.v1";
// Includes before/after/readback gates for every bounded active record.
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 128;

/// Native verified context, never accepted as authority from the web UI/model.
#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessContext {
    pub pin: TrustPin,
    pub actor: String,
    pub audience: String,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessIntent {
    #[cfg_attr(feature = "operation-schemas", schemars(range(min = 1, max = 1)))]
    pub schema: u8,
    #[cfg_attr(
        feature = "operation-schemas",
        schemars(regex(pattern = "^connect\\.access\\.update\\.v1$"))
    )]
    pub operation: String,
    pub id: String,
    pub context: AccessContext,
    pub collection: String,
    pub name: String,
    pub before: AccessPolicy,
    pub after: AccessPolicy,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Prepared,
    Submitted,
    Unknown,
    StateObserved,
    Conflict,
    Cancelled,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Authorization {
    NotEvaluated,
    CoreAccepted,
    Unknown,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRecord {
    pub intent: AccessIntent,
    pub digest: String,
    pub stage: Stage,
    pub authorization: Authorization,
    /// Readback is a state observation, not attribution or a signed receipt.
    pub observed: Option<AccessPolicy>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Records {
    schema: u8,
    records: Vec<AccessRecord>,
}
impl Records {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == 1 && self.records.len() <= MAX_RECORDS,
            "Unsupported workflow journal"
        );
        let mut ids = std::collections::BTreeSet::new();
        for record in &self.records {
            ensure!(
                record.digest == record.intent.digest()? && ids.insert(&record.intent.id),
                "Workflow history needs attention; it was preserved"
            );
            ensure!(
                record.stage != Stage::Prepared
                    || (record.authorization == Authorization::NotEvaluated
                        && record.observed.is_none()),
                "Invalid prepared workflow state"
            );
            ensure!(
                record.stage != Stage::StateObserved || record.observed.is_some(),
                "Workflow readback is missing"
            );
            if let Some(observed) = &record.observed {
                ensure!(
                    normalize(observed.clone(), None)? == *observed,
                    "Invalid workflow readback"
                );
            }
        }
        Ok(())
    }
    fn read(path: &Path) -> Result<Self> {
        let mut budget = MAX_BYTES;
        Self::read_budgeted(path, &mut budget)
    }
    fn read_budgeted(path: &Path, budget: &mut u64) -> Result<Self> {
        no_link(path)?;
        ensure!(
            std::fs::metadata(path)?.is_file(),
            "Invalid workflow history file"
        );
        let limit = (*budget).min(MAX_BYTES);
        ensure!(limit > 0, "Workflow history scan limit reached");
        let mut bytes = Vec::new();
        File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
        *budget = budget.saturating_sub(bytes.len() as u64);
        ensure!(bytes.len() as u64 <= limit, "Workflow journal is too large");
        let records: Self =
            serde_json::from_value(parse_strict_json(std::str::from_utf8(&bytes)?)?)?;
        records.validate()?;
        Ok(records)
    }
}

/// Exclusive writer, bounded strict JSON, atomic replacement and fsync. Stores
/// public policy metadata in the app container, never keys, tokens or file data.
/// Corruption/lock failure refuses further dispatch; history is never reset.
pub struct AccessJournal {
    path: PathBuf,
    records: Records,
    _lock: File,
    usable: bool,
}

fn key(value: &str) -> Result<()> {
    ensure!(
        STANDARD.decode(value)?.len() == 32,
        "Invalid device or network identity"
    );
    Ok(())
}

pub(crate) fn normalize(
    mut policy: AccessPolicy,
    now: Option<DateTime<Utc>>,
) -> Result<AccessPolicy> {
    ensure!(
        policy.version > 0 && policy.version < (1 << 53),
        "Invalid policy version"
    );
    ensure!(
        (1..=31).contains(&policy.recipients.len()),
        "Choose at least one device"
    );
    for recipient in &policy.recipients {
        key(recipient)?;
    }
    policy.recipients.sort();
    policy.recipients.dedup();
    ensure!(
        (1..=crate::transfer_limits::MAX_FILE_BYTES).contains(&policy.max_bytes)
            && (1..=3600).contains(&policy.max_seconds),
        "Invalid access limit"
    );
    if let Some(expires) = &policy.expires_at {
        let at = DateTime::parse_from_rfc3339(expires)?.with_timezone(&Utc);
        ensure!(
            now.is_none_or(|now| at > now),
            "Choose a future expiry date"
        );
        policy.expires_at = Some(at.to_rfc3339());
    }
    ensure!(
        policy.extra_gates.len() <= 24 && serde_json::to_vec(&policy.extra_gates)?.len() <= 16000,
        "Too many additional policy rules"
    );
    // Core still validates the gate vocabulary and semantics at execution.
    let mut ids = std::collections::BTreeSet::new();
    for gate in &policy.extra_gates {
        let id = gate
            .get("gate_id")
            .and_then(|id| id.as_str())
            .context("A policy rule needs an ID")?;
        ensure!(
            !["collection", "peer", "size", "duration"].contains(&id) && ids.insert(id),
            "Policy rule IDs must be distinct and non-reserved"
        );
    }
    canonical_digest(&serde_json::to_value(&policy)?)?;
    Ok(policy)
}

impl AccessIntent {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == 1 && self.operation == OPERATION,
            "Unsupported access operation schema"
        );
        uuid::Uuid::parse_str(&self.id)?;
        uuid::Uuid::parse_str(&self.collection)?;
        key(&self.context.actor)?;
        key(&self.context.audience)?;
        key(&self.context.pin.root_public_key)?;
        ensure!(
            !self.context.pin.network_name.is_empty() && self.context.pin.network_name.len() <= 320,
            "Invalid network name"
        );
        ensure!(
            !self.name.trim().is_empty()
                && self.name.chars().count() <= 64
                && !self.name.chars().any(char::is_control),
            "Invalid shared item name"
        );
        ensure!(
            self.expires_at > self.created_at
                && self.expires_at - self.created_at <= Duration::minutes(5),
            "Invalid review expiry"
        );
        ensure!(
            normalize(self.before.clone(), None)? == self.before
                && normalize(self.after.clone(), None)? == self.after
                && self.before.version == self.after.version
                && !self.after.recipients.contains(&self.context.actor),
            "Invalid access intent"
        );
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        // Use the SDK canonicalizer. This is a Connect intent domain, not a core artifact.
        Ok(canonical_digest(
            &serde_json::json!({"domain":"genesismesh-connect/access-intent/v1","intent":self}),
        )?)
    }
}

fn no_link(path: &Path) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        ensure!(
            !metadata.file_type().is_symlink(),
            "Workflow storage cannot be a symbolic link"
        );
    }
    Ok(())
}

impl AccessJournal {
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(
            path.is_absolute(),
            "Workflow storage must be an absolute native path"
        );
        let parent = path.parent().context("Missing workflow directory")?;
        ensure!(parent.is_dir(), "Workflow directory missing");
        no_link(parent)?;
        no_link(path)?;
        let lock_path = path.with_extension("lock");
        no_link(&lock_path)?;
        let initialized = lock_path.exists();
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path)?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .context("Another access change is running; wait for it to finish")?;
        let records = if path.exists() {
            Records::read(path)?
        } else {
            ensure!(
                !initialized,
                "Workflow history is missing. Restore it before changing access; it has not been reset"
            );
            Records {
                schema: 1,
                records: vec![],
            }
        };
        records.validate()?;
        let mut journal = Self {
            path: path.to_owned(),
            records,
            _lock: lock,
            usable: true,
        };
        // A process died after persisting dispatch. Never infer that it failed.
        let mut recovered = false;
        for record in &mut journal.records.records {
            if record.stage == Stage::Submitted {
                record.stage = Stage::Unknown;
                recovered = true;
            }
        }
        if recovered || !path.exists() {
            journal.save()?;
        }
        Ok(journal)
    }
    fn save(&mut self) -> Result<()> {
        ensure!(
            self.usable,
            "Workflow persistence failed; reopen the journal before continuing"
        );
        self.usable = false;
        let bytes = serde_json::to_vec(&self.records)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "Workflow journal is full; no change was dispatched"
        );
        let parent = self.path.parent().context("Missing workflow directory")?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist(&self.path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        self.usable = true;
        Ok(())
    }
    fn archive_completed(&mut self) -> Result<()> {
        ensure!(self.usable, "Workflow journal unavailable");
        // Only settled records may leave the active file. Never discard an
        // unconfirmed dispatch, live review, or its original intent identity.
        let ids: std::collections::BTreeSet<_> = self
            .records
            .records
            .iter()
            .filter(|r| matches!(r.stage, Stage::StateObserved | Stage::Conflict))
            .take(MAX_RECORDS / 2)
            .map(|r| r.intent.id.clone())
            .collect();
        ensure!(
            !ids.is_empty(),
            "Too many unfinished access changes; check their status first"
        );
        let archive = self.path.with_extension("archive");
        no_link(&archive)?;
        if !archive.exists() {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&archive)?;
            #[cfg(unix)]
            File::open(archive.parent().context("Missing workflow directory")?)?.sync_all()?;
        }
        ensure!(
            archive.is_dir(),
            "Workflow archive needs attention; it has been preserved"
        );
        let archived = Records {
            schema: 1,
            records: self
                .records
                .records
                .iter()
                .filter(|r| ids.contains(&r.intent.id))
                .cloned()
                .collect(),
        };
        let bytes = serde_json::to_vec(&archived)?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "Workflow archive is too large"
        );
        let mut file = tempfile::NamedTempFile::new_in(&archive)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(archive.join(format!("{}.json", uuid::Uuid::new_v4())))?;
        #[cfg(unix)]
        File::open(&archive)?.sync_all()?;
        // A crash before active replacement leaves duplicates, never missing
        // history. An archive failure leaves all original active records.
        self.records.records.retain(|r| !ids.contains(&r.intent.id));
        self.save()
    }
    pub fn list(&self, context: &AccessContext, collection: &str) -> Vec<AccessRecord> {
        self.records
            .records
            .iter()
            .filter(|r| &r.intent.context == context && r.intent.collection == collection)
            .cloned()
            .collect()
    }
    pub fn prepare(
        &mut self,
        context: AccessContext,
        collection: String,
        name: String,
        before: AccessPolicy,
        after: AccessPolicy,
        now: DateTime<Utc>,
    ) -> Result<AccessRecord> {
        ensure!(self.usable, "Workflow journal unavailable");
        ensure!(
            !self
                .list(&context, &collection)
                .iter()
                .any(|r| matches!(r.stage, Stage::Submitted | Stage::Unknown)),
            "An earlier access change has an uncertain result. Check its status before changing access again"
        );
        // Retain dispatched records, archiving settled history before removing
        // it from the active file. Only obsolete unsubmitted reviews are pruned.
        self.records.records.retain(|r| {
            !matches!(r.stage, Stage::Prepared | Stage::Cancelled) || r.intent.expires_at > now
        });
        if self.records.records.len() >= MAX_RECORDS {
            self.archive_completed()?;
        }
        let intent = AccessIntent {
            schema: 1,
            operation: OPERATION.into(),
            id: uuid::Uuid::new_v4().to_string(),
            context,
            collection,
            name,
            before: normalize(before, None)?,
            after: normalize(after, Some(now))?,
            created_at: now,
            expires_at: now + Duration::minutes(5),
        };
        let record = AccessRecord {
            digest: intent.digest()?,
            intent,
            stage: Stage::Prepared,
            authorization: Authorization::NotEvaluated,
            observed: None,
            updated_at: now,
        };
        self.records.records.push(record.clone());
        self.save()?;
        Ok(record)
    }
    pub fn get(&self, id: &str, context: &AccessContext) -> Result<AccessRecord> {
        self.records
            .records
            .iter()
            .find(|r| r.intent.id == id && &r.intent.context == context)
            .cloned()
            .context("This review belongs to another device or network, or is no longer available")
    }
    /// Persist BEFORE the caller invokes the existing core-authorized adapter.
    pub fn submit(
        &mut self,
        id: &str,
        digest: &str,
        context: &AccessContext,
        current: AccessPolicy,
        now: DateTime<Utc>,
    ) -> Result<AccessRecord> {
        let record = self.get(id, context)?;
        ensure!(
            !self
                .list(context, &record.intent.collection)
                .iter()
                .any(|other| other.intent.id != id
                    && matches!(other.stage, Stage::Submitted | Stage::Unknown)),
            "An earlier access change has an uncertain result. Check its status first"
        );
        ensure!(
            record.stage == Stage::Prepared && record.digest == digest,
            "Review this exact change before saving; it may already have been submitted"
        );
        ensure!(
            now >= record.intent.created_at && now < record.intent.expires_at,
            "This review expired; review the current settings again"
        );
        ensure!(
            normalize(current, None)? == record.intent.before,
            "Access changed since your review. Reload its settings before saving"
        );
        normalize(record.intent.after.clone(), Some(now))?;
        let record = self.change(id)?;
        record.stage = Stage::Submitted;
        record.authorization = Authorization::Unknown;
        record.updated_at = now;
        let result = record.clone();
        self.save()?;
        Ok(result)
    }
    fn change(&mut self, id: &str) -> Result<&mut AccessRecord> {
        ensure!(self.usable, "Workflow journal unavailable");
        self.records
            .records
            .iter_mut()
            .find(|r| r.intent.id == id)
            .context("Workflow not found")
    }
    pub fn core_accepted(&mut self, id: &str) -> Result<()> {
        let record = self.change(id)?;
        ensure!(record.stage == Stage::Submitted, "Workflow not submitted");
        record.authorization = Authorization::CoreAccepted;
        self.save()
    }
    pub fn uncertain(&mut self, id: &str) -> Result<()> {
        let record = self.change(id)?;
        ensure!(
            matches!(record.stage, Stage::Submitted | Stage::Unknown),
            "Workflow not submitted"
        );
        record.stage = Stage::Unknown;
        record.updated_at = Utc::now();
        self.save()
    }
    /// Read-only reconciliation. Matching state does not prove which request
    /// caused it. Unchanged state cannot rule out an in-flight mutation.
    pub fn observe(&mut self, id: &str, current: AccessPolicy) -> Result<AccessRecord> {
        let current = normalize(current, None)?;
        let record = self.change(id)?;
        ensure!(
            matches!(
                record.stage,
                Stage::Submitted | Stage::Unknown | Stage::Conflict | Stage::StateObserved
            ),
            "This workflow has no submitted change to check"
        );
        let mut wanted = record.intent.after.clone();
        wanted.version += 1;
        record.stage = if current == wanted {
            Stage::StateObserved
        } else if current.version > record.intent.before.version
            || (current.version == record.intent.before.version && current != record.intent.before)
        {
            Stage::Conflict
        } else {
            Stage::Unknown
        };
        record.observed = Some(current);
        record.updated_at = Utc::now();
        let result = record.clone();
        self.save()?;
        Ok(result)
    }
    pub fn cancel(&mut self, id: &str, context: &AccessContext) -> Result<()> {
        ensure!(
            self.get(id, context)?.stage == Stage::Prepared,
            "A submitted change cannot be cancelled or retried here; check its status"
        );
        let record = self.change(id)?;
        record.stage = Stage::Cancelled;
        record.updated_at = Utc::now();
        self.save()
    }
}
