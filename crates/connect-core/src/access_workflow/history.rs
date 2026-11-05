//! Local, unsigned workflow history. Never an execution or approval source.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

const MAX_ARCHIVES: usize = 256;
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoryScope {
    pub pin: TrustPin,
    pub actor: String,
}
impl HistoryScope {
    pub fn id(&self) -> Result<String> {
        key(&self.pin.root_public_key)?;
        key(&self.actor)?;
        canonical_digest(&serde_json::json!({"domain":"genesismesh-connect/local-history-scope/v1","scope":self})).map_err(Into::into)
    }
    fn includes(&self, record: &AccessRecord) -> bool {
        record.intent.context.pin == self.pin && record.intent.context.actor == self.actor
    }
}

/// Native current state, never part of a caller-supplied query.
pub struct HistoryContext {
    pub scope: HistoryScope,
    pub audience: Option<String>,
    pub owned: BTreeSet<String>,
    pub disconnected: bool,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoryFilter {
    #[default]
    All,
    NeedsAttention,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryCursor {
    pub scope_id: String,
    pub filter: HistoryFilter,
    pub before_created_at: DateTime<Utc>,
    pub before_id: String,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryQuery {
    #[serde(default)]
    pub filter: HistoryFilter,
    #[serde(default)]
    pub cursor: Option<HistoryCursor>,
    #[serde(default = "default_page_size")]
    #[cfg_attr(feature = "operation-schemas", schemars(range(min = 1, max = 50)))]
    pub limit: u8,
}
fn default_page_size() -> u8 {
    20
}
impl Default for HistoryQuery {
    fn default() -> Self {
        Self {
            filter: HistoryFilter::All,
            cursor: None,
            limit: default_page_size(),
        }
    }
}
impl HistoryQuery {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=50).contains(&self.limit),
            "Choose 1 to 50 history items"
        );
        if let Some(cursor) = &self.cursor {
            uuid::Uuid::parse_str(&cursor.before_id)?;
            ensure!(cursor.scope_id.len() == 64, "Invalid history cursor");
        }
        Ok(())
    }
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRecordQuery {
    #[cfg_attr(feature = "operation-schemas", schemars(with = "uuid::Uuid"))]
    pub id: String,
}
impl LocalRecordQuery {
    pub fn validate(&self) -> Result<()> {
        uuid::Uuid::parse_str(&self.id)?;
        Ok(())
    }
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryHint {
    CheckStatus,
    Disconnected,
    PreviousHost,
    ItemStopped,
    Archived,
    Settled,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivitySummary {
    pub id: String,
    pub collection: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub stage: Stage,
    pub authorization: Authorization,
    pub policy_before: u64,
    pub policy_observed: Option<u64>,
    pub recipients_before: usize,
    pub recipients_after: usize,
    pub archived: bool,
    pub needs_attention: bool,
    pub recovery: RecoveryHint,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryPage {
    pub scope_id: String,
    pub entries: Vec<ActivitySummary>,
    pub next: Option<HistoryCursor>,
    pub attention_count: usize,
    pub incomplete: bool,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAccessRecord {
    pub format: String,
    pub evidence_class: String,
    pub signed: bool,
    pub archived: bool,
    pub record: AccessRecord,
}

#[cfg_attr(feature = "operation-schemas", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecordExport {
    Saved,
    Cancelled,
    ShareSheetOpened,
}
impl LocalAccessRecord {
    pub fn document(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)? + "\n")
    }
}

struct Loaded {
    records: Vec<(AccessRecord, bool)>,
    incomplete: bool,
}
impl AccessJournal {
    fn load_history(&self, scope: &HistoryScope) -> Result<Loaded> {
        ensure!(self.usable, "Workflow journal unavailable");
        scope.id()?;
        let mut records: BTreeMap<String, (AccessRecord, bool)> = self
            .records
            .records
            .iter()
            .filter(|r| scope.includes(r))
            .map(|r| (r.intent.id.clone(), (r.clone(), false)))
            .collect();
        let active: BTreeSet<String> = records.keys().cloned().collect();
        let archive = self.path.with_extension("archive");
        if !archive.try_exists()? {
            return Ok(Loaded {
                records: records.into_values().collect(),
                incomplete: false,
            });
        }
        if no_link(&archive).is_err() || !archive.is_dir() {
            return Ok(Loaded {
                records: records.into_values().collect(),
                incomplete: true,
            });
        }
        let mut incomplete = false;
        let mut paths = Vec::new();
        match std::fs::read_dir(&archive) {
            Ok(directory) => {
                for (index, entry) in directory.enumerate() {
                    if index >= MAX_ARCHIVES {
                        incomplete = true;
                        break;
                    }
                    let Ok(entry) = entry else {
                        incomplete = true;
                        continue;
                    };
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else {
                        incomplete = true;
                        continue;
                    };
                    // OS metadata and interrupted temporary writes are not archives.
                    if name.starts_with('.') {
                        continue;
                    }
                    if entry.path().extension().and_then(|s| s.to_str()) != Some("json")
                        || uuid::Uuid::parse_str(name.trim_end_matches(".json")).is_err()
                    {
                        incomplete = true;
                        continue;
                    }
                    paths.push(entry.path());
                    if paths.len() > MAX_ARCHIVES {
                        incomplete = true;
                        break;
                    }
                }
            }
            Err(_) => incomplete = true,
        }
        paths.sort();
        paths.truncate(MAX_ARCHIVES);
        let mut budget = MAX_SCAN_BYTES;
        for path in paths {
            let size = match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_file() && !m.file_type().is_symlink() => m.len(),
                _ => {
                    incomplete = true;
                    continue;
                }
            };
            if size > MAX_BYTES || size > budget {
                incomplete = true;
                continue;
            }
            let archive = match Records::read_budgeted(&path, &mut budget) {
                Ok(records) => records,
                Err(_) => {
                    incomplete = true;
                    continue;
                }
            };
            for record in archive.records.into_iter().filter(|r| scope.includes(r)) {
                if let Some((old, _)) = records.get(&record.intent.id) {
                    if old.digest != record.digest {
                        incomplete = true;
                        continue;
                    }
                    // Atomic compaction can leave an archive plus its active
                    // copy. The active writer's current state always wins.
                    if active.contains(&record.intent.id) || old.updated_at >= record.updated_at {
                        continue;
                    }
                }
                records.insert(record.intent.id.clone(), (record, true));
            }
        }
        Ok(Loaded {
            records: records.into_values().collect(),
            incomplete,
        })
    }

    fn history_summaries(&self, context: &HistoryContext) -> Result<(Vec<ActivitySummary>, bool)> {
        let Loaded {
            mut records,
            incomplete,
        } = self.load_history(&context.scope)?;
        records.sort_by(|(a, _), (b, _)| {
            (b.intent.created_at, &b.intent.id).cmp(&(a.intent.created_at, &a.intent.id))
        });
        let mut latest = BTreeSet::new();
        let mut entries = Vec::new();
        for (record, archived) in records {
            let target = (
                record.intent.collection.clone(),
                record.intent.context.audience.clone(),
            );
            let dispatched = !matches!(record.stage, Stage::Prepared | Stage::Cancelled);
            let newest = dispatched && latest.insert(target);
            let needs_attention = newest
                && matches!(
                    record.stage,
                    Stage::Unknown | Stage::Submitted | Stage::Conflict
                );
            let recovery = if archived {
                RecoveryHint::Archived
            } else if !needs_attention {
                RecoveryHint::Settled
            } else if context.audience.as_deref() != Some(&record.intent.context.audience) {
                RecoveryHint::PreviousHost
            } else if !context.owned.contains(&record.intent.collection) {
                RecoveryHint::ItemStopped
            } else if context.disconnected {
                RecoveryHint::Disconnected
            } else {
                RecoveryHint::CheckStatus
            };
            entries.push(ActivitySummary {
                id: record.intent.id,
                collection: record.intent.collection,
                name: record.intent.name,
                created_at: record.intent.created_at,
                updated_at: record.updated_at,
                stage: record.stage,
                authorization: record.authorization,
                policy_before: record.intent.before.version,
                policy_observed: record.observed.map(|p| p.version),
                recipients_before: record.intent.before.recipients.len(),
                recipients_after: record.intent.after.recipients.len(),
                archived,
                needs_attention,
                recovery,
            });
        }
        Ok((entries, incomplete))
    }

    pub fn history_summary(&self, context: &HistoryContext, id: &str) -> Result<ActivitySummary> {
        uuid::Uuid::parse_str(id)?;
        self.history_summaries(context)?
            .0
            .into_iter()
            .find(|entry| entry.id == id)
            .context("This local record is unavailable for this device and network")
    }

    pub fn history_page(
        &self,
        context: &HistoryContext,
        query: &HistoryQuery,
    ) -> Result<HistoryPage> {
        query.validate()?;
        let scope_id = context.scope.id()?;
        if let Some(cursor) = &query.cursor {
            ensure!(
                cursor.scope_id == scope_id && cursor.filter == query.filter,
                "History context changed. Refresh Activity before loading more"
            );
        }
        let (mut entries, incomplete) = self.history_summaries(context)?;
        let attention_count = entries.iter().filter(|entry| entry.needs_attention).count();
        entries.retain(|entry| {
            (query.filter != HistoryFilter::NeedsAttention || entry.needs_attention)
                && query.cursor.as_ref().is_none_or(|cursor| {
                    (entry.created_at, &entry.id) < (cursor.before_created_at, &cursor.before_id)
                })
        });
        let next = if entries.len() > usize::from(query.limit) {
            entries.truncate(usize::from(query.limit));
            let last = entries.last().context("Missing page item")?;
            Some(HistoryCursor {
                scope_id: scope_id.clone(),
                filter: query.filter,
                before_created_at: last.created_at,
                before_id: last.id.clone(),
            })
        } else {
            None
        };
        Ok(HistoryPage {
            scope_id,
            entries,
            next,
            attention_count,
            incomplete,
        })
    }

    pub fn history_record(&self, scope: &HistoryScope, id: &str) -> Result<LocalAccessRecord> {
        uuid::Uuid::parse_str(id)?;
        let loaded = self.load_history(scope)?;
        let (record,archived)=loaded.records.into_iter().find(|(r,_)|r.intent.id==id).context("This local record is unavailable for this device and network. Older history may need attention")?;
        Ok(LocalAccessRecord {
            format: "genesismesh-connect/local-access-history/v1".into(),
            evidence_class: "unsigned_local_workflow_metadata".into(),
            signed: false,
            archived,
            record,
        })
    }
}
