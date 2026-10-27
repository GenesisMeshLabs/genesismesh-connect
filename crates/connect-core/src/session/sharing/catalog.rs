//! A separate listing protocol includes large files without hashing every file
//! just to browse. The signed revision marker is checked when taking a snapshot;
//! its full content digest is then verified by the download protocol.
use super::*;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub bytes: u64,
    pub version: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub collection_id: String,
    pub files: Vec<Entry>,
    pub next: Option<String>,
}
