//! Directory-aware metadata, separate from the legacy flat catalog wire format.
use super::*;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    File,
    Folder,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub bytes: u64,
    pub version: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub collection_id: String,
    pub directory: Vec<String>,
    pub files: Vec<Entry>,
    pub next: Option<String>,
}

pub(in crate::session) fn validate(
    page: &Page,
    request: &super::listing::ListRequest,
) -> Result<()> {
    storage::directory(&page.directory)?;
    storage::name(&page.collection_id)?;
    ensure!(
        page.directory == request.directory
            && page.files.len() <= 32
            && request
                .collection_id
                .as_ref()
                .is_none_or(|id| id == &page.collection_id),
        "Wrong folder response"
    );
    let mut previous = request.after.as_deref();
    for entry in &page.files {
        storage::name(&entry.name)?;
        ensure!(
            entry.bytes <= super::download::MAX_FILE_BYTES
                && (entry.kind == Kind::File || entry.bytes == 0)
                && entry.version.len() == 64
                && entry.version.bytes().all(|b| b.is_ascii_hexdigit())
                && previous.is_none_or(|name| entry.name.as_str() > name),
            "Invalid folder entry"
        );
        previous = Some(&entry.name);
    }
    ensure!(
        page.next
            .as_ref()
            .is_none_or(|name| page.files.last().is_some_and(|entry| &entry.name == name)),
        "Invalid next page"
    );
    Ok(())
}
