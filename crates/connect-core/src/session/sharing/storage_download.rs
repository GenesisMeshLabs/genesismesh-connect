//! Metadata-only browsing and immutable, disk-backed download snapshots.
use super::*;
use crate::session::sharing::{catalog::Entry, download::MAX_FILE_BYTES};
use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    sync::Arc,
};

pub(in crate::session::sharing) struct Snapshot {
    file: tempfile::NamedTempFile,
    pub size: u64,
    pub sha256: String,
}
impl Snapshot {
    pub fn window(&self, offset: u64, length: usize) -> Result<(File, String)> {
        ensure!(
            offset <= self.size && length as u64 <= self.size - offset,
            "Invalid download range"
        );
        // Each window owns a cursor; reopening avoids dup()'s shared position.
        let mut file = self.file.reopen()?;
        file.seek(SeekFrom::Start(offset))?;
        let mut hash = Sha256::new();
        let mut remaining = length;
        let mut buffer = Zeroizing::new([0u8; 8192]);
        while remaining > 0 {
            let count = file.read(&mut buffer[..remaining.min(8192)])?;
            ensure!(count > 0, "Snapshot ended early");
            hash.update(&buffer[..count]);
            remaining -= count;
        }
        file.seek(SeekFrom::Start(offset))?;
        Ok((file, super::hex(&hash.finalize())))
    }
}

fn revision(metadata: &cap_std::fs::Metadata) -> Result<String> {
    let modified = metadata
        .modified()?
        .into_std()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    Ok(genesis_mesh_sdk::canonical_digest(&serde_json::json!({
        "device":metadata.dev(),"file":metadata.ino(),"size":metadata.len(),"modified_ns":modified
    }))?)
}

impl Collection {
    pub fn browse(
        &self,
        after: Option<&str>,
    ) -> Result<(Vec<super::super::browse::Entry>, Option<String>)> {
        use super::super::browse::{Entry, Kind};
        use cap_fs_ext::DirExt;
        if let Some(after) = after {
            name(after)?;
        }
        let mut names = Vec::new();
        for (index, entry) in self.directory.entries()?.enumerate() {
            ensure!(index < 512, "This folder has more than 512 entries");
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str()
                && super::name(name).is_ok()
                && after.is_none_or(|after| name > after)
            {
                names.push(name.to_owned());
            }
        }
        names.sort();
        let mut entries = Vec::new();
        let mut next = None;
        for name in names {
            let metadata = self.directory.symlink_metadata(&name)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            let entry = if metadata.is_dir() {
                let Ok(directory) = self.directory.open_dir_nofollow(&name) else {
                    continue;
                };
                Entry {
                    name,
                    kind: Kind::Folder,
                    bytes: 0,
                    version: revision(&directory.dir_metadata()?)?,
                }
            } else {
                let Ok((_, file)) = self.downloadable(&name) else {
                    continue;
                };
                Entry {
                    name: file.name,
                    kind: Kind::File,
                    bytes: file.bytes,
                    version: file.version,
                }
            };
            if entries.len() == 32 {
                next = entries.last().map(|entry: &Entry| entry.name.clone());
                break;
            }
            entries.push(entry);
        }
        Ok((entries, next))
    }
    pub fn check_download_version(&self, name: &str, version: &str, size: u64) -> Result<()> {
        let (_, entry) = self.downloadable(name)?;
        ensure!(
            entry.version == version && entry.bytes == size,
            "The file changed. Refresh the file list and try again."
        );
        Ok(())
    }
    fn downloadable(&self, file_name: &str) -> Result<(cap_std::fs::File, Entry)> {
        name(file_name)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_fs_ext::OpenOptionsSyncExt;
            options.nonblock(true);
        }
        let file = self.directory.open_with(file_name, &options)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= MAX_FILE_BYTES,
            "Choose a regular file up to 1 GiB with one link"
        );
        let entry = Entry {
            name: file_name.to_owned(),
            bytes: metadata.len(),
            version: revision(&metadata)?,
        };
        Ok((file, entry))
    }

    pub fn catalog(&self, after: Option<&str>) -> Result<(Vec<Entry>, Option<String>)> {
        if let Some(after) = after {
            name(after)?;
        }
        let mut names = Vec::new();
        for (index, entry) in self.directory.entries()?.enumerate() {
            ensure!(index < 512, "Choose a folder with at most 512 entries");
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str()
                && super::name(name).is_ok()
                && after.is_none_or(|after| name > after)
            {
                names.push(name.to_owned());
            }
        }
        names.sort();
        let mut files = Vec::new();
        let mut next = None;
        for name in names {
            if let Ok((_, entry)) = self.downloadable(&name) {
                if files.len() == 32 {
                    next = files.last().map(|entry: &Entry| entry.name.clone());
                    break;
                }
                files.push(entry);
            }
        }
        Ok((files, next))
    }

    pub fn download_snapshot(
        &self,
        file_name: &str,
        expected: &str,
        cache: &Path,
    ) -> Result<Arc<Snapshot>> {
        let (source, entry) = self.downloadable(file_name)?;
        ensure!(
            entry.version == expected,
            "The file changed. Refresh the file list and try again."
        );
        let mut source = source.into_std();
        source.try_lock_shared().context("The file is in use")?;
        let mut snapshot = tempfile::NamedTempFile::new_in(cache)?;
        let mut hash = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = Zeroizing::new([0u8; 64 * 1024]);
        loop {
            let count = source.read(&mut *buffer)?;
            if count == 0 {
                break;
            }
            copied += count as u64;
            ensure!(
                copied <= entry.bytes && copied <= MAX_FILE_BYTES,
                "The file changed while preparing it"
            );
            snapshot.write_all(&buffer[..count])?;
            hash.update(&buffer[..count]);
        }
        ensure!(
            copied == entry.bytes
                && revision(&cap_std::fs::Metadata::from_file(&source)?)? == entry.version,
            "The file changed while preparing it"
        );
        snapshot.as_file().sync_all()?;
        Ok(Arc::new(Snapshot {
            file: snapshot,
            size: copied,
            sha256: super::hex(&hash.finalize()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_folders_are_confined_and_paged_without_following_links() -> Result<()> {
        use super::super::super::browse::Kind;
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().join("share");
        let outside = fixture.path().join("outside");
        std::fs::create_dir_all(root.join("Photos/Été 2026"))?;
        std::fs::create_dir(&outside)?;
        std::fs::write(outside.join("private.txt"), b"outside")?;
        std::fs::write(root.join("Photos/Été 2026/image.jpg"), vec![7; 131072])?;
        let collection = Collection::open(&root)?;
        let (page, _) = collection.browse(None)?;
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].kind, Kind::Folder);
        let path = vec!["Photos".to_owned(), "Été 2026".to_owned()];
        let child = collection.nested(&path)?;
        let (files, _) = child.browse(None)?;
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "image.jpg");
        assert_eq!(files[0].bytes, 131072);
        let cache = tempfile::tempdir()?;
        assert!(
            child
                .download_snapshot(&files[0].name, &files[0].version, cache.path())
                .is_ok()
        );
        for bad in [
            "..",
            ".",
            "/outside",
            "C:outside",
            "Photos/Été 2026",
            "Photos\\outside",
            "",
        ] {
            assert!(collection.nested(&[bad.into()]).is_err(), "{bad}");
        }
        assert!(collection.nested(&vec!["Photos".into(); 17]).is_err());
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join("escape"))?;
        #[cfg(windows)]
        {
            // Junctions require no symlink privilege and must be refused too.
            let status = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(root.join("escape"))
                .arg(&outside)
                .stdout(std::process::Stdio::null())
                .status()?;
            assert!(status.success());
        }
        assert!(collection.nested(&["escape".into()]).is_err());
        assert!(
            collection
                .browse(None)?
                .0
                .iter()
                .all(|entry| entry.name != "escape")
        );
        for index in 0..35 {
            std::fs::write(root.join(format!("file{index:02}.txt")), b"sample")?;
        }
        let (first, next) = collection.browse(None)?;
        let (second, end) = collection.browse(next.as_deref())?;
        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 4);
        assert!(end.is_none());
        assert_eq!(std::fs::read(outside.join("private.txt"))?, b"outside");
        Ok(())
    }
    #[test]
    fn catalog_and_snapshot_include_large_files_but_reject_links_and_stale_versions() -> Result<()>
    {
        let root = tempfile::tempdir()?;
        let cache = tempfile::tempdir()?;
        let bytes = vec![17u8; 2 * 1024 * 1024 + 3];
        std::fs::write(root.path().join("large.bin"), &bytes)?;
        std::fs::create_dir(root.path().join("subfolder"))?;
        let collection = Collection::open(root.path())?;
        let (entries, next) = collection.catalog(None)?;
        assert_eq!(entries.len(), 1);
        assert!(next.is_none());
        let entry = &entries[0];
        assert_eq!(entry.bytes, bytes.len() as u64);
        let snapshot = collection.download_snapshot(&entry.name, &entry.version, cache.path())?;
        assert_eq!(snapshot.sha256, super::super::sha(&bytes));
        let (mut window, digest) = snapshot.window(65536, 131072)?;
        let mut data = vec![0; 131072];
        window.read_exact(&mut data)?;
        assert_eq!(data, bytes[65536..65536 + 131072]);
        assert_eq!(digest, super::super::sha(&data));
        assert!(snapshot.window(snapshot.size, 1).is_err());
        std::fs::hard_link(
            root.path().join("large.bin"),
            root.path().join("linked.bin"),
        )?;
        assert!(collection.catalog(None)?.0.is_empty());
        assert!(
            collection
                .download_snapshot("../large.bin", &entry.version, cache.path())
                .is_err()
        );
        std::fs::remove_file(root.path().join("linked.bin"))?;
        std::fs::write(root.path().join("large.bin"), b"changed")?;
        assert!(
            collection
                .check_download_version(&entry.name, &entry.version, entry.bytes)
                .is_err()
        );
        assert!(
            collection
                .download_snapshot(&entry.name, &entry.version, cache.path())
                .is_err()
        );
        // An already prepared snapshot is immutable even if its source changes.
        assert_eq!(snapshot.sha256, super::super::sha(&bytes));
        Ok(())
    }
}
