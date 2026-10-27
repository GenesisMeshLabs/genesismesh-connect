use anyhow::{Context, Result, ensure};
use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};
use zeroize::Zeroizing;
#[path = "storage_download.rs"]
mod downloads;
pub(super) use downloads::Snapshot;

pub(super) const MAX_FILE: usize = 64 * 1024;
pub(super) fn directory(segments: &[String]) -> Result<()> {
    ensure!(
        segments.len() <= 16 && segments.iter().map(String::len).sum::<usize>() <= 2048,
        "Folder path is too deep"
    );
    for segment in segments {
        name(segment)?;
    }
    Ok(())
}
pub(super) fn name(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value != "."
            && value != ".."
            && !value.ends_with('.')
            && !value.ends_with(' ')
            && value
                .chars()
                .all(|c| !c.is_control() && !"/\\:*?\"<>|".contains(c)),
        "Use one flat file name"
    );
    let stem = value.split('.').next().unwrap().to_ascii_uppercase();
    ensure!(
        !["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            && !(stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.as_bytes()[3].is_ascii_digit()),
        "Reserved file name"
    );
    Ok(())
}
pub(super) fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) struct Collection {
    directory: Dir,
}
impl Collection {
    pub fn nested(&self, segments: &[String]) -> Result<Self> {
        use cap_fs_ext::DirExt;
        directory(segments)?;
        let mut directory = self.directory.try_clone()?;
        // One component per no-follow operation: intermediate links/junctions
        // must never redirect a browse or download outside the selected root.
        for segment in segments {
            directory = directory.open_dir_nofollow(segment)?;
        }
        Ok(Self { directory })
    }
    pub fn list(
        &self,
        after: Option<&str>,
    ) -> Result<(Vec<super::listing::FileEntry>, Option<String>)> {
        if let Some(after) = after {
            name(after)?;
        }
        let mut names = Vec::new();
        // Bound filesystem work as well as the response. Refuse large roots
        // instead of silently returning an incomplete directory as complete.
        for (index, entry) in self.directory.entries()?.enumerate() {
            ensure!(
                index < 512,
                "Choose a folder with at most 512 entries for this preview"
            );
            let entry = entry?;
            let Some(file) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name(&file).is_ok() && after.is_none_or(|after| file.as_str() > after) {
                names.push(file);
            }
        }
        names.sort();
        let mut files = Vec::new();
        let mut next = None;
        for file_name in names {
            // The same capability-relative, no-follow snapshot check used by
            // reads excludes links, directories, oversized and changing files.
            if let Ok(bytes) = self.snapshot(&file_name) {
                if files.len() == 32 {
                    next = files
                        .last()
                        .map(|f: &super::listing::FileEntry| f.name.clone());
                    break;
                }
                files.push(super::listing::FileEntry {
                    name: file_name,
                    bytes: bytes.len(),
                    sha256: sha(&bytes),
                });
            }
        }
        Ok((files, next))
    }
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "Collection root must be absolute");
        Ok(Self {
            directory: Dir::open_ambient_dir(path, cap_std::ambient_authority())?,
        })
    }
    pub fn snapshot(&self, file_name: &str) -> Result<Zeroizing<Vec<u8>>> {
        name(file_name)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_fs_ext::OpenOptionsSyncExt;
            options.nonblock(true);
        }
        let file = self.directory.open_with(file_name, &options)?;
        let before = file.metadata()?;
        ensure!(
            before.is_file() && before.nlink() == 1 && before.len() as usize <= MAX_FILE,
            "Use a regular file up to 64 KiB with one link"
        );
        let mut bytes = Zeroizing::new(Vec::new());
        let file = file.into_std();
        file.try_lock_shared().context("File is in use")?;
        let mut limited = file.take((MAX_FILE + 1) as u64);
        limited.read_to_end(&mut bytes)?;
        let after = limited.get_ref().metadata()?;
        ensure!(
            bytes.len() <= MAX_FILE
                && before.len() == after.len()
                && before
                    .modified()
                    .context("Missing modification time")?
                    .into_std()
                    == after.modified()?
                && bytes.len() as u64 == after.len(),
            "File changed while reading"
        );
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_paths_devices_links_and_large_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        std::fs::write(root.path().join("sample.txt"), b"sample")?;
        std::fs::write(outside.path().join("outside.txt"), b"outside")?;
        let directory = Collection::open(root.path())?;
        assert_eq!(&*directory.snapshot("sample.txt")?, b"sample");
        for value in [
            "../outside.txt",
            "a/b",
            "a\\b",
            "C:sample",
            "sample:stream",
            "CON.txt",
            "NUL",
            "x.",
            "..",
            "",
        ] {
            assert!(directory.snapshot(value).is_err(), "{value}");
        }
        std::fs::hard_link(
            outside.path().join("outside.txt"),
            root.path().join("hard.txt"),
        )?;
        assert!(directory.snapshot("hard.txt").is_err());
        std::fs::write(root.path().join("large.txt"), vec![0; MAX_FILE + 1])?;
        assert!(directory.snapshot("large.txt").is_err());
        std::fs::create_dir(root.path().join("dir"))?;
        assert!(directory.snapshot("dir").is_err());
        Ok(())
    }
}
