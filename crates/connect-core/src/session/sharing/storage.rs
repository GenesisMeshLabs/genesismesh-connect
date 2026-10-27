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
/// The names an incoming `file_name` may be saved under, in order: itself,
/// then "name (2).ext" up to 99, trimmed to fit, never losing the extension.
fn candidates(file_name: &str) -> Vec<String> {
    let (stem, extension) = match file_name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem, Some(extension)),
        _ => (file_name, None),
    };
    (1..=99)
        .filter_map(|index| {
            if index == 1 {
                return Some(file_name.to_owned());
            }
            let suffix = match extension {
                Some(extension) => format!(" ({index}).{extension}"),
                None => format!(" ({index})"),
            };
            let mut stem = stem.to_owned();
            while stem.len() + suffix.len() > 128 && stem.pop().is_some() {}
            let candidate = format!("{}{suffix}", stem.trim_end());
            name(&candidate).is_ok().then_some(candidate)
        })
        .collect()
}
/// A name an inbox can save, even beside a file of the same name.
pub(super) fn receivable(file_name: &str) -> Result<()> {
    name(file_name)?;
    ensure!(candidates(file_name).len() > 1, "Use a shorter file name");
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
    storage_path: std::path::PathBuf,
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
        Ok(Self {
            directory,
            storage_path: segments
                .iter()
                .fold(self.storage_path.clone(), |path, part| path.join(part)),
        })
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
    /// Save a verified incoming file under `file_name`, or "name (2).ext" and
    /// so on when that exists: an existing file is never replaced. The bytes
    /// go to a hidden file first and get their name by a hard link, which
    /// fails rather than replace anything, so a partly written file is never
    /// seen under the real name. Where the filesystem has no hard links (FAT
    /// or exFAT drives), the name is reserved exclusively and written through.
    /// Returns the name used.
    pub fn commit(&self, file_name: &str, source: &mut std::fs::File) -> Result<String> {
        use std::io::{Seek, SeekFrom};
        name(file_name)?;
        let candidates = candidates(file_name);
        ensure!(candidates.len() > 1, "Use a shorter file name");
        let mut create = OpenOptions::new();
        create
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        let write = |target: &mut std::fs::File, source: &mut std::fs::File| -> Result<()> {
            source.seek(SeekFrom::Start(0))?;
            use std::io::Write;
            let size = source.metadata()?.len();
            crate::transfer_limits::ensure_space(&self.storage_path, size)?;
            let mut buffer = [0u8; 64 * 1024];
            let mut remaining = size;
            let mut checked = 0;
            loop {
                let count = source.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                ensure!(
                    count as u64 <= remaining,
                    "Incoming file changed while saving"
                );
                if checked == 0 || checked >= crate::transfer_limits::SPACE_CHECK_BYTES {
                    crate::transfer_limits::ensure_space(&self.storage_path, remaining)?;
                    checked = 0;
                }
                target.write_all(&buffer[..count])?;
                remaining -= count as u64;
                checked += count as u64;
            }
            ensure!(remaining == 0, "Incoming file ended early");
            target.sync_all()?;
            Ok(())
        };
        let hidden = format!(".connect-incoming-{}", uuid::Uuid::new_v4());
        let staged = (|| {
            let mut target = self.directory.open_with(&hidden, &create)?.into_std();
            write(&mut target, source)
        })();
        if let Err(error) = staged {
            let _ = self.directory.remove_file(&hidden);
            return Err(error);
        }
        let mut linked = true;
        for candidate in &candidates {
            match self
                .directory
                .hard_link(&hidden, &self.directory, candidate)
            {
                Ok(()) => {
                    // The file is saved; a hidden name left behind does not
                    // undo that.
                    let _ = self.directory.remove_file(&hidden);
                    return Ok(candidate.clone());
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => {
                    linked = false;
                    break;
                }
            }
        }
        let _ = self.directory.remove_file(&hidden);
        ensure!(!linked, "This folder already has 99 files with that name");
        for candidate in candidates {
            let mut target = match self.directory.open_with(&candidate, &create) {
                Ok(target) => target.into_std(),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            };
            if let Err(error) = write(&mut target, source) {
                drop(target);
                let _ = self.directory.remove_file(&candidate);
                return Err(error);
            }
            return Ok(candidate);
        }
        anyhow::bail!("This folder already has 99 files with that name")
    }
    /// The name `commit` saved these exact bytes under, if one of the names
    /// it chooses from holds them and was written `since` then: whether a
    /// save under way when the device stopped was completed. An older copy
    /// of the same bytes is not taken for it.
    pub fn committed(
        &self,
        file_name: &str,
        size: u64,
        sha256: &str,
        since: std::time::SystemTime,
    ) -> Option<String> {
        // Room for filesystems that keep coarse times, such as FAT's two
        // seconds.
        let since = since - std::time::Duration::from_secs(2);
        candidates(file_name).into_iter().find(|candidate| {
            (|| {
                let mut options = OpenOptions::new();
                options.read(true).follow(FollowSymlinks::No);
                let file = self.directory.open_with(candidate, &options)?;
                let metadata = file.metadata()?;
                ensure!(
                    metadata.is_file()
                        && metadata.len() == size
                        && metadata.modified()?.into_std() >= since,
                    "Another file"
                );
                let mut file = file.into_std();
                let mut hash = Sha256::new();
                let mut buffer = Zeroizing::new(vec![0u8; 65536]);
                loop {
                    let count = file.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    hash.update(&buffer[..count]);
                }
                Ok::<_, anyhow::Error>(hex(&hash.finalize()) == sha256)
            })()
            .unwrap_or(false)
        })
    }
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "Collection root must be absolute");
        Ok(Self {
            directory: Dir::open_ambient_dir(path, cap_std::ambient_authority())?,
            storage_path: path.to_owned(),
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

    #[test]
    fn incoming_files_never_replace_existing_ones() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("photo.jpg"), b"original")?;
        let directory = Collection::open(root.path())?;
        let mut source = tempfile::tempfile()?;
        std::io::Write::write_all(&mut source, b"incoming")?;
        assert_eq!(directory.commit("photo.jpg", &mut source)?, "photo (2).jpg");
        assert_eq!(directory.commit("photo.jpg", &mut source)?, "photo (3).jpg");
        assert_eq!(directory.commit("notes", &mut source)?, "notes");
        assert_eq!(directory.commit("notes", &mut source)?, "notes (2)");
        assert_eq!(std::fs::read(root.path().join("photo.jpg"))?, b"original");
        assert_eq!(
            std::fs::read(root.path().join("photo (3).jpg"))?,
            b"incoming"
        );
        for unsafe_name in ["../escape.txt", "a/b", "CON", ""] {
            assert!(
                directory.commit(unsafe_name, &mut source).is_err(),
                "{unsafe_name}"
            );
        }
        // A long name gives up characters for the number, never the extension.
        let long = format!("{}.txt", "n".repeat(124));
        assert_eq!(directory.commit(&long, &mut source)?, long);
        let second = directory.commit(&long, &mut source)?;
        assert!(
            second.len() <= 128 && second.ends_with(" (2).txt"),
            "{second}"
        );
        // No hidden staging file stays behind.
        let hidden = std::fs::read_dir(root.path())?
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".connect-incoming")
            });
        assert!(!hidden);
        assert!(
            directory
                .commit(&format!("a.{}", "x".repeat(125)), &mut source)
                .is_err()
        );
        // A link at a candidate name is never followed or replaced.
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir()?;
            std::fs::write(outside.path().join("target.txt"), b"outside")?;
            std::os::unix::fs::symlink(
                outside.path().join("target.txt"),
                root.path().join("linked.txt"),
            )?;
            assert_eq!(
                directory.commit("linked.txt", &mut source)?,
                "linked (2).txt"
            );
            assert_eq!(
                std::fs::read(outside.path().join("target.txt"))?,
                b"outside"
            );
        }
        Ok(())
    }
}
