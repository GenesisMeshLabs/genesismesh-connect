use super::Saved;
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(super) const MAX: u64 = 4096;

pub(super) fn check(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "Use native-selected absolute setup storage"
    );
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                ensure!(
                    !meta.file_type().is_symlink(),
                    "Setup storage cannot contain links"
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    ensure!(
                        meta.file_attributes() & 0x400 == 0,
                        "Setup storage cannot contain reparse points"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && ancestor == path => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(super) struct Journal {
    pub(super) saved: Saved,
    path: PathBuf,
    bytes: Vec<u8>,
    _lock: File,
}
fn read(path: &Path) -> Result<Vec<u8>> {
    check(path)?;
    let file = File::open(path)?;
    let meta = file.metadata()?;
    ensure!(meta.is_file() && meta.len() <= MAX, "Invalid setup journal");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(meta.nlink() == 1, "Setup journal has extra links");
    }
    let mut bytes = vec![];
    file.take(MAX + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX,
        "Invalid setup journal size"
    );
    Ok(bytes)
}
impl Journal {
    pub(super) fn acquire(parent: &Path, fresh: Option<Saved>) -> Result<Self> {
        check(parent)?;
        ensure!(parent.is_dir(), "Native setup directory must already exist");
        let path = parent.join("foreground-setup.json");
        let lock_path = parent.join("foreground-setup.lock");
        check(&path)?;
        check(&lock_path)?;
        if fresh.is_some() {
            ensure!(
                !path.exists() && !lock_path.exists(),
                "Existing setup must be opened or reviewed"
            );
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if fresh.is_some() {
            options.create_new(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options
            .open(lock_path)
            .context("Existing setup lock is unavailable")?;
        ensure!(lock.metadata()?.is_file(), "Invalid setup lock");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(lock.metadata()?.nlink() == 1, "Setup lock has extra links");
        }
        fs2::FileExt::try_lock_exclusive(&lock).context("Another foreground setup is active")?;
        match fresh {
            Some(saved) => {
                let mut journal = Self {
                    saved,
                    path,
                    bytes: vec![],
                    _lock: lock,
                };
                journal.commit()?;
                Ok(journal)
            }
            None => {
                let bytes = read(&path)?;
                let value = genesis_mesh_sdk::parse_strict_json(std::str::from_utf8(&bytes)?)?;
                let saved: Saved = serde_json::from_value(value)?;
                saved.validate()?;
                Ok(Self {
                    saved,
                    path,
                    bytes,
                    _lock: lock,
                })
            }
        }
    }
    pub(super) fn commit(&mut self) -> Result<()> {
        self.saved.validate()?;
        check(&self.path)?;
        let parent = self.path.parent().context("Missing setup parent")?;
        let bytes = serde_json::to_vec(&self.saved)?;
        ensure!(bytes.len() as u64 <= MAX, "Setup record is too large");
        if self.bytes.is_empty() {
            // Exclusive initial creation, no hard-link fallback. A partial first
            // write stays invalid for explicit review; no external work ran yet.
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut initial = options.open(&self.path)?;
            initial.write_all(&bytes)?;
            initial.sync_all()?;
        } else {
            self.check_current()?;
            let mut pending = tempfile::NamedTempFile::new_in(parent)?;
            pending.write_all(&bytes)?;
            pending.as_file().sync_all()?;
            pending.persist(&self.path)?;
        }
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        self.bytes = bytes;
        Ok(())
    }
    pub(super) fn check_current(&self) -> Result<()> {
        ensure!(read(&self.path)? == self.bytes, "Setup journal changed");
        Ok(())
    }
}
