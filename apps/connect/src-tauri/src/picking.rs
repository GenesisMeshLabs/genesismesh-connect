//! Native selection owns the path; web content supplies neither a path nor a URI.
use anyhow::{Context, Result, ensure};
use std::path::PathBuf;
#[cfg(mobile)]
use tauri::Manager;
static PICKING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) struct Picked {
    pub path: PathBuf,
    pub name: String,
    temporary: bool,
}
impl Drop for Picked {
    fn drop(&mut self) {
        if self.temporary {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
pub(crate) async fn file(app: &tauri::AppHandle, media: bool) -> Result<Option<Picked>> {
    let _picker = PICKING
        .try_lock()
        .context("Finish choosing the current file first")?;
    #[cfg(desktop)]
    {
        let _ = app;
        let mut dialog = rfd::AsyncFileDialog::new().set_title(if media {
            "Choose a photo or video"
        } else {
            "Choose a file"
        });
        if media {
            dialog = dialog.add_filter(
                "Photos and videos",
                &[
                    "jpg", "jpeg", "png", "heic", "heif", "webp", "gif", "mp4", "mov", "m4v", "mkv",
                ],
            );
        }
        let Some(picked) = dialog.pick_file().await else {
            return Ok(None);
        };
        let path = picked.path().to_owned();
        let name = path
            .file_name()
            .context("File has no name")?
            .to_string_lossy()
            .into_owned();
        Ok(Some(Picked {
            path,
            name,
            temporary: false,
        }))
    }
    #[cfg(mobile)]
    {
        use tauri_plugin_view::ViewExt;
        let handle = app.clone();
        let picked = tokio::task::spawn_blocking(move || {
            handle.view().pick(tauri_plugin_view::PickRequest { media })
        })
        .await??;
        let Some(path) = picked.path else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        let cache = app.path().app_cache_dir()?.join("connect-picked");
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && path.canonicalize()?.parent() == Some(cache.canonicalize()?.as_path()),
            "Invalid selected-file storage"
        );
        let file = Picked {
            path,
            name: picked.name.context("File has no name")?,
            temporary: true,
        };
        ensure!(
            metadata.len() <= connect_core::transfer_limits::MAX_FILE_BYTES,
            "File is too large"
        );
        Ok(Some(file))
    }
}
/// A private snapshot for a single-file share. No partially written copy is
/// published, no whole-file allocation is made, and the original is untouched.
pub(crate) fn copy(picked: &Picked, directory: &std::path::Path) -> Result<()> {
    let mut input = std::fs::File::open(&picked.path)?;
    copy_file(&mut input, &picked.name, directory)
}
pub(crate) fn copy_file(
    input: &mut std::fs::File,
    name: &str,
    directory: &std::path::Path,
) -> Result<()> {
    use std::io::{Read, Write};
    connect_core::validate_shared_file_name(name)?;
    let before = input.metadata()?;
    ensure!(
        before.is_file() && before.len() <= connect_core::transfer_limits::MAX_FILE_BYTES,
        "Choose a regular file"
    );
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(directory.join(name))?;
    let mut remaining = before.len();
    let mut buffer = [0; 64 * 1024];
    let mut checked = 0;
    connect_core::transfer_limits::ensure_space(directory, remaining)?;
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        ensure!(n as u64 <= remaining, "The file changed while preparing it");
        if checked >= connect_core::transfer_limits::SPACE_CHECK_BYTES {
            connect_core::transfer_limits::ensure_space(directory, remaining)?;
            checked = 0;
        }
        output.write_all(&buffer[..n])?;
        remaining -= n as u64;
        checked += n as u64;
    }
    let after = input.metadata()?;
    ensure!(
        remaining == 0 && before.len() == after.len() && before.modified()? == after.modified()?,
        "The file changed while preparing it"
    );
    output.sync_all()?;
    Ok(())
}

/// Only the app-created single-file snapshot is disposable. A user-selected
/// folder, including an inbox, is never removed when its access is stopped.
pub(crate) fn remove_shared_copy(
    profile: &std::path::Path,
    directory: &std::path::Path,
) -> Result<()> {
    let root = profile.join("shared-files");
    if directory.parent() != Some(root.as_path()) || !root.is_dir() {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "Invalid shared copy"
    );
    let root_metadata = std::fs::symlink_metadata(&root)?;
    let canonical_root = root.canonicalize()?;
    let canonical_profile = profile.canonicalize()?;
    ensure!(
        root_metadata.is_dir()
            && !root_metadata.file_type().is_symlink()
            && canonical_root.parent() == Some(canonical_profile.as_path()),
        "Invalid shared copy root"
    );
    let canonical = directory.canonicalize()?;
    ensure!(
        canonical.parent() == Some(canonical_root.as_path()),
        "Invalid shared copy location"
    );
    std::fs::remove_dir_all(canonical)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn shared_copy_root_cannot_redirect_cleanup() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let profile = temp.path().join("profile");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&profile)?;
        std::fs::create_dir_all(outside.join("file-1"))?;
        std::fs::write(outside.join("file-1/keep.txt"), b"keep")?;
        std::os::unix::fs::symlink(&outside, profile.join("shared-files"))?;
        assert!(remove_shared_copy(&profile, &profile.join("shared-files/file-1")).is_err());
        assert_eq!(std::fs::read(outside.join("file-1/keep.txt"))?, b"keep");
        Ok(())
    }
    #[test]
    fn removing_a_share_only_removes_its_private_copy() -> Result<()> {
        let root = tempfile::tempdir()?;
        let profile = root.path().join("device");
        let copy = profile.join("shared-files/file-1");
        let source = root.path().join("originals");
        std::fs::create_dir_all(&copy)?;
        std::fs::create_dir(&source)?;
        std::fs::write(copy.join("photo.jpg"), b"copy")?;
        std::fs::write(source.join("photo.jpg"), b"source")?;
        remove_shared_copy(&profile, &source)?;
        assert_eq!(std::fs::read(source.join("photo.jpg"))?, b"source");
        remove_shared_copy(&profile, &copy)?;
        assert!(!copy.exists());
        Ok(())
    }
}
