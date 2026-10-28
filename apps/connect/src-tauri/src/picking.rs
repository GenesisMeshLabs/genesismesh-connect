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
pub(crate) const MAX_SELECTION: usize = 100;
pub(crate) async fn file(app: &tauri::AppHandle, media: bool) -> Result<Option<Picked>> {
    Ok(files(app, media, false).await?.pop())
}
pub(crate) async fn files(
    app: &tauri::AppHandle,
    media: bool,
    multiple: bool,
) -> Result<Vec<Picked>> {
    let _picker = PICKING
        .try_lock()
        .context("Finish choosing the current files first")?;
    #[cfg(desktop)]
    {
        let _ = app;
        let mut dialog = rfd::AsyncFileDialog::new().set_title(if media {
            "Choose photos or videos"
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
        let selected = if multiple {
            dialog.pick_files().await.unwrap_or_default()
        } else {
            dialog.pick_file().await.into_iter().collect()
        };
        ensure!(
            selected.len() <= MAX_SELECTION,
            "Choose up to 100 files at a time"
        );
        selected
            .into_iter()
            .map(|file| {
                let path = file.path().to_owned();
                let name = path
                    .file_name()
                    .context("File has no name")?
                    .to_string_lossy()
                    .into_owned();
                Ok(Picked {
                    path,
                    name,
                    temporary: false,
                })
            })
            .collect()
    }
    #[cfg(mobile)]
    {
        use tauri_plugin_view::ViewExt;
        let handle = app.clone();
        let selected = tokio::task::spawn_blocking(move || {
            handle
                .view()
                .pick(tauri_plugin_view::PickRequest { media, multiple })
        })
        .await??;
        let cache = app.path().app_cache_dir()?.join("connect-picked");
        let mut files = Vec::new();
        for selected in selected.files {
            files.push(selected_file(
                &cache,
                PathBuf::from(selected.path),
                selected.name,
            )?);
        }
        ensure!(
            files.len() <= MAX_SELECTION && (multiple || files.len() <= 1),
            "Choose up to 100 files at a time"
        );
        Ok(files)
    }
}
#[cfg(any(mobile, test))]
fn selected_file(cache: &std::path::Path, path: PathBuf, name: String) -> Result<Picked> {
    let metadata = std::fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && path.canonicalize()?.parent() == Some(cache.canonicalize()?.as_path()),
        "Invalid selected-file storage"
    );
    let picked = Picked {
        path,
        name,
        temporary: true,
    };
    ensure!(
        metadata.len() <= connect_core::transfer_limits::MAX_FILE_BYTES,
        "File is too large"
    );
    Ok(picked)
}
/// Publish a batch only after every private copy is complete. Duplicate provider
/// names are disambiguated, including case aliases on Windows filesystems.
pub(crate) fn copy_batch(files: &[Picked], directory: &std::path::Path) -> Result<()> {
    ensure!(
        !files.is_empty() && files.len() <= MAX_SELECTION,
        "Choose up to 100 files at a time"
    );
    let mut total = 0u64;
    for file in files {
        connect_core::validate_shared_file_name(&file.name)?;
        total = total
            .checked_add(std::fs::metadata(&file.path)?.len())
            .context("Selection is too large")?;
    }
    connect_core::transfer_limits::ensure_space(directory, total)?;
    let mut names = std::collections::BTreeSet::new();
    for picked in files {
        let name = unique_name(&picked.name, &mut names)?;
        let mut input = std::fs::File::open(&picked.path)?;
        copy_file(&mut input, &name, directory)?;
    }
    Ok(())
}
fn unique_name(name: &str, names: &mut std::collections::BTreeSet<String>) -> Result<String> {
    connect_core::validate_shared_file_name(name)?;
    let path = std::path::Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .context("Invalid file name")?;
    let extension = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{s}"))
        .unwrap_or_default();
    for suffix in 1..=MAX_SELECTION {
        let candidate = if suffix == 1 {
            name.to_owned()
        } else {
            format!("{stem} ({suffix}){extension}")
        };
        connect_core::validate_shared_file_name(&candidate)?;
        if names.insert(candidate.to_lowercase()) {
            return Ok(candidate);
        }
    }
    anyhow::bail!("Too many files with the same name")
}
/// A private snapshot for a single-file share. No partially written copy is
/// published, no whole-file allocation is made, and the original is untouched.
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
    #[test]
    fn mobile_picker_uses_the_exact_app_cache_and_cleans_only_its_copy() -> Result<()> {
        let root = tempfile::tempdir()?;
        let expected = root.path().join("org.genesismesh.connect/connect-picked");
        let wrong = root.path().join("connect-picked");
        std::fs::create_dir_all(&expected)?;
        std::fs::create_dir(&wrong)?;
        std::fs::write(expected.join("selected.bin"), b"copy")?;
        std::fs::write(wrong.join("original.bin"), b"keep")?;
        assert!(selected_file(&expected, wrong.join("original.bin"), "photo.jpg".into()).is_err());
        let selected = selected_file(&expected, expected.join("selected.bin"), "photo.jpg".into())?;
        drop(selected);
        assert!(!expected.join("selected.bin").exists());
        assert_eq!(std::fs::read(wrong.join("original.bin"))?, b"keep");
        Ok(())
    }
    #[test]
    fn batch_preserves_bytes_and_disambiguates_photo_names() -> Result<()> {
        let root = tempfile::tempdir()?;
        let a = root.path().join("a");
        let b = root.path().join("b");
        std::fs::write(&a, b"first photo")?;
        std::fs::write(&b, b"second photo")?;
        let destination = root.path().join("shared");
        std::fs::create_dir(&destination)?;
        let selected = vec![
            Picked {
                path: a.clone(),
                name: "Photo.JPG".into(),
                temporary: false,
            },
            Picked {
                path: b.clone(),
                name: "photo.jpg".into(),
                temporary: false,
            },
        ];
        copy_batch(&selected, &destination)?;
        assert_eq!(
            std::fs::read(destination.join("Photo.JPG"))?,
            b"first photo"
        );
        assert_eq!(
            std::fs::read(destination.join("photo (2).jpg"))?,
            b"second photo"
        );
        assert_eq!(std::fs::read(a)?, b"first photo");
        assert_eq!(std::fs::read(b)?, b"second photo");
        Ok(())
    }
    #[test]
    fn invalid_batch_is_refused_before_creating_shared_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = root.path().join("original");
        std::fs::write(&source, b"keep")?;
        let destination = root.path().join("shared");
        std::fs::create_dir(&destination)?;
        let selected = vec![
            Picked {
                path: source.clone(),
                name: "safe.jpg".into(),
                temporary: false,
            },
            Picked {
                path: source.clone(),
                name: "../escape.jpg".into(),
                temporary: false,
            },
        ];
        assert!(copy_batch(&selected, &destination).is_err());
        assert_eq!(std::fs::read_dir(destination)?.count(), 0);
        assert_eq!(std::fs::read(source)?, b"keep");
        Ok(())
    }
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
