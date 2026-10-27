//! File sizes cross signed JSON and the JavaScript UI. Keep every byte count
//! exact there; actual transfer capacity is bounded by storage, not this ceiling.
use anyhow::{Context, Result, ensure};
use std::path::Path;

pub const MAX_FILE_BYTES: u64 = (1u64 << 53) - 1;
pub const SPACE_CHECK_BYTES: u64 = 8 * 1024 * 1024;

fn fits(available: u64, total: u64, additional: u64) -> bool {
    // Keep room for the OS and other apps: 5%, bounded between 64 MiB and 1 GiB.
    let reserve = (total / 20).clamp(64 * 1024 * 1024, 1024 * 1024 * 1024);
    additional <= available.saturating_sub(reserve)
}

/// Check the filesystem used for staging, not the source filesystem. Call at
/// admission and again during writes; other apps may consume space meanwhile.
pub fn ensure_space(path: &Path, additional: u64) -> Result<()> {
    let disk = fs2::statvfs(path).context("Could not check available storage")?;
    ensure!(
        fits(disk.available_space(), disk.total_space(), additional),
        "Not enough free storage to finish this transfer while leaving room for the device. Free some space and try again."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn large_files_do_not_overflow_and_leave_system_headroom() {
        let gib = 1024 * 1024 * 1024;
        assert!(fits(20 * gib, 100 * gib, 12 * gib));
        assert!(!fits(12 * gib, 100 * gib, 12 * gib));
        assert!(!fits(0, 100 * gib, 1));
        assert!(!fits(gib, 100 * gib, u64::MAX));
        assert!(!fits(32 * gib, 100 * gib, MAX_FILE_BYTES));
        assert_eq!(MAX_FILE_BYTES as f64 as u64, MAX_FILE_BYTES);
    }
}
