//! Match local resources by their native directory, never their display name.
use connect_core::session::sharing::{ShareConfig, SpaceKind};
use std::path::Path;

pub(crate) fn same_directory(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

pub(crate) fn existing<'a>(
    shares: &'a [ShareConfig],
    directory: &Path,
    kind: SpaceKind,
) -> Option<&'a ShareConfig> {
    shares
        .iter()
        .find(|s| s.kind == kind && same_directory(&s.directory, directory))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_alias_reuses_the_share_but_names_and_kinds_do_not() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let a = root.path().join("a/Photos");
        let b = root.path().join("b/Photos");
        std::fs::create_dir_all(&a)?;
        std::fs::create_dir_all(&b)?;
        let shares = vec![ShareConfig {
            collection_id: "saved-id".into(),
            directory: a.clone(),
            ..Default::default()
        }];
        assert_eq!(
            existing(&shares, &a.join("."), SpaceKind::Folder)
                .unwrap()
                .collection_id,
            "saved-id"
        );
        assert!(existing(&shares, &b, SpaceKind::Folder).is_none());
        assert!(existing(&shares, &a, SpaceKind::Inbox).is_none());
        assert!(!same_directory(&a, &root.path().join("missing")));
        Ok(())
    }
}
