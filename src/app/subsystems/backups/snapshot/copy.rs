//! Copies a read-only volume snapshot into backup staging.
//!
//! The copy never follows links. It omits only links an engine recreates by
//! itself and refuses everything else that the backup archive could not hold
//! (other links, sockets, devices), so a capture either restores or fails.

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use crate::server::jobs::import_export::{DataArchiveSourcePolicy, omits_engine_link};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct CopyStats {
    pub files: u64,
    pub directories: u64,
    pub bytes: u64,
    pub omitted_links: u64,
}

/// Copies `source` (the snapshot root) to the new directory `destination`.
/// Fails once more than `max_bytes` or `max_entries` would be copied.
pub(super) fn copy_snapshot(
    source: &Path,
    destination: &Path,
    policy: DataArchiveSourcePolicy,
    max_bytes: u64,
    max_entries: usize,
) -> Result<CopyStats, String> {
    fs::create_dir(destination).map_err(|error| format!("{}: {error}", destination.display()))?;
    copy_mode(source, destination)?;
    let mut stats = CopyStats::default();
    for (index, entry) in walkdir::WalkDir::new(source)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .enumerate()
    {
        if index >= max_entries {
            return Err(format!("the volume has more than {max_entries} entries"));
        }
        let entry = entry.map_err(|error| format!("read the snapshot: {error}"))?;
        let relative = entry
            .path()
            .strip_prefix(source)
            .map_err(|_| "snapshot entry escaped its root".to_string())?;
        let target = destination.join(relative);
        let file_type = entry.file_type();
        if file_type.is_dir() {
            fs::create_dir(&target).map_err(|error| format!("{}: {error}", target.display()))?;
            copy_mode(entry.path(), &target)?;
            stats.directories += 1;
        } else if file_type.is_file() {
            let size = entry
                .metadata()
                .map_err(|error| format!("{}: {error}", entry.path().display()))?
                .len();
            stats.bytes = stats.bytes.saturating_add(size);
            if stats.bytes > max_bytes {
                return Err(format!(
                    "the volume holds more than the {max_bytes}-byte capture budget"
                ));
            }
            fs::copy(entry.path(), &target)
                .map_err(|error| format!("copy {}: {error}", relative.display()))?;
            stats.files += 1;
        } else if file_type.is_symlink() {
            let link = fs::read_link(entry.path())
                .map_err(|error| format!("{}: {error}", entry.path().display()))?;
            if !omits_engine_link(policy, relative, &link) {
                return Err(format!(
                    "the volume contains a link {} -> {}, which the backup cannot hold",
                    relative.display(),
                    link.display()
                ));
            }
            stats.omitted_links += 1;
        } else {
            return Err(format!(
                "the volume contains a special file {}, which the backup cannot hold",
                relative.display()
            ));
        }
    }
    Ok(stats)
}

fn copy_mode(source: &Path, target: &Path) -> Result<(), String> {
    let mode = fs::symlink_metadata(source)
        .map_err(|error| format!("{}: {error}", source.display()))?
        .permissions()
        .mode();
    fs::set_permissions(target, fs::Permissions::from_mode(mode & 0o7777))
        .map_err(|error| format!("{}: {error}", target.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn snapshot() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("db/sub")).unwrap();
        fs::write(root.path().join("db/sub/table.ibd"), vec![7_u8; 100]).unwrap();
        fs::write(root.path().join("ibdata1"), b"x").unwrap();
        fs::set_permissions(root.path().join("db"), fs::Permissions::from_mode(0o750)).unwrap();
        root
    }

    #[test]
    fn copies_files_directories_and_modes() {
        let source = snapshot();
        let out = tempfile::tempdir().unwrap();
        let destination = out.path().join("snapshot");
        let stats = copy_snapshot(
            source.path(),
            &destination,
            DataArchiveSourcePolicy::Strict,
            1 << 20,
            100,
        )
        .unwrap();
        assert_eq!((stats.files, stats.directories, stats.bytes), (2, 2, 101));
        assert_eq!(
            fs::read(destination.join("db/sub/table.ibd")).unwrap(),
            vec![7_u8; 100]
        );
        assert_eq!(
            fs::metadata(destination.join("db"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
    }

    #[test]
    fn budgets_and_entry_caps_stop_the_copy() {
        let source = snapshot();
        let out = tempfile::tempdir().unwrap();
        assert!(
            copy_snapshot(
                source.path(),
                &out.path().join("a"),
                DataArchiveSourcePolicy::Strict,
                50,
                100
            )
            .is_err()
        );
        assert!(
            copy_snapshot(
                source.path(),
                &out.path().join("b"),
                DataArchiveSourcePolicy::Strict,
                1 << 20,
                2
            )
            .is_err()
        );
    }

    #[test]
    fn only_engine_recreated_links_are_omitted() {
        let source = snapshot();
        symlink(
            "/var/run/mysqld/mysqld.sock",
            source.path().join("mysql.sock"),
        )
        .unwrap();
        let out = tempfile::tempdir().unwrap();
        assert!(
            copy_snapshot(
                source.path(),
                &out.path().join("strict"),
                DataArchiveSourcePolicy::Strict,
                1 << 20,
                100
            )
            .is_err()
        );
        let stats = copy_snapshot(
            source.path(),
            &out.path().join("mysql"),
            DataArchiveSourcePolicy::MysqlDataDirectory,
            1 << 20,
            100,
        )
        .unwrap();
        assert_eq!(stats.omitted_links, 1);
        assert!(!out.path().join("mysql/mysql.sock").exists());

        symlink("/etc", source.path().join("db/escape")).unwrap();
        assert!(
            copy_snapshot(
                source.path(),
                &out.path().join("escape"),
                DataArchiveSourcePolicy::MysqlDataDirectory,
                1 << 20,
                100
            )
            .is_err()
        );
    }

    #[test]
    fn special_files_are_refused() {
        let source = snapshot();
        let _listener =
            std::os::unix::net::UnixListener::bind(source.path().join("db/live.sock")).unwrap();
        let out = tempfile::tempdir().unwrap();
        let error = copy_snapshot(
            source.path(),
            &out.path().join("x"),
            DataArchiveSourcePolicy::Strict,
            1 << 20,
            100,
        )
        .unwrap_err();
        assert!(error.contains("special file"), "{error}");
    }
}
