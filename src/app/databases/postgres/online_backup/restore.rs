//! Prepare a directory-format base backup so PostgreSQL replays its own WAL.

use std::{fs, path::Path};

// INTEGRATION: `subsystems/backups/restore.rs` already calls
// `OnlineBackupStrategy::prepare_restore` through `import_export/physical.rs`
// `StagedDataPreparation` (`restore_prepared_archive`) after the archive is
// extracted and before startup validation and rollback. That call must pass
// the extracted PGDATA (`extracted_root.join(restore_target)`, for example
// `<data-volume>/18/docker`) and only for recipe
// `postgres.basebackup.directory` version 1. Do not send a crash-consistent
// stopped tarball through this function. `backup_label` stays in place so
// PostgreSQL replays the WAL stored in the backup; `recovery.signal` is not
// required. Ownership is fixed later by `restore_instance_data_owner`.

const SUPPORTED_MAJORS: std::ops::RangeInclusive<u32> = 14..=18;

pub(crate) fn prepare_basebackup_restore(pgdata: &Path) -> Result<(), String> {
    require_regular(&pgdata.join("PG_VERSION"))?;
    let version = fs::read_to_string(pgdata.join("PG_VERSION"))
        .map_err(|error| format!("PG_VERSION: {error}"))?;
    let major: u32 = version
        .trim()
        .parse()
        .map_err(|_| format!("PG_VERSION {version:?} is not a supported major"))?;
    if !SUPPORTED_MAJORS.contains(&major) {
        return Err(format!(
            "PG_VERSION {major} is outside the certified 14-18 restore range"
        ));
    }
    require_regular(&pgdata.join("backup_label"))?;
    require_regular(&pgdata.join("backup_manifest"))?;
    require_directory(&pgdata.join("pg_wal"))?;
    require_empty_directory(&pgdata.join("pg_tblspc"))?;
    refuse_present(
        &pgdata.join("tablespace_map"),
        "tablespace_map is present; user tablespaces are not supported",
    )?;
    refuse_present(
        &pgdata.join("standby.signal"),
        "standby.signal would start the restored server as a standby",
    )?;
    refuse_present(
        &pgdata.join("recovery.signal"),
        "recovery.signal is not used; backup_label selects the included WAL",
    )?;
    remove_regular(&pgdata.join("postmaster.pid"))?;
    remove_regular(&pgdata.join("postmaster.opts"))?;
    require_regular(&pgdata.join("backup_label"))?;
    Ok(())
}

fn require_regular(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(())
}

fn require_directory(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }
    Ok(())
}

fn require_empty_directory(path: &Path) -> Result<(), String> {
    require_directory(path)?;
    let mut entries = fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if entries.next().is_some() {
        return Err(format!(
            "{} is not empty; user tablespaces are not supported",
            path.display()
        ));
    }
    Ok(())
}

fn refuse_present(path: &Path, reason: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(reason.to_string()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

fn remove_regular(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("{}: {error}", path.display())),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(format!("{} is a symlink", path.display()))
        }
        Ok(metadata) if metadata.is_file() => {
            fs::remove_file(path).map_err(|error| format!("remove {}: {error}", path.display()))
        }
        Ok(_) => Err(format!("{} is not a regular file", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn tree() -> PathBufGuard {
        let path = std::env::temp_dir().join(format!("dbev-pg-restore-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(path.join("pg_wal")).unwrap();
        fs::create_dir_all(path.join("pg_tblspc")).unwrap();
        fs::write(path.join("PG_VERSION"), "18\n").unwrap();
        fs::write(path.join("backup_label"), "LABEL: keep\n").unwrap();
        fs::write(path.join("backup_manifest"), "{}\n").unwrap();
        fs::write(path.join("postmaster.pid"), "1\n").unwrap();
        fs::write(path.join("postmaster.opts"), "postgres\n").unwrap();
        PathBufGuard(path)
    }

    struct PathBufGuard(std::path::PathBuf);

    impl Drop for PathBufGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn restores_a_directory_backup_and_keeps_the_label() {
        let root = tree();
        prepare_basebackup_restore(&root.0).unwrap();
        assert!(!root.0.join("postmaster.pid").exists());
        assert!(!root.0.join("postmaster.opts").exists());
        assert_eq!(
            fs::read_to_string(root.0.join("backup_label")).unwrap(),
            "LABEL: keep\n"
        );
        assert!(root.0.join("backup_manifest").is_file());
    }

    #[test]
    fn rejects_the_wrong_version_tablespaces_and_standby_signals() {
        let missing = tree();
        fs::remove_file(missing.0.join("backup_label")).unwrap();
        assert!(prepare_basebackup_restore(&missing.0).is_err());

        let old = tree();
        fs::write(old.0.join("PG_VERSION"), "13\n").unwrap();
        assert!(prepare_basebackup_restore(&old.0).is_err());

        let spaced = tree();
        fs::write(spaced.0.join("pg_tblspc").join("16384"), "link").unwrap();
        assert!(prepare_basebackup_restore(&spaced.0).is_err());

        let standby = tree();
        fs::write(standby.0.join("standby.signal"), "").unwrap();
        assert!(prepare_basebackup_restore(&standby.0).is_err());

        let linked = tree();
        symlink("somewhere", linked.0.join("pg_wal").join("unused")).ok();
        fs::remove_dir_all(linked.0.join("pg_wal")).unwrap();
        symlink("/tmp", linked.0.join("pg_wal")).unwrap();
        assert!(prepare_basebackup_restore(&linked.0).is_err());
    }
}
