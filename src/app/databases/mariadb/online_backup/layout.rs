//! Staged and restored layout of a prepared `mariadb-backup` tree.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::io::files::{require_directory, require_regular_file};

/// Capture directory below the staging root.
pub(super) const DATA_ROOT: &str = "mariadb";
/// Where the prepared tree sits in the archive. MariaDB encodes `-` in
/// schema directory names, so no data directory entry can collide with it.
pub(super) const RESTORE_TARGET: &str = "dbev-online-backup";
/// Current and pre-11 names of the checkpoints file.
const CHECKPOINT_FILES: [&str; 2] = ["mariadb_backup_checkpoints", "xtrabackup_checkpoints"];
const MAX_WALK_DEPTH: usize = 8;
const MAX_WALK_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Checkpoints {
    pub file_name: &'static str,
    pub from_lsn: u64,
    pub to_lsn: u64,
    pub last_lsn: u64,
}

fn parse_checkpoints(file_name: &'static str, text: &str) -> Result<Checkpoints, String> {
    let value = |key: &str| {
        text.lines()
            .filter_map(|line| line.split_once('='))
            .find(|(name, _)| name.trim() == key)
            .map(|(_, value)| value.trim())
            .ok_or_else(|| format!("{file_name} has no {key}"))
    };
    let lsn = |key: &str| -> Result<u64, String> {
        value(key)?
            .parse()
            .map_err(|_| format!("{file_name} {key} is not a number"))
    };
    if value("backup_type")? != "full-prepared" {
        return Err(format!(
            "{file_name} does not describe a prepared full backup"
        ));
    }
    let checkpoints = Checkpoints {
        file_name,
        from_lsn: lsn("from_lsn")?,
        to_lsn: lsn("to_lsn")?,
        last_lsn: lsn("last_lsn")?,
    };
    if checkpoints.from_lsn != 0 || checkpoints.to_lsn == 0 {
        return Err(format!("{file_name} does not describe a full backup"));
    }
    Ok(checkpoints)
}

/// The tree is a prepared full backup with no linked or external files.
pub(super) fn check_prepared(root: &Path) -> Result<Checkpoints, String> {
    require_directory(root)?;
    let (file_name, path) = CHECKPOINT_FILES
        .iter()
        .map(|name| (*name, root.join(name)))
        .find(|(_, path)| path.exists())
        .ok_or("the backup has no checkpoints file")?;
    require_regular_file(&path)?;
    let text = fs::read_to_string(&path).map_err(|error| format!("{file_name}: {error}"))?;
    let checkpoints = parse_checkpoints(file_name, &text)?;
    require_directory(&root.join("mysql"))?;
    refuse_links(root)?;
    Ok(checkpoints)
}

/// Tables created with `DATA DIRECTORY` leave `.isl` links to files outside
/// the data directory, which neither the helper nor restore can reach.
pub(super) fn refuse_external_tablespaces(data: &Path) -> Result<(), String> {
    refuse_links(data)
}

fn refuse_links(root: &Path) -> Result<(), String> {
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut entries = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_WALK_DEPTH {
            return Err(format!("{} is nested too deeply", directory.display()));
        }
        for entry in
            fs::read_dir(&directory).map_err(|error| format!("{}: {error}", directory.display()))?
        {
            entries += 1;
            if entries > MAX_WALK_ENTRIES {
                return Err(format!("{} has too many entries", root.display()));
            }
            let entry = entry.map_err(|error| format!("{}: {error}", directory.display()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("{}: {error}", path.display()))?;
            if file_type.is_symlink() {
                return Err(format!("{} is a symbolic link", path.display()));
            }
            if path.extension().is_some_and(|extension| extension == "isl") {
                return Err(format!(
                    "{} links a tablespace outside the data directory",
                    path.display()
                ));
            }
            if file_type.is_dir() {
                pending.push((path, depth + 1));
            }
        }
    }
    Ok(())
}

/// Moves the extracted prepared tree from `RESTORE_TARGET` to the data
/// volume root it replaces.
pub(super) fn install_prepared(extracted_root: &Path) -> Result<(), String> {
    let names = entry_names(extracted_root)?;
    if names != [RESTORE_TARGET] {
        return Err(format!(
            "the extracted backup must hold only {RESTORE_TARGET}, found {names:?}"
        ));
    }
    let tree = extracted_root.join(RESTORE_TARGET);
    check_prepared(&tree)?;
    let entries: Vec<PathBuf> = entry_names(&tree)?
        .into_iter()
        .map(|name| tree.join(name))
        .collect();
    if entries
        .iter()
        .any(|entry| entry.file_name().is_some_and(|name| name == RESTORE_TARGET))
    {
        return Err(format!("the backup itself contains {RESTORE_TARGET}"));
    }
    for entry in entries {
        let name = entry.file_name().ok_or("unnamed backup entry")?;
        fs::rename(&entry, extracted_root.join(name))
            .map_err(|error| format!("install {}: {error}", entry.display()))?;
    }
    fs::remove_dir(&tree).map_err(|error| format!("remove {}: {error}", tree.display()))
}

fn entry_names(directory: &Path) -> Result<Vec<String>, String> {
    let mut names = fs::read_dir(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(|error| format!("{}: {error}", directory.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREPARED: &str =
        "backup_type = full-prepared\nfrom_lsn = 0\nto_lsn = 47321\nlast_lsn = 47321\n";

    fn prepared_tree(root: &Path) {
        fs::create_dir_all(root.join("mysql")).unwrap();
        fs::create_dir_all(root.join("app")).unwrap();
        fs::write(root.join("ibdata1"), b"x").unwrap();
        fs::write(root.join("app/orders.ibd"), b"x").unwrap();
        fs::write(root.join("mariadb_backup_checkpoints"), PREPARED).unwrap();
    }

    #[test]
    fn prepared_full_backups_are_accepted() {
        let temp = tempfile::tempdir().unwrap();
        prepared_tree(temp.path());
        let checkpoints = check_prepared(temp.path()).unwrap();
        assert_eq!(checkpoints.file_name, "mariadb_backup_checkpoints");
        assert_eq!((checkpoints.from_lsn, checkpoints.to_lsn), (0, 47321));
    }

    #[test]
    fn unprepared_incremental_or_linked_trees_are_refused() {
        for text in [
            PREPARED.replace("full-prepared", "full-backuped"),
            PREPARED.replace("from_lsn = 0", "from_lsn = 12"),
            "backup_type = full-prepared\n".to_string(),
        ] {
            let temp = tempfile::tempdir().unwrap();
            prepared_tree(temp.path());
            fs::write(temp.path().join("mariadb_backup_checkpoints"), text).unwrap();
            assert!(check_prepared(temp.path()).is_err());
        }
        let temp = tempfile::tempdir().unwrap();
        prepared_tree(temp.path());
        fs::write(temp.path().join("app/remote.isl"), b"/srv/remote.ibd").unwrap();
        assert!(check_prepared(temp.path()).is_err());
        assert!(refuse_external_tablespaces(temp.path()).is_err());
    }

    #[test]
    fn restore_moves_the_tree_to_the_volume_root() {
        let temp = tempfile::tempdir().unwrap();
        prepared_tree(&temp.path().join(RESTORE_TARGET));
        install_prepared(temp.path()).unwrap();
        assert!(temp.path().join("ibdata1").is_file());
        assert!(temp.path().join("app/orders.ibd").is_file());
        assert!(!temp.path().join(RESTORE_TARGET).exists());

        let stray = tempfile::tempdir().unwrap();
        prepared_tree(&stray.path().join(RESTORE_TARGET));
        fs::write(stray.path().join("ibdata1"), b"x").unwrap();
        assert!(install_prepared(stray.path()).is_err());
    }
}
