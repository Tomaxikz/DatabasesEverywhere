//! Builds a restorable ClickHouse data directory from the live volume and the
//! frozen parts.
//!
//! The live walk copies everything except runtime scratch (`shadow`, `tmp`,
//! `flags`, `metadata_dropped`, `preprocessed_configs`, `status`) and every
//! directory inside a table's store directory: parts, `detached` and
//! in-flight temporaries. Each frozen table then gets its parts from
//! `shadow/<name>`, which mirrors the data directory layout. Files that
//! disappear while the server keeps working are skipped. Links are refused
//! except the ones ClickHouse recreates itself; nothing is followed.

use std::{
    collections::HashSet,
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Instant,
};

use crate::server::jobs::import_export::{DataArchiveSourcePolicy, omits_engine_link};

const SKIPPED_TOP_LEVEL: [&str; 6] = [
    "shadow",
    "tmp",
    "flags",
    "metadata_dropped",
    "preprocessed_configs",
    "status",
];
/// `store/<xyz>/<uuid>/<entry>`: depth of a part directory.
const PART_DEPTH: usize = 4;
const DEADLINE_CHECK_INTERVAL: usize = 256;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct CopyStats {
    pub files: u64,
    pub bytes: u64,
    pub parts: u64,
    pub omitted_links: u64,
}

pub(super) struct Limits {
    pub max_bytes: u64,
    pub max_entries: usize,
    pub deadline: Instant,
}

struct Budget<'a> {
    limits: &'a Limits,
    entries: usize,
    stats: CopyStats,
}

impl Budget<'_> {
    fn entry(&mut self) -> Result<(), String> {
        self.entries += 1;
        if self.entries > self.limits.max_entries {
            return Err(format!(
                "the volume has more than {} entries",
                self.limits.max_entries
            ));
        }
        if self.entries.is_multiple_of(DEADLINE_CHECK_INTERVAL)
            && Instant::now() >= self.limits.deadline
        {
            return Err("the copy exceeded the online backup deadline".to_string());
        }
        Ok(())
    }

    fn file(&mut self, size: u64) -> Result<(), String> {
        self.stats.bytes = self.stats.bytes.saturating_add(size);
        if self.stats.bytes > self.limits.max_bytes {
            return Err(format!(
                "the volume holds more than the {}-byte capture budget",
                self.limits.max_bytes
            ));
        }
        self.stats.files += 1;
        Ok(())
    }
}

fn is_store_part(relative: &Path, depth: usize) -> bool {
    depth == PART_DEPTH && relative.starts_with("store")
}

fn vanished(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
}

/// Copies `data` into the new directory `destination`, grafting the parts of
/// `frozen` table directories from `shadow`.
pub(super) fn copy_frozen(
    data: &Path,
    shadow: &Path,
    frozen: &HashSet<PathBuf>,
    destination: &Path,
    limits: &Limits,
) -> Result<CopyStats, String> {
    require_real_directory(data)?;
    fs::create_dir(destination).map_err(|error| format!("{}: {error}", destination.display()))?;
    copy_mode(data, destination)?;
    let mut budget = Budget {
        limits,
        entries: 0,
        stats: CopyStats::default(),
    };
    copy_live(data, destination, &mut budget)?;
    if fs::symlink_metadata(shadow).is_ok() {
        require_real_directory(shadow)?;
        graft_parts(shadow, frozen, destination, &mut budget)?;
    }
    Ok(budget.stats)
}

fn copy_live(data: &Path, destination: &Path, budget: &mut Budget<'_>) -> Result<(), String> {
    let walk = walkdir::WalkDir::new(data)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            let Ok(relative) = entry.path().strip_prefix(data) else {
                return false;
            };
            let skipped = entry.depth() == 1
                && relative
                    .to_str()
                    .is_some_and(|name| SKIPPED_TOP_LEVEL.contains(&name));
            !skipped && !(entry.file_type().is_dir() && is_store_part(relative, entry.depth()))
        });
    for entry in walk {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.io_error().is_some_and(vanished) => continue,
            Err(error) => return Err(format!("read the data directory: {error}")),
        };
        budget.entry()?;
        let relative = entry
            .path()
            .strip_prefix(data)
            .map_err(|_| "data directory entry escaped its root".to_string())?;
        copy_entry(
            entry.path(),
            relative,
            &destination.join(relative),
            true,
            budget,
        )?;
    }
    Ok(())
}

fn graft_parts(
    shadow: &Path,
    frozen: &HashSet<PathBuf>,
    destination: &Path,
    budget: &mut Budget<'_>,
) -> Result<(), String> {
    for entry in walkdir::WalkDir::new(shadow)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            // Descend only into the store directories of frozen tables.
            let Ok(relative) = entry.path().strip_prefix(shadow) else {
                return false;
            };
            match entry.depth() {
                1 => relative == Path::new("store"),
                2 => true,
                3 => frozen.contains(relative),
                _ => true,
            }
        })
    {
        let entry = entry.map_err(|error| format!("read the frozen parts: {error}"))?;
        budget.entry()?;
        let relative = entry
            .path()
            .strip_prefix(shadow)
            .map_err(|_| "frozen part escaped its root".to_string())?;
        if entry.depth() < PART_DEPTH {
            if !entry.file_type().is_dir() {
                return Err(format!(
                    "unexpected entry {} in the frozen parts",
                    relative.display()
                ));
            }
            continue;
        }
        let target = destination.join(relative);
        if entry.depth() == PART_DEPTH {
            // A table dropped after its freeze has no directory to receive parts.
            if !target.parent().is_some_and(Path::is_dir) {
                continue;
            }
            if !entry.file_type().is_dir() {
                return Err(format!(
                    "frozen part {} is not a directory",
                    relative.display()
                ));
            }
            budget.stats.parts += 1;
        } else if !target.parent().is_some_and(Path::is_dir) {
            continue;
        }
        copy_entry(entry.path(), relative, &target, false, budget)?;
    }
    Ok(())
}

/// Copies one walked entry. `live` entries may vanish mid-copy and may be
/// engine-recreated links; frozen parts may be neither.
fn copy_entry(
    source: &Path,
    relative: &Path,
    target: &Path,
    live: bool,
    budget: &mut Budget<'_>,
) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if live && vanished(&error) => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", relative.display())),
    };
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        fs::create_dir(target).map_err(|error| format!("{}: {error}", relative.display()))?;
        copy_mode(source, target)
    } else if file_type.is_file() {
        budget.file(metadata.len())?;
        match fs::copy(source, target) {
            Ok(_) => Ok(()),
            Err(error) if live && vanished(&error) => {
                budget.stats.files -= 1;
                budget.stats.bytes = budget.stats.bytes.saturating_sub(metadata.len());
                Ok(())
            }
            Err(error) => Err(format!("copy {}: {error}", relative.display())),
        }
    } else if file_type.is_symlink() {
        let link =
            fs::read_link(source).map_err(|error| format!("{}: {error}", relative.display()))?;
        if live
            && omits_engine_link(
                DataArchiveSourcePolicy::ClickhouseDataDirectory,
                relative,
                &link,
            )
        {
            budget.stats.omitted_links += 1;
            Ok(())
        } else {
            Err(format!(
                "the volume contains a link {} -> {}, which the backup cannot hold",
                relative.display(),
                link.display()
            ))
        }
    } else {
        Err(format!(
            "the volume contains a special file {}, which the backup cannot hold",
            relative.display()
        ))
    }
}

fn require_real_directory(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(format!("{} is not a directory", path.display()))
    }
}

fn copy_mode(source: &Path, target: &Path) -> Result<(), String> {
    let mode = fs::symlink_metadata(source)
        .map_err(|error| format!("{}: {error}", source.display()))?
        .permissions()
        .mode();
    fs::set_permissions(target, fs::Permissions::from_mode(mode & 0o7777))
        .map_err(|error| format!("{}: {error}", target.display()))
}

/// Counts the grafted parts in a finished copy, requiring each to carry its
/// `checksums.txt`.
pub(super) fn count_parts(root: &Path) -> Result<u64, String> {
    let store = root.join("store");
    if fs::symlink_metadata(&store).is_err() {
        return Ok(0);
    }
    let mut parts = 0_u64;
    for entry in walkdir::WalkDir::new(&store)
        .min_depth(PART_DEPTH - 1)
        .max_depth(PART_DEPTH - 1)
        .follow_links(false)
    {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry.file_type().is_dir() {
            continue;
        }
        let checksums = entry.path().join("checksums.txt");
        if !fs::symlink_metadata(&checksums).is_ok_and(|metadata| metadata.is_file()) {
            return Err(format!(
                "part {} has no checksums.txt",
                entry
                    .path()
                    .strip_prefix(root)
                    .unwrap_or(entry.path())
                    .display()
            ));
        }
        parts += 1;
    }
    Ok(parts)
}

/// Removes `shadow/<name>` below the host data directory, refusing links.
pub(super) fn remove_shadow(data: &Path, name: &str) -> Result<(), String> {
    let shadow = data.join("shadow");
    match fs::symlink_metadata(&shadow) {
        Err(error) if vanished(&error) => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", shadow.display())),
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(format!("{} is not a directory", shadow.display()));
        }
        Ok(_) => {}
    }
    let frozen = shadow.join(name);
    match fs::symlink_metadata(&frozen) {
        Err(error) if vanished(&error) => Ok(()),
        Err(error) => Err(format!("{}: {error}", frozen.display())),
        Ok(metadata) if !metadata.file_type().is_dir() => {
            Err(format!("{} is not a directory", frozen.display()))
        }
        Ok(_) => {
            fs::remove_dir_all(&frozen).map_err(|error| format!("{}: {error}", frozen.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    const TABLE: &str = "store/4b8/4b8f2c1e-9a7d-4f3b-8c6e-2d1a0f9e8b7c";
    const DATABASE: &str = "store/a1b/a1b2c3d4-0000-4000-8000-000000000001";

    fn write(root: &Path, relative: &str, contents: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// A live data directory with one table whose `all_2_2_0` part is newer
    /// than the freeze and whose `all_1_1_0` was merged away after it.
    fn volume() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        write(&data, "metadata/default.sql", b"ATTACH DATABASE default");
        symlink(
            format!("/var/lib/clickhouse/{DATABASE}"),
            data.join("metadata/default"),
        )
        .unwrap();
        write(
            &data,
            &format!("{DATABASE}/events.sql"),
            b"ATTACH TABLE events",
        );
        fs::create_dir_all(data.join("data/default")).unwrap();
        symlink(format!("../../{TABLE}"), data.join("data/default/events")).unwrap();
        write(&data, &format!("{TABLE}/format_version.txt"), b"1");
        write(&data, &format!("{TABLE}/all_2_2_0/checksums.txt"), b"live");
        write(
            &data,
            &format!("{TABLE}/detached/broken/checksums.txt"),
            b"old",
        );
        write(&data, "access/users.list", b"u");
        write(&data, "status", b"PID: 1");
        write(&data, "tmp/scratch", b"t");
        write(&data, "shadow/increment.txt", b"1");
        write(
            &data,
            &format!("shadow/dbev_bk_x/{TABLE}/all_1_1_0/checksums.txt"),
            b"frozen",
        );
        write(
            &data,
            &format!("shadow/dbev_bk_x/{TABLE}/all_1_1_0/data.bin"),
            b"rows",
        );
        write(
            &data,
            &format!("shadow/dbev_bk_x/{TABLE}/all_1_1_0/p.proj/checksums.txt"),
            b"p",
        );
        root
    }

    fn limits() -> Limits {
        Limits {
            max_bytes: 1 << 20,
            max_entries: 1000,
            deadline: Instant::now() + std::time::Duration::from_secs(60),
        }
    }

    #[test]
    fn frozen_parts_replace_the_live_ones() {
        let root = volume();
        let data = root.path().join("data");
        let out = root.path().join("out");
        let frozen = HashSet::from([PathBuf::from(TABLE)]);
        let stats = copy_frozen(
            &data,
            &data.join("shadow/dbev_bk_x"),
            &frozen,
            &out,
            &limits(),
        )
        .unwrap();
        assert_eq!(stats.parts, 1);
        assert_eq!(stats.omitted_links, 2);
        assert_eq!(
            fs::read(out.join(format!("{TABLE}/all_1_1_0/data.bin"))).unwrap(),
            b"rows"
        );
        assert!(
            out.join(format!("{TABLE}/all_1_1_0/p.proj/checksums.txt"))
                .is_file()
        );
        assert!(out.join(format!("{TABLE}/format_version.txt")).is_file());
        assert!(out.join(format!("{DATABASE}/events.sql")).is_file());
        assert!(out.join("access/users.list").is_file());
        for absent in [
            format!("{TABLE}/all_2_2_0"),
            format!("{TABLE}/detached"),
            "status".to_string(),
            "tmp".to_string(),
            "shadow".to_string(),
            "metadata/default".to_string(),
        ] {
            assert!(fs::symlink_metadata(out.join(&absent)).is_err(), "{absent}");
        }
        assert_eq!(count_parts(&out).unwrap(), 1);
    }

    #[test]
    fn unfrozen_tables_keep_no_parts_and_foreign_links_fail() {
        let root = volume();
        let data = root.path().join("data");
        let stats = copy_frozen(
            &data,
            &data.join("shadow/dbev_bk_x"),
            &HashSet::new(),
            &root.path().join("none"),
            &limits(),
        )
        .unwrap();
        assert_eq!(stats.parts, 0);
        assert_eq!(count_parts(&root.path().join("none")).unwrap(), 0);

        symlink("/etc/passwd", data.join("access/escape")).unwrap();
        let error = copy_frozen(
            &data,
            &data.join("shadow/dbev_bk_x"),
            &HashSet::new(),
            &root.path().join("linked"),
            &limits(),
        )
        .unwrap_err();
        assert!(error.contains("link"), "{error}");
    }

    #[test]
    fn budgets_stop_the_copy() {
        let root = volume();
        let data = root.path().join("data");
        let shadow = data.join("shadow/dbev_bk_x");
        let frozen = HashSet::from([PathBuf::from(TABLE)]);
        let small = Limits {
            max_bytes: 4,
            ..limits()
        };
        assert!(copy_frozen(&data, &shadow, &frozen, &root.path().join("a"), &small).is_err());
        let few = Limits {
            max_entries: 3,
            ..limits()
        };
        assert!(copy_frozen(&data, &shadow, &frozen, &root.path().join("b"), &few).is_err());
    }

    #[test]
    fn parts_without_checksums_fail_the_count() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), &format!("{TABLE}/all_1_1_0/data.bin"), b"x");
        assert!(count_parts(root.path()).unwrap_err().contains("checksums"));
    }

    #[test]
    fn shadow_removal_is_idempotent_and_refuses_links() {
        let root = volume();
        let data = root.path().join("data");
        remove_shadow(&data, "dbev_bk_x").unwrap();
        assert!(!data.join("shadow/dbev_bk_x").exists());
        assert!(data.join("shadow/increment.txt").exists());
        remove_shadow(&data, "dbev_bk_x").unwrap();
        symlink("/etc", data.join("shadow/dbev_bk_y")).unwrap();
        assert!(remove_shadow(&data, "dbev_bk_y").is_err());
        assert!(Path::new("/etc").exists());
    }
}
