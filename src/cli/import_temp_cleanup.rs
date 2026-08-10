use std::{
    collections::HashSet,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::shared::protocol::Protocol;

const MAX_ROOT_ENTRIES: usize = 4096;
const MAX_TREE_ENTRIES: usize = 4096;
const MAX_TREE_DEPTH: usize = 32;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const DUMP_EXTENSIONS: &[&str] = &[
    "postgres.sql",
    "mariadb.sql",
    "mysql.sql",
    "mongodb.archive.gz",
    "clickhouse.sql",
];

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct ImportTempCleanupSummary {
    pub scanned_entries: usize,
    pub removed_files: usize,
    pub removed_directories: usize,
    pub protected_rollbacks: usize,
    pub skipped_entries: usize,
}

#[derive(Debug)]
struct RootEntry {
    path: PathBuf,
    name: String,
    file_type: fs::FileType,
    kind: EntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EntryKind {
    Manifest { recovery_id: String },
    ImportFile,
    ExportFile,
    RollbackFile,
    UnarchiveDirectory,
    AtomicManifestTemporary,
    Unknown,
}

#[derive(Debug, Deserialize)]
struct LogicalRecoveryManifest {
    schema_version: u32,
    recovery_kind: String,
    instance_id: String,
    protocol: String,
    rollback_file: String,
}

pub(super) async fn cleanup_orphaned_import_export_staging(
    tmp_root: &Path,
) -> anyhow::Result<ImportTempCleanupSummary> {
    let root = tmp_root.join("import-export");
    tokio::task::spawn_blocking(move || {
        cleanup_root_with_limits(&root, MAX_ROOT_ENTRIES, MAX_TREE_ENTRIES)
    })
    .await
    .context("failed to join logical import staging cleanup")?
}

fn cleanup_root_with_limits(
    root: &Path,
    max_root_entries: usize,
    max_tree_entries: usize,
) -> anyhow::Result<ImportTempCleanupSummary> {
    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(ImportTempCleanupSummary::default());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect staging root {}", root.display()));
        }
    };
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        bail!("logical import staging root must be a real directory");
    }

    let entries = collect_root_entries(root, max_root_entries)?;
    let mut protected_rollbacks = HashSet::new();
    for entry in &entries {
        if let EntryKind::Manifest { recovery_id } = &entry.kind {
            protected_rollbacks.insert(validate_manifest(entry, recovery_id)?);
        }
    }
    for entry in &entries {
        if entry.kind == EntryKind::UnarchiveDirectory && entry.file_type.is_dir() {
            validate_directory_tree(&entry.path, max_tree_entries)?;
        }
    }

    let mut summary = ImportTempCleanupSummary {
        scanned_entries: entries.len(),
        protected_rollbacks: protected_rollbacks.len(),
        ..ImportTempCleanupSummary::default()
    };
    for entry in entries {
        match &entry.kind {
            EntryKind::ImportFile | EntryKind::ExportFile | EntryKind::AtomicManifestTemporary => {
                if remove_allowlisted_file(&entry)? {
                    summary.removed_files += 1;
                } else {
                    summary.skipped_entries += 1;
                }
            }
            EntryKind::RollbackFile if !protected_rollbacks.contains(&entry.name) => {
                if remove_allowlisted_file(&entry)? {
                    summary.removed_files += 1;
                } else {
                    summary.skipped_entries += 1;
                }
            }
            EntryKind::UnarchiveDirectory => {
                if remove_allowlisted_directory(&entry, max_tree_entries)? {
                    summary.removed_directories += 1;
                } else {
                    summary.skipped_entries += 1;
                }
            }
            EntryKind::Manifest { .. } | EntryKind::RollbackFile | EntryKind::Unknown => {
                summary.skipped_entries += 1
            }
        }
    }
    Ok(summary)
}

fn collect_root_entries(root: &Path, max_entries: usize) -> anyhow::Result<Vec<RootEntry>> {
    let mut entries = Vec::new();
    for result in fs::read_dir(root)
        .with_context(|| format!("failed to scan staging root {}", root.display()))?
    {
        let entry = result
            .with_context(|| format!("failed while scanning staging root {}", root.display()))?;
        if entries.len() >= max_entries {
            bail!(
                "logical import staging root {} exceeds the {}-entry scan safety limit",
                root.display(),
                max_entries
            );
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect staging entry {}", path.display()))?;
        let name = match entry.file_name().to_str() {
            Some(name) => name.to_string(),
            None => {
                entries.push(RootEntry {
                    path,
                    name: String::new(),
                    file_type: metadata.file_type(),
                    kind: EntryKind::Unknown,
                });
                continue;
            }
        };
        entries.push(RootEntry {
            path,
            kind: classify_entry(&name),
            name,
            file_type: metadata.file_type(),
        });
    }
    Ok(entries)
}

fn classify_entry(name: &str) -> EntryKind {
    if let Some(recovery_id) = wrapped_v4_uuid(name, ".dbe-import-recovery-", ".json") {
        return EntryKind::Manifest { recovery_id };
    }
    if atomic_manifest_temporary(name) {
        return EntryKind::AtomicManifestTemporary;
    }
    if wrapped_v4_uuid(name, ".dbe-unarchive-", "").is_some() {
        return EntryKind::UnarchiveDirectory;
    }
    if dump_temporary(name, ".dbe-import-rollback-") {
        return EntryKind::RollbackFile;
    }
    if dump_temporary(name, ".dbe-import-") {
        return EntryKind::ImportFile;
    }
    if dump_temporary(name, ".dbe-export-") {
        return EntryKind::ExportFile;
    }
    EntryKind::Unknown
}

fn dump_temporary(name: &str, prefix: &str) -> bool {
    DUMP_EXTENSIONS.iter().any(|extension| {
        let suffix = format!(".{extension}");
        wrapped_v4_uuid(name, prefix, &suffix).is_some()
    })
}

fn atomic_manifest_temporary(name: &str) -> bool {
    let Some(value) = name.strip_prefix("..dbe-import-recovery-") else {
        return false;
    };
    let Some(value) = value.strip_suffix(".tmp") else {
        return false;
    };
    let Some((recovery_id, write_id)) = value.split_once(".json.") else {
        return false;
    };
    is_canonical_v4_uuid(recovery_id) && is_canonical_v4_uuid(write_id)
}

fn wrapped_v4_uuid(name: &str, prefix: &str, suffix: &str) -> Option<String> {
    let value = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    is_canonical_v4_uuid(value).then(|| value.to_string())
}

fn is_canonical_v4_uuid(value: &str) -> bool {
    value.len() == 36
        && uuid::Uuid::parse_str(value).is_ok_and(|parsed| {
            parsed.get_version_num() == 4 && parsed.hyphenated().to_string() == value
        })
}

fn validate_manifest(entry: &RootEntry, recovery_id: &str) -> anyhow::Result<String> {
    let contents =
        crate::shared::files::read_private_regular_file_bounded(&entry.path, MAX_MANIFEST_BYTES)
            .with_context(|| {
                format!("failed to read recovery manifest {}", entry.path.display())
            })?;
    let manifest: LogicalRecoveryManifest = serde_json::from_slice(&contents)
        .with_context(|| format!("invalid recovery manifest {}", entry.path.display()))?;
    if manifest.schema_version != 1 || manifest.recovery_kind != "logical_remote_import" {
        bail!(
            "unsupported logical recovery manifest schema or kind in {}",
            entry.path.display()
        );
    }
    crate::shared::ids::validate_instance_id(&manifest.instance_id)
        .with_context(|| format!("unsafe instance id in {}", entry.path.display()))?;
    let protocol = manifest
        .protocol
        .parse::<Protocol>()
        .with_context(|| format!("invalid protocol in {}", entry.path.display()))?;
    let extension = logical_dump_extension(protocol).ok_or_else(|| {
        anyhow::anyhow!(
            "non-logical protocol in recovery manifest {}",
            entry.path.display()
        )
    })?;
    let expected = format!(".dbe-import-rollback-{recovery_id}.{extension}");
    if manifest.rollback_file != expected {
        bail!(
            "recovery manifest {} names rollback file {:?}, expected {:?}",
            entry.path.display(),
            manifest.rollback_file,
            expected
        );
    }
    Ok(expected)
}

fn logical_dump_extension(protocol: Protocol) -> Option<&'static str> {
    match protocol {
        Protocol::Postgres => Some("postgres.sql"),
        Protocol::Mariadb => Some("mariadb.sql"),
        Protocol::Mysql => Some("mysql.sql"),
        Protocol::Mongodb => Some("mongodb.archive.gz"),
        Protocol::Clickhouse => Some("clickhouse.sql"),
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => None,
    }
}

fn validate_directory_tree(root: &Path, max_entries: usize) -> anyhow::Result<()> {
    let mut scanned = 0_usize;
    validate_directory_tree_at(root, 0, max_entries, &mut scanned)
}

fn validate_directory_tree_at(
    root: &Path,
    depth: usize,
    max_entries: usize,
    scanned: &mut usize,
) -> anyhow::Result<()> {
    if depth > MAX_TREE_DEPTH {
        bail!(
            "orphaned unarchive directory {} exceeds the {}-level depth limit",
            root.display(),
            MAX_TREE_DEPTH
        );
    }
    for result in fs::read_dir(root)
        .with_context(|| format!("failed to scan unarchive directory {}", root.display()))?
    {
        let entry = result.with_context(|| {
            format!(
                "failed while scanning unarchive directory {}",
                root.display()
            )
        })?;
        *scanned = scanned.saturating_add(1);
        if *scanned > max_entries {
            bail!(
                "orphaned unarchive directory {} exceeds the {}-entry safety limit",
                root.display(),
                max_entries
            );
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect unarchive entry {}", path.display()))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            validate_directory_tree_at(&path, depth + 1, max_entries, scanned)?;
        }
    }
    Ok(())
}

fn remove_allowlisted_file(entry: &RootEntry) -> anyhow::Result<bool> {
    if entry.file_type.is_symlink() || !entry.file_type.is_file() {
        return Ok(false);
    }
    let current = match fs::symlink_metadata(&entry.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect orphan {}", entry.path.display()));
        }
    };
    if current.file_type().is_symlink() || !current.is_file() {
        return Ok(false);
    }
    crate::shared::files::remove_private_file_durable(&entry.path)
        .with_context(|| format!("failed to remove orphan {}", entry.path.display()))?;
    Ok(true)
}

fn remove_allowlisted_directory(entry: &RootEntry, max_entries: usize) -> anyhow::Result<bool> {
    if entry.file_type.is_symlink() || !entry.file_type.is_dir() {
        return Ok(false);
    }
    let current = match fs::symlink_metadata(&entry.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect orphan directory {}",
                    entry.path.display()
                )
            });
        }
    };
    if current.file_type().is_symlink() || !current.is_dir() {
        return Ok(false);
    }
    validate_directory_tree(&entry.path, max_entries)?;
    fs::remove_dir_all(&entry.path)
        .with_context(|| format!("failed to remove orphan directory {}", entry.path.display()))?;
    sync_directory_path(
        entry
            .path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("orphan directory has no parent"))?,
    )?;
    Ok(true)
}

#[cfg(unix)]
fn sync_directory_path(path: &Path) -> anyhow::Result<()> {
    use rustix::fs::{Mode, OFlags};

    let directory = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("failed to open staging parent {}", path.display()))?;
    match rustix::fs::fsync(&directory) {
        Ok(()) | Err(rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP) => Ok(()),
        Err(error) => Err(std::io::Error::from(error))
            .with_context(|| format!("failed to sync staging parent {}", path.display())),
    }
}

#[cfg(not(unix))]
fn sync_directory_path(_path: &Path) -> anyhow::Result<()> {
    bail!("durable logical import staging cleanup is supported only on Unix")
}

#[cfg(test)]
mod tests;
