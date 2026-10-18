pub mod catalog;
pub mod drivers;
pub mod manifest;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    config::{BackupStorageDriver, Config},
    databases::protocol::Protocol,
    io::{
        files::is_safe_flat_file_name,
        ownership::{allow_traversal_below, secure_private_dir_keeping_traversal},
    },
    utils::ids::validate_instance_id,
};

/// Schema version written by this daemon. Readers also accept
/// [`manifest::LEGACY_MANIFEST_SCHEMA_VERSION`].
pub const BACKUP_MANIFEST_SCHEMA_VERSION: u32 = manifest::MANIFEST_SCHEMA_VERSION;
pub(crate) const MAX_METADATA_BYTES: u64 = 64 * 1024;
const PHYSICAL_SUFFIX: &str = ".physical.tar.gz";
const LOGICAL_SUFFIX: &str = ".logical.dump";
const CATALOG_SUFFIX: &str = ".catalog.json";
const METADATA_SUFFIX: &str = ".metadata.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredBackup {
    pub schema_version: u32,
    pub backup_id: String,
    pub instance_id: String,
    pub protocol: Protocol,
    #[serde(default)]
    pub layout: BackupLayout,
    pub size_bytes: u64,
    pub created_at: String,
    pub created_at_unix: i64,
    pub sha256: String,
    pub catalog_available: bool,
    /// Restore contract; present exactly for schema 2 manifests. Schema 1
    /// daemons reject it as an unknown field, which keeps them from
    /// restoring formats they do not understand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<manifest::ManifestDetails>,
}

/// A stored backup in a format this daemon cannot interpret, such as a newer
/// manifest schema. It is listed opaquely, never restored and never pruned
/// by retention; only an explicit delete removes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedBackup {
    pub backup_id: String,
    pub diagnostic: String,
}

#[derive(Debug, Default)]
pub struct BackupInventory {
    pub backups: Vec<StoredBackup>,
    pub unsupported: Vec<UnsupportedBackup>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackupLayout {
    #[default]
    Physical,
    Logical,
}

impl StoredBackup {
    pub fn validate(&self, expected_instance_id: &str) -> Result<(), BackupStoreError> {
        validate_instance_id(expected_instance_id)
            .map_err(|error| BackupStoreError::Corrupt(error.to_string()))?;
        validate_backup_id(&self.backup_id)?;
        let created_at_is_consistent = matches!(
            OffsetDateTime::parse(&self.created_at, &Rfc3339),
            Ok(created_at) if created_at.unix_timestamp() == self.created_at_unix
        );
        match (self.schema_version, &self.details) {
            (manifest::LEGACY_MANIFEST_SCHEMA_VERSION, None) => {}
            (manifest::MANIFEST_SCHEMA_VERSION, Some(details)) => details.validate(self.layout)?,
            (version, _) if !is_supported_schema(version) => {
                return Err(unsupported_schema(&self.backup_id, version));
            }
            _ => {
                return Err(BackupStoreError::Corrupt(format!(
                    "backup metadata for {} does not match schema {}",
                    self.backup_id, self.schema_version
                )));
            }
        }
        if self.instance_id != expected_instance_id
            || !is_sha256(&self.sha256)
            || !created_at_is_consistent
        {
            return Err(BackupStoreError::Corrupt(format!(
                "backup metadata for {} is invalid",
                self.backup_id
            )));
        }
        Ok(())
    }

    pub(crate) fn to_json(&self) -> Result<Vec<u8>, BackupStoreError> {
        serde_json::to_vec_pretty(self)
            .map_err(|error| BackupStoreError::Corrupt(error.to_string()))
    }

    pub(crate) fn from_json(
        bytes: &[u8],
        expected_instance_id: &str,
        label: &str,
    ) -> Result<Self, BackupStoreError> {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| BackupStoreError::Corrupt(format!("invalid {label}: {error}")))?;
        // Check the version before strict field parsing so a newer format is
        // reported as unsupported rather than as corruption.
        if let Some(version) = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
        {
            let version = u32::try_from(version).unwrap_or(u32::MAX);
            if !is_supported_schema(version) {
                let backup_id = value
                    .get("backup_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                return Err(unsupported_schema(backup_id, version));
            }
        }
        let manifest: Self = serde_json::from_value(value)
            .map_err(|error| BackupStoreError::Corrupt(format!("invalid {label}: {error}")))?;
        manifest.validate(expected_instance_id)?;
        Ok(manifest)
    }

    /// Restore path dictated by the stored format, never by placement.
    pub fn restore_format(&self) -> manifest::RestoreFormat<'_> {
        match (&self.details, self.layout) {
            (Some(details), _) => details.restore_format(),
            (None, BackupLayout::Physical) => {
                manifest::RestoreFormat::DataDirectoryArchive { legacy: true }
            }
            (None, BackupLayout::Logical) => manifest::RestoreFormat::LogicalDump { legacy: true },
        }
    }

    /// Recorded consistency guarantee. Schema 1 records carry none.
    pub fn consistency(&self) -> Option<manifest::ConsistencyLevel> {
        self.details.as_ref().map(|details| details.consistency)
    }

    pub(crate) async fn verify_archive(
        &self,
        path: &Path,
        label: &str,
    ) -> Result<(), BackupStoreError> {
        let metadata = tokio::fs::symlink_metadata(path)
            .await
            .map_err(|source| io_error(format!("inspect {label}"), source))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != self.size_bytes
        {
            return Err(BackupStoreError::Corrupt(format!(
                "{label} has unexpected type or size"
            )));
        }
        if sha256_file(path).await? != self.sha256 {
            return Err(BackupStoreError::Corrupt(format!(
                "{label} SHA-256 does not match its metadata"
            )));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BackupBundle {
    pub directory: PathBuf,
    pub archive: PathBuf,
    pub catalog: PathBuf,
    pub metadata: PathBuf,
}

impl BackupBundle {
    pub async fn create(
        backups_root: &Path,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<Self, BackupStoreError> {
        check_instance_id(instance_id)?;
        validate_backup_id(backup_id)?;
        let staging = backups_root.join(".staging").join(instance_id);
        prepare_private_dir(&staging, "backup staging directory").await?;
        let directory = staging.join(format!(".{}.bundle", uuid::Uuid::new_v4()));
        create_private_directory(&directory, "backup bundle directory").await?;
        Ok(Self {
            archive: directory.join(backup_id),
            catalog: directory.join(catalog_file_name(backup_id)),
            metadata: directory.join(metadata_file_name(backup_id)),
            directory,
        })
    }

    pub async fn write_catalog(&self, bytes: &[u8]) -> Result<(), BackupStoreError> {
        atomic_write(&self.catalog, bytes, "backup catalog").await
    }

    pub async fn write_metadata(&self, manifest: &StoredBackup) -> Result<(), BackupStoreError> {
        let bytes = manifest.to_json()?;
        atomic_write(&self.metadata, &bytes, "backup metadata").await
    }

    pub async fn cleanup(&self) {
        if let Err(error) =
            crate::io::files::ignore_missing(tokio::fs::remove_dir_all(&self.directory).await)
        {
            tracing::warn!(
                path = %self.directory.display(),
                %error,
                "failed to remove backup staging bundle"
            );
        }
    }
}

/// Lets the rootless runtime group `gid` bind-mount `staging`, a capture
/// directory below `<backups_root>/.staging/<instance>`. The backups root and
/// each staging ancestor become daemon-owned 0710: traversable, never
/// listable. Private preparation keeps that grant, and everything else below
/// the root (instance backup directories, bundles) keeps its private mode.
/// Fails with the blocking ancestor when the runtime still cannot reach it.
pub async fn allow_staging_traversal(
    backups_root: &Path,
    staging: &Path,
    owner: (u32, u32),
) -> Result<(), BackupStoreError> {
    let root = backups_root.to_path_buf();
    let target = staging.to_path_buf();
    let daemon_uid = rustix::process::geteuid().as_raw();
    tokio::task::spawn_blocking(move || {
        allow_traversal_below(&root, &target, daemon_uid, owner.1)?;
        crate::io::ownership::ensure_traversable(&target, owner.0, owner.1)
    })
    .await
    .map_err(|error| BackupStoreError::Runtime(format!("staging traversal task failed: {error}")))?
    .map_err(|source| io_error("grant rootless runtime traversal to backup staging", source))
}

/// Removes incomplete bundles from an earlier run. Online capture
/// directories (`.staging/<instance>/.<job>.capture`) are kept: a helper
/// container may still write to one until journal recovery confirms it gone
/// and removes the directory itself.
pub async fn cleanup_staging(backups_root: &Path) -> Result<bool, BackupStoreError> {
    let staging = backups_root.join(".staging");
    match tokio::fs::symlink_metadata(&staging).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(io_error("inspect backup staging directory", source)),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(BackupStoreError::Corrupt(
                "backup staging path must be a real directory".to_string(),
            ));
        }
        Ok(_) => {}
    }
    let mut removed = false;
    let mut instances = tokio::fs::read_dir(&staging)
        .await
        .map_err(|source| io_error("read backup staging", source))?;
    while let Some(instance) = instances
        .next_entry()
        .await
        .map_err(|source| io_error("read backup staging", source))?
    {
        let path = instance.path();
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|source| io_error("inspect backup staging entry", source))?;
        if !metadata.is_dir() {
            remove_staging_entry(&path, &metadata).await?;
            removed = true;
            continue;
        }
        let mut kept = false;
        let mut entries = tokio::fs::read_dir(&path)
            .await
            .map_err(|source| io_error("read backup staging", source))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|source| io_error("read backup staging", source))?
        {
            let entry_path = entry.path();
            let entry_metadata = tokio::fs::symlink_metadata(&entry_path)
                .await
                .map_err(|source| io_error("inspect backup staging entry", source))?;
            if entry_metadata.is_dir() && is_capture_dir_name(&entry.file_name()) {
                kept = true;
                continue;
            }
            remove_staging_entry(&entry_path, &entry_metadata).await?;
            removed = true;
        }
        if !kept {
            tokio::fs::remove_dir(&path)
                .await
                .map_err(|source| io_error("remove incomplete backup staging", source))?;
            removed = true;
        }
    }
    Ok(removed)
}

/// `.<job uuid>.capture`, the online capture staging of one job.
pub(crate) fn is_capture_dir_name(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.strip_prefix('.')
            .and_then(|name| name.strip_suffix(".capture"))
            .is_some_and(|job| job.len() == 32 && job.bytes().all(|byte| byte.is_ascii_hexdigit()))
    })
}

async fn remove_staging_entry(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), BackupStoreError> {
    let removed = if metadata.is_dir() {
        tokio::fs::remove_dir_all(path).await
    } else {
        tokio::fs::remove_file(path).await
    };
    removed.map_err(|source| io_error("remove incomplete backup staging", source))
}

pub async fn cleanup_materializations(tmp_root: &Path) -> Result<usize, BackupStoreError> {
    let mut removed = 0;
    for name in ["backup-materialized", "backup-catalogs"] {
        if cleanup_internal_dir(&tmp_root.join(name), "backup materialization").await? {
            removed += 1;
        }
    }
    Ok(removed)
}

async fn cleanup_internal_dir(path: &Path, label: &str) -> Result<bool, BackupStoreError> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(io_error(format!("inspect {label} directory"), source)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackupStoreError::Corrupt(format!(
            "{label} path must be a real directory"
        )));
    }
    tokio::fs::remove_dir_all(path)
        .await
        .map_err(|source| io_error(format!("remove incomplete {label}"), source))?;
    Ok(true)
}

#[derive(Debug)]
pub struct MaterializedBackup {
    pub path: PathBuf,
    pub temporary: bool,
    capacity: Option<crate::server::disk::capacity::DiskCapacityReservation>,
}

impl Drop for MaterializedBackup {
    fn drop(&mut self) {
        if self.temporary
            && let Err(error) = crate::io::files::ignore_missing(std::fs::remove_file(&self.path))
        {
            tracing::warn!(path = %self.path.display(), %error, "failed to remove materialized backup")
        }
        // Release reserved bytes only after the file has been unlinked.
        self.capacity.take();
    }
}

#[derive(Debug, Clone)]
pub enum BackupStorage {
    Local(drivers::local::LocalBackupDriver),
    S3(Box<drivers::s3::S3BackupDriver>),
    Kopia(drivers::kopia::KopiaBackupDriver),
}

impl BackupStorage {
    pub fn from_config(config: &Config) -> Result<Self, BackupStoreError> {
        let backups_root = PathBuf::from(config.paths.backups_root());
        match config.backups.storage.driver {
            BackupStorageDriver::Local => Ok(Self::Local(drivers::local::LocalBackupDriver::new(
                backups_root,
            ))),
            BackupStorageDriver::S3 => Ok(Self::S3(Box::new(drivers::s3::S3BackupDriver::new(
                config.backups.storage.s3.clone(),
            )?))),
            BackupStorageDriver::Kopia => Ok(Self::Kopia(drivers::kopia::KopiaBackupDriver::new(
                config.backups.storage.kopia.clone(),
                backups_root,
            )?)),
        }
    }

    pub fn kind(&self) -> BackupStorageDriver {
        match self {
            Self::Local(_) => BackupStorageDriver::Local,
            Self::S3(_) => BackupStorageDriver::S3,
            Self::Kopia(_) => BackupStorageDriver::Kopia,
        }
    }

    pub async fn preflight(&self) -> Result<(), BackupStoreError> {
        self.driver().preflight().await
    }

    pub async fn commit(
        &self,
        bundle: &BackupBundle,
        manifest: &StoredBackup,
        journal: &dyn drivers::PublicationJournal,
    ) -> Result<(), BackupStoreError> {
        self.driver().commit(bundle, manifest, journal).await
    }

    /// Identity of the storage target, recorded before publication so
    /// cleanup never acts on a different target.
    pub fn identity(&self) -> String {
        match self {
            Self::Local(driver) => driver.identity(),
            Self::S3(driver) => driver.identity(),
            Self::Kopia(driver) => driver.identity(),
        }
    }

    pub async fn list(&self, instance_id: &str) -> Result<Vec<StoredBackup>, BackupStoreError> {
        Ok(self.inventory(instance_id).await?.backups)
    }

    /// Readable backups, newest first, plus opaque unsupported entries.
    pub async fn inventory(&self, instance_id: &str) -> Result<BackupInventory, BackupStoreError> {
        let mut inventory = self.driver().inventory(instance_id).await?;
        inventory
            .backups
            .sort_by_key(|backup| std::cmp::Reverse(backup.created_at_unix));
        inventory
            .unsupported
            .sort_by(|left, right| left.backup_id.cmp(&right.backup_id));
        Ok(inventory)
    }

    /// Idempotently removes every object of a backup id whose publication
    /// did not settle, plus its journaled `resources`, and confirms removal.
    pub async fn purge_unpublished(
        &self,
        instance_id: &str,
        backup_id: &str,
        resources: &[drivers::PublicationResource],
    ) -> Result<(), BackupStoreError> {
        validate_backup_id(backup_id)?;
        self.driver()
            .purge_unpublished(instance_id, backup_id, resources)
            .await
    }

    pub async fn find(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<StoredBackup, BackupStoreError> {
        validate_backup_id(backup_id)?;
        self.driver().find(instance_id, backup_id).await
    }

    pub async fn delete(&self, instance_id: &str, backup_id: &str) -> Result<(), BackupStoreError> {
        validate_backup_id(backup_id)?;
        self.driver().delete(instance_id, backup_id).await
    }

    fn driver(&self) -> &dyn drivers::BackupDriver {
        match self {
            Self::Local(driver) => driver,
            Self::S3(driver) => driver.as_ref(),
            Self::Kopia(driver) => driver,
        }
    }

    pub(crate) async fn materialize(
        &self,
        instance_id: &str,
        backup_id: &str,
        tmp_root: &Path,
        capacity: Option<crate::server::disk::capacity::DiskCapacityReservation>,
        slots: std::sync::Arc<tokio::sync::Semaphore>,
    ) -> Result<MaterializedBackup, BackupStoreError> {
        validate_backup_id(backup_id)?;
        if let Self::Local(driver) = self {
            return driver.materialize(instance_id, backup_id).await;
        }
        let capacity = capacity.ok_or_else(|| {
            BackupStoreError::Runtime(
                "remote backup materialization requires a disk reservation".to_string(),
            )
        })?;
        let slot = slots.try_acquire_owned().map_err(|_| {
            BackupStoreError::Runtime(
                "remote backup materialization is at capacity; retry later".to_string(),
            )
        })?;
        let destination = materialization_path(tmp_root, instance_id, backup_id).await?;
        let guard = MaterializedBackup {
            path: destination,
            temporary: true,
            capacity: Some(capacity),
        };
        let driver = self.clone();
        let instance_id = instance_id.to_string();
        let backup_id = backup_id.to_string();
        // A cancelled HTTP waiter must not race cleanup against a still-running
        // file open or Kopia process. The bounded worker owns the spool and its
        // reservation until the driver finishes, even when nobody awaits it.
        tokio::spawn(async move {
            let _slot = slot;
            match driver {
                Self::S3(driver) => {
                    driver
                        .materialize(&instance_id, &backup_id, &guard.path)
                        .await?
                }
                Self::Kopia(driver) => {
                    driver
                        .materialize(&instance_id, &backup_id, &guard.path)
                        .await?
                }
                Self::Local(_) => unreachable!("local backups do not need materialization"),
            }
            Ok(guard)
        })
        .await
        .map_err(|error| {
            BackupStoreError::Runtime(format!("backup materialization worker failed: {error}"))
        })?
    }

    pub async fn read_catalog(
        &self,
        instance_id: &str,
        backup_id: &str,
        max_bytes: u64,
        tmp_root: &Path,
    ) -> Result<Option<Vec<u8>>, BackupStoreError> {
        validate_backup_id(backup_id)?;
        match self {
            Self::Local(driver) => driver.read_catalog(instance_id, backup_id, max_bytes).await,
            Self::S3(driver) => driver.read_catalog(instance_id, backup_id, max_bytes).await,
            Self::Kopia(driver) => {
                driver
                    .read_catalog(instance_id, backup_id, max_bytes, tmp_root)
                    .await
            }
        }
    }

    pub async fn delete_instance(&self, instance_id: &str) -> Result<usize, BackupStoreError> {
        match self {
            Self::S3(driver) => return driver.delete_instance(instance_id).await,
            Self::Kopia(driver) => return driver.delete_instance(instance_id).await,
            Self::Local(_) => {}
        }
        let inventory = self.inventory(instance_id).await?;
        for backup_id in inventory
            .backups
            .iter()
            .map(|backup| &backup.backup_id)
            .chain(inventory.unsupported.iter().map(|entry| &entry.backup_id))
        {
            self.delete(instance_id, backup_id).await?;
        }
        Ok(inventory.backups.len() + inventory.unsupported.len())
    }
}

pub async fn build_manifest(
    backup_id: String,
    instance_id: String,
    protocol: Protocol,
    layout: BackupLayout,
    archive: &Path,
    catalog_available: bool,
    details: manifest::ManifestDetails,
) -> Result<StoredBackup, BackupStoreError> {
    details.validate(layout)?;
    let metadata = tokio::fs::metadata(archive)
        .await
        .map_err(|source| io_error("inspect backup archive", source))?;
    if !metadata.is_file() {
        return Err(BackupStoreError::Corrupt(
            "backup archive is not a regular file".to_string(),
        ));
    }
    let created = OffsetDateTime::now_utc();
    Ok(StoredBackup {
        schema_version: BACKUP_MANIFEST_SCHEMA_VERSION,
        backup_id,
        instance_id,
        protocol,
        layout,
        size_bytes: metadata.len(),
        created_at: created
            .format(&Rfc3339)
            .map_err(|error| BackupStoreError::Corrupt(error.to_string()))?,
        created_at_unix: created.unix_timestamp(),
        sha256: sha256_file(archive).await?,
        catalog_available,
        details: Some(details),
    })
}

fn is_supported_schema(version: u32) -> bool {
    matches!(
        version,
        manifest::LEGACY_MANIFEST_SCHEMA_VERSION | manifest::MANIFEST_SCHEMA_VERSION
    )
}

#[cfg(test)]
pub(crate) fn test_details(layout: BackupLayout) -> manifest::ManifestDetails {
    let consistency = match layout {
        BackupLayout::Physical => manifest::ConsistencyLevel::StoppedCopy,
        BackupLayout::Logical => manifest::ConsistencyLevel::PerObject,
    };
    manifest::ManifestDetails::built_in(
        layout,
        consistency,
        manifest::CaptureInterval {
            started_at_unix: 0,
            finished_at_unix: 0,
        },
        manifest::EngineRecord::default(),
    )
}

fn unsupported_schema(backup_id: &str, version: u32) -> BackupStoreError {
    BackupStoreError::UnsupportedFormat(format!(
        "backup {backup_id} uses manifest schema {version}, which this daemon cannot read; upgrade the daemon to restore it"
    ))
}

pub async fn sha256_file(path: &Path) -> Result<String, BackupStoreError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        crate::utils::hash::sha256_reader(std::fs::File::open(&path)?)
    })
    .await
    .map_err(|error| BackupStoreError::Runtime(format!("backup hash task failed: {error}")))?
    .map_err(|source| io_error("hash backup archive", source))
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn new_backup_id(layout: BackupLayout) -> String {
    let suffix = match layout {
        BackupLayout::Physical => PHYSICAL_SUFFIX,
        BackupLayout::Logical => LOGICAL_SUFFIX,
    };
    format!("{}{suffix}", uuid::Uuid::new_v4())
}

pub fn catalog_file_name(backup_id: &str) -> String {
    format!("{backup_id}{CATALOG_SUFFIX}")
}

pub fn metadata_file_name(backup_id: &str) -> String {
    format!("{backup_id}{METADATA_SUFFIX}")
}

pub fn validate_backup_id(backup_id: &str) -> Result<(), BackupStoreError> {
    if !is_safe_flat_file_name(backup_id)
        || backup_id.ends_with(CATALOG_SUFFIX)
        || backup_id.ends_with(METADATA_SUFFIX)
    {
        return Err(BackupStoreError::InvalidBackupId);
    }
    Ok(())
}

pub(crate) fn check_instance_id(instance_id: &str) -> Result<(), BackupStoreError> {
    validate_instance_id(instance_id)
        .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))
}

pub(crate) async fn prepare_private_dir(path: &Path, label: &str) -> Result<(), BackupStoreError> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|source| io_error(format!("create {label}"), source))?;
    secure_directory(path, label).await
}

async fn create_private_directory(path: &Path, label: &str) -> Result<(), BackupStoreError> {
    tokio::fs::create_dir(path)
        .await
        .map_err(|source| io_error(format!("create {label}"), source))?;
    secure_directory(path, label).await
}

async fn secure_directory(path: &Path, label: &str) -> Result<(), BackupStoreError> {
    let path = path.to_path_buf();
    let result = tokio::task::spawn_blocking(move || secure_private_dir_keeping_traversal(&path))
        .await
        .map_err(|error| BackupStoreError::Runtime(format!("{label} task failed: {error}")))?;
    match result {
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Err(
            BackupStoreError::Corrupt(format!("{label} must be a real directory")),
        ),
        Err(error) => Err(io_error(format!("secure {label}"), error)),
        Ok(()) => Ok(()),
    }
}

async fn atomic_write(path: &Path, bytes: &[u8], label: &str) -> Result<(), BackupStoreError> {
    let path = path.to_path_buf();
    let bytes = bytes.to_vec();
    tokio::task::spawn_blocking(move || crate::io::files::atomic_write_private(&path, &bytes))
        .await
        .map_err(|error| BackupStoreError::Runtime(format!("{label} write task failed: {error}")))?
        .map_err(|source| io_error(format!("write {label}"), source))
}

async fn materialization_path(
    tmp_root: &Path,
    instance_id: &str,
    backup_id: &str,
) -> Result<PathBuf, BackupStoreError> {
    check_instance_id(instance_id)?;
    let root = tmp_root.join("backup-materialized").join(instance_id);
    prepare_private_dir(&root, "backup materialization directory").await?;
    Ok(root.join(format!("{}.{}", uuid::Uuid::new_v4(), backup_id)))
}

pub(crate) async fn remove_file_if_exists(path: &Path) {
    if let Err(error) = crate::io::files::ignore_missing(tokio::fs::remove_file(path).await) {
        tracing::warn!(path = %path.display(), %error, "failed to remove backup file")
    }
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn io_error(operation: impl Into<String>, source: std::io::Error) -> BackupStoreError {
    BackupStoreError::Io {
        operation: operation.into(),
        source,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BackupStoreError {
    #[error("invalid backup id")]
    InvalidBackupId,
    #[error("backup not found")]
    NotFound,
    #[error("invalid backup storage configuration: {0}")]
    InvalidConfiguration(String),
    #[error("backup data is corrupt: {0}")]
    Corrupt(String),
    /// Written by a newer daemon in a format this build must not interpret.
    #[error("unsupported backup format: {0}")]
    UnsupportedFormat(String),
    #[error("backup storage operation failed: {0}")]
    Remote(String),
    #[error("{operation}: {source}")]
    Io {
        operation: String,
        #[source]
        source: std::io::Error,
    },
    #[error("backup runtime error: {0}")]
    Runtime(String),
}

#[cfg(test)]
mod tests;
