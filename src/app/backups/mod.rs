pub mod catalog;
pub mod drivers;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    config::{BackupStorageDriver, Config},
    shared::{
        files::{is_safe_flat_file_name, secure_private_dir},
        ids::validate_instance_id,
        protocol::Protocol,
    },
};

pub const BACKUP_MANIFEST_SCHEMA_VERSION: u32 = 1;
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
        let created_at = OffsetDateTime::parse(&self.created_at, &Rfc3339);
        if self.schema_version != BACKUP_MANIFEST_SCHEMA_VERSION
            || self.instance_id != expected_instance_id
            || !is_sha256(&self.sha256)
            || !matches!(
                created_at,
                Ok(created_at) if created_at.unix_timestamp() == self.created_at_unix
            )
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
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| BackupStoreError::Corrupt(format!("invalid {label}: {error}")))?;
        manifest.validate(expected_instance_id)?;
        Ok(manifest)
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
        match tokio::fs::remove_dir_all(&self.directory).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                path = %self.directory.display(),
                %error,
                "failed to remove backup staging bundle"
            ),
        }
    }
}

pub async fn cleanup_staging(backups_root: &Path) -> Result<bool, BackupStoreError> {
    cleanup_internal_dir(&backups_root.join(".staging"), "backup staging").await
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
    capacity: Option<crate::api::import_export::DiskCapacityReservation>,
}

impl Drop for MaterializedBackup {
    fn drop(&mut self) {
        if self.temporary {
            match std::fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::warn!(path = %self.path.display(), %error, "failed to remove materialized backup")
                }
            }
        }
        // Release reserved bytes only after the file has been unlinked.
        self.capacity.take();
    }
}

const MAX_MATERIALIZATIONS: usize = 8;
static MATERIALIZATION_SLOTS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_MATERIALIZATIONS);

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
        match self {
            Self::Local(driver) => driver.preflight().await,
            Self::S3(driver) => driver.preflight().await,
            Self::Kopia(driver) => driver.preflight().await,
        }
    }

    pub async fn commit(
        &self,
        bundle: &BackupBundle,
        manifest: &StoredBackup,
    ) -> Result<(), BackupStoreError> {
        match self {
            Self::Local(driver) => driver.commit(bundle, manifest).await,
            Self::S3(driver) => driver.commit(bundle, manifest).await,
            Self::Kopia(driver) => driver.commit(bundle, manifest).await,
        }
    }

    pub async fn list(&self, instance_id: &str) -> Result<Vec<StoredBackup>, BackupStoreError> {
        let mut backups = match self {
            Self::Local(driver) => driver.list(instance_id).await?,
            Self::S3(driver) => driver.list(instance_id).await?,
            Self::Kopia(driver) => driver.list(instance_id).await?,
        };
        backups.sort_by_key(|backup| std::cmp::Reverse(backup.created_at_unix));
        Ok(backups)
    }

    pub async fn find(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<StoredBackup, BackupStoreError> {
        validate_backup_id(backup_id)?;
        match self {
            Self::Local(driver) => driver.find(instance_id, backup_id).await,
            Self::S3(driver) => driver.find(instance_id, backup_id).await,
            Self::Kopia(driver) => driver.find(instance_id, backup_id).await,
        }
    }

    pub async fn delete(&self, instance_id: &str, backup_id: &str) -> Result<(), BackupStoreError> {
        validate_backup_id(backup_id)?;
        match self {
            Self::Local(driver) => driver.delete(instance_id, backup_id).await,
            Self::S3(driver) => driver.delete(instance_id, backup_id).await,
            Self::Kopia(driver) => driver.delete(instance_id, backup_id).await,
        }
    }

    pub(crate) async fn materialize(
        &self,
        instance_id: &str,
        backup_id: &str,
        tmp_root: &Path,
        capacity: Option<crate::api::import_export::DiskCapacityReservation>,
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
        let slot = MATERIALIZATION_SLOTS.try_acquire().map_err(|_| {
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
        let backups = self.list(instance_id).await?;
        for backup in &backups {
            self.delete(instance_id, &backup.backup_id).await?;
        }
        Ok(backups.len())
    }
}

pub async fn build_manifest(
    backup_id: String,
    instance_id: String,
    protocol: Protocol,
    layout: BackupLayout,
    archive: &Path,
    catalog_available: bool,
) -> Result<StoredBackup, BackupStoreError> {
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
    })
}

pub async fn sha256_file(path: &Path) -> Result<String, BackupStoreError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use std::io::Read;

        let mut file = std::fs::File::open(&path)?;
        let mut buffer = [0_u8; 128 * 1024];
        let mut hasher = Sha256::new();
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok::<_, std::io::Error>(format!("{:x}", hasher.finalize()))
    })
    .await
    .map_err(|error| BackupStoreError::Runtime(format!("backup hash task failed: {error}")))?
    .map_err(|source| io_error("hash backup archive", source))
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
    let result = tokio::task::spawn_blocking(move || secure_private_dir(&path))
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
    tokio::task::spawn_blocking(move || crate::shared::files::atomic_write_private(&path, &bytes))
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
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "failed to remove backup file")
        }
    }
}

fn is_sha256(value: &str) -> bool {
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn materialized_guard_cleans_only_temporary_files() {
        let temp = tempfile::tempdir().unwrap();
        for temporary in [true, false] {
            let path = temp.path().join(if temporary {
                "remote.dump"
            } else {
                "local.dump"
            });
            tokio::fs::write(&path, b"backup").await.unwrap();
            drop(MaterializedBackup {
                path: path.clone(),
                temporary,
                capacity: None,
            });
            assert_eq!(path.exists(), !temporary);
        }
    }

    #[tokio::test]
    async fn cancelled_download_waiter_leaves_cleanup_with_the_worker() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("spool.dump");
        tokio::fs::write(&path, b"partial").await.unwrap();
        let guard = MaterializedBackup {
            path: path.clone(),
            temporary: true,
            capacity: None,
        };
        let (release, resume) = tokio::sync::oneshot::channel();
        let (started, waiting) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            started.send(()).unwrap();
            resume.await.unwrap();
            tokio::fs::write(&guard.path, b"complete").await.unwrap();
            guard
        });
        let completed = worker.abort_handle();
        let waiter = tokio::spawn(worker);
        waiting.await.unwrap();
        waiter.abort();
        let _ = waiter.await;
        assert!(path.exists(), "spool belongs to the still-running worker");
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !completed.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            !path.exists(),
            "unobserved worker result must clean its spool"
        );
    }

    #[test]
    fn backup_ids_cannot_address_internal_sidecars() {
        assert!(validate_backup_id("id.physical.tar.gz").is_ok());
        assert!(validate_backup_id("id.logical.dump").is_ok());
        assert!(validate_backup_id("id.physical.tar.gz.catalog.json").is_err());
        assert!(validate_backup_id("id.physical.tar.gz.metadata.json").is_err());
        assert!(validate_backup_id("../id.physical.tar.gz").is_err());
    }

    #[test]
    fn old_manifests_default_to_physical_while_new_ids_mark_logical_backups() {
        let old: StoredBackup = serde_json::from_value(serde_json::json!({
            "schema_version": BACKUP_MANIFEST_SCHEMA_VERSION,
            "backup_id": "old.physical.tar.gz",
            "instance_id": "inst_old",
            "protocol": "postgres",
            "size_bytes": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "created_at_unix": 1767225600,
            "sha256": "0".repeat(64),
            "catalog_available": false
        }))
        .unwrap();
        assert_eq!(old.layout, BackupLayout::Physical);
        assert!(new_backup_id(BackupLayout::Logical).ends_with(".logical.dump"));
    }

    #[tokio::test]
    async fn startup_cleanup_removes_only_incomplete_staging() {
        let temp = tempfile::tempdir().unwrap();
        let staging = temp.path().join(".staging").join("inst_one");
        tokio::fs::create_dir_all(&staging).await.unwrap();
        tokio::fs::write(staging.join("partial"), b"data")
            .await
            .unwrap();
        tokio::fs::write(temp.path().join("published.physical.tar.gz"), b"backup")
            .await
            .unwrap();

        assert!(cleanup_staging(temp.path()).await.unwrap());
        assert!(!temp.path().join(".staging").exists());
        assert!(temp.path().join("published.physical.tar.gz").exists());
    }

    #[tokio::test]
    async fn startup_cleanup_removes_backup_materializations_only() {
        let temp = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(temp.path().join("backup-materialized"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(temp.path().join("backup-catalogs"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(temp.path().join("remote-import"))
            .await
            .unwrap();

        assert_eq!(cleanup_materializations(temp.path()).await.unwrap(), 2);
        assert!(temp.path().join("remote-import").exists());
    }
}
