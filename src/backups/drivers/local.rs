use std::{
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::backups::{
    BACKUP_MANIFEST_SCHEMA_VERSION, BackupBundle, BackupStoreError, MaterializedBackup,
    StoredBackup, catalog_file_name, ensure_private_directory, io_error, is_sha256,
    metadata_file_name, remove_file_if_exists, sha256_file, system_time_fields, validate_backup_id,
};
use crate::shared::{files::read_private_regular_file_bounded, ids::validate_instance_id};

const MAX_METADATA_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct LocalBackupDriver {
    root: PathBuf,
}

impl LocalBackupDriver {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub async fn preflight(&self) -> Result<(), BackupStoreError> {
        ensure_private_directory(&self.root, "backup root").await
    }

    pub async fn commit(
        &self,
        bundle: &BackupBundle,
        manifest: &StoredBackup,
    ) -> Result<(), BackupStoreError> {
        manifest.validate(&manifest.instance_id)?;
        verify_regular_file(&bundle.archive, "staged backup archive").await?;
        verify_regular_file(&bundle.metadata, "staged backup metadata").await?;
        if manifest.catalog_available {
            verify_regular_file(&bundle.catalog, "staged backup catalog").await?;
        }

        let destination = self.instance_root(&manifest.instance_id)?;
        ensure_private_directory(&destination, "instance backup directory").await?;
        let archive = destination.join(&manifest.backup_id);
        let metadata = destination.join(metadata_file_name(&manifest.backup_id));
        let catalog = destination.join(catalog_file_name(&manifest.backup_id));

        if manifest.catalog_available {
            rename_new(&bundle.catalog, &catalog, "publish backup catalog").await?;
        }
        if let Err(error) = rename_new(&bundle.metadata, &metadata, "publish backup metadata").await
        {
            remove_file_if_exists(&catalog).await;
            return Err(error);
        }
        if let Err(error) = rename_new(&bundle.archive, &archive, "publish backup archive").await {
            remove_file_if_exists(&metadata).await;
            remove_file_if_exists(&catalog).await;
            return Err(error);
        }
        Ok(())
    }

    pub async fn list(&self, instance_id: &str) -> Result<Vec<StoredBackup>, BackupStoreError> {
        let root = self.instance_root(instance_id)?;
        match verify_real_directory(&root, "instance backup directory").await {
            Ok(()) => {}
            Err(BackupStoreError::NotFound) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        }
        let mut entries = tokio::fs::read_dir(&root)
            .await
            .map_err(|source| io_error("read instance backup directory", source))?;

        let mut backups = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|source| io_error("read backup directory entry", source))?
        {
            let path = entry.path();
            let metadata = tokio::fs::symlink_metadata(&path)
                .await
                .map_err(|source| io_error("inspect backup directory entry", source))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                continue;
            }
            let Some(backup_id) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if validate_backup_id(backup_id).is_err()
                || backup_id.ends_with(".catalog.json")
                || backup_id.ends_with(".metadata.json")
                || backup_id.ends_with(".sha256")
            {
                continue;
            }
            backups.push(
                self.read_manifest_or_legacy(instance_id, backup_id, &path, &metadata)
                    .await?,
            );
        }
        Ok(backups)
    }

    pub async fn find(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<StoredBackup, BackupStoreError> {
        let path = self.verified_archive(instance_id, backup_id).await?;
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|source| io_error("inspect backup archive", source))?;
        self.read_manifest_or_legacy(instance_id, backup_id, &path, &metadata)
            .await
    }

    pub async fn delete(&self, instance_id: &str, backup_id: &str) -> Result<(), BackupStoreError> {
        let archive = self.verified_archive(instance_id, backup_id).await?;
        tokio::fs::remove_file(&archive)
            .await
            .map_err(|source| io_error("delete backup archive", source))?;
        let root = self.instance_root(instance_id)?;
        remove_file_if_exists(&root.join(metadata_file_name(backup_id))).await;
        remove_file_if_exists(&root.join(catalog_file_name(backup_id))).await;
        remove_file_if_exists(&root.join(format!("{backup_id}.sha256"))).await;
        Ok(())
    }

    pub async fn materialize(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<MaterializedBackup, BackupStoreError> {
        let path = self.verified_archive(instance_id, backup_id).await?;
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|source| io_error("inspect backup archive", source))?;
        let manifest = self
            .read_manifest_or_legacy(instance_id, backup_id, &path, &metadata)
            .await?;
        if manifest.protocol.is_some() {
            let actual_sha256 = sha256_file(&path).await?;
            if actual_sha256 != manifest.sha256 {
                return Err(BackupStoreError::Corrupt(format!(
                    "backup archive checksum does not match {backup_id}"
                )));
            }
        }
        Ok(MaterializedBackup {
            path,
            temporary: false,
        })
    }

    pub async fn read_catalog(
        &self,
        instance_id: &str,
        backup_id: &str,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, BackupStoreError> {
        let _ = self.verified_archive(instance_id, backup_id).await?;
        let path = self
            .instance_root(instance_id)?
            .join(catalog_file_name(backup_id));
        let path_for_read = path.clone();
        match tokio::task::spawn_blocking(move || {
            read_private_regular_file_bounded(&path_for_read, max_bytes)
        })
        .await
        .map_err(|error| BackupStoreError::Runtime(format!("catalog read task failed: {error}")))?
        {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(io_error("read backup catalog", source)),
        }
    }

    fn instance_root(&self, instance_id: &str) -> Result<PathBuf, BackupStoreError> {
        validate_instance_id(instance_id)
            .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        Ok(self.root.join(instance_id))
    }

    async fn verified_archive(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<PathBuf, BackupStoreError> {
        validate_backup_id(backup_id)?;
        let root = self.instance_root(instance_id)?;
        verify_real_directory(&root, "instance backup directory").await?;
        let canonical_root = tokio::fs::canonicalize(&root)
            .await
            .map_err(|source| io_error("resolve instance backup directory", source))?;
        let path = root.join(backup_id);
        let metadata =
            tokio::fs::symlink_metadata(&path)
                .await
                .map_err(|source| match source.kind() {
                    std::io::ErrorKind::NotFound => BackupStoreError::NotFound,
                    _ => io_error("inspect backup archive", source),
                })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(BackupStoreError::Corrupt(
                "backup archive must be a real regular file".to_string(),
            ));
        }
        let canonical = tokio::fs::canonicalize(path)
            .await
            .map_err(|source| io_error("resolve backup archive", source))?;
        if !canonical.starts_with(canonical_root) {
            return Err(BackupStoreError::Corrupt(
                "backup archive resolves outside its instance root".to_string(),
            ));
        }
        Ok(canonical)
    }

    async fn read_manifest_or_legacy(
        &self,
        instance_id: &str,
        backup_id: &str,
        archive: &Path,
        archive_metadata: &std::fs::Metadata,
    ) -> Result<StoredBackup, BackupStoreError> {
        let manifest_path = self
            .instance_root(instance_id)?
            .join(metadata_file_name(backup_id));
        if let Some(manifest) = read_manifest(&manifest_path).await? {
            manifest.validate(instance_id)?;
            if manifest.backup_id != backup_id
                || manifest.size_bytes != archive_metadata.len()
                || !is_sha256(&manifest.sha256)
            {
                return Err(BackupStoreError::Corrupt(format!(
                    "backup metadata does not match {backup_id}"
                )));
            }
            return Ok(manifest);
        }

        let (created_at, created_at_unix) = system_time_fields(
            archive_metadata
                .modified()
                .unwrap_or(SystemTime::UNIX_EPOCH),
        )?;
        let catalog_available = tokio::fs::symlink_metadata(
            self.instance_root(instance_id)?
                .join(catalog_file_name(backup_id)),
        )
        .await
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink());
        Ok(StoredBackup {
            schema_version: BACKUP_MANIFEST_SCHEMA_VERSION,
            backup_id: backup_id.to_string(),
            instance_id: instance_id.to_string(),
            protocol: None,
            size_bytes: archive_metadata.len(),
            created_at,
            created_at_unix,
            sha256: sha256_file(archive).await?,
            catalog_available,
        })
    }
}

async fn read_manifest(path: &Path) -> Result<Option<StoredBackup>, BackupStoreError> {
    let path = path.to_path_buf();
    let result = tokio::task::spawn_blocking(move || {
        read_private_regular_file_bounded(&path, MAX_METADATA_BYTES)
    })
    .await
    .map_err(|error| BackupStoreError::Runtime(format!("metadata read task failed: {error}")))?;
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("read backup metadata", source)),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| BackupStoreError::Corrupt(format!("invalid backup metadata: {error}")))
}

async fn verify_real_directory(path: &Path, label: &str) -> Result<(), BackupStoreError> {
    let metadata =
        tokio::fs::symlink_metadata(path)
            .await
            .map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => BackupStoreError::NotFound,
                _ => io_error(format!("inspect {label}"), source),
            })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackupStoreError::Corrupt(format!(
            "{label} must be a real directory"
        )));
    }
    Ok(())
}

async fn verify_regular_file(path: &Path, label: &str) -> Result<(), BackupStoreError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|source| io_error(format!("inspect {label}"), source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackupStoreError::Corrupt(format!(
            "{label} must be a real regular file"
        )));
    }
    Ok(())
}

async fn rename_new(
    source: &Path,
    destination: &Path,
    operation: &str,
) -> Result<(), BackupStoreError> {
    if tokio::fs::symlink_metadata(destination).await.is_ok() {
        return Err(BackupStoreError::Corrupt(format!(
            "refusing to replace existing backup file {}",
            destination.display()
        )));
    }
    tokio::fs::rename(source, destination)
        .await
        .map_err(|source| io_error(operation, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backups::{BackupBundle, build_manifest, new_backup_id};
    use crate::shared::protocol::Protocol;

    #[tokio::test]
    async fn local_driver_round_trips_a_bundle_and_catalog() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("backups");
        let driver = LocalBackupDriver::new(root.clone());
        driver.preflight().await.unwrap();
        let backup_id = new_backup_id();
        let bundle = BackupBundle::create(&root, "inst_one", &backup_id)
            .await
            .unwrap();
        tokio::fs::write(&bundle.archive, b"archive").await.unwrap();
        bundle.write_catalog(br#"{"objects":[]}"#).await.unwrap();
        let manifest = build_manifest(
            backup_id.clone(),
            "inst_one".to_string(),
            Protocol::Postgres,
            &bundle.archive,
            true,
        )
        .await
        .unwrap();
        bundle.write_metadata(&manifest).await.unwrap();

        driver.commit(&bundle, &manifest).await.unwrap();

        let listed = driver.list("inst_one").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].sha256, manifest.sha256);
        assert_eq!(
            driver
                .read_catalog("inst_one", &backup_id, 1024)
                .await
                .unwrap()
                .unwrap(),
            br#"{"objects":[]}"#
        );
        assert!(
            !driver
                .materialize("inst_one", &backup_id)
                .await
                .unwrap()
                .temporary
        );
        driver.delete("inst_one", &backup_id).await.unwrap();
        assert!(driver.list("inst_one").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn local_driver_rejects_a_tampered_managed_archive() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("backups");
        let driver = LocalBackupDriver::new(root.clone());
        driver.preflight().await.unwrap();
        let backup_id = new_backup_id();
        let bundle = BackupBundle::create(&root, "inst_one", &backup_id)
            .await
            .unwrap();
        tokio::fs::write(&bundle.archive, b"archive").await.unwrap();
        let manifest = build_manifest(
            backup_id.clone(),
            "inst_one".to_string(),
            Protocol::Postgres,
            &bundle.archive,
            false,
        )
        .await
        .unwrap();
        bundle.write_metadata(&manifest).await.unwrap();
        driver.commit(&bundle, &manifest).await.unwrap();

        tokio::fs::write(root.join("inst_one").join(&backup_id), b"changed")
            .await
            .unwrap();
        let error = driver
            .materialize("inst_one", &backup_id)
            .await
            .unwrap_err();
        assert!(matches!(error, BackupStoreError::Corrupt(_)));
    }
}
