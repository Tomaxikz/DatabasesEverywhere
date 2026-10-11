use std::path::{Path, PathBuf};

use futures::future::BoxFuture;

use crate::io::files::read_bounded_private_file;
use crate::server::backup::{
    BackupBundle, BackupInventory, BackupStoreError, MAX_METADATA_BYTES, MaterializedBackup,
    StoredBackup, UnsupportedBackup, catalog_file_name, check_instance_id, io_error,
    metadata_file_name, prepare_private_dir, remove_file_if_exists, validate_backup_id,
};

#[derive(Debug, Clone)]
pub struct LocalBackupDriver {
    root: PathBuf,
}

impl super::BackupPreflight for LocalBackupDriver {
    fn preflight(&self) -> BoxFuture<'_, Result<(), BackupStoreError>> {
        Box::pin(Self::preflight(self))
    }
}

impl super::BackupCommit for LocalBackupDriver {
    fn commit<'a>(
        &'a self,
        bundle: &'a BackupBundle,
        manifest: &'a StoredBackup,
        // Local publication creates nothing beyond the backup id's files.
        _journal: &'a dyn super::PublicationJournal,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(Self::commit(self, bundle, manifest))
    }
}

impl super::BackupListing for LocalBackupDriver {
    fn inventory<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<BackupInventory, BackupStoreError>> {
        Box::pin(Self::inventory(self, instance_id))
    }

    fn find<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
    ) -> BoxFuture<'a, Result<StoredBackup, BackupStoreError>> {
        Box::pin(Self::find(self, instance_id, backup_id))
    }
}

impl super::BackupDelete for LocalBackupDriver {
    fn delete<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(Self::delete(self, instance_id, backup_id))
    }

    fn purge_unpublished<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
        _resources: &'a [super::PublicationResource],
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(Self::purge_unpublished(self, instance_id, backup_id))
    }
}

impl LocalBackupDriver {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub async fn preflight(&self) -> Result<(), BackupStoreError> {
        prepare_private_dir(&self.root, "backup root").await
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
        // The archive is the inventory commit marker, so every sidecar and the
        // archive contents must be durable before the archive becomes visible.
        sync_file(&bundle.archive, "staged backup archive").await?;
        sync_file(&bundle.metadata, "staged backup metadata").await?;
        if manifest.catalog_available {
            sync_file(&bundle.catalog, "staged backup catalog").await?;
        }

        let destination = self.instance_root(&manifest.instance_id)?;
        prepare_private_dir(&destination, "instance backup directory").await?;
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
        if let Err(error) = sync_file(&metadata, "published backup metadata").await {
            remove_file_if_exists(&metadata).await;
            remove_file_if_exists(&catalog).await;
            return Err(error);
        }
        if let Err(error) = rename_new(&bundle.archive, &archive, "publish backup archive").await {
            remove_file_if_exists(&metadata).await;
            remove_file_if_exists(&catalog).await;
            return Err(error);
        }
        // A failure here leaves a complete, verifiable bundle whose directory
        // entry may not yet be durable; report it rather than unpublishing.
        sync_file(&archive, "published backup archive").await
    }

    pub fn identity(&self) -> String {
        format!("local:{}", self.root.display())
    }

    pub async fn list(&self, instance_id: &str) -> Result<Vec<StoredBackup>, BackupStoreError> {
        Ok(self.inventory(instance_id).await?.backups)
    }

    pub async fn inventory(&self, instance_id: &str) -> Result<BackupInventory, BackupStoreError> {
        let root = self.instance_root(instance_id)?;
        match verify_real_directory(&root, "instance backup directory").await {
            Ok(()) => {}
            Err(BackupStoreError::NotFound) => return Ok(BackupInventory::default()),
            Err(error) => return Err(error),
        }
        let mut entries = tokio::fs::read_dir(&root)
            .await
            .map_err(|source| io_error("read instance backup directory", source))?;

        let mut inventory = BackupInventory::default();
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
            if validate_backup_id(backup_id).is_err() {
                continue;
            }
            match self.load_manifest(instance_id, backup_id, &metadata).await {
                Ok(manifest) => inventory.backups.push(manifest),
                // Newer formats are listed opaquely and never interpreted;
                // retention keeps them until an explicit delete.
                Err(BackupStoreError::UnsupportedFormat(reason)) => {
                    inventory.unsupported.push(UnsupportedBackup {
                        backup_id: backup_id.to_string(),
                        diagnostic: reason,
                    })
                }
                Err(error) => return Err(error),
            }
        }
        Ok(inventory)
    }

    /// Removes the archive (the commit marker) first, then its sidecars.
    pub async fn purge_unpublished(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<(), BackupStoreError> {
        validate_backup_id(backup_id)?;
        let root = self.instance_root(instance_id)?;
        match verify_real_directory(&root, "instance backup directory").await {
            Ok(()) => {}
            Err(BackupStoreError::NotFound) => return Ok(()),
            Err(error) => return Err(error),
        }
        for name in [
            backup_id.to_string(),
            metadata_file_name(backup_id),
            catalog_file_name(backup_id),
        ] {
            remove_regular_if_present(&root.join(name)).await?;
        }
        Ok(())
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
        self.load_manifest(instance_id, backup_id, &metadata).await
    }

    pub async fn delete(&self, instance_id: &str, backup_id: &str) -> Result<(), BackupStoreError> {
        let archive = self.verified_archive(instance_id, backup_id).await?;
        tokio::fs::remove_file(&archive)
            .await
            .map_err(|source| io_error("delete backup archive", source))?;
        let root = self.instance_root(instance_id)?;
        remove_file_if_exists(&root.join(metadata_file_name(backup_id))).await;
        remove_file_if_exists(&root.join(catalog_file_name(backup_id))).await;
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
            .load_manifest(instance_id, backup_id, &metadata)
            .await?;
        manifest.verify_archive(&path, "backup archive").await?;
        Ok(MaterializedBackup {
            path,
            temporary: false,
            capacity: None,
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
        let read_result =
            tokio::task::spawn_blocking(move || read_bounded_private_file(&path, max_bytes))
                .await
                .map_err(|error| {
                    BackupStoreError::Runtime(format!("catalog read task failed: {error}"))
                })?;
        match read_result {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(io_error("read backup catalog", source)),
        }
    }

    fn instance_root(&self, instance_id: &str) -> Result<PathBuf, BackupStoreError> {
        check_instance_id(instance_id)?;
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

    async fn load_manifest(
        &self,
        instance_id: &str,
        backup_id: &str,
        archive_metadata: &std::fs::Metadata,
    ) -> Result<StoredBackup, BackupStoreError> {
        let manifest_path = self
            .instance_root(instance_id)?
            .join(metadata_file_name(backup_id));
        let manifest = read_manifest(&manifest_path, instance_id).await?;
        if manifest.backup_id != backup_id || manifest.size_bytes != archive_metadata.len() {
            return Err(BackupStoreError::Corrupt(format!(
                "backup metadata does not match {backup_id}"
            )));
        }
        Ok(manifest)
    }
}

async fn read_manifest(path: &Path, instance_id: &str) -> Result<StoredBackup, BackupStoreError> {
    let path = path.to_path_buf();
    let result =
        tokio::task::spawn_blocking(move || read_bounded_private_file(&path, MAX_METADATA_BYTES))
            .await
            .map_err(|error| {
                BackupStoreError::Runtime(format!("metadata read task failed: {error}"))
            })?;
    let bytes = result.map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            BackupStoreError::Corrupt("backup metadata is missing".to_string())
        } else {
            io_error("read backup metadata", source)
        }
    })?;
    StoredBackup::from_json(&bytes, instance_id, "backup metadata")
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

async fn remove_regular_if_present(path: &Path) -> Result<(), BackupStoreError> {
    match tokio::fs::symlink_metadata(path).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect unpublished backup file", source)),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(BackupStoreError::Corrupt(format!(
                "refusing to remove {}: not a regular file",
                path.display()
            )))
        }
        Ok(_) => match tokio::fs::remove_file(path).await {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(io_error("remove unpublished backup file", error))
            }
            _ => Ok(()),
        },
    }
}

async fn sync_file(path: &Path, label: &str) -> Result<(), BackupStoreError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::io::files::sync_private_file(&path))
        .await
        .map_err(|error| BackupStoreError::Runtime(format!("{label} sync task failed: {error}")))?
        .map_err(|source| io_error(format!("sync {label}"), source))
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
    use crate::databases::protocol::Protocol;
    use crate::server::backup::{
        BackupBundle, BackupLayout, build_manifest, new_backup_id, test_details,
    };

    #[tokio::test]
    async fn local_driver_round_trips_a_bundle_and_catalog() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("backups");
        let driver = LocalBackupDriver::new(root.clone());
        driver.preflight().await.unwrap();
        let backup_id = new_backup_id(BackupLayout::Physical);
        let bundle = BackupBundle::create(&root, "inst_one", &backup_id)
            .await
            .unwrap();
        tokio::fs::write(&bundle.archive, b"archive").await.unwrap();
        bundle.write_catalog(br#"{"objects":[]}"#).await.unwrap();
        let manifest = build_manifest(
            backup_id.clone(),
            "inst_one".to_string(),
            Protocol::Postgres,
            BackupLayout::Physical,
            &bundle.archive,
            true,
            test_details(BackupLayout::Physical),
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
        let backup_id = new_backup_id(BackupLayout::Physical);
        let bundle = BackupBundle::create(&root, "inst_one", &backup_id)
            .await
            .unwrap();
        tokio::fs::write(&bundle.archive, b"archive").await.unwrap();
        let manifest = build_manifest(
            backup_id.clone(),
            "inst_one".to_string(),
            Protocol::Postgres,
            BackupLayout::Physical,
            &bundle.archive,
            false,
            test_details(BackupLayout::Physical),
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

    #[tokio::test]
    async fn local_driver_skips_but_never_reinterprets_future_formats() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("backups");
        let driver = LocalBackupDriver::new(root.clone());
        driver.preflight().await.unwrap();
        let instance_root = root.join("inst_one");
        prepare_private_dir(&instance_root, "test").await.unwrap();
        let backup_id = "future.physical.tar.gz";
        tokio::fs::write(instance_root.join(backup_id), b"archive")
            .await
            .unwrap();
        let future = serde_json::json!({
            "schema_version": 3,
            "backup_id": backup_id,
            "instance_id": "inst_one",
            "recipe": "unknown"
        });
        crate::io::files::atomic_write_private(
            &instance_root.join(metadata_file_name(backup_id)),
            &serde_json::to_vec(&future).unwrap(),
        )
        .unwrap();

        assert!(driver.list("inst_one").await.unwrap().is_empty());
        let inventory = driver.inventory("inst_one").await.unwrap();
        assert_eq!(inventory.unsupported.len(), 1);
        assert_eq!(inventory.unsupported[0].backup_id, backup_id);
        assert!(inventory.unsupported[0].diagnostic.contains("schema 3"));
        assert!(matches!(
            driver.find("inst_one", backup_id).await,
            Err(BackupStoreError::UnsupportedFormat(_))
        ));
        assert!(matches!(
            driver.materialize("inst_one", backup_id).await,
            Err(BackupStoreError::UnsupportedFormat(_))
        ));
        // Only an explicit delete removes it.
        driver.delete("inst_one", backup_id).await.unwrap();
        assert!(
            driver
                .inventory("inst_one")
                .await
                .unwrap()
                .unsupported
                .is_empty()
        );
        assert!(!instance_root.join(metadata_file_name(backup_id)).exists());
    }

    #[tokio::test]
    async fn local_purge_removes_partial_publications_idempotently() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("backups");
        let driver = LocalBackupDriver::new(root.clone());
        driver.preflight().await.unwrap();
        // Nothing published yet: purging is a no-op.
        driver
            .purge_unpublished("inst_one", "partial.physical.tar.gz")
            .await
            .unwrap();
        let instance_root = root.join("inst_one");
        prepare_private_dir(&instance_root, "test").await.unwrap();
        let backup_id = "partial.physical.tar.gz";
        // A crash between the metadata and archive renames leaves sidecars.
        for name in [metadata_file_name(backup_id), catalog_file_name(backup_id)] {
            tokio::fs::write(instance_root.join(name), b"partial")
                .await
                .unwrap();
        }
        tokio::fs::write(instance_root.join("other.physical.tar.gz"), b"keep")
            .await
            .unwrap();
        driver
            .purge_unpublished("inst_one", backup_id)
            .await
            .unwrap();
        driver
            .purge_unpublished("inst_one", backup_id)
            .await
            .unwrap();
        assert!(!instance_root.join(metadata_file_name(backup_id)).exists());
        assert!(!instance_root.join(catalog_file_name(backup_id)).exists());
        assert!(instance_root.join("other.physical.tar.gz").exists());
        assert!(
            driver
                .purge_unpublished("inst_one", "../escape")
                .await
                .is_err()
        );
    }
}
