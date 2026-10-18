use std::path::Path;

use super::{METADATA_KEY_SUFFIX, S3BackupDriver};
use crate::server::backup::{
    BackupBundle, BackupInventory, BackupStoreError, MAX_METADATA_BYTES, StoredBackup,
    UnsupportedBackup,
    drivers::{PublicationJournal, PublicationResource},
    io_error, sha256_file, validate_backup_id,
};

impl S3BackupDriver {
    pub async fn preflight(&self) -> Result<(), BackupStoreError> {
        if self.credentials.access_key_id.is_empty()
            || self.credentials.secret_access_key.is_empty()
        {
            return Err(BackupStoreError::InvalidConfiguration(
                "S3 credentials are empty".to_string(),
            ));
        }
        Ok(())
    }

    pub async fn commit(
        &self,
        bundle: &BackupBundle,
        manifest: &StoredBackup,
        journal: &dyn PublicationJournal,
    ) -> Result<(), BackupStoreError> {
        manifest.validate(&manifest.instance_id)?;
        let archive_key = self.archive_key(&manifest.instance_id, &manifest.backup_id)?;
        let catalog_key = self.catalog_key(&manifest.instance_id, &manifest.backup_id)?;
        let metadata_key = self.metadata_key(&manifest.instance_id, &manifest.backup_id)?;

        if let Err(error) = self
            .put_file(
                &archive_key,
                &bundle.archive,
                manifest.size_bytes,
                &manifest.sha256,
                journal,
            )
            .await
        {
            // A timed-out PUT can have reached S3 even when the client never
            // received its response. Keep such an object out of the inventory.
            self.cleanup_incomplete(&archive_key, None, None).await;
            return Err(error);
        }
        if manifest.catalog_available {
            let catalog_metadata = tokio::fs::metadata(&bundle.catalog)
                .await
                .map_err(|source| io_error("inspect backup catalog", source))?;
            let catalog_sha = sha256_file(&bundle.catalog).await?;
            if let Err(error) = self
                .put_file(
                    &catalog_key,
                    &bundle.catalog,
                    catalog_metadata.len(),
                    &catalog_sha,
                    journal,
                )
                .await
            {
                // Include the catalog key because its PUT may have committed
                // remotely before a transport error reached this process.
                self.cleanup_incomplete(&archive_key, Some(&catalog_key), None)
                    .await;
                return Err(error);
            }
        }
        let metadata = manifest.to_json()?;
        if let Err(error) = self.put_bytes(&metadata_key, metadata).await {
            self.cleanup_incomplete(
                &archive_key,
                manifest.catalog_available.then_some(catalog_key.as_str()),
                Some(&metadata_key),
            )
            .await;
            return Err(error);
        }
        Ok(())
    }

    pub fn identity(&self) -> String {
        format!(
            "s3:{}|{}|{}",
            self.base,
            self.config.bucket,
            self.config.prefix.trim_matches('/')
        )
    }

    pub async fn list(&self, instance_id: &str) -> Result<Vec<StoredBackup>, BackupStoreError> {
        Ok(self.inventory(instance_id).await?.backups)
    }

    pub async fn inventory(&self, instance_id: &str) -> Result<BackupInventory, BackupStoreError> {
        let prefix = self.instance_prefix(instance_id)?;
        let keys = self.list_keys(&prefix).await?;
        let mut inventory = BackupInventory::default();
        for key in keys {
            if !key.ends_with(METADATA_KEY_SUFFIX) {
                continue;
            }
            match self.get_manifest_by_key(instance_id, &key).await {
                Ok(manifest) => inventory.backups.push(manifest),
                Err(BackupStoreError::NotFound) => {}
                // Newer formats are listed opaquely; retention keeps them.
                Err(BackupStoreError::UnsupportedFormat(reason)) => {
                    match backup_id_from_metadata_key(&prefix, &key) {
                        Some(backup_id) => inventory.unsupported.push(UnsupportedBackup {
                            backup_id,
                            diagnostic: reason,
                        }),
                        None => tracing::warn!(
                            object_key = %key,
                            %reason,
                            "ignored unsupported S3 backup metadata with an invalid key"
                        ),
                    }
                }
                Err(error @ (BackupStoreError::InvalidBackupId | BackupStoreError::Corrupt(_))) => {
                    tracing::warn!(
                        object_key = %key,
                        %error,
                        "ignored invalid S3 backup metadata"
                    )
                }
                Err(error) => return Err(error),
            }
        }
        Ok(inventory)
    }

    /// Hides the metadata first, aborts every multipart upload of the archive
    /// and catalog keys (journaled or listed) so none can complete into an
    /// object later, then removes the catalog and archive. Every object may
    /// already be absent.
    pub async fn purge_unpublished(
        &self,
        instance_id: &str,
        backup_id: &str,
        resources: &[PublicationResource],
    ) -> Result<(), BackupStoreError> {
        let metadata = self.metadata_key(instance_id, backup_id)?;
        let catalog = self.catalog_key(instance_id, backup_id)?;
        let archive = self.archive_key(instance_id, backup_id)?;
        let journaled = journaled_uploads(resources, &[&archive, &catalog])?;
        self.delete_object(&metadata, true).await?;
        for key in [&archive, &catalog] {
            let upload_ids = journaled
                .iter()
                .filter(|(upload_key, _)| upload_key == key)
                .map(|(_, upload_id)| *upload_id)
                .collect::<Vec<_>>();
            self.purge_multipart_uploads(key, &upload_ids).await?;
        }
        for key in [catalog, archive] {
            self.delete_object(&key, true).await?;
        }
        Ok(())
    }

    pub async fn find(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<StoredBackup, BackupStoreError> {
        let key = self.metadata_key(instance_id, backup_id)?;
        self.get_manifest_by_key(instance_id, &key).await
    }

    pub async fn delete(&self, instance_id: &str, backup_id: &str) -> Result<(), BackupStoreError> {
        // An unsupported format cannot say whether it has a catalog, so an
        // explicit delete removes every object of the id.
        let catalog_available = match self.find(instance_id, backup_id).await {
            Ok(manifest) => manifest.catalog_available,
            Err(BackupStoreError::UnsupportedFormat(_)) => true,
            Err(error) => return Err(error),
        };
        let archive = self.archive_key(instance_id, backup_id)?;
        let catalog = self.catalog_key(instance_id, backup_id)?;
        let metadata = self.metadata_key(instance_id, backup_id)?;
        self.delete_object(&archive, true).await?;
        if catalog_available {
            self.delete_object(&catalog, true).await?;
        }
        self.delete_object(&metadata, false).await
    }

    pub async fn materialize(
        &self,
        instance_id: &str,
        backup_id: &str,
        destination: &Path,
    ) -> Result<(), BackupStoreError> {
        let manifest = self.find(instance_id, backup_id).await?;
        let key = self.archive_key(instance_id, backup_id)?;
        self.download_file(&key, destination, &manifest).await
    }

    pub async fn read_catalog(
        &self,
        instance_id: &str,
        backup_id: &str,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, BackupStoreError> {
        let manifest = self.find(instance_id, backup_id).await?;
        if !manifest.catalog_available {
            return Ok(None);
        }
        let key = self.catalog_key(instance_id, backup_id)?;
        self.get_bytes(&key, max_bytes).await.map(Some)
    }

    pub async fn delete_instance(&self, instance_id: &str) -> Result<usize, BackupStoreError> {
        let prefix = self.instance_prefix(instance_id)?;
        let mut keys = self.list_keys(&prefix).await?;
        let published = keys
            .iter()
            .filter(|key| key.ends_with(METADATA_KEY_SUFFIX))
            .count();
        // Hide published entries first, then remove archives, catalogs, and
        // any crash-orphaned objects that never received metadata.
        keys.sort_by_key(|key| !key.ends_with(METADATA_KEY_SUFFIX));
        for key in keys {
            self.delete_object(&key, true).await?;
        }
        Ok(published)
    }

    async fn get_manifest_by_key(
        &self,
        instance_id: &str,
        key: &str,
    ) -> Result<StoredBackup, BackupStoreError> {
        let bytes = self.get_bytes(key, MAX_METADATA_BYTES).await?;
        let manifest = StoredBackup::from_json(&bytes, instance_id, "S3 backup metadata")?;
        if self.metadata_key(instance_id, &manifest.backup_id)? != key {
            return Err(BackupStoreError::Corrupt(
                "S3 backup metadata key does not match its backup id".to_string(),
            ));
        }
        Ok(manifest)
    }
}

/// Journaled `(key, upload id)` pairs. A resource of another provider or of
/// a key this backup does not own is never acted on.
fn journaled_uploads<'a>(
    resources: &'a [PublicationResource],
    owned: &[&str],
) -> Result<Vec<(&'a str, &'a str)>, BackupStoreError> {
    resources
        .iter()
        .map(|resource| match resource {
            PublicationResource::S3MultipartUpload { key, upload_id }
                if owned.contains(&key.as_str()) =>
            {
                Ok((key.as_str(), upload_id.as_str()))
            }
            other => Err(BackupStoreError::Corrupt(format!(
                "publication journal holds {other:?}, which this S3 backup does not own"
            ))),
        })
        .collect()
}

fn backup_id_from_metadata_key(prefix: &str, key: &str) -> Option<String> {
    let backup_id = key
        .strip_prefix(prefix)?
        .strip_suffix(METADATA_KEY_SUFFIX)?;
    validate_backup_id(backup_id).ok()?;
    Some(backup_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_entries_take_their_id_from_the_metadata_key() {
        let prefix = "dbev/instances/inst_one/backups/";
        assert_eq!(
            backup_id_from_metadata_key(
                prefix,
                "dbev/instances/inst_one/backups/new.physical.tar.gz.metadata.json"
            )
            .as_deref(),
            Some("new.physical.tar.gz")
        );
        for key in [
            "dbev/instances/inst_two/backups/new.physical.tar.gz.metadata.json",
            "dbev/instances/inst_one/backups/new.physical.tar.gz",
            "dbev/instances/inst_one/backups/../x.metadata.json",
            "dbev/instances/inst_one/backups/.metadata.json",
        ] {
            assert!(backup_id_from_metadata_key(prefix, key).is_none(), "{key}");
        }
    }

    #[test]
    fn only_journaled_uploads_of_owned_keys_are_aborted() {
        let upload = |key: &str| PublicationResource::S3MultipartUpload {
            key: key.to_string(),
            upload_id: "id".to_string(),
        };
        let owned = ["p/a", "p/a.catalog.json"];
        assert_eq!(
            journaled_uploads(&[upload("p/a")], &owned).unwrap(),
            vec![("p/a", "id")]
        );
        assert!(journaled_uploads(&[upload("p/other")], &owned).is_err());
        assert!(
            journaled_uploads(
                &[PublicationResource::KopiaSourcePath("/p".to_string())],
                &owned
            )
            .is_err()
        );
    }
}
