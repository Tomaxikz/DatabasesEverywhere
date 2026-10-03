use super::*;

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

    pub async fn list(&self, instance_id: &str) -> Result<Vec<StoredBackup>, BackupStoreError> {
        let prefix = self.instance_prefix(instance_id)?;
        let keys = self.list_keys(&prefix).await?;
        let mut backups = Vec::new();
        for key in keys {
            if !key.ends_with(METADATA_KEY_SUFFIX) {
                continue;
            }
            match self.get_manifest_by_key(instance_id, &key).await {
                Ok(manifest) => backups.push(manifest),
                Err(BackupStoreError::NotFound) => {}
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
        Ok(backups)
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
        let manifest = self.find(instance_id, backup_id).await?;
        let archive = self.archive_key(instance_id, backup_id)?;
        let catalog = self.catalog_key(instance_id, backup_id)?;
        let metadata = self.metadata_key(instance_id, backup_id)?;
        self.delete_object(&archive, true).await?;
        if manifest.catalog_available {
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
