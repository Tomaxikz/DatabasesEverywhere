use super::S3BackupDriver;
use crate::server::backup::{
    BackupStoreError, catalog_file_name, check_instance_id, metadata_file_name, validate_backup_id,
};

impl S3BackupDriver {
    pub(super) fn instance_prefix(&self, instance_id: &str) -> Result<String, BackupStoreError> {
        check_instance_id(instance_id)?;
        let prefix = self.config.prefix.trim_matches('/');
        let relative = format!("instances/{instance_id}/backups/");
        Ok(if prefix.is_empty() {
            relative
        } else {
            format!("{prefix}/{relative}")
        })
    }

    pub(super) fn archive_key(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<String, BackupStoreError> {
        validate_backup_id(backup_id)?;
        Ok(format!("{}{backup_id}", self.instance_prefix(instance_id)?))
    }

    pub(super) fn catalog_key(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<String, BackupStoreError> {
        validate_backup_id(backup_id)?;
        Ok(format!(
            "{}{}",
            self.instance_prefix(instance_id)?,
            catalog_file_name(backup_id)
        ))
    }

    pub(super) fn metadata_key(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<String, BackupStoreError> {
        validate_backup_id(backup_id)?;
        Ok(format!(
            "{}{}",
            self.instance_prefix(instance_id)?,
            metadata_file_name(backup_id)
        ))
    }

    pub(super) async fn cleanup_incomplete(
        &self,
        archive: &str,
        catalog: Option<&str>,
        metadata: Option<&str>,
    ) {
        if let Some(metadata) = metadata {
            self.cleanup_object(metadata).await;
        }
        if let Some(catalog) = catalog {
            self.cleanup_object(catalog).await;
        }
        self.cleanup_object(archive).await;
    }

    async fn cleanup_object(&self, key: &str) {
        if let Err(error) = self.delete_object(key, true).await {
            tracing::warn!(
                object_key = key,
                %error,
                "failed to remove an incomplete S3 backup object"
            );
        }
    }
}
