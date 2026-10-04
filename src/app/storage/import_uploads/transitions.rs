use super::{
    ImportUploadArchiveFormat, ImportUploadRepository, ImportUploadStorageError,
    validation::{
        to_sqlite_integer, validate_catalog_json, validate_last_error, validate_sha256,
        validate_timestamp, validate_token,
    },
};

impl ImportUploadRepository {
    pub async fn mark_uploaded(
        &self,
        instance_id: &str,
        upload_id: &str,
        size_bytes: u64,
        sha256: &str,
        updated_at: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        validate_sha256(sha256)?;
        validate_timestamp("updated_at", updated_at)?;
        let size_bytes = to_sqlite_integer(size_bytes, "size_bytes")?;
        let result = sqlx::query(
            r#"
            UPDATE import_uploads
            SET state = 'uploaded',
                sha256 = ?4,
                catalog_json = NULL,
                last_error = NULL,
                updated_at = ?5
            WHERE instance_id = ?1
              AND upload_id = ?2
              AND state = 'uploading'
              AND size_bytes = ?3
            "#,
        )
        .bind(instance_id)
        .bind(upload_id)
        .bind(size_bytes)
        .bind(sha256)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_processing(
        &self,
        instance_id: &str,
        upload_id: &str,
        updated_at: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        validate_timestamp("updated_at", updated_at)?;
        let result = sqlx::query(
            r#"
            UPDATE import_uploads
            SET state = 'processing', last_error = NULL, updated_at = ?3
            WHERE instance_id = ?1 AND upload_id = ?2 AND state = 'ready'
            "#,
        )
        .bind(instance_id)
        .bind(upload_id)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_ready(
        &self,
        instance_id: &str,
        upload_id: &str,
        catalog_json: Option<&str>,
        updated_at: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        validate_catalog_json(catalog_json)?;
        validate_timestamp("updated_at", updated_at)?;
        let result = sqlx::query(
            r#"
            UPDATE import_uploads
            SET state = 'ready', catalog_json = ?3, last_error = NULL, updated_at = ?4
            WHERE instance_id = ?1
              AND upload_id = ?2
              AND state = 'uploaded'
            "#,
        )
        .bind(instance_id)
        .bind(upload_id)
        .bind(catalog_json)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn restore_ready(
        &self,
        instance_id: &str,
        upload_id: &str,
        archive_format: Option<ImportUploadArchiveFormat>,
        catalog_json: Option<&str>,
        last_error: Option<&str>,
        updated_at: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        validate_catalog_json(catalog_json)?;
        if let Some(last_error) = last_error {
            validate_last_error(last_error)?;
        }
        validate_timestamp("updated_at", updated_at)?;
        let result = sqlx::query(
            r#"
            UPDATE import_uploads
            SET state = 'ready',
                archive_format = COALESCE(?3, archive_format),
                catalog_json = ?4,
                last_error = ?5,
                updated_at = ?6
            WHERE instance_id = ?1 AND upload_id = ?2 AND state = 'processing'
            "#,
        )
        .bind(instance_id)
        .bind(upload_id)
        .bind(archive_format.map(ImportUploadArchiveFormat::as_str))
        .bind(catalog_json)
        .bind(last_error)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_failed(
        &self,
        instance_id: &str,
        upload_id: &str,
        last_error: &str,
        updated_at: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        validate_last_error(last_error)?;
        validate_timestamp("updated_at", updated_at)?;
        let result = sqlx::query(
            r#"
            UPDATE import_uploads
            SET state = 'failed', last_error = ?3, updated_at = ?4
            WHERE instance_id = ?1
              AND upload_id = ?2
              AND state IN ('uploading', 'uploaded', 'processing', 'ready')
            "#,
        )
        .bind(instance_id)
        .bind(upload_id)
        .bind(last_error)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn claim_for_job(
        &self,
        instance_id: &str,
        upload_id: &str,
        job_id: &str,
        updated_at: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        validate_token("job_id", job_id)?;
        validate_timestamp("updated_at", updated_at)?;
        let result = sqlx::query(
            r#"
            UPDATE import_uploads
            SET state = 'importing', claimed_job_id = ?3, last_error = NULL, updated_at = ?4
            WHERE instance_id = ?1
              AND upload_id = ?2
              AND state = 'ready'
              AND unixepoch(expires_at) > unixepoch(?4)
            "#,
        )
        .bind(instance_id)
        .bind(upload_id)
        .bind(job_id)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn release_failed_claim(
        &self,
        instance_id: &str,
        upload_id: &str,
        job_id: &str,
        last_error: &str,
        updated_at: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        validate_token("job_id", job_id)?;
        validate_last_error(last_error)?;
        validate_timestamp("updated_at", updated_at)?;
        let result = sqlx::query(
            r#"
            UPDATE import_uploads
            SET state = 'ready', claimed_job_id = NULL, last_error = ?4, updated_at = ?5
            WHERE instance_id = ?1
              AND upload_id = ?2
              AND state = 'importing'
              AND claimed_job_id = ?3
            "#,
        )
        .bind(instance_id)
        .bind(upload_id)
        .bind(job_id)
        .bind(last_error)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_consumed(
        &self,
        instance_id: &str,
        upload_id: &str,
        job_id: &str,
        updated_at: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        validate_token("job_id", job_id)?;
        validate_timestamp("updated_at", updated_at)?;
        let result = sqlx::query(
            r#"
            UPDATE import_uploads
            SET state = 'consumed', last_error = NULL, updated_at = ?4
            WHERE instance_id = ?1
              AND upload_id = ?2
              AND state = 'importing'
              AND claimed_job_id = ?3
            "#,
        )
        .bind(instance_id)
        .bind(upload_id)
        .bind(job_id)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn claim_for_deletion(
        &self,
        instance_id: &str,
        upload_id: &str,
        updated_at: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        validate_timestamp("updated_at", updated_at)?;
        let result = sqlx::query(
            r#"
            UPDATE import_uploads
            SET state = 'deleting', claimed_job_id = NULL, updated_at = ?3
            WHERE instance_id = ?1
              AND upload_id = ?2
              AND state IN ('ready', 'uploaded', 'failed', 'consumed')
            "#,
        )
        .bind(instance_id)
        .bind(upload_id)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn abort_uploading(
        &self,
        instance_id: &str,
        upload_id: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        let result = sqlx::query(
            "DELETE FROM import_uploads WHERE instance_id = ?1 AND upload_id = ?2 AND state = 'uploading'",
        )
        .bind(instance_id)
        .bind(upload_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn finalize_delete(
        &self,
        instance_id: &str,
        upload_id: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        let result = sqlx::query(
            "DELETE FROM import_uploads WHERE instance_id = ?1 AND upload_id = ?2 AND state = 'deleting'",
        )
        .bind(instance_id)
        .bind(upload_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<u64, ImportUploadStorageError> {
        let result = sqlx::query("DELETE FROM import_uploads WHERE instance_id = ?1")
            .bind(instance_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
