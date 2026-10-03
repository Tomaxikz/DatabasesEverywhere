use super::*;

impl ImportUploadRepository {
    pub async fn list_recoverable(
        &self,
        limit: u32,
    ) -> Result<Vec<ImportUpload>, ImportUploadStorageError> {
        self.list_recoverable_after(None, limit).await
    }

    pub async fn list_recoverable_after(
        &self,
        after_upload_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<ImportUpload>, ImportUploadStorageError> {
        let rows = sqlx::query(
            r#"
            SELECT upload_id, instance_id, original_filename, stored_filename, protocol, state,
                   size_bytes, sha256, catalog_json, last_error, claimed_job_id, created_at,
                   updated_at, expires_at, archive_format
            FROM import_uploads
            WHERE state IN ('uploading', 'uploaded', 'processing', 'importing', 'consumed', 'deleting')
              AND (?1 IS NULL OR upload_id > ?1)
            ORDER BY upload_id
            LIMIT ?2
            "#,
        )
        .bind(after_upload_id)
        .bind(i64::from(limit.clamp(1, MAX_SCAN_LIMIT)))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_upload).collect()
    }

    pub async fn list_cleanup_after(
        &self,
        after_upload_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<ImportUpload>, ImportUploadStorageError> {
        let rows = sqlx::query(
            r#"
            SELECT upload_id, instance_id, original_filename, stored_filename, protocol, state,
                   size_bytes, sha256, catalog_json, last_error, claimed_job_id, created_at,
                   updated_at, expires_at, archive_format
            FROM import_uploads
            WHERE state IN ('consumed', 'deleting')
              AND (?1 IS NULL OR upload_id > ?1)
            ORDER BY upload_id
            LIMIT ?2
            "#,
        )
        .bind(after_upload_id)
        .bind(i64::from(limit.clamp(1, MAX_SCAN_LIMIT)))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_upload).collect()
    }

    pub async fn list_recovery_after(
        &self,
        after_upload_id: Option<&str>,
        now: &str,
        minimum_age_seconds: u32,
        limit: u32,
    ) -> Result<Vec<ImportUpload>, ImportUploadStorageError> {
        validate_timestamp("now", now)?;
        let rows = sqlx::query(
            r#"
            SELECT upload_id, instance_id, original_filename, stored_filename, protocol, state,
                   size_bytes, sha256, catalog_json, last_error, claimed_job_id, created_at,
                   updated_at, expires_at, archive_format
            FROM import_uploads
            WHERE state IN ('uploading', 'uploaded', 'processing', 'importing')
              AND (?1 IS NULL OR upload_id > ?1)
              AND unixepoch(updated_at) <= unixepoch(?2) - ?3
            ORDER BY upload_id
            LIMIT ?4
            "#,
        )
        .bind(after_upload_id)
        .bind(now)
        .bind(i64::from(minimum_age_seconds))
        .bind(i64::from(limit.clamp(1, MAX_SCAN_LIMIT)))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_upload).collect()
    }

    pub async fn list_expired(
        &self,
        now: &str,
        limit: u32,
    ) -> Result<Vec<ImportUpload>, ImportUploadStorageError> {
        validate_timestamp("now", now)?;
        let rows = sqlx::query(
            r#"
            SELECT upload_id, instance_id, original_filename, stored_filename, protocol, state,
                   size_bytes, sha256, catalog_json, last_error, claimed_job_id, created_at,
                   updated_at, expires_at, archive_format
            FROM import_uploads
            WHERE unixepoch(expires_at) <= unixepoch(?1)
              AND state IN ('uploaded', 'ready', 'failed')
            ORDER BY expires_at, upload_id
            LIMIT ?2
            "#,
        )
        .bind(now)
        .bind(i64::from(limit.clamp(1, MAX_SCAN_LIMIT)))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_upload).collect()
    }

    pub async fn active_usage(
        &self,
        instance_id: Option<&str>,
    ) -> Result<ImportUploadUsage, ImportUploadStorageError> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) AS active_count, COALESCE(SUM(size_bytes), 0) AS active_bytes
            FROM import_uploads
            WHERE (?1 IS NULL OR instance_id = ?1)
            "#,
        )
        .bind(instance_id)
        .fetch_one(&self.pool)
        .await?;
        let active_count: i64 = row.try_get("active_count")?;
        let active_bytes: i64 = row.try_get("active_bytes")?;
        Ok(ImportUploadUsage {
            active_count: from_sqlite_integer(active_count, "active_count")?,
            active_bytes: from_sqlite_integer(active_bytes, "active_bytes")?,
        })
    }

    pub async fn reconcile_interrupted(
        &self,
        instance_id: &str,
        upload_id: &str,
        claimed_job_id: &str,
        disposition: InterruptedImportDisposition,
        reason: &str,
        updated_at: &str,
    ) -> Result<bool, ImportUploadStorageError> {
        validate_token("claimed_job_id", claimed_job_id)?;
        validate_last_error(reason)?;
        validate_timestamp("updated_at", updated_at)?;
        let state = match disposition {
            InterruptedImportDisposition::Ready => ImportUploadState::Ready,
            InterruptedImportDisposition::Failed => ImportUploadState::Failed,
        };
        let result = sqlx::query(
            r#"
            UPDATE import_uploads
            SET state = ?4, claimed_job_id = NULL, last_error = ?5, updated_at = ?6
            WHERE instance_id = ?1
              AND upload_id = ?2
              AND state = 'importing'
              AND claimed_job_id = ?3
            "#,
        )
        .bind(instance_id)
        .bind(upload_id)
        .bind(claimed_job_id)
        .bind(state.as_str())
        .bind(reason)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }
}
