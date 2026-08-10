use std::str::FromStr;

use sqlx::{Row, SqlitePool};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::shared::protocol::Protocol;

pub const MAX_CATALOG_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_LAST_ERROR_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportUploadState {
    Uploading,
    Uploaded,
    Processing,
    Ready,
    Failed,
    Importing,
    Consumed,
    Deleting,
}

impl ImportUploadState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uploading => "uploading",
            Self::Uploaded => "uploaded",
            Self::Processing => "processing",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Importing => "importing",
            Self::Consumed => "consumed",
            Self::Deleting => "deleting",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ImportUploadParseError> {
        match value {
            "uploading" => Ok(Self::Uploading),
            "uploaded" => Ok(Self::Uploaded),
            "processing" => Ok(Self::Processing),
            "ready" => Ok(Self::Ready),
            "failed" => Ok(Self::Failed),
            "importing" => Ok(Self::Importing),
            "consumed" => Ok(Self::Consumed),
            "deleting" => Ok(Self::Deleting),
            _ => Err(ImportUploadParseError::State(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportUploadArchiveFormat {
    Plain,
    Gzip,
    Bzip2,
    Tar,
    TarGzip,
    Zip,
}

impl ImportUploadArchiveFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Tar => "tar",
            Self::TarGzip => "tar.gz",
            Self::Zip => "zip",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ImportUploadParseError> {
        match value {
            "plain" => Ok(Self::Plain),
            "gzip" => Ok(Self::Gzip),
            "bzip2" => Ok(Self::Bzip2),
            "tar" => Ok(Self::Tar),
            "tar.gz" => Ok(Self::TarGzip),
            "zip" => Ok(Self::Zip),
            _ => Err(ImportUploadParseError::ArchiveFormat(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportUpload {
    pub upload_id: String,
    pub instance_id: String,
    pub original_filename: String,
    pub stored_filename: String,
    pub protocol: Protocol,
    pub archive_format: Option<ImportUploadArchiveFormat>,
    pub state: ImportUploadState,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    pub catalog_json: Option<String>,
    pub last_error: Option<String>,
    pub claimed_job_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewImportUpload {
    pub upload_id: String,
    pub instance_id: String,
    pub original_filename: String,
    pub stored_filename: String,
    pub protocol: Protocol,
    pub archive_format: Option<ImportUploadArchiveFormat>,
    pub size_bytes: u64,
    pub created_at: String,
    pub expires_at: String,
}

impl NewImportUpload {
    fn into_upload(self) -> ImportUpload {
        ImportUpload {
            upload_id: self.upload_id,
            instance_id: self.instance_id,
            original_filename: self.original_filename,
            stored_filename: self.stored_filename,
            protocol: self.protocol,
            archive_format: self.archive_format,
            state: ImportUploadState::Uploading,
            size_bytes: self.size_bytes,
            sha256: None,
            catalog_json: None,
            last_error: None,
            claimed_job_id: None,
            updated_at: self.created_at.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportUploadUsage {
    pub active_count: u64,
    pub active_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportUploadAdmission {
    Admitted(Box<ImportUpload>),
    InstanceCountExceeded {
        active_count: u64,
        limit: u64,
    },
    TotalBytesExceeded {
        active_bytes: u64,
        requested_bytes: u64,
        limit: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptedImportDisposition {
    Ready,
    Failed,
}

#[derive(Debug, Clone)]
pub struct ImportUploadRepository {
    pool: SqlitePool,
}

impl ImportUploadRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        upload: NewImportUpload,
    ) -> Result<ImportUpload, ImportUploadStorageError> {
        let upload = upload.into_upload();
        self.insert(&upload).await?;
        Ok(upload)
    }

    pub async fn insert(&self, upload: &ImportUpload) -> Result<(), ImportUploadStorageError> {
        validate_upload(upload)?;
        let size_bytes = to_sqlite_integer(upload.size_bytes, "size_bytes")?;
        let result = sqlx::query(
            r#"
            INSERT INTO import_uploads (
                upload_id,
                instance_id,
                original_filename,
                stored_filename,
                protocol,
                state,
                size_bytes,
                sha256,
                catalog_json,
                last_error,
                claimed_job_id,
                created_at,
                updated_at,
                expires_at,
                archive_format
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
        )
        .bind(&upload.upload_id)
        .bind(&upload.instance_id)
        .bind(&upload.original_filename)
        .bind(&upload.stored_filename)
        .bind(upload.protocol.as_str())
        .bind(upload.state.as_str())
        .bind(size_bytes)
        .bind(&upload.sha256)
        .bind(&upload.catalog_json)
        .bind(&upload.last_error)
        .bind(&upload.claimed_job_id)
        .bind(&upload.created_at)
        .bind(&upload.updated_at)
        .bind(&upload.expires_at)
        .bind(upload.archive_format.map(ImportUploadArchiveFormat::as_str))
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(error) if is_unique_violation(&error) => {
                Err(ImportUploadStorageError::AlreadyExists {
                    upload_id: upload.upload_id.clone(),
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn insert_if_within_limits(
        &self,
        upload: NewImportUpload,
        max_per_instance: u64,
        max_total_bytes: u64,
    ) -> Result<ImportUploadAdmission, ImportUploadStorageError> {
        let upload = upload.into_upload();
        validate_upload(&upload)?;
        let size_bytes = to_sqlite_integer(upload.size_bytes, "size_bytes")?;
        let max_per_instance_sql = to_sqlite_integer(max_per_instance, "max_per_instance")?;
        let max_total_bytes_sql = to_sqlite_integer(max_total_bytes, "max_total_bytes")?;
        if upload.size_bytes > max_total_bytes {
            return Ok(ImportUploadAdmission::TotalBytesExceeded {
                active_bytes: self.active_usage(None).await?.active_bytes,
                requested_bytes: upload.size_bytes,
                limit: max_total_bytes,
            });
        }

        let result = sqlx::query(
            r#"
            INSERT INTO import_uploads (
                upload_id, instance_id, original_filename, stored_filename, protocol, state,
                size_bytes, sha256, catalog_json, last_error, claimed_job_id, created_at,
                updated_at, expires_at, archive_format
            )
            SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?17
            WHERE (
                SELECT COUNT(*)
                FROM import_uploads
                WHERE instance_id = ?2
            ) < ?15
              AND (
                SELECT COALESCE(SUM(size_bytes), 0)
                FROM import_uploads
              ) <= (?16 - ?7)
            "#,
        )
        .bind(&upload.upload_id)
        .bind(&upload.instance_id)
        .bind(&upload.original_filename)
        .bind(&upload.stored_filename)
        .bind(upload.protocol.as_str())
        .bind(upload.state.as_str())
        .bind(size_bytes)
        .bind(&upload.sha256)
        .bind(&upload.catalog_json)
        .bind(&upload.last_error)
        .bind(&upload.claimed_job_id)
        .bind(&upload.created_at)
        .bind(&upload.updated_at)
        .bind(&upload.expires_at)
        .bind(max_per_instance_sql)
        .bind(max_total_bytes_sql)
        .bind(upload.archive_format.map(ImportUploadArchiveFormat::as_str))
        .execute(&self.pool)
        .await;

        match result {
            Ok(result) if result.rows_affected() == 1 => {
                Ok(ImportUploadAdmission::Admitted(Box::new(upload)))
            }
            Ok(_) => {
                let instance_usage = self.active_usage(Some(&upload.instance_id)).await?;
                if instance_usage.active_count >= max_per_instance {
                    return Ok(ImportUploadAdmission::InstanceCountExceeded {
                        active_count: instance_usage.active_count,
                        limit: max_per_instance,
                    });
                }
                let active_bytes = self.active_usage(None).await?.active_bytes;
                Ok(ImportUploadAdmission::TotalBytesExceeded {
                    active_bytes,
                    requested_bytes: upload.size_bytes,
                    limit: max_total_bytes,
                })
            }
            Err(error) if is_unique_violation(&error) => {
                Err(ImportUploadStorageError::AlreadyExists {
                    upload_id: upload.upload_id,
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    pub async fn get(
        &self,
        instance_id: &str,
        upload_id: &str,
    ) -> Result<Option<ImportUpload>, ImportUploadStorageError> {
        let row = sqlx::query(
            r#"
            SELECT upload_id, instance_id, original_filename, stored_filename, protocol, state,
                   size_bytes, sha256, catalog_json, last_error, claimed_job_id, created_at,
                   updated_at, expires_at, archive_format
            FROM import_uploads
            WHERE instance_id = ?1 AND upload_id = ?2
            LIMIT 1
            "#,
        )
        .bind(instance_id)
        .bind(upload_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_upload).transpose()
    }

    pub async fn list_active_for_instance(
        &self,
        instance_id: &str,
        limit: u32,
    ) -> Result<Vec<ImportUpload>, ImportUploadStorageError> {
        let rows = sqlx::query(
            r#"
            SELECT upload_id, instance_id, original_filename, stored_filename, protocol, state,
                   size_bytes, sha256, catalog_json, last_error, claimed_job_id, created_at,
                   updated_at, expires_at, archive_format
            FROM import_uploads
            WHERE instance_id = ?1 AND state NOT IN ('consumed', 'deleting')
            ORDER BY created_at DESC, upload_id DESC
            LIMIT ?2
            "#,
        )
        .bind(instance_id)
        .bind(i64::from(limit.clamp(1, 500)))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_upload).collect()
    }

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

    pub async fn restore_ready_after_processing(
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

    pub async fn claim_ready_for_job(
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

    pub async fn release_claim_after_failed_job(
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
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_upload).collect()
    }

    pub async fn list_terminal_cleanup_after(
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
        .bind(i64::from(limit.clamp(1, 1_000)))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_upload).collect()
    }

    pub async fn list_nonterminal_recovery_after(
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
        .bind(i64::from(limit.clamp(1, 1_000)))
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
        .bind(i64::from(limit.clamp(1, 1_000)))
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

    pub async fn reconcile_interrupted_importing(
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

fn row_to_upload(row: sqlx::sqlite::SqliteRow) -> Result<ImportUpload, ImportUploadStorageError> {
    let protocol: String = row.try_get("protocol")?;
    let state: String = row.try_get("state")?;
    let archive_format: Option<String> = row.try_get("archive_format")?;
    let size_bytes: i64 = row.try_get("size_bytes")?;
    let upload = ImportUpload {
        upload_id: row.try_get("upload_id")?,
        instance_id: row.try_get("instance_id")?,
        original_filename: row.try_get("original_filename")?,
        stored_filename: row.try_get("stored_filename")?,
        protocol: parse_protocol(&protocol)?,
        archive_format: archive_format
            .as_deref()
            .map(ImportUploadArchiveFormat::parse)
            .transpose()?,
        state: ImportUploadState::parse(&state)?,
        size_bytes: from_sqlite_integer(size_bytes, "size_bytes")?,
        sha256: row.try_get("sha256")?,
        catalog_json: row.try_get("catalog_json")?,
        last_error: row.try_get("last_error")?,
        claimed_job_id: row.try_get("claimed_job_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        expires_at: row.try_get("expires_at")?,
    };
    validate_upload(&upload)?;
    Ok(upload)
}

fn parse_protocol(value: &str) -> Result<Protocol, ImportUploadParseError> {
    match value {
        "postgres" | "redis" | "valkey" | "mariadb" | "mysql" | "mongodb" | "clickhouse"
        | "qdrant" => Protocol::from_str(value)
            .map_err(|_| ImportUploadParseError::Protocol(value.to_string())),
        _ => Err(ImportUploadParseError::Protocol(value.to_string())),
    }
}

fn validate_upload(upload: &ImportUpload) -> Result<(), ImportUploadValidationError> {
    validate_token("upload_id", &upload.upload_id)?;
    validate_token("instance_id", &upload.instance_id)?;
    validate_original_filename(&upload.original_filename)?;
    validate_stored_filename(&upload.stored_filename)?;
    let created_at = validate_timestamp("created_at", &upload.created_at)?;
    let updated_at = validate_timestamp("updated_at", &upload.updated_at)?;
    let expires_at = validate_timestamp("expires_at", &upload.expires_at)?;
    if updated_at < created_at {
        return Err(ImportUploadValidationError::InvalidTimestampOrder);
    }
    if expires_at <= created_at {
        return Err(ImportUploadValidationError::InvalidExpiration);
    }
    to_sqlite_integer(upload.size_bytes, "size_bytes")?;
    if upload.size_bytes == 0 {
        return Err(ImportUploadValidationError::EmptyUpload);
    }
    if let Some(sha256) = upload.sha256.as_deref() {
        validate_sha256(sha256)?;
    }
    validate_catalog_json(upload.catalog_json.as_deref())?;
    if let Some(last_error) = upload.last_error.as_deref() {
        validate_last_error(last_error)?;
    }
    if let Some(job_id) = upload.claimed_job_id.as_deref() {
        validate_token("claimed_job_id", job_id)?;
    }
    let requires_digest = matches!(
        upload.state,
        ImportUploadState::Uploaded
            | ImportUploadState::Processing
            | ImportUploadState::Ready
            | ImportUploadState::Importing
            | ImportUploadState::Consumed
    );
    if requires_digest && upload.sha256.is_none() {
        return Err(ImportUploadValidationError::MissingSha256 {
            state: upload.state,
        });
    }
    let requires_claim = matches!(
        upload.state,
        ImportUploadState::Importing | ImportUploadState::Consumed
    );
    if requires_claim != upload.claimed_job_id.is_some() {
        return Err(ImportUploadValidationError::InvalidClaim {
            state: upload.state,
        });
    }
    Ok(())
}

fn validate_token(field: &'static str, value: &str) -> Result<(), ImportUploadValidationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ImportUploadValidationError::InvalidToken { field });
    }
    Ok(())
}

fn validate_original_filename(value: &str) -> Result<(), ImportUploadValidationError> {
    if value.is_empty()
        || value.len() > 255
        || matches!(value, "." | "..")
        || value.chars().any(|character| {
            character == '/' || character == '\\' || character == '\0' || character.is_control()
        })
    {
        return Err(ImportUploadValidationError::InvalidOriginalFilename);
    }
    Ok(())
}

fn validate_stored_filename(value: &str) -> Result<(), ImportUploadValidationError> {
    if value.is_empty()
        || value.len() > 255
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ImportUploadValidationError::InvalidStoredFilename);
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ImportUploadValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ImportUploadValidationError::InvalidSha256);
    }
    Ok(())
}

fn validate_catalog_json(value: Option<&str>) -> Result<(), ImportUploadValidationError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.len() > MAX_CATALOG_JSON_BYTES
        || serde_json::from_str::<serde_json::Value>(value).is_err()
    {
        return Err(ImportUploadValidationError::InvalidCatalogJson);
    }
    Ok(())
}

fn validate_last_error(value: &str) -> Result<(), ImportUploadValidationError> {
    if value.is_empty() || value.len() > MAX_LAST_ERROR_BYTES || value.contains('\0') {
        return Err(ImportUploadValidationError::InvalidLastError);
    }
    Ok(())
}

fn validate_timestamp(
    field: &'static str,
    value: &str,
) -> Result<OffsetDateTime, ImportUploadValidationError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| ImportUploadValidationError::InvalidTimestamp { field })
}

fn to_sqlite_integer(value: u64, field: &'static str) -> Result<i64, ImportUploadValidationError> {
    i64::try_from(value).map_err(|_| ImportUploadValidationError::IntegerOutOfRange { field })
}

fn from_sqlite_integer(value: i64, field: &'static str) -> Result<u64, ImportUploadParseError> {
    u64::try_from(value).map_err(|_| ImportUploadParseError::NegativeInteger { field, value })
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
}

#[derive(Debug, thiserror::Error)]
pub enum ImportUploadStorageError {
    #[error("sqlite query failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("import upload row parse failed: {0}")]
    Parse(#[from] ImportUploadParseError),
    #[error("invalid import upload: {0}")]
    Validation(#[from] ImportUploadValidationError),
    #[error("import upload {upload_id} already exists")]
    AlreadyExists { upload_id: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ImportUploadParseError {
    #[error("unsupported protocol value {0:?}")]
    Protocol(String),
    #[error("unsupported state value {0:?}")]
    State(String),
    #[error("unsupported archive format value {0:?}")]
    ArchiveFormat(String),
    #[error("{field} contains negative sqlite integer {value}")]
    NegativeInteger { field: &'static str, value: i64 },
}

#[derive(Debug, thiserror::Error)]
pub enum ImportUploadValidationError {
    #[error("{field} must contain 1-128 ASCII letters, digits, dots, dashes, or underscores")]
    InvalidToken { field: &'static str },
    #[error("original_filename must be a safe 1-255 byte filename")]
    InvalidOriginalFilename,
    #[error("stored_filename must be a safe 1-255 byte ASCII filename")]
    InvalidStoredFilename,
    #[error("sha256 must contain exactly 64 lowercase hexadecimal characters")]
    InvalidSha256,
    #[error("catalog_json must be valid JSON no larger than 1 MiB")]
    InvalidCatalogJson,
    #[error("last_error must contain 1-16384 bytes without NUL characters")]
    InvalidLastError,
    #[error("{field} must be an RFC 3339 timestamp")]
    InvalidTimestamp { field: &'static str },
    #[error("updated_at cannot precede created_at")]
    InvalidTimestampOrder,
    #[error("expires_at must be later than created_at")]
    InvalidExpiration,
    #[error("{field} exceeds SQLite's signed integer range")]
    IntegerOutOfRange { field: &'static str },
    #[error("size_bytes must be greater than zero")]
    EmptyUpload,
    #[error("state {state:?} requires a SHA-256 digest")]
    MissingSha256 { state: ImportUploadState },
    #[error("state {state:?} has inconsistent claimed_job_id")]
    InvalidClaim { state: ImportUploadState },
}

#[cfg(test)]
mod tests;
