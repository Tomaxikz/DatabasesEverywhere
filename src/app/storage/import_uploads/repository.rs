use sqlx::SqlitePool;

use super::{
    ImportUpload, ImportUploadAdmission, ImportUploadArchiveFormat, ImportUploadStorageError,
    MAX_ACTIVE_LIST_LIMIT, NewImportUpload,
    validation::{is_unique_violation, row_to_upload, to_sqlite_integer, validate_upload},
};

#[derive(Debug, Clone)]
pub struct ImportUploadRepository {
    pub(super) pool: SqlitePool,
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

    pub async fn insert_within_limits(
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

    pub async fn list_active(
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
        .bind(i64::from(limit.clamp(1, MAX_ACTIVE_LIST_LIMIT)))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_upload).collect()
    }
}
