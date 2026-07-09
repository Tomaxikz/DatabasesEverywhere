use sqlx::{Row, SqlitePool};

use crate::jobs::import_export::{
    ImportExportAction, ImportExportJob, ImportExportStatus, JobParseError,
};

#[derive(Debug, Clone)]
pub struct ImportExportJobRepository {
    pool: SqlitePool,
}

impl ImportExportJobRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, job: &ImportExportJob) -> Result<(), ImportExportJobStorageError> {
        sqlx::query(
            r#"
            INSERT INTO import_export_jobs (
                job_id,
                instance_id,
                action,
                status,
                artifact_path,
                error,
                created_at,
                updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(job_id) DO UPDATE SET
                instance_id = excluded.instance_id,
                action = excluded.action,
                status = excluded.status,
                artifact_path = excluded.artifact_path,
                error = excluded.error,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&job.job_id)
        .bind(&job.instance_id)
        .bind(job.action.as_str())
        .bind(job.status.as_str())
        .bind(&job.artifact_path)
        .bind(&job.error)
        .bind(&job.created_at)
        .bind(&job.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(
        &self,
        job_id: &str,
    ) -> Result<Option<ImportExportJob>, ImportExportJobStorageError> {
        let row = sqlx::query(
            r#"
            SELECT job_id, instance_id, action, status, artifact_path, error, created_at, updated_at
            FROM import_export_jobs
            WHERE job_id = ?1
            LIMIT 1
            "#,
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_job).transpose()
    }

    pub async fn list(
        &self,
        instance_id: Option<&str>,
        status: Option<ImportExportStatus>,
        limit: u32,
    ) -> Result<Vec<ImportExportJob>, ImportExportJobStorageError> {
        let limit = limit.clamp(1, 500);
        let status = status.map(ImportExportStatus::as_str);
        let rows = sqlx::query(
            r#"
            SELECT job_id, instance_id, action, status, artifact_path, error, created_at, updated_at
            FROM import_export_jobs
            WHERE (?1 IS NULL OR instance_id = ?1)
              AND (?2 IS NULL OR status = ?2)
            ORDER BY created_at DESC
            LIMIT ?3
            "#,
        )
        .bind(instance_id)
        .bind(status)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_job).collect()
    }

    pub async fn update_status(
        &self,
        job: &ImportExportJob,
    ) -> Result<(), ImportExportJobStorageError> {
        let result = sqlx::query(
            r#"
            UPDATE import_export_jobs
            SET status = ?2,
                artifact_path = ?3,
                error = ?4,
                updated_at = ?5
            WHERE job_id = ?1
            "#,
        )
        .bind(&job.job_id)
        .bind(job.status.as_str())
        .bind(&job.artifact_path)
        .bind(&job.error)
        .bind(&job.updated_at)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(ImportExportJobStorageError::NotFound {
                job_id: job.job_id.clone(),
            });
        }
        Ok(())
    }

    pub async fn running_instance_ids(&self) -> Result<Vec<String>, ImportExportJobStorageError> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT instance_id
            FROM import_export_jobs
            WHERE status = 'running'
            ORDER BY instance_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| row.try_get("instance_id").map_err(Into::into))
            .collect()
    }

    pub async fn fail_unfinished(
        &self,
        reason: &str,
        updated_at: &str,
    ) -> Result<u64, ImportExportJobStorageError> {
        let result = sqlx::query(
            r#"
            UPDATE import_export_jobs
            SET status = 'failed',
                error = ?1,
                updated_at = ?2
            WHERE status IN ('queued', 'running')
            "#,
        )
        .bind(reason)
        .bind(updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn count_by_status(
        &self,
    ) -> Result<Vec<(ImportExportStatus, u64)>, ImportExportJobStorageError> {
        let rows = sqlx::query(
            r#"
            SELECT status, COUNT(*) AS count
            FROM import_export_jobs
            GROUP BY status
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let status: String = row.try_get("status")?;
                let count: i64 = row.try_get("count")?;
                Ok((ImportExportStatus::parse(&status)?, count as u64))
            })
            .collect()
    }

    pub async fn prune_completed(
        &self,
        keep_latest: u32,
    ) -> Result<u64, ImportExportJobStorageError> {
        let result = sqlx::query(
            r#"
            DELETE FROM import_export_jobs
            WHERE status IN ('succeeded', 'failed')
              AND job_id NOT IN (
                  SELECT job_id
                  FROM import_export_jobs
                  WHERE status IN ('succeeded', 'failed')
                  ORDER BY updated_at DESC, job_id DESC
                  LIMIT ?1
              )
            "#,
        )
        .bind(i64::from(keep_latest.max(1)))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

fn row_to_job(
    row: sqlx::sqlite::SqliteRow,
) -> Result<ImportExportJob, ImportExportJobStorageError> {
    let action: String = row.try_get("action")?;
    let status: String = row.try_get("status")?;
    Ok(ImportExportJob {
        job_id: row.try_get("job_id")?,
        instance_id: row.try_get("instance_id")?,
        action: ImportExportAction::parse(&action)?,
        status: ImportExportStatus::parse(&status)?,
        artifact_path: row.try_get("artifact_path")?,
        error: row.try_get("error")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ImportExportJobStorageError {
    #[error("sqlite query failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("job row parse failed: {0}")]
    Parse(#[from] JobParseError),
    #[error("import/export job {job_id} was not found")]
    NotFound { job_id: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        jobs::import_export::{ImportExportAction, ImportExportStatus},
        storage::sqlite,
    };

    #[tokio::test]
    async fn upserts_and_reads_import_export_job() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = ImportExportJobRepository::new(pool);
        let mut job = sample_job();

        repository.insert(&job).await.unwrap();
        job.status = ImportExportStatus::Succeeded;
        job.updated_at = "2026-01-01T12:01:00Z".to_string();
        repository.update_status(&job).await.unwrap();

        let stored = repository.get("job_1").await.unwrap().unwrap();
        assert_eq!(stored.status, ImportExportStatus::Succeeded);
        assert_eq!(stored.instance_id, "inst_abc");
    }

    #[tokio::test]
    async fn marks_unfinished_jobs_failed() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = ImportExportJobRepository::new(pool);
        repository.insert(&sample_job()).await.unwrap();

        let changed = repository
            .fail_unfinished(
                "daemon restarted before job completed",
                "2026-01-01T12:02:00Z",
            )
            .await
            .unwrap();

        let stored = repository.get("job_1").await.unwrap().unwrap();
        assert_eq!(changed, 1);
        assert_eq!(stored.status, ImportExportStatus::Failed);
        assert_eq!(
            stored.error.as_deref(),
            Some("daemon restarted before job completed")
        );
    }

    #[tokio::test]
    async fn reports_missing_job_status_updates() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = ImportExportJobRepository::new(pool);

        let error = repository.update_status(&sample_job()).await.unwrap_err();

        assert!(matches!(
            error,
            ImportExportJobStorageError::NotFound { job_id } if job_id == "job_1"
        ));
    }

    #[tokio::test]
    async fn lists_only_instances_with_running_jobs_once() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = ImportExportJobRepository::new(pool);
        let mut job = sample_job();
        repository.insert(&job).await.unwrap();
        job.job_id = "job_2".to_string();
        job.status = ImportExportStatus::Running;
        repository.insert(&job).await.unwrap();
        job.job_id = "job_3".to_string();
        job.instance_id = "inst_other".to_string();
        job.status = ImportExportStatus::Running;
        repository.insert(&job).await.unwrap();

        assert_eq!(
            repository.running_instance_ids().await.unwrap(),
            vec!["inst_abc".to_string(), "inst_other".to_string()]
        );
    }

    #[tokio::test]
    async fn counts_jobs_by_status() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = ImportExportJobRepository::new(pool);
        let mut job = sample_job();

        repository.insert(&job).await.unwrap();
        job.job_id = "job_2".to_string();
        job.status = ImportExportStatus::Failed;
        repository.insert(&job).await.unwrap();

        let counts = repository.count_by_status().await.unwrap();
        assert!(counts.contains(&(ImportExportStatus::Queued, 1)));
        assert!(counts.contains(&(ImportExportStatus::Failed, 1)));
    }

    #[tokio::test]
    async fn prunes_only_old_completed_jobs() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = ImportExportJobRepository::new(pool);
        for (id, status, updated_at) in [
            ("old", ImportExportStatus::Succeeded, "2026-01-01T00:00:00Z"),
            ("new", ImportExportStatus::Failed, "2026-01-02T00:00:00Z"),
            ("queued", ImportExportStatus::Queued, "2025-01-01T00:00:00Z"),
        ] {
            let mut job = sample_job();
            job.job_id = id.to_string();
            job.status = status;
            job.updated_at = updated_at.to_string();
            repository.insert(&job).await.unwrap();
        }

        assert_eq!(repository.prune_completed(1).await.unwrap(), 1);
        assert!(repository.get("old").await.unwrap().is_none());
        assert!(repository.get("new").await.unwrap().is_some());
        assert!(repository.get("queued").await.unwrap().is_some());
    }

    fn sample_job() -> ImportExportJob {
        ImportExportJob {
            job_id: "job_1".to_string(),
            instance_id: "inst_abc".to_string(),
            action: ImportExportAction::Export,
            status: ImportExportStatus::Queued,
            artifact_path: Some("/tmp/export.tar.gz".to_string()),
            error: None,
            created_at: "2026-01-01T12:00:00Z".to_string(),
            updated_at: "2026-01-01T12:00:00Z".to_string(),
        }
    }
}
