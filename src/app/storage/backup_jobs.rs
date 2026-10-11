use sqlx::{Row, SqlitePool};

const KEEP_TERMINAL_JOBS: i64 = 500;

/// Durable online backup coordinator states.
///
/// `admitted -> capturing -> captured -> validated -> published` is the only
/// success path. Any in-flight state may move to `failed` once every owned
/// resource is released, or to `cleanup_pending` when one is not. Recovery
/// moves a `cleanup_pending` job whose upload turns out to have completed
/// to `published`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupJobState {
    Admitted,
    Capturing,
    Captured,
    Validated,
    Published,
    Failed,
    CleanupPending,
}

impl BackupJobState {
    pub const IN_FLIGHT: [Self; 4] = [
        Self::Admitted,
        Self::Capturing,
        Self::Captured,
        Self::Validated,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Capturing => "capturing",
            Self::Captured => "captured",
            Self::Validated => "validated",
            Self::Published => "published",
            Self::Failed => "failed",
            Self::CleanupPending => "cleanup_pending",
        }
    }

    fn parse(value: &str) -> Result<Self, BackupJobStorageError> {
        [
            Self::Admitted,
            Self::Capturing,
            Self::Captured,
            Self::Validated,
            Self::Published,
            Self::Failed,
            Self::CleanupPending,
        ]
        .into_iter()
        .find(|state| state.as_str() == value)
        .ok_or_else(|| BackupJobStorageError::InvalidState(value.to_string()))
    }

    /// States from which `self` may be entered.
    fn predecessors(self) -> &'static [Self] {
        match self {
            Self::Admitted => &[],
            Self::Capturing => &[Self::Admitted],
            Self::Captured => &[Self::Capturing],
            Self::Validated => &[Self::Captured],
            Self::Published => &[Self::Validated, Self::CleanupPending],
            Self::Failed => &[
                Self::Admitted,
                Self::Capturing,
                Self::Captured,
                Self::Validated,
                Self::CleanupPending,
            ],
            Self::CleanupPending => &[
                Self::Admitted,
                Self::Capturing,
                Self::Captured,
                Self::Validated,
                Self::CleanupPending,
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupJobRecord {
    pub job_id: String,
    pub instance_id: String,
    pub backup_id: String,
    pub strategy: String,
    pub runtime_generation: String,
    pub source_identity: String,
    pub staging_path: String,
    pub state: BackupJobState,
    pub error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupResourceRecord {
    pub kind: String,
    pub name: String,
    pub survives_restart: bool,
}

/// Unsettled publication of one backup id (`backup_publications`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationState {
    /// Upload started; whether the backup became visible is unknown.
    Publishing,
    /// Every object of the backup id must be removed.
    Unpublish,
}

impl PublicationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Publishing => "publishing",
            Self::Unpublish => "unpublish",
        }
    }

    fn parse(value: &str) -> Result<Self, BackupJobStorageError> {
        [Self::Publishing, Self::Unpublish]
            .into_iter()
            .find(|state| state.as_str() == value)
            .ok_or_else(|| BackupJobStorageError::InvalidState(value.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupPublicationRecord {
    pub backup_id: String,
    pub instance_id: String,
    pub storage_kind: String,
    pub storage_identity: String,
    pub job_id: Option<String>,
    pub state: PublicationState,
    pub error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// One `backup_publication_resources` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationResourceRecord {
    pub kind: String,
    pub locator: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct BackupJobRepository {
    pool: SqlitePool,
}

impl BackupJobRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Records a new job before any resource or staging exists.
    pub async fn admit(&self, job: &BackupJobRecord) -> Result<(), BackupJobStorageError> {
        if job.state != BackupJobState::Admitted {
            return Err(BackupJobStorageError::InvalidState(
                job.state.as_str().to_string(),
            ));
        }
        sqlx::query(
            r#"
            INSERT INTO backup_jobs (
                job_id, instance_id, backup_id, strategy, runtime_generation,
                source_identity, staging_path, state, error, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?9)
            "#,
        )
        .bind(&job.job_id)
        .bind(&job.instance_id)
        .bind(&job.backup_id)
        .bind(&job.strategy)
        .bind(&job.runtime_generation)
        .bind(&job.source_identity)
        .bind(&job.staging_path)
        .bind(job.state.as_str())
        .bind(&job.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Moves a job forward only along an allowed edge.
    pub async fn transition(
        &self,
        job_id: &str,
        to: BackupJobState,
        error: Option<&str>,
        now: &str,
    ) -> Result<(), BackupJobStorageError> {
        let allowed = serde_json::to_string(
            &to.predecessors()
                .iter()
                .map(|state| state.as_str())
                .collect::<Vec<_>>(),
        )
        .map_err(|error| BackupJobStorageError::InvalidState(error.to_string()))?;
        let updated = sqlx::query(
            r#"
            UPDATE backup_jobs
            SET state = ?1, error = COALESCE(?2, error), updated_at = ?3
            WHERE job_id = ?4 AND state IN (SELECT value FROM json_each(?5))
            "#,
        )
        .bind(to.as_str())
        .bind(error)
        .bind(now)
        .bind(job_id)
        .bind(allowed)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if updated == 0 {
            return Err(BackupJobStorageError::InvalidTransition {
                job_id: job_id.to_string(),
                to: to.as_str(),
            });
        }
        Ok(())
    }

    /// Records an owned resource. Only jobs that may still create resources
    /// accept registrations, so a recovered job cannot grow new ones.
    pub async fn register_resource(
        &self,
        job_id: &str,
        resource: &BackupResourceRecord,
        now: &str,
    ) -> Result<(), BackupJobStorageError> {
        let inserted = sqlx::query(
            r#"
            INSERT INTO backup_job_resources (job_id, kind, name, survives_restart, released, registered_at)
            SELECT ?1, ?2, ?3, ?4, 0, ?5
            WHERE EXISTS (
                SELECT 1 FROM backup_jobs
                WHERE job_id = ?1 AND state IN ('admitted', 'capturing', 'captured')
            )
            ON CONFLICT(job_id, kind, name) DO UPDATE SET released = 0
            "#,
        )
        .bind(job_id)
        .bind(&resource.kind)
        .bind(&resource.name)
        .bind(i64::from(resource.survives_restart))
        .bind(now)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if inserted == 0 {
            return Err(BackupJobStorageError::InvalidTransition {
                job_id: job_id.to_string(),
                to: "register_resource",
            });
        }
        Ok(())
    }

    pub async fn release_resource(
        &self,
        job_id: &str,
        kind: &str,
        name: &str,
    ) -> Result<(), BackupJobStorageError> {
        sqlx::query(
            "UPDATE backup_job_resources SET released = 1 WHERE job_id = ?1 AND kind = ?2 AND name = ?3",
        )
        .bind(job_id)
        .bind(kind)
        .bind(name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn unreleased_resources(
        &self,
        job_id: &str,
    ) -> Result<Vec<BackupResourceRecord>, BackupJobStorageError> {
        let rows = sqlx::query(
            r#"
            SELECT kind, name, survives_restart FROM backup_job_resources
            WHERE job_id = ?1 AND released = 0
            ORDER BY registered_at, kind, name
            "#,
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(BackupResourceRecord {
                    kind: row.try_get("kind")?,
                    name: row.try_get("name")?,
                    survives_restart: row.try_get::<i64, _>("survives_restart")? != 0,
                })
            })
            .collect()
    }

    /// Jobs interrupted mid-flight or still owning resources.
    pub async fn needing_recovery(
        &self,
        instance_id: Option<&str>,
    ) -> Result<Vec<BackupJobRecord>, BackupJobStorageError> {
        let rows = sqlx::query(
            r#"
            SELECT job_id, instance_id, backup_id, strategy, runtime_generation,
                   source_identity, staging_path, state, error, created_at, updated_at
            FROM backup_jobs
            WHERE state IN ('admitted', 'capturing', 'captured', 'validated', 'cleanup_pending')
              AND (?1 IS NULL OR instance_id = ?1)
            ORDER BY created_at, job_id
            "#,
        )
        .bind(instance_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_job).collect()
    }

    pub async fn get(
        &self,
        job_id: &str,
    ) -> Result<Option<BackupJobRecord>, BackupJobStorageError> {
        let row = sqlx::query(
            r#"
            SELECT job_id, instance_id, backup_id, strategy, runtime_generation,
                   source_identity, staging_path, state, error, created_at, updated_at
            FROM backup_jobs WHERE job_id = ?1
            "#,
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_job).transpose()
    }

    /// Keeps a bounded audit tail of finished jobs.
    pub async fn prune_terminal(&self) -> Result<u64, BackupJobStorageError> {
        let result = sqlx::query(
            r#"
            DELETE FROM backup_jobs
            WHERE state IN ('published', 'failed')
              AND job_id NOT IN (
                  SELECT job_id FROM backup_jobs
                  WHERE state IN ('published', 'failed')
                  ORDER BY updated_at DESC
                  LIMIT ?1
              )
            "#,
        )
        .bind(KEEP_TERMINAL_JOBS)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Journals a publication before any object is uploaded.
    pub async fn begin_publication(
        &self,
        record: &BackupPublicationRecord,
    ) -> Result<(), BackupJobStorageError> {
        if record.state != PublicationState::Publishing {
            return Err(BackupJobStorageError::InvalidState(
                record.state.as_str().to_string(),
            ));
        }
        sqlx::query(
            r#"
            INSERT INTO backup_publications (
                backup_id, instance_id, storage_kind, storage_identity, job_id,
                state, error, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?7)
            "#,
        )
        .bind(&record.backup_id)
        .bind(&record.instance_id)
        .bind(&record.storage_kind)
        .bind(&record.storage_identity)
        .bind(&record.job_id)
        .bind(record.state.as_str())
        .bind(&record.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Requires every object of the backup id to be removed. Never reverts.
    pub async fn mark_unpublish(
        &self,
        backup_id: &str,
        error: Option<&str>,
        now: &str,
    ) -> Result<(), BackupJobStorageError> {
        let updated = sqlx::query(
            r#"
            UPDATE backup_publications
            SET state = 'unpublish', error = COALESCE(?1, error), updated_at = ?2
            WHERE backup_id = ?3
            "#,
        )
        .bind(error)
        .bind(now)
        .bind(backup_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if updated == 0 {
            return Err(BackupJobStorageError::InvalidTransition {
                job_id: backup_id.to_string(),
                to: "unpublish",
            });
        }
        Ok(())
    }

    /// Records why a publication is still unsettled.
    pub async fn note_publication_error(
        &self,
        backup_id: &str,
        error: &str,
        now: &str,
    ) -> Result<(), BackupJobStorageError> {
        sqlx::query(
            "UPDATE backup_publications SET error = ?1, updated_at = ?2 WHERE backup_id = ?3",
        )
        .bind(error)
        .bind(now)
        .bind(backup_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The outcome is settled: published for a live instance, or removed.
    /// Its resources go with it.
    pub async fn settle_publication(&self, backup_id: &str) -> Result<(), BackupJobStorageError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM backup_publication_resources WHERE backup_id = ?1")
            .bind(backup_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM backup_publications WHERE backup_id = ?1")
            .bind(backup_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Records a remote resource of an unsettled publication. Idempotent;
    /// fails when the publication is not journaled.
    pub async fn record_publication_resource(
        &self,
        backup_id: &str,
        resource: &PublicationResourceRecord,
        now: &str,
    ) -> Result<(), BackupJobStorageError> {
        let inserted = sqlx::query(
            r#"
            INSERT INTO backup_publication_resources (backup_id, kind, locator, detail, created_at)
            SELECT backup_id, ?2, ?3, ?4, ?5 FROM backup_publications WHERE backup_id = ?1
            ON CONFLICT (backup_id, kind, locator, detail) DO NOTHING
            "#,
        )
        .bind(backup_id)
        .bind(&resource.kind)
        .bind(&resource.locator)
        .bind(&resource.detail)
        .bind(now)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if inserted == 0 && self.publication(backup_id).await?.is_none() {
            return Err(BackupJobStorageError::InvalidTransition {
                job_id: backup_id.to_string(),
                to: "publication resource",
            });
        }
        Ok(())
    }

    pub async fn publication_resources(
        &self,
        backup_id: &str,
    ) -> Result<Vec<PublicationResourceRecord>, BackupJobStorageError> {
        let rows = sqlx::query(
            r#"
            SELECT kind, locator, detail FROM backup_publication_resources
            WHERE backup_id = ?1
            ORDER BY created_at, kind, locator, detail
            "#,
        )
        .bind(backup_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(PublicationResourceRecord {
                    kind: row.try_get("kind")?,
                    locator: row.try_get("locator")?,
                    detail: row.try_get("detail")?,
                })
            })
            .collect()
    }

    pub async fn publication(
        &self,
        backup_id: &str,
    ) -> Result<Option<BackupPublicationRecord>, BackupJobStorageError> {
        let row = sqlx::query(
            r#"
            SELECT backup_id, instance_id, storage_kind, storage_identity, job_id,
                   state, error, created_at, updated_at
            FROM backup_publications WHERE backup_id = ?1
            "#,
        )
        .bind(backup_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_publication).transpose()
    }

    pub async fn unsettled_publications(
        &self,
        instance_id: Option<&str>,
    ) -> Result<Vec<BackupPublicationRecord>, BackupJobStorageError> {
        let rows = sqlx::query(
            r#"
            SELECT backup_id, instance_id, storage_kind, storage_identity, job_id,
                   state, error, created_at, updated_at
            FROM backup_publications
            WHERE ?1 IS NULL OR instance_id = ?1
            ORDER BY created_at, backup_id
            "#,
        )
        .bind(instance_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_publication).collect()
    }
}

fn row_to_publication(
    row: sqlx::sqlite::SqliteRow,
) -> Result<BackupPublicationRecord, BackupJobStorageError> {
    let state: String = row.try_get("state")?;
    Ok(BackupPublicationRecord {
        backup_id: row.try_get("backup_id")?,
        instance_id: row.try_get("instance_id")?,
        storage_kind: row.try_get("storage_kind")?,
        storage_identity: row.try_get("storage_identity")?,
        job_id: row.try_get("job_id")?,
        state: PublicationState::parse(&state)?,
        error: row.try_get("error")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_job(row: sqlx::sqlite::SqliteRow) -> Result<BackupJobRecord, BackupJobStorageError> {
    let state: String = row.try_get("state")?;
    Ok(BackupJobRecord {
        job_id: row.try_get("job_id")?,
        instance_id: row.try_get("instance_id")?,
        backup_id: row.try_get("backup_id")?,
        strategy: row.try_get("strategy")?,
        runtime_generation: row.try_get("runtime_generation")?,
        source_identity: row.try_get("source_identity")?,
        staging_path: row.try_get("staging_path")?,
        state: BackupJobState::parse(&state)?,
        error: row.try_get("error")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum BackupJobStorageError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error("backup job has unknown state {0}")]
    InvalidState(String),
    #[error("backup job {job_id} cannot move to {to} from its current state")]
    InvalidTransition { job_id: String, to: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sqlite;

    fn job(job_id: &str) -> BackupJobRecord {
        BackupJobRecord {
            job_id: job_id.to_string(),
            instance_id: "inst_one".to_string(),
            backup_id: format!("{job_id}.physical.tar.gz"),
            strategy: "postgres.pg_basebackup".to_string(),
            runtime_generation: "abc@2026-01-01T00:00:00Z".to_string(),
            source_identity: "{}".to_string(),
            staging_path: "/backups/.staging/inst_one/job".to_string(),
            state: BackupJobState::Admitted,
            error: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn slot(name: &str) -> BackupResourceRecord {
        BackupResourceRecord {
            kind: "replication_slot".to_string(),
            name: name.to_string(),
            survives_restart: false,
        }
    }

    #[tokio::test]
    async fn jobs_follow_only_the_declared_state_machine() {
        let dir = tempfile::tempdir().unwrap();
        let repository = BackupJobRepository::new(sqlite::connect(dir.path()).await.unwrap());
        repository.admit(&job("job_a")).await.unwrap();
        let now = "2026-01-01T00:00:01Z";

        assert!(
            repository
                .transition("job_a", BackupJobState::Published, None, now)
                .await
                .is_err()
        );
        for state in [
            BackupJobState::Capturing,
            BackupJobState::Captured,
            BackupJobState::Validated,
            BackupJobState::Published,
        ] {
            repository
                .transition("job_a", state, None, now)
                .await
                .unwrap();
        }
        assert!(
            repository
                .transition("job_a", BackupJobState::Failed, Some("late"), now)
                .await
                .is_err()
        );
        assert!(repository.needing_recovery(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn resources_are_journaled_until_released_and_recovery_sees_them() {
        let dir = tempfile::tempdir().unwrap();
        let repository = BackupJobRepository::new(sqlite::connect(dir.path()).await.unwrap());
        repository.admit(&job("job_b")).await.unwrap();
        let now = "2026-01-01T00:00:01Z";
        repository
            .transition("job_b", BackupJobState::Capturing, None, now)
            .await
            .unwrap();
        repository
            .register_resource("job_b", &slot("dbev_bk_a"), now)
            .await
            .unwrap();
        repository
            .register_resource("job_b", &slot("dbev_bk_b"), now)
            .await
            .unwrap();
        repository
            .release_resource("job_b", "replication_slot", "dbev_bk_a")
            .await
            .unwrap();
        assert_eq!(
            repository.unreleased_resources("job_b").await.unwrap(),
            vec![slot("dbev_bk_b")]
        );

        let pending = repository.needing_recovery(Some("inst_one")).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].state, BackupJobState::Capturing);
        assert!(
            repository
                .needing_recovery(Some("inst_two"))
                .await
                .unwrap()
                .is_empty()
        );

        repository
            .transition(
                "job_b",
                BackupJobState::CleanupPending,
                Some("crashed"),
                now,
            )
            .await
            .unwrap();
        // A job being recovered can no longer acquire resources.
        assert!(
            repository
                .register_resource("job_b", &slot("dbev_bk_c"), now)
                .await
                .is_err()
        );
        repository
            .transition("job_b", BackupJobState::Failed, None, now)
            .await
            .unwrap();
        let stored = repository.get("job_b").await.unwrap().unwrap();
        assert_eq!(stored.state, BackupJobState::Failed);
        assert_eq!(stored.error.as_deref(), Some("crashed"));
        assert!(repository.needing_recovery(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn publications_stay_journaled_until_settled_and_never_revert() {
        let dir = tempfile::tempdir().unwrap();
        let repository = BackupJobRepository::new(sqlite::connect(dir.path()).await.unwrap());
        let now = "2026-01-01T00:00:01Z";
        let record = BackupPublicationRecord {
            backup_id: "one.physical.tar.gz".to_string(),
            instance_id: "inst_one".to_string(),
            storage_kind: "s3".to_string(),
            storage_identity: "https://s3.example/bucket/prefix".to_string(),
            job_id: Some("job_a".to_string()),
            state: PublicationState::Publishing,
            error: None,
            created_at: now.to_string(),
            updated_at: now.to_string(),
        };
        repository.begin_publication(&record).await.unwrap();
        // One publication per backup id.
        assert!(repository.begin_publication(&record).await.is_err());
        let unpublish = BackupPublicationRecord {
            state: PublicationState::Unpublish,
            ..record.clone()
        };
        assert!(repository.begin_publication(&unpublish).await.is_err());

        repository
            .mark_unpublish(&record.backup_id, Some("upload failed"), now)
            .await
            .unwrap();
        repository
            .note_publication_error(&record.backup_id, "storage unavailable", now)
            .await
            .unwrap();
        let pending = repository
            .unsettled_publications(Some("inst_one"))
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].state, PublicationState::Unpublish);
        assert_eq!(pending[0].error.as_deref(), Some("storage unavailable"));
        assert!(
            repository
                .unsettled_publications(Some("inst_two"))
                .await
                .unwrap()
                .is_empty()
        );

        repository
            .settle_publication(&record.backup_id)
            .await
            .unwrap();
        assert!(
            repository
                .publication(&record.backup_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .mark_unpublish(&record.backup_id, None, now)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn publication_resources_are_idempotent_and_settle_with_their_publication() {
        let dir = tempfile::tempdir().unwrap();
        let repository = BackupJobRepository::new(sqlite::connect(dir.path()).await.unwrap());
        let now = "2026-01-01T00:00:01Z";
        let upload = PublicationResourceRecord {
            kind: "s3_multipart_upload".to_string(),
            locator: "dbev/instances/inst_one/backups/one.physical.tar.gz".to_string(),
            detail: "upload-1".to_string(),
        };
        // A resource never outlives or precedes its publication.
        assert!(
            repository
                .record_publication_resource("one.physical.tar.gz", &upload, now)
                .await
                .is_err()
        );
        repository
            .begin_publication(&BackupPublicationRecord {
                backup_id: "one.physical.tar.gz".to_string(),
                instance_id: "inst_one".to_string(),
                storage_kind: "s3".to_string(),
                storage_identity: "s3:https://s3.example/|bucket|prefix".to_string(),
                job_id: None,
                state: PublicationState::Publishing,
                error: None,
                created_at: now.to_string(),
                updated_at: now.to_string(),
            })
            .await
            .unwrap();
        for _ in 0..2 {
            repository
                .record_publication_resource("one.physical.tar.gz", &upload, now)
                .await
                .unwrap();
        }
        assert_eq!(
            repository
                .publication_resources("one.physical.tar.gz")
                .await
                .unwrap(),
            vec![upload.clone()]
        );
        repository
            .settle_publication("one.physical.tar.gz")
            .await
            .unwrap();
        assert!(
            repository
                .publication_resources("one.physical.tar.gz")
                .await
                .unwrap()
                .is_empty()
        );
    }
}
