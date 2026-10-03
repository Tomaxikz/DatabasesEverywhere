use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sqlx::{Row, SqliteConnection, SqlitePool, sqlite::SqliteRow};

use crate::{
    instance::metadata::InstanceMetadata,
    instance::placement::{DeploymentMode, PlacementError},
    utils::{backend::BackendEndpoint, protocol::Protocol, time::now_rfc3339},
};

mod commit;
mod error;
mod model;
mod recovery;
mod rows;
mod stage;
#[cfg(test)]
mod tests;

pub use self::error::*;
pub use self::model::*;
use self::recovery::*;
use self::rows::*;
pub use self::stage::*;

#[derive(Debug, Clone)]
pub struct DeploymentMigrationRepository {
    pool: SqlitePool,
}

impl DeploymentMigrationRepository {
    pub(super) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn start(
        &self,
        metadata: &InstanceMetadata,
        target_mode: DeploymentMode,
        target_pool_id: Option<&str>,
        target_limits: Option<&crate::utils::limits::InstanceLimits>,
    ) -> Result<DeploymentMigration, DeploymentMigrationError> {
        target_mode.check(metadata.protocol)?;
        if metadata.deployment_mode == target_mode {
            return Err(DeploymentMigrationError::SameMode(target_mode));
        }
        let migration_id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        let result = sqlx::query(
            r#"
            INSERT INTO deployment_migrations (
                migration_id, instance_id, protocol, source_mode, target_mode,
                source_runtime_id, stage, created_at, updated_at, target_pool_id, target_limits_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'requested', ?7, ?7, ?8, ?9)
            "#,
        )
        .bind(&migration_id)
        .bind(&metadata.instance_id)
        .bind(metadata.protocol.as_str())
        .bind(metadata.deployment_mode.as_str())
        .bind(target_mode.as_str())
        .bind(metadata.runtime_id())
        .bind(&now)
        .bind(target_pool_id)
        .bind(target_limits.map(serde_json::to_string).transpose()?)
        .execute(&self.pool)
        .await;
        if let Err(error) = result {
            if is_unique_error(&error) {
                return Err(DeploymentMigrationError::ActiveMigration(
                    metadata.instance_id.clone(),
                ));
            }
            return Err(error.into());
        }
        self.get_existing(&migration_id).await
    }

    async fn get_existing(
        &self,
        migration_id: &str,
    ) -> Result<DeploymentMigration, DeploymentMigrationError> {
        self.get(migration_id)
            .await?
            .ok_or_else(|| DeploymentMigrationError::NotFound(migration_id.to_string()))
    }

    async fn get_at_revision(
        &self,
        migration_id: &str,
        expected_revision: u64,
    ) -> Result<DeploymentMigration, DeploymentMigrationError> {
        let current = self.get_existing(migration_id).await?;
        if current.revision != expected_revision {
            return Err(DeploymentMigrationError::StaleRevision {
                expected: expected_revision,
                actual: current.revision,
            });
        }
        Ok(current)
    }

    pub async fn get(
        &self,
        migration_id: &str,
    ) -> Result<Option<DeploymentMigration>, DeploymentMigrationError> {
        sqlx::query("SELECT * FROM deployment_migrations WHERE migration_id = ?1 LIMIT 1")
            .bind(migration_id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(read_migration)
            .transpose()
    }

    pub async fn list_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<DeploymentMigration>, DeploymentMigrationError> {
        let rows = sqlx::query(
            r#"
            SELECT * FROM deployment_migrations
            WHERE instance_id = ?1
            ORDER BY created_at DESC, migration_id DESC
            "#,
        )
        .bind(instance_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(read_migration).collect()
    }

    pub async fn list_active(&self) -> Result<Vec<DeploymentMigration>, DeploymentMigrationError> {
        let rows = sqlx::query(
            r#"
            SELECT * FROM deployment_migrations
            WHERE stage NOT IN ('completed', 'failed', 'cancelled')
            ORDER BY created_at, migration_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(read_migration).collect()
    }

    pub async fn transition(
        &self,
        migration_id: &str,
        expected_revision: u64,
        next: MigrationStage,
        patch: MigrationPatch<'_>,
    ) -> Result<DeploymentMigration, DeploymentMigrationError> {
        let current = self
            .get_at_revision(migration_id, expected_revision)
            .await?;
        if !current.stage.allows(next) {
            return Err(DeploymentMigrationError::InvalidTransition {
                from: current.stage,
                to: next,
            });
        }
        let target_runtime_id = patch
            .target_runtime_id
            .or(current.target_runtime_id.as_deref());
        let source_fenced = patch.source_fenced.unwrap_or(current.source_fenced);
        if next == MigrationStage::TargetPrepared && target_runtime_id.is_none() {
            return Err(DeploymentMigrationError::TargetRuntimeRequired);
        }
        if next == MigrationStage::SourceFenced && !source_fenced {
            return Err(DeploymentMigrationError::SourceFenceRequired);
        }
        if next == MigrationStage::CutoverCommitted
            && (target_runtime_id.is_none() || !source_fenced)
        {
            return Err(DeploymentMigrationError::CutoverNotReady);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(DeploymentMigrationError::RevisionOverflow)?;
        let (failure_code, failure_message) = patch
            .failure
            .map(|failure| (Some(failure.code()), Some(failure.message())))
            .unwrap_or((None, None));
        let updated = sqlx::query(
            r#"
            UPDATE deployment_migrations
            SET stage = ?1,
                revision = ?2,
                target_runtime_id = COALESCE(?3, target_runtime_id),
                source_fenced = COALESCE(?4, source_fenced),
                cutover_committed = CASE WHEN ?1 = 'cutover_committed' THEN 1 ELSE cutover_committed END,
                failure_code = ?5,
                failure_message = ?6,
                updated_at = ?7
            WHERE migration_id = ?8 AND revision = ?9 AND stage = ?10
            "#,
        )
        .bind(next.as_str())
        .bind(u64_to_i64(revision)?)
        .bind(patch.target_runtime_id)
        .bind(patch.source_fenced)
        .bind(failure_code)
        .bind(failure_message)
        .bind(now_rfc3339())
        .bind(migration_id)
        .bind(u64_to_i64(expected_revision)?)
        .bind(current.stage.as_str())
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() != 1 {
            let actual = self
                .get(migration_id)
                .await?
                .map(|record| record.revision)
                .unwrap_or_default();
            return Err(DeploymentMigrationError::StaleRevision {
                expected: expected_revision,
                actual,
            });
        }
        self.get_existing(migration_id).await
    }
}
