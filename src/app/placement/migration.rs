use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};

use crate::{
    instances::metadata::InstanceMetadata,
    placement::{DeploymentMode, PlacementError},
    shared::{protocol::Protocol, time::now_rfc3339},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStage {
    Requested,
    Preflight,
    TargetPreparing,
    TargetPrepared,
    SourceFencing,
    SourceFenced,
    Exporting,
    Exported,
    Importing,
    Imported,
    Validating,
    CutoverPending,
    CutoverCommitted,
    VerifyingCutover,
    CleaningSource,
    RollingBack,
    CleanupPending,
    ManualIntervention,
    Completed,
    Failed,
    Cancelled,
}

impl MigrationStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Preflight => "preflight",
            Self::TargetPreparing => "target_preparing",
            Self::TargetPrepared => "target_prepared",
            Self::SourceFencing => "source_fencing",
            Self::SourceFenced => "source_fenced",
            Self::Exporting => "exporting",
            Self::Exported => "exported",
            Self::Importing => "importing",
            Self::Imported => "imported",
            Self::Validating => "validating",
            Self::CutoverPending => "cutover_pending",
            Self::CutoverCommitted => "cutover_committed",
            Self::VerifyingCutover => "verifying_cutover",
            Self::CleaningSource => "cleaning_source",
            Self::RollingBack => "rolling_back",
            Self::CleanupPending => "cleanup_pending",
            Self::ManualIntervention => "manual_intervention",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    pub const fn crossed_cutover(self) -> bool {
        matches!(
            self,
            Self::CutoverCommitted
                | Self::VerifyingCutover
                | Self::CleaningSource
                | Self::CleanupPending
                | Self::Completed
        )
    }

    pub const fn recovery_stage(self) -> Option<Self> {
        match self {
            Self::Requested | Self::Preflight => Some(Self::Failed),
            Self::TargetPreparing
            | Self::TargetPrepared
            | Self::SourceFencing
            | Self::SourceFenced
            | Self::Exporting
            | Self::Exported
            | Self::Importing
            | Self::Imported
            | Self::Validating
            | Self::CutoverPending => Some(Self::RollingBack),
            Self::CutoverCommitted | Self::VerifyingCutover | Self::CleaningSource => {
                Some(Self::CleanupPending)
            }
            Self::RollingBack | Self::CleanupPending | Self::ManualIntervention => None,
            Self::Completed | Self::Failed | Self::Cancelled => None,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "requested" => Self::Requested,
            "preflight" => Self::Preflight,
            "target_preparing" => Self::TargetPreparing,
            "target_prepared" => Self::TargetPrepared,
            "source_fencing" => Self::SourceFencing,
            "source_fenced" => Self::SourceFenced,
            "exporting" => Self::Exporting,
            "exported" => Self::Exported,
            "importing" => Self::Importing,
            "imported" => Self::Imported,
            "validating" => Self::Validating,
            "cutover_pending" => Self::CutoverPending,
            "cutover_committed" => Self::CutoverCommitted,
            "verifying_cutover" => Self::VerifyingCutover,
            "cleaning_source" => Self::CleaningSource,
            "rolling_back" => Self::RollingBack,
            "cleanup_pending" => Self::CleanupPending,
            "manual_intervention" => Self::ManualIntervention,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    const fn allows(self, next: Self) -> bool {
        use MigrationStage as S;
        match self {
            S::Requested => matches!(next, S::Preflight | S::Failed | S::Cancelled),
            S::Preflight => matches!(next, S::TargetPreparing | S::Failed | S::Cancelled),
            S::TargetPreparing => matches!(next, S::TargetPrepared | S::RollingBack),
            S::TargetPrepared => matches!(next, S::SourceFencing | S::RollingBack),
            S::SourceFencing => matches!(next, S::SourceFenced | S::RollingBack),
            S::SourceFenced => matches!(next, S::Exporting | S::RollingBack),
            S::Exporting => matches!(next, S::Exported | S::RollingBack),
            S::Exported => matches!(next, S::Importing | S::RollingBack),
            S::Importing => matches!(next, S::Imported | S::RollingBack),
            S::Imported => matches!(next, S::Validating | S::RollingBack),
            S::Validating => matches!(next, S::CutoverPending | S::RollingBack),
            S::CutoverPending => matches!(next, S::CutoverCommitted | S::RollingBack),
            S::CutoverCommitted => matches!(next, S::VerifyingCutover | S::CleanupPending),
            S::VerifyingCutover => matches!(next, S::CleaningSource | S::CleanupPending),
            S::CleaningSource => matches!(next, S::Completed | S::CleanupPending),
            S::RollingBack => matches!(next, S::Failed | S::ManualIntervention),
            S::CleanupPending => matches!(next, S::CleaningSource | S::ManualIntervention),
            S::ManualIntervention => matches!(next, S::RollingBack | S::CleanupPending),
            S::Completed | S::Failed | S::Cancelled => false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentMigration {
    pub migration_id: String,
    pub instance_id: String,
    pub protocol: Protocol,
    pub source_mode: DeploymentMode,
    pub target_mode: DeploymentMode,
    pub source_runtime_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_runtime_id: Option<String>,
    pub stage: MigrationStage,
    pub revision: u64,
    pub source_fenced: bool,
    pub cutover_committed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationFailure {
    PreflightFailed,
    PreCutoverFailure,
    StructuralValidationTimedOut,
    PostCutoverFailure,
    RolledBackBeforeCutover,
    TargetVerificationFailed,
    RestartBeforeMutation,
    RestartBeforeCutover,
    RestartAfterCutover,
}

impl MigrationFailure {
    pub const ALL: [Self; 9] = [
        Self::PreflightFailed,
        Self::PreCutoverFailure,
        Self::StructuralValidationTimedOut,
        Self::PostCutoverFailure,
        Self::RolledBackBeforeCutover,
        Self::TargetVerificationFailed,
        Self::RestartBeforeMutation,
        Self::RestartBeforeCutover,
        Self::RestartAfterCutover,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::PreflightFailed => "preflight_failed",
            Self::PreCutoverFailure => "pre_cutover_failure",
            Self::StructuralValidationTimedOut => "structural_validation_timed_out",
            Self::PostCutoverFailure => "post_cutover_failure",
            Self::RolledBackBeforeCutover => "rolled_back_before_cutover",
            Self::TargetVerificationFailed => "target_verification_failed",
            Self::RestartBeforeMutation => "daemon_restarted_before_mutation",
            Self::RestartBeforeCutover => "daemon_restarted_before_cutover",
            Self::RestartAfterCutover => "daemon_restarted_after_cutover",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::PreflightFailed => {
                "migration preflight failed before creating or fencing any runtime"
            }
            Self::PreCutoverFailure => {
                "migration failed before cutover; provisional target rollback is pending"
            }
            Self::StructuralValidationTimedOut => {
                "deployment structural validation timed out before cutover; migration was not cut over"
            }
            Self::PostCutoverFailure => {
                "migration target is authoritative; target verification and source cleanup remain pending"
            }
            Self::RolledBackBeforeCutover => {
                "provisional target was removed and the verified source route was restored"
            }
            Self::TargetVerificationFailed => {
                "committed target could not be verified; source retained for manual recovery"
            }
            Self::RestartBeforeMutation => {
                "daemon restarted during migration preflight; no source mutation occurred; retry the migration"
            }
            Self::RestartBeforeCutover => {
                "daemon restarted before placement cutover; source remains authoritative and rollback must finish before retry"
            }
            Self::RestartAfterCutover => {
                "daemon restarted after placement cutover; target remains authoritative and source cleanup must finish"
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MigrationPatch<'a> {
    pub target_runtime_id: Option<&'a str>,
    pub source_fenced: Option<bool>,
    pub failure: Option<MigrationFailure>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MigrationRecoverySummary {
    pub failed_before_mutation: usize,
    pub rollback_pending: usize,
    pub cleanup_pending: usize,
    pub already_pending: usize,
}

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
                source_runtime_id, stage, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'requested', ?7, ?7)
            "#,
        )
        .bind(&migration_id)
        .bind(&metadata.instance_id)
        .bind(metadata.protocol.as_str())
        .bind(metadata.deployment_mode.as_str())
        .bind(target_mode.as_str())
        .bind(metadata.runtime_id())
        .bind(&now)
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
        self.get(&migration_id)
            .await?
            .ok_or(DeploymentMigrationError::NotFound(migration_id))
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
            .get(migration_id)
            .await?
            .ok_or_else(|| DeploymentMigrationError::NotFound(migration_id.to_string()))?;
        if current.revision != expected_revision {
            return Err(DeploymentMigrationError::StaleRevision {
                expected: expected_revision,
                actual: current.revision,
            });
        }
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
        self.get(migration_id)
            .await?
            .ok_or_else(|| DeploymentMigrationError::NotFound(migration_id.to_string()))
    }

    /// Atomically moves a provisional shared-pool reservation onto the public
    /// instance identity, swaps its normalized placement/backend metadata, and
    /// records the cutover commit. The source dedicated runtime row is retained
    /// until live target verification succeeds, so cleanup can move forward
    /// after a restart without ever routing back to stale data.
    pub async fn commit_dedicated_to_shared(
        &self,
        migration_id: &str,
        expected_revision: u64,
        provisional_reservation_id: &str,
        target: &InstanceMetadata,
    ) -> Result<DeploymentMigration, DeploymentMigrationError> {
        if target.deployment_mode != DeploymentMode::Shared {
            return Err(DeploymentMigrationError::InvalidCutoverTarget);
        }
        let current = self
            .get(migration_id)
            .await?
            .ok_or_else(|| DeploymentMigrationError::NotFound(migration_id.to_string()))?;
        if current.revision != expected_revision {
            return Err(DeploymentMigrationError::StaleRevision {
                expected: expected_revision,
                actual: current.revision,
            });
        }
        if current.stage != MigrationStage::CutoverPending
            || current.source_mode != DeploymentMode::Dedicated
            || current.target_mode != DeploymentMode::Shared
            || current.instance_id != target.instance_id
            || current.protocol != target.protocol
            || current.target_runtime_id.as_deref() != Some(target.runtime_id())
            || !current.source_fenced
        {
            return Err(DeploymentMigrationError::CutoverNotReady);
        }
        let metadata_json = serde_json::to_string(target)?;
        let limits_json = serde_json::to_string(&target.limits)?;
        let (backend_kind, socket_path, backend_host, backend_port) = match &target.backend {
            crate::shared::backend::BackendEndpoint::UnixSocket { socket_path } => {
                ("unix_socket", Some(socket_path.as_str()), None, None)
            }
            crate::shared::backend::BackendEndpoint::DockerTcp { host, port } => (
                "docker_tcp",
                None,
                Some(host.as_str()),
                Some(i64::from(*port)),
            ),
        };
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(DeploymentMigrationError::RevisionOverflow)?;
        let now = now_rfc3339();
        let mut transaction = self.pool.begin().await?;

        let reservation = sqlx::query(
            r#"
            UPDATE engine_runtime_reservations
            SET instance_id = ?1, updated_at = ?2
            WHERE instance_id = ?3 AND runtime_id = ?4
            "#,
        )
        .bind(&target.instance_id)
        .bind(&now)
        .bind(provisional_reservation_id)
        .bind(target.runtime_id())
        .execute(&mut *transaction)
        .await?;
        if reservation.rows_affected() != 1 {
            return Err(DeploymentMigrationError::ReservationMissing(
                provisional_reservation_id.to_string(),
            ));
        }

        let metadata = sqlx::query(
            r#"
            UPDATE instance_metadata
            SET status = ?1,
                deployment_mode = 'shared',
                runtime_id = ?2,
                disk_limit_blocked = 0,
                backend_kind = ?3,
                backend_socket_path = ?4,
                backend_host = ?5,
                backend_port = ?6,
                runtime_kind = ?7,
                container_name = ?8,
                network = ?9,
                limits_json = ?10,
                metadata_json = ?11,
                updated_at = ?12
            WHERE instance_id = ?13
              AND protocol = ?14
              AND deployment_mode = 'dedicated'
              AND runtime_id = ?13
            "#,
        )
        .bind(target.status.as_str())
        .bind(target.runtime_id())
        .bind(backend_kind)
        .bind(socket_path)
        .bind(backend_host)
        .bind(backend_port)
        .bind(target.runtime.kind.as_str())
        .bind(&target.runtime.container_name)
        .bind(&target.runtime.network_mode)
        .bind(limits_json)
        .bind(metadata_json)
        .bind(&now)
        .bind(&target.instance_id)
        .bind(target.protocol.as_str())
        .execute(&mut *transaction)
        .await?;
        if metadata.rows_affected() != 1 {
            return Err(DeploymentMigrationError::SourcePlacementChanged);
        }

        // Shared tenants use only their tenant credential. Retaining old root
        // or administrator credentials would create unnecessary secret copies.
        sqlx::query(
            r#"
            UPDATE instance_route_auth
            SET mariadb_root_password = NULL,
                mysql_root_password = NULL,
                mongodb_root_password = NULL,
                postgres_admin_password = NULL,
                updated_at = ?1
            WHERE instance_id = ?2
            "#,
        )
        .bind(&now)
        .bind(&target.instance_id)
        .execute(&mut *transaction)
        .await?;

        let migration = sqlx::query(
            r#"
            UPDATE deployment_migrations
            SET stage = 'cutover_committed', revision = ?1,
                cutover_committed = 1, failure_code = NULL,
                failure_message = NULL, updated_at = ?2
            WHERE migration_id = ?3 AND revision = ?4
              AND stage = 'cutover_pending' AND source_fenced = 1
              AND target_runtime_id = ?5
            "#,
        )
        .bind(u64_to_i64(next_revision)?)
        .bind(&now)
        .bind(migration_id)
        .bind(u64_to_i64(expected_revision)?)
        .bind(target.runtime_id())
        .execute(&mut *transaction)
        .await?;
        if migration.rows_affected() != 1 {
            return Err(DeploymentMigrationError::StaleRevision {
                expected: expected_revision,
                actual: current.revision,
            });
        }
        transaction.commit().await?;
        self.get(migration_id)
            .await?
            .ok_or_else(|| DeploymentMigrationError::NotFound(migration_id.to_string()))
    }

    /// Atomically makes a prepared dedicated runtime authoritative and removes
    /// the source shared reservation. The source tenant itself is retained in
    /// its shared engine until live target verification and forward cleanup.
    pub async fn commit_shared_to_dedicated(
        &self,
        migration_id: &str,
        expected_revision: u64,
        source_reservation_id: &str,
        target: &InstanceMetadata,
    ) -> Result<DeploymentMigration, DeploymentMigrationError> {
        if target.deployment_mode != DeploymentMode::Dedicated
            || target.runtime_id() != target.instance_id
        {
            return Err(DeploymentMigrationError::InvalidCutoverTarget);
        }
        let current = self
            .get(migration_id)
            .await?
            .ok_or_else(|| DeploymentMigrationError::NotFound(migration_id.to_string()))?;
        if current.revision != expected_revision {
            return Err(DeploymentMigrationError::StaleRevision {
                expected: expected_revision,
                actual: current.revision,
            });
        }
        if current.stage != MigrationStage::CutoverPending
            || current.source_mode != DeploymentMode::Shared
            || current.target_mode != DeploymentMode::Dedicated
            || current.instance_id != target.instance_id
            || current.protocol != target.protocol
            || current.target_runtime_id.as_deref() != Some(target.runtime_id())
            || !current.source_fenced
        {
            return Err(DeploymentMigrationError::CutoverNotReady);
        }

        let metadata_json = serde_json::to_string(target)?;
        let limits_json = serde_json::to_string(&target.limits)?;
        let (backend_kind, socket_path, backend_host, backend_port) = match &target.backend {
            crate::shared::backend::BackendEndpoint::UnixSocket { socket_path } => {
                ("unix_socket", Some(socket_path.as_str()), None, None)
            }
            crate::shared::backend::BackendEndpoint::DockerTcp { host, port } => (
                "docker_tcp",
                None,
                Some(host.as_str()),
                Some(i64::from(*port)),
            ),
        };
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(DeploymentMigrationError::RevisionOverflow)?;
        let now = now_rfc3339();
        let mut transaction = self.pool.begin().await?;
        let reservation = sqlx::query(
            r#"
            SELECT reservation.runtime_id
            FROM engine_runtime_reservations AS reservation
            WHERE reservation.instance_id = ?1
            "#,
        )
        .bind(&target.instance_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| DeploymentMigrationError::ReservationMissing(target.instance_id.clone()))?;
        let source_runtime_id: String = reservation.try_get("runtime_id")?;
        if source_runtime_id != current.source_runtime_id {
            return Err(DeploymentMigrationError::SourcePlacementChanged);
        }

        let metadata = sqlx::query(
            r#"
            UPDATE instance_metadata
            SET status = ?1,
                deployment_mode = 'dedicated',
                runtime_id = ?2,
                disk_limit_blocked = 0,
                backend_kind = ?3,
                backend_socket_path = ?4,
                backend_host = ?5,
                backend_port = ?6,
                runtime_kind = ?7,
                container_name = ?8,
                network = ?9,
                limits_json = ?10,
                metadata_json = ?11,
                updated_at = ?12
            WHERE instance_id = ?13
              AND protocol = ?14
              AND deployment_mode = 'shared'
              AND runtime_id = ?15
            "#,
        )
        .bind(target.status.as_str())
        .bind(target.runtime_id())
        .bind(backend_kind)
        .bind(socket_path)
        .bind(backend_host)
        .bind(backend_port)
        .bind(target.runtime.kind.as_str())
        .bind(&target.runtime.container_name)
        .bind(&target.runtime.network_mode)
        .bind(limits_json)
        .bind(metadata_json)
        .bind(&now)
        .bind(&target.instance_id)
        .bind(target.protocol.as_str())
        .bind(&source_runtime_id)
        .execute(&mut *transaction)
        .await?;
        if metadata.rows_affected() != 1 {
            return Err(DeploymentMigrationError::SourcePlacementChanged);
        }

        // Keep the source capacity reserved until its physical tenant has
        // actually been dropped. The migration-owned id is excluded from
        // orphan cleanup and keeps node admission honest during forward
        // cleanup or manual recovery.
        let retained = sqlx::query(
            r#"
            UPDATE engine_runtime_reservations
            SET instance_id = ?1, updated_at = ?2
            WHERE instance_id = ?3 AND runtime_id = ?4
            "#,
        )
        .bind(source_reservation_id)
        .bind(&now)
        .bind(&target.instance_id)
        .bind(&source_runtime_id)
        .execute(&mut *transaction)
        .await?;
        if retained.rows_affected() != 1 {
            return Err(DeploymentMigrationError::ReservationMissing(
                target.instance_id.clone(),
            ));
        }

        let migration = sqlx::query(
            r#"
            UPDATE deployment_migrations
            SET stage = 'cutover_committed', revision = ?1,
                cutover_committed = 1, failure_code = NULL,
                failure_message = NULL, updated_at = ?2
            WHERE migration_id = ?3 AND revision = ?4
              AND stage = 'cutover_pending' AND source_fenced = 1
              AND target_runtime_id = ?5
            "#,
        )
        .bind(u64_to_i64(next_revision)?)
        .bind(&now)
        .bind(migration_id)
        .bind(u64_to_i64(expected_revision)?)
        .bind(target.runtime_id())
        .execute(&mut *transaction)
        .await?;
        if migration.rows_affected() != 1 {
            return Err(DeploymentMigrationError::StaleRevision {
                expected: expected_revision,
                actual: current.revision,
            });
        }
        transaction.commit().await?;
        self.get(migration_id)
            .await?
            .ok_or_else(|| DeploymentMigrationError::NotFound(migration_id.to_string()))
    }

    pub async fn recover_unfinished(
        &self,
    ) -> Result<MigrationRecoverySummary, DeploymentMigrationError> {
        let mut summary = MigrationRecoverySummary::default();
        for migration in self.list_active().await? {
            let Some(next) = migration.stage.recovery_stage() else {
                summary.already_pending += 1;
                continue;
            };
            let failure = match next {
                MigrationStage::Failed => MigrationFailure::RestartBeforeMutation,
                MigrationStage::RollingBack => MigrationFailure::RestartBeforeCutover,
                MigrationStage::CleanupPending => MigrationFailure::RestartAfterCutover,
                _ => {
                    return Err(DeploymentMigrationError::InvalidValue(
                        "recovery_stage",
                        next.as_str().to_string(),
                    ));
                }
            };
            self.transition(
                &migration.migration_id,
                migration.revision,
                next,
                MigrationPatch {
                    failure: Some(failure),
                    ..MigrationPatch::default()
                },
            )
            .await?;
            match next {
                MigrationStage::Failed => summary.failed_before_mutation += 1,
                MigrationStage::RollingBack => summary.rollback_pending += 1,
                MigrationStage::CleanupPending => summary.cleanup_pending += 1,
                _ => {
                    return Err(DeploymentMigrationError::InvalidValue(
                        "recovery_stage",
                        next.as_str().to_string(),
                    ));
                }
            }
        }
        Ok(summary)
    }
}

fn read_migration(row: &SqliteRow) -> Result<DeploymentMigration, DeploymentMigrationError> {
    let protocol_value: String = row.try_get("protocol")?;
    let protocol = Protocol::from_str(&protocol_value)
        .map_err(|_| DeploymentMigrationError::InvalidValue("protocol", protocol_value.clone()))?;
    let source_mode_value: String = row.try_get("source_mode")?;
    let source_mode = DeploymentMode::parse(&source_mode_value).ok_or_else(|| {
        DeploymentMigrationError::InvalidValue("source_mode", source_mode_value.clone())
    })?;
    let target_mode_value: String = row.try_get("target_mode")?;
    let target_mode = DeploymentMode::parse(&target_mode_value).ok_or_else(|| {
        DeploymentMigrationError::InvalidValue("target_mode", target_mode_value.clone())
    })?;
    let stage_value: String = row.try_get("stage")?;
    let stage = MigrationStage::parse(&stage_value)
        .ok_or_else(|| DeploymentMigrationError::InvalidValue("stage", stage_value.clone()))?;
    let revision: i64 = row.try_get("revision")?;
    Ok(DeploymentMigration {
        migration_id: row.try_get("migration_id")?,
        instance_id: row.try_get("instance_id")?,
        protocol,
        source_mode,
        target_mode,
        source_runtime_id: row.try_get("source_runtime_id")?,
        target_runtime_id: row.try_get("target_runtime_id")?,
        stage,
        revision: u64::try_from(revision)
            .map_err(|_| DeploymentMigrationError::InvalidInteger("revision", revision))?,
        source_fenced: row.try_get("source_fenced")?,
        cutover_committed: row.try_get("cutover_committed")?,
        failure_code: row.try_get("failure_code")?,
        failure_message: row.try_get("failure_message")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn is_unique_error(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation())
}

fn u64_to_i64(value: u64) -> Result<i64, DeploymentMigrationError> {
    i64::try_from(value).map_err(|_| DeploymentMigrationError::RevisionOverflow)
}

#[derive(Debug, thiserror::Error)]
pub enum DeploymentMigrationError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Placement(#[from] PlacementError),
    #[error("instance already uses {0:?} deployment")]
    SameMode(DeploymentMode),
    #[error("instance {0} already has an active deployment migration")]
    ActiveMigration(String),
    #[error("deployment migration {0} was not found")]
    NotFound(String),
    #[error("deployment migration revision changed: expected {expected}, found {actual}")]
    StaleRevision { expected: u64, actual: u64 },
    #[error("deployment migration cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: MigrationStage,
        to: MigrationStage,
    },
    #[error("deployment migration revision overflowed")]
    RevisionOverflow,
    #[error("deployment migration cannot mark the target prepared without a target runtime")]
    TargetRuntimeRequired,
    #[error("deployment migration cannot advance until the source route and sessions are fenced")]
    SourceFenceRequired,
    #[error(
        "deployment migration cannot commit cutover before target preparation and source fencing"
    )]
    CutoverNotReady,
    #[error("deployment migration cutover target is not a shared placement")]
    InvalidCutoverTarget,
    #[error("deployment migration provisional reservation {0} is missing")]
    ReservationMissing(String),
    #[error("deployment migration source placement changed before cutover")]
    SourcePlacementChanged,
    #[error("invalid deployment migration {0}: {1}")]
    InvalidValue(&'static str, String),
    #[error("invalid deployment migration {0}: {1}")]
    InvalidInteger(&'static str, i64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        instances::metadata::{
            DatabaseIdentity, DesiredInstanceState, InstanceStatus, PublicEndpoint, RuntimeKind,
            RuntimeMetadata, SCHEMA_VERSION,
        },
        placement::{
            ENGINE_RUNTIME_SCHEMA_VERSION, EngineRuntime, EngineRuntimeStatus, PlacementRepository,
            ReserveTenant, RuntimeReservation,
        },
        shared::{backend::BackendEndpoint, limits::InstanceLimits},
        storage::{repositories::InstanceRepository, sqlite},
    };

    fn metadata(instance_id: &str) -> InstanceMetadata {
        InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: instance_id.to_string(),
            deployment_mode: DeploymentMode::Dedicated,
            runtime_id: instance_id.to_string(),
            protocol: Protocol::Postgres,
            status: InstanceStatus::Running,
            desired_state: DesiredInstanceState::Running,
            disk_limit_blocked: false,
            public: PublicEndpoint {
                host: "db.example.test".to_string(),
                port: 5432,
            },
            backend: BackendEndpoint::UnixSocket {
                socket_path: "/tmp/postgres.sock".to_string(),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: "postgres".to_string(),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: "app".to_string(),
                username: "app".to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mysql_native_password_sha1_stage2: None,
            mysql_root_password: None,
            mongodb_root_password: None,
            postgres_admin_password: Some("admin".to_string()),
            tenant_password: Some("tenant".to_string()),
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn metadata_in_mode(instance_id: &str, mode: DeploymentMode) -> InstanceMetadata {
        let mut metadata = metadata(instance_id);
        metadata.deployment_mode = mode;
        if mode == DeploymentMode::Shared {
            metadata.runtime_id = format!("pool-{instance_id}");
            metadata.postgres_admin_password = None;
        }
        metadata
    }

    async fn repository() -> (DeploymentMigrationRepository, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(directory.path()).await.unwrap();
        (DeploymentMigrationRepository::new(pool), directory)
    }

    #[tokio::test]
    async fn active_workflow_is_unique_and_terminal_history_allows_retry() {
        let (repository, _directory) = repository().await;
        let first = repository
            .start(&metadata("inst-a"), DeploymentMode::Shared)
            .await
            .unwrap();
        assert!(matches!(
            repository
                .start(&metadata("inst-a"), DeploymentMode::Shared)
                .await,
            Err(DeploymentMigrationError::ActiveMigration(_))
        ));
        repository
            .transition(
                &first.migration_id,
                first.revision,
                MigrationStage::Failed,
                MigrationPatch {
                    failure: Some(MigrationFailure::PreflightFailed),
                    ..MigrationPatch::default()
                },
            )
            .await
            .unwrap();
        repository
            .start(&metadata("inst-a"), DeploymentMode::Shared)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn transition_compare_and_swap_rejects_stale_and_invalid_writers() {
        let (repository, _directory) = repository().await;
        let migration = repository
            .start(&metadata("inst-a"), DeploymentMode::Shared)
            .await
            .unwrap();
        let preflight = repository
            .transition(
                &migration.migration_id,
                migration.revision,
                MigrationStage::Preflight,
                MigrationPatch::default(),
            )
            .await
            .unwrap();
        assert!(matches!(
            repository
                .transition(
                    &migration.migration_id,
                    migration.revision,
                    MigrationStage::Cancelled,
                    MigrationPatch::default(),
                )
                .await,
            Err(DeploymentMigrationError::StaleRevision { .. })
        ));
        assert!(matches!(
            repository
                .transition(
                    &migration.migration_id,
                    preflight.revision,
                    MigrationStage::Completed,
                    MigrationPatch::default(),
                )
                .await,
            Err(DeploymentMigrationError::InvalidTransition { .. })
        ));
    }

    #[tokio::test]
    async fn boot_recovery_classifies_every_crash_stage_in_both_directions() {
        let (repository, _directory) = repository().await;
        let cases = [
            (MigrationStage::Requested, MigrationStage::Failed),
            (MigrationStage::Preflight, MigrationStage::Failed),
            (MigrationStage::TargetPreparing, MigrationStage::RollingBack),
            (MigrationStage::TargetPrepared, MigrationStage::RollingBack),
            (MigrationStage::SourceFencing, MigrationStage::RollingBack),
            (MigrationStage::SourceFenced, MigrationStage::RollingBack),
            (MigrationStage::Exporting, MigrationStage::RollingBack),
            (MigrationStage::Exported, MigrationStage::RollingBack),
            (MigrationStage::Importing, MigrationStage::RollingBack),
            (MigrationStage::Imported, MigrationStage::RollingBack),
            (MigrationStage::Validating, MigrationStage::RollingBack),
            (MigrationStage::CutoverPending, MigrationStage::RollingBack),
            (
                MigrationStage::CutoverCommitted,
                MigrationStage::CleanupPending,
            ),
            (
                MigrationStage::VerifyingCutover,
                MigrationStage::CleanupPending,
            ),
            (
                MigrationStage::CleaningSource,
                MigrationStage::CleanupPending,
            ),
        ];
        let mut expected = Vec::new();
        for source_mode in [DeploymentMode::Dedicated, DeploymentMode::Shared] {
            let target_mode = match source_mode {
                DeploymentMode::Dedicated => DeploymentMode::Shared,
                DeploymentMode::Shared => DeploymentMode::Dedicated,
            };
            for (index, (crash_stage, recovery_stage)) in cases.iter().copied().enumerate() {
                let mode = source_mode.as_str();
                let source = metadata_in_mode(&format!("{mode}-{index}"), source_mode);
                let mut migration = repository.start(&source, target_mode).await.unwrap();
                if crash_stage != MigrationStage::Requested {
                    migration = advance_to(&repository, migration, crash_stage).await;
                }
                expected.push((migration.migration_id, recovery_stage));
            }
        }

        let summary = repository.recover_unfinished().await.unwrap();
        assert_eq!(summary.failed_before_mutation, 4);
        assert_eq!(summary.rollback_pending, 20);
        assert_eq!(summary.cleanup_pending, 6);
        for (migration_id, stage) in expected {
            let recovered = repository.get(&migration_id).await.unwrap().unwrap();
            assert_eq!(recovered.stage, stage, "migration {migration_id}");
            assert_eq!(
                recovered.cutover_committed,
                stage == MigrationStage::CleanupPending
            );
        }
    }

    #[tokio::test]
    async fn dedicated_to_shared_cutover_is_one_atomic_metadata_and_reservation_commit() {
        let (repository, _directory) = repository().await;
        let instances = InstanceRepository::new(repository.pool.clone());
        let placements = PlacementRepository::new(repository.pool.clone());
        let source = metadata("inst-a");
        instances.upsert(&source).await.unwrap();
        placements
            .save(&EngineRuntime::legacy_dedicated(
                &source,
                EngineRuntimeStatus::Running,
                "postgres:18".to_string(),
            ))
            .await
            .unwrap();
        let shared_runtime = EngineRuntime {
            schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
            runtime_id: "runtime-target".to_string(),
            protocol: source.protocol,
            deployment_mode: DeploymentMode::Shared,
            status: EngineRuntimeStatus::Running,
            backend: BackendEndpoint::UnixSocket {
                socket_path: "/tmp/shared-postgres.sock".to_string(),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: "shared-postgres".to_string(),
                network_mode: "none".to_string(),
            },
            limits: source.limits.clone(),
            image: "postgres:18".to_string(),
            database_version: None,
            compatibility: None,
            compatibility_key: "postgres:18".to_string(),
            max_tenants: 10,
            reserved: RuntimeReservation::default(),
            admin_secret: Some("pool-admin".to_string()),
            created_at: source.created_at.clone(),
            updated_at: source.updated_at.clone(),
        };
        placements.save(&shared_runtime).await.unwrap();
        placements
            .reserve(ReserveTenant {
                instance_id: "migration-temp",
                runtime_id: &shared_runtime.runtime_id,
                database: &source.database.name,
                username: &source.database.username,
                limits: &source.limits,
            })
            .await
            .unwrap();
        placements.mark_provisioned("migration-temp").await.unwrap();
        let pending = advance_to(
            &repository,
            repository
                .start(&source, DeploymentMode::Shared)
                .await
                .unwrap(),
            MigrationStage::CutoverPending,
        )
        .await;
        let mut target = source.clone();
        target.deployment_mode = DeploymentMode::Shared;
        target.runtime_id.clone_from(&shared_runtime.runtime_id);
        target.backend = shared_runtime.backend.clone();
        target.runtime = shared_runtime.runtime.clone();
        target.postgres_admin_password = None;
        target.limits.disk_enforced = true;
        target.limits.disk_enforcement_method = "host_linux_project_quota".to_string();
        assert_eq!(
            placements
                .root_charged_disk_mib("runtime-target")
                .await
                .unwrap(),
            12_800
        );

        let committed = repository
            .commit_dedicated_to_shared(
                &pending.migration_id,
                pending.revision,
                "migration-temp",
                &target,
            )
            .await
            .unwrap();

        assert_eq!(committed.stage, MigrationStage::CutoverCommitted);
        assert!(committed.cutover_committed);
        let stored = instances.get("inst-a").await.unwrap().unwrap();
        assert_eq!(stored.deployment_mode, DeploymentMode::Shared);
        assert_eq!(stored.runtime_id(), "runtime-target");
        assert!(stored.postgres_admin_password.is_none());
        assert_eq!(
            placements.tenants("runtime-target").await.unwrap(),
            vec!["inst-a".to_string()]
        );
        assert_eq!(
            placements
                .root_charged_disk_mib("runtime-target")
                .await
                .unwrap(),
            2_560
        );
        assert!(placements.get("inst-a").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn shared_to_dedicated_cutover_is_one_atomic_metadata_and_reservation_commit() {
        let (repository, _directory) = repository().await;
        let instances = InstanceRepository::new(repository.pool.clone());
        let placements = PlacementRepository::new(repository.pool.clone());
        let mut source = metadata_in_mode("inst-b", DeploymentMode::Shared);
        source.runtime_id = "pool-source".to_string();
        source.backend = BackendEndpoint::UnixSocket {
            socket_path: "/tmp/shared-postgres.sock".to_string(),
        };
        source.runtime.container_name = "shared-postgres".to_string();
        source.limits.disk_enforced = true;
        source.limits.disk_enforcement_method = "host_linux_project_quota".to_string();
        let source_runtime = EngineRuntime {
            schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
            runtime_id: source.runtime_id.clone(),
            protocol: source.protocol,
            deployment_mode: DeploymentMode::Shared,
            status: EngineRuntimeStatus::Running,
            backend: source.backend.clone(),
            runtime: source.runtime.clone(),
            limits: source.limits.clone(),
            image: "postgres:18".to_string(),
            database_version: None,
            compatibility: None,
            compatibility_key: "postgres:18".to_string(),
            max_tenants: 10,
            reserved: RuntimeReservation::default(),
            admin_secret: Some("pool-admin".to_string()),
            created_at: source.created_at.clone(),
            updated_at: source.updated_at.clone(),
        };
        placements.save(&source_runtime).await.unwrap();
        placements
            .reserve(ReserveTenant {
                instance_id: &source.instance_id,
                runtime_id: &source_runtime.runtime_id,
                database: &source.database.name,
                username: &source.database.username,
                limits: &source.limits,
            })
            .await
            .unwrap();
        placements
            .mark_provisioned(&source.instance_id)
            .await
            .unwrap();
        instances.upsert(&source).await.unwrap();
        assert_eq!(
            placements
                .root_charged_disk_mib("pool-source")
                .await
                .unwrap(),
            2_560
        );

        let mut target = source.clone();
        target.deployment_mode = DeploymentMode::Dedicated;
        target.runtime_id.clone_from(&target.instance_id);
        target.backend = BackendEndpoint::UnixSocket {
            socket_path: "/tmp/dedicated-postgres.sock".to_string(),
        };
        target.runtime.container_name = "dedicated-postgres".to_string();
        target.postgres_admin_password = Some("target-admin".to_string());
        instances
            .stage_dedicated_admin_secrets(&target)
            .await
            .unwrap();
        placements
            .save(&EngineRuntime::legacy_dedicated(
                &target,
                EngineRuntimeStatus::Running,
                "postgres:18".to_string(),
            ))
            .await
            .unwrap();
        let pending = advance_to(
            &repository,
            repository
                .start(&source, DeploymentMode::Dedicated)
                .await
                .unwrap(),
            MigrationStage::CutoverPending,
        )
        .await;
        let source_reservation_id = format!("migration_{}", pending.migration_id.replace('-', ""));

        let committed = repository
            .commit_shared_to_dedicated(
                &pending.migration_id,
                pending.revision,
                &source_reservation_id,
                &target,
            )
            .await
            .unwrap();

        assert_eq!(committed.stage, MigrationStage::CutoverCommitted);
        assert!(committed.cutover_committed);
        let stored = instances.get("inst-b").await.unwrap().unwrap();
        assert_eq!(stored.deployment_mode, DeploymentMode::Dedicated);
        assert_eq!(stored.runtime_id(), "inst-b");
        assert_eq!(
            stored.postgres_admin_password.as_deref(),
            Some("target-admin")
        );
        assert_eq!(stored.tenant_password, source.tenant_password);
        assert_eq!(
            placements.tenants("pool-source").await.unwrap(),
            vec![source_reservation_id.clone()]
        );
        assert_eq!(placements.tenant_count("pool-source").await.unwrap(), 1);
        assert_eq!(
            placements
                .root_charged_disk_mib("pool-source")
                .await
                .unwrap(),
            12_800
        );
        placements.release(&source_reservation_id).await.unwrap();
        assert_eq!(placements.tenant_count("pool-source").await.unwrap(), 0);
        assert_eq!(
            placements
                .root_charged_disk_mib("pool-source")
                .await
                .unwrap(),
            2_048
        );
        assert!(placements.get("inst-b").await.unwrap().is_some());
    }

    async fn advance_to(
        repository: &DeploymentMigrationRepository,
        mut migration: DeploymentMigration,
        target: MigrationStage,
    ) -> DeploymentMigration {
        let target_runtime_id = match migration.target_mode {
            DeploymentMode::Dedicated => migration.instance_id.clone(),
            DeploymentMode::Shared => "runtime-target".to_string(),
        };
        let path = [
            MigrationStage::Preflight,
            MigrationStage::TargetPreparing,
            MigrationStage::TargetPrepared,
            MigrationStage::SourceFencing,
            MigrationStage::SourceFenced,
            MigrationStage::Exporting,
            MigrationStage::Exported,
            MigrationStage::Importing,
            MigrationStage::Imported,
            MigrationStage::Validating,
            MigrationStage::CutoverPending,
            MigrationStage::CutoverCommitted,
            MigrationStage::VerifyingCutover,
            MigrationStage::CleaningSource,
        ];
        for stage in path {
            migration = repository
                .transition(
                    &migration.migration_id,
                    migration.revision,
                    stage,
                    MigrationPatch {
                        target_runtime_id: (stage == MigrationStage::TargetPrepared)
                            .then_some(target_runtime_id.as_str()),
                        source_fenced: (stage == MigrationStage::SourceFenced).then_some(true),
                        ..MigrationPatch::default()
                    },
                )
                .await
                .unwrap();
            if stage == target {
                return migration;
            }
        }
        panic!("target stage not in test path");
    }
}
