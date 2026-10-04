use sqlx::Row;

use super::{
    DeploymentMigration, DeploymentMigrationError, DeploymentMigrationRepository,
    recovery::cutover_is_ready,
    rows::{backend_columns, mark_cutover_committed},
};
use crate::{
    server::{metadata::InstanceMetadata, placement::DeploymentMode},
    utils::time::now_rfc3339,
};

impl DeploymentMigrationRepository {
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
            .get_at_revision(migration_id, expected_revision)
            .await?;
        if !cutover_is_ready(
            &current,
            DeploymentMode::Dedicated,
            DeploymentMode::Shared,
            target,
        ) {
            return Err(DeploymentMigrationError::CutoverNotReady);
        }
        let metadata_json = serde_json::to_string(target)?;
        let limits_json = serde_json::to_string(&target.limits)?;
        let (backend_kind, socket_path, backend_host, backend_port) =
            backend_columns(&target.backend);
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

        mark_cutover_committed(
            &mut transaction,
            migration_id,
            expected_revision,
            next_revision,
            &now,
            target.runtime_id(),
        )
        .await?;
        transaction.commit().await?;
        self.get_existing(migration_id).await
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
            .get_at_revision(migration_id, expected_revision)
            .await?;
        if !cutover_is_ready(
            &current,
            DeploymentMode::Shared,
            DeploymentMode::Dedicated,
            target,
        ) {
            return Err(DeploymentMigrationError::CutoverNotReady);
        }

        let metadata_json = serde_json::to_string(target)?;
        let limits_json = serde_json::to_string(&target.limits)?;
        let (backend_kind, socket_path, backend_host, backend_port) =
            backend_columns(&target.backend);
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(DeploymentMigrationError::RevisionOverflow)?;
        let now = now_rfc3339();
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
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

        mark_cutover_committed(
            &mut transaction,
            migration_id,
            expected_revision,
            next_revision,
            &now,
            target.runtime_id(),
        )
        .await?;
        transaction.commit().await?;
        self.get_existing(migration_id).await
    }
}
