use sqlx::{Row, sqlite::SqliteRow};

use super::{PlacementRepository, PlacementRepositoryError, i64_to_u64, parse_protocol};
use crate::{
    placement::model::{EngineRuntime, PlacementError, TenantReservation, TenantReservationState},
    shared::limits::InstanceLimits,
};

impl PlacementRepository {
    pub async fn check_tenant_identity(
        &self,
        runtime_id: &str,
        database: &str,
        username: &str,
    ) -> Result<(), PlacementRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                EXISTS(
                    SELECT 1 FROM instance_metadata
                    WHERE deployment_mode = 'shared'
                      AND runtime_id = ?1
                      AND database_name = ?2
                    UNION ALL
                    SELECT 1 FROM engine_runtime_reservations
                    WHERE runtime_id = ?1 AND database_name = ?2
                ) AS database_in_use,
                EXISTS(
                    SELECT 1 FROM instance_metadata
                    WHERE deployment_mode = 'shared'
                      AND runtime_id = ?1
                      AND database_username = ?3
                    UNION ALL
                    SELECT 1 FROM engine_runtime_reservations
                    WHERE runtime_id = ?1 AND database_username = ?3
                ) AS username_in_use
            "#,
        )
        .bind(runtime_id)
        .bind(database)
        .bind(username)
        .fetch_one(&self.pool)
        .await?;
        if row.try_get::<bool, _>("database_in_use")? {
            return Err(PlacementRepositoryError::DatabaseInUse {
                runtime_id: runtime_id.to_string(),
                database: database.to_string(),
            });
        }
        if row.try_get::<bool, _>("username_in_use")? {
            return Err(PlacementRepositoryError::UsernameInUse {
                runtime_id: runtime_id.to_string(),
                username: username.to_string(),
            });
        }
        Ok(())
    }

    pub async fn tenants(&self, runtime_id: &str) -> Result<Vec<String>, PlacementRepositoryError> {
        Ok(self
            .reservations(runtime_id)
            .await?
            .into_iter()
            .map(|reservation| reservation.instance_id)
            .collect())
    }

    pub async fn reservations(
        &self,
        runtime_id: &str,
    ) -> Result<Vec<TenantReservation>, PlacementRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT reservation.*, runtime.protocol
            FROM engine_runtime_reservations AS reservation
            JOIN engine_runtimes AS runtime ON runtime.runtime_id = reservation.runtime_id
            WHERE reservation.runtime_id = ?1
            ORDER BY reservation.instance_id
            "#,
        )
        .bind(runtime_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(read_reservation).collect()
    }

    pub async fn reservation_runtime(
        &self,
        instance_id: &str,
    ) -> Result<Option<EngineRuntime>, PlacementRepositoryError> {
        let runtime_id = sqlx::query_scalar::<_, String>(
            "SELECT runtime_id FROM engine_runtime_reservations WHERE instance_id = ?1",
        )
        .bind(instance_id)
        .fetch_optional(&self.pool)
        .await?;
        match runtime_id {
            Some(runtime_id) => self.get(&runtime_id).await,
            None => Ok(None),
        }
    }

    /// Returns the shared-pool capacity that is still charged to the pool
    /// root. A tenant with a durable hard child quota contributes only its
    /// pooled engine-global spill reserve; its data bytes are charged to the
    /// child project. Missing or soft tenant metadata is counted in full, and
    /// every reservation contributes to spill so interrupted provisioning or
    /// migration remains conservative.
    pub async fn root_charged_disk_mib(
        &self,
        runtime_id: &str,
    ) -> Result<u64, PlacementRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT runtime.protocol,
                   COALESCE(SUM(reservation.disk_mib), 0) AS tenant_disk_mib,
                   COALESCE(SUM(
                       CASE
                           WHEN instance.instance_id IS NULL
                             OR COALESCE(
                                 json_extract(instance.limits_json, '$.disk_enforced'),
                                 0
                             ) = 0
                           THEN reservation.disk_mib
                           ELSE 0
                       END
                   ), 0) AS root_charged_disk_mib
            FROM engine_runtimes AS runtime
            LEFT JOIN engine_runtime_reservations AS reservation
              ON reservation.runtime_id = runtime.runtime_id
            LEFT JOIN instance_metadata AS instance
              ON instance.instance_id = reservation.instance_id
             AND instance.deployment_mode = 'shared'
             AND instance.runtime_id = reservation.runtime_id
             AND instance.protocol = runtime.protocol
             AND instance.database_name = reservation.database_name
             AND instance.database_username = reservation.database_username
             AND json_extract(instance.limits_json, '$.disk_mib') = reservation.disk_mib
            WHERE runtime.runtime_id = ?1
              AND runtime.deployment_mode = 'shared'
            GROUP BY runtime.runtime_id, runtime.protocol
            "#,
        )
        .bind(runtime_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| PlacementRepositoryError::RuntimeNotFound(runtime_id.to_string()))?;
        let protocol = parse_protocol(row.try_get("protocol")?)?;
        let tenant_disk = i64_to_u64(
            row.try_get("root_charged_disk_mib")?,
            "root_charged_disk_mib",
        )?;
        let all_tenant_disk = i64_to_u64(row.try_get("tenant_disk_mib")?, "tenant_disk_mib")?;
        let overhead = crate::placement::policy::engine_disk_overhead(protocol)
            .ok_or(PlacementError::UnsupportedSharedProtocol(protocol))?;
        let spill = crate::placement::policy::root_spill_mib(protocol, all_tenant_disk)
            .ok_or(PlacementError::UnsupportedSharedProtocol(protocol))?;
        overhead
            .checked_add(tenant_disk)
            .and_then(|disk| disk.checked_add(spill))
            .ok_or_else(|| {
                PlacementRepositoryError::InvalidReservation(
                    "root-charged shared-pool disk capacity overflow".to_string(),
                )
            })
    }

    pub async fn tenant_count(&self, runtime_id: &str) -> Result<u32, PlacementRepositoryError> {
        let count: i64 =
            sqlx::query_scalar("SELECT tenant_count FROM engine_runtimes WHERE runtime_id = ?1")
                .bind(runtime_id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| PlacementRepositoryError::RuntimeNotFound(runtime_id.to_string()))?;
        u32::try_from(count).map_err(|_| PlacementRepositoryError::InvalidInteger {
            field: "tenant_count",
            value: count,
        })
    }

    pub async fn list_orphans(&self) -> Result<Vec<TenantReservation>, PlacementRepositoryError> {
        let rows = sqlx::query(&orphan_reservation_select(
            "ORDER BY reservation.instance_id",
        ))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(read_reservation).collect()
    }

    pub async fn get_orphan(
        &self,
        instance_id: &str,
    ) -> Result<Option<TenantReservation>, PlacementRepositoryError> {
        let row = sqlx::query(&orphan_reservation_select(
            "AND reservation.instance_id = ?1 LIMIT 1",
        ))
        .bind(instance_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(read_reservation).transpose()
    }

    pub async fn get_reservation(
        &self,
        instance_id: &str,
    ) -> Result<Option<TenantReservation>, PlacementRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT reservation.*, runtime.protocol
            FROM engine_runtime_reservations AS reservation
            JOIN engine_runtimes AS runtime ON runtime.runtime_id = reservation.runtime_id
            WHERE reservation.instance_id = ?1
            LIMIT 1
            "#,
        )
        .bind(instance_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(read_reservation).transpose()
    }
}

fn orphan_reservation_select(suffix: &str) -> String {
    format!(
        r#"
        SELECT reservation.*, runtime.protocol
        FROM engine_runtime_reservations AS reservation
        JOIN engine_runtimes AS runtime ON runtime.runtime_id = reservation.runtime_id
        LEFT JOIN instance_metadata AS instance
          ON instance.instance_id = reservation.instance_id
        WHERE instance.instance_id IS NULL
          AND NOT EXISTS (
              SELECT 1
              FROM deployment_migrations AS migration
              WHERE migration.stage NOT IN ('completed', 'failed', 'cancelled')
                AND reservation.instance_id =
                    'migration_' || replace(migration.migration_id, '-', '')
          )
        {suffix}
        "#
    )
}

fn read_reservation(row: &SqliteRow) -> Result<TenantReservation, PlacementRepositoryError> {
    let state_value: String = row.try_get("state")?;
    let state = TenantReservationState::parse(&state_value).ok_or_else(|| {
        PlacementRepositoryError::InvalidValue {
            field: "reservation_state",
            value: state_value,
        }
    })?;
    let memory_mib: i64 = row.try_get("memory_mib")?;
    let disk_mib: i64 = row.try_get("disk_mib")?;
    Ok(TenantReservation {
        instance_id: row.try_get("instance_id")?,
        runtime_id: row.try_get("runtime_id")?,
        database: row.try_get("database_name")?,
        username: row.try_get("database_username")?,
        state,
        limits: InstanceLimits {
            cpu_cores: row.try_get("cpu_cores")?,
            memory_mib: i64_to_u64(memory_mib, "memory_mib")?,
            disk_mib: i64_to_u64(disk_mib, "disk_mib")?,
            disk_enforced: false,
            disk_enforcement_method: "shared_pool_reservation".to_string(),
        },
    })
}

pub(super) fn claim_matches(
    reservation: &TenantReservation,
    runtime_id: &str,
    database: &str,
    username: &str,
    limits: &InstanceLimits,
) -> bool {
    reservation.runtime_id == runtime_id
        && reservation.database == database
        && reservation.username == username
        && reservation.state == TenantReservationState::Reserved
        && reservation.limits.cpu_cores.to_bits() == limits.cpu_cores.to_bits()
        && reservation.limits.memory_mib == limits.memory_mib
        && reservation.limits.disk_mib == limits.disk_mib
}
