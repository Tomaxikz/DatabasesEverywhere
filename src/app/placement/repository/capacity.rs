use std::time::Duration;

use sqlx::{Row, Sqlite, Transaction};

use super::{
    PlacementRepository, PlacementRepositoryError, i64_to_u64, parse_protocol,
    reservations::claim_matches, u64_to_i64,
};
use crate::{
    placement::model::{
        EngineRuntime, PlacementError, ReserveTenant, TenantReservation, TenantReservationState,
    },
    shared::{limits::InstanceLimits, protocol::Protocol, time::now_rfc3339},
};

const SQLITE_WRITE_ATTEMPTS: u32 = 5;

impl PlacementRepository {
    pub async fn reserve(
        &self,
        request: ReserveTenant<'_>,
    ) -> Result<EngineRuntime, PlacementRepositoryError> {
        self.reserve_inner(request, false).await
    }

    /// Reserves the first tenant in a newly persisted runtime before its
    /// container is launched. The creating runtime plus this reservation form
    /// one durable node-capacity commit, while normal placement remains
    /// restricted to running runtimes.
    pub async fn reserve_starting(
        &self,
        request: ReserveTenant<'_>,
    ) -> Result<EngineRuntime, PlacementRepositoryError> {
        self.reserve_inner(request, true).await
    }

    async fn reserve_inner(
        &self,
        request: ReserveTenant<'_>,
        starting_runtime: bool,
    ) -> Result<EngineRuntime, PlacementRepositoryError> {
        let ReserveTenant {
            instance_id,
            runtime_id,
            database,
            username,
            limits: requested,
        } = request;
        check_reservation(requested)?;
        check_identity(database, "database_name")?;
        check_identity(username, "database_username")?;
        let now = now_rfc3339();
        let memory_mib = u64_to_i64(requested.memory_mib, "memory_mib")?;
        let disk_mib = u64_to_i64(requested.disk_mib, "disk_mib")?;
        let mut transaction = self.pool.begin().await?;
        let runtime_row = sqlx::query(
            "SELECT protocol, reserved_disk_mib FROM engine_runtimes WHERE runtime_id = ?1",
        )
        .bind(runtime_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| PlacementRepositoryError::RuntimeNotFound(runtime_id.to_string()))?;
        let protocol = parse_protocol(runtime_row.try_get("protocol")?)?;
        let reserved_disk_mib = i64_to_u64(
            runtime_row.try_get("reserved_disk_mib")?,
            "reserved_disk_mib",
        )?;
        let next_reserved_disk_mib = reserved_disk_mib
            .checked_add(requested.disk_mib)
            .ok_or_else(|| {
                PlacementRepositoryError::InvalidReservation(
                    "shared runtime disk reservation overflow".to_string(),
                )
            })?;
        let limit_disk_mib =
            crate::placement::policy::pool_disk_mib(protocol, next_reserved_disk_mib)
                .ok_or(PlacementError::UnsupportedSharedProtocol(protocol))?;
        let limit_disk_mib = u64_to_i64(limit_disk_mib, "limit_disk_mib")?;
        let overhead = crate::placement::policy::runtime_overhead(protocol)
            .ok_or(PlacementError::UnsupportedSharedProtocol(protocol))?;
        let overhead_memory = u64_to_i64(overhead.memory_mib, "overhead_memory_mib")?;

        let already_reserved = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM engine_runtime_reservations WHERE instance_id = ?1)",
        )
        .bind(instance_id)
        .fetch_one(&mut *transaction)
        .await?;
        if already_reserved {
            return Err(PlacementRepositoryError::AlreadyReserved(
                instance_id.to_string(),
            ));
        }
        let identity = sqlx::query(
            r#"
            SELECT
                EXISTS(
                    SELECT 1 FROM engine_runtime_reservations
                    WHERE runtime_id = ?1 AND database_name = ?2
                    UNION ALL
                    SELECT 1 FROM instance_metadata
                    WHERE deployment_mode = 'shared'
                      AND runtime_id = ?1 AND database_name = ?2
                ) AS database_in_use,
                EXISTS(
                    SELECT 1 FROM engine_runtime_reservations
                    WHERE runtime_id = ?1 AND database_username = ?3
                    UNION ALL
                    SELECT 1 FROM instance_metadata
                    WHERE deployment_mode = 'shared'
                      AND runtime_id = ?1 AND database_username = ?3
                ) AS username_in_use
            "#,
        )
        .bind(runtime_id)
        .bind(database)
        .bind(username)
        .fetch_one(&mut *transaction)
        .await?;
        if identity.try_get::<bool, _>("database_in_use")? {
            return Err(PlacementRepositoryError::DatabaseInUse {
                runtime_id: runtime_id.to_string(),
                database: database.to_string(),
            });
        }
        if identity.try_get::<bool, _>("username_in_use")? {
            return Err(PlacementRepositoryError::UsernameInUse {
                runtime_id: runtime_id.to_string(),
                username: username.to_string(),
            });
        }

        let update = sqlx::query(
            r#"
            UPDATE engine_runtimes
            SET tenant_count = tenant_count + 1,
                reserved_cpu_cores = reserved_cpu_cores + ?1,
                reserved_memory_mib = reserved_memory_mib + ?2,
                reserved_disk_mib = reserved_disk_mib + ?3,
                limit_cpu_cores = reserved_cpu_cores + ?1 + ?6,
                limit_memory_mib = reserved_memory_mib + ?2 + ?7,
                limit_disk_mib = ?8,
                limits_json = json_set(
                    limits_json,
                    '$.cpu_cores', reserved_cpu_cores + ?1 + ?6,
                    '$.memory_mib', reserved_memory_mib + ?2 + ?7,
                    '$.disk_mib', ?8
                ),
                updated_at = ?4
            WHERE runtime_id = ?5
              AND deployment_mode = 'shared'
              AND (
                    (status = 'running' AND ?11 = 0)
                 OR (status = 'creating' AND tenant_count = 0 AND ?11 = 1)
               )
              AND tenant_count < max_tenants
              AND reserved_cpu_cores + ?1 + ?6 <= ?9
              AND reserved_memory_mib + ?2 + ?7 <= ?10
            "#,
        )
        .bind(requested.cpu_cores)
        .bind(memory_mib)
        .bind(disk_mib)
        .bind(&now)
        .bind(runtime_id)
        .bind(overhead.cpu_cores)
        .bind(overhead_memory)
        .bind(limit_disk_mib)
        .bind(crate::shared::limits::MAX_CPU_CORES)
        .bind(u64_to_i64(
            crate::shared::limits::MAX_MEMORY_MIB,
            "max_memory_mib",
        )?)
        .bind(i64::from(starting_runtime))
        .execute(&mut *transaction)
        .await?;
        if update.rows_affected() != 1 {
            return Err(PlacementRepositoryError::CapacityUnavailable(
                runtime_id.to_string(),
            ));
        }

        sqlx::query(
            r#"
            INSERT INTO engine_runtime_reservations (
                instance_id, runtime_id, database_name, database_username, state,
                cpu_cores, memory_mib, disk_mib, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, 'reserved', ?5, ?6, ?7, ?8, ?8)
            "#,
        )
        .bind(instance_id)
        .bind(runtime_id)
        .bind(database)
        .bind(username)
        .bind(requested.cpu_cores)
        .bind(memory_mib)
        .bind(disk_mib)
        .bind(&now)
        .execute(&mut *transaction)
        .await?;

        sync_runtime_capacity(
            &mut transaction,
            runtime_id,
            protocol,
            overhead,
            overhead_memory,
            &now,
        )
        .await?;

        if let Err(error) = transaction.commit().await {
            let committed = self
                .get_reservation(instance_id)
                .await
                .ok()
                .flatten()
                .is_some_and(|reservation| {
                    claim_matches(&reservation, runtime_id, database, username, requested)
                });
            if !committed {
                return Err(error.into());
            }
            tracing::warn!(
                event = "audit shared_tenant_reservation_commit_ack_lost",
                %instance_id,
                %runtime_id,
                "shared tenant reservation was committed despite a lost SQLite acknowledgement"
            );
        }

        self.get(runtime_id)
            .await?
            .ok_or_else(|| PlacementRepositoryError::RuntimeNotFound(runtime_id.to_string()))
    }

    pub async fn mark_provisioned(
        &self,
        instance_id: &str,
    ) -> Result<TenantReservation, PlacementRepositoryError> {
        let update = match sqlx::query(
            r#"
            UPDATE engine_runtime_reservations
            SET state = 'provisioned', updated_at = ?1
            WHERE instance_id = ?2 AND state IN ('reserved', 'provisioned')
            "#,
        )
        .bind(now_rfc3339())
        .bind(instance_id)
        .execute(&self.pool)
        .await
        {
            Ok(update) => update,
            Err(error) => {
                let committed = self
                    .get_reservation(instance_id)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|reservation| {
                        reservation.state == TenantReservationState::Provisioned
                    });
                if !committed {
                    return Err(error.into());
                }
                tracing::warn!(
                    event = "audit shared_tenant_provision_commit_ack_lost",
                    %instance_id,
                    "shared tenant provisioning was committed despite a lost SQLite acknowledgement"
                );
                return self.get_reservation(instance_id).await?.ok_or_else(|| {
                    PlacementRepositoryError::ReservationNotFound(instance_id.to_string())
                });
            }
        };
        if update.rows_affected() != 1 {
            if let Some(reservation) = self.get_reservation(instance_id).await?
                && reservation.state == TenantReservationState::Provisioned
            {
                return Ok(reservation);
            }
            return Err(PlacementRepositoryError::ReservationNotFound(
                instance_id.to_string(),
            ));
        }
        self.get_reservation(instance_id)
            .await?
            .ok_or_else(|| PlacementRepositoryError::ReservationNotFound(instance_id.to_string()))
    }

    pub async fn release(&self, instance_id: &str) -> Result<bool, PlacementRepositoryError> {
        let mut transaction = self.pool.begin().await?;
        let attached = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM instance_metadata
                WHERE instance_id = ?1 AND deployment_mode = 'shared'
            )
            "#,
        )
        .bind(instance_id)
        .fetch_one(&mut *transaction)
        .await?;
        if attached {
            return Err(PlacementRepositoryError::InstanceStillAttached(
                instance_id.to_string(),
            ));
        }
        let reservation = sqlx::query(
            r#"
            SELECT reservation.runtime_id, runtime.protocol
            FROM engine_runtime_reservations AS reservation
            JOIN engine_runtimes AS runtime ON runtime.runtime_id = reservation.runtime_id
            WHERE reservation.instance_id = ?1
            "#,
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(reservation) = reservation else {
            return Ok(false);
        };
        let runtime_id: String = reservation.try_get("runtime_id")?;
        let protocol = parse_protocol(reservation.try_get("protocol")?)?;
        let overhead = crate::placement::policy::runtime_overhead(protocol)
            .ok_or(PlacementError::UnsupportedSharedProtocol(protocol))?;
        let overhead_memory = u64_to_i64(overhead.memory_mib, "overhead_memory_mib")?;

        sqlx::query("DELETE FROM engine_runtime_reservations WHERE instance_id = ?1")
            .bind(instance_id)
            .execute(&mut *transaction)
            .await?;
        let now = now_rfc3339();
        sync_runtime_capacity(
            &mut transaction,
            &runtime_id,
            protocol,
            overhead,
            overhead_memory,
            &now,
        )
        .await?;
        if let Err(error) = transaction.commit().await {
            match self.get_reservation(instance_id).await {
                Ok(None) => {
                    tracing::warn!(
                        event = "audit shared_tenant_release_commit_ack_lost",
                        %instance_id,
                        %runtime_id,
                        "shared tenant capacity was released despite a lost SQLite acknowledgement"
                    );
                }
                Ok(Some(_)) | Err(_) => return Err(error.into()),
            }
        }
        Ok(true)
    }

    pub async fn resize(
        &self,
        instance_id: &str,
        requested: &InstanceLimits,
    ) -> Result<EngineRuntime, PlacementRepositoryError> {
        let mut attempt = 1;
        loop {
            match self.resize_once(instance_id, requested).await {
                Err(PlacementRepositoryError::Sqlx(error))
                    if sqlite_write_contention(&error) && attempt < SQLITE_WRITE_ATTEMPTS =>
                {
                    tokio::time::sleep(Duration::from_millis(u64::from(attempt) * 10)).await;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    async fn resize_once(
        &self,
        instance_id: &str,
        requested: &InstanceLimits,
    ) -> Result<EngineRuntime, PlacementRepositoryError> {
        check_reservation(requested)?;
        let new_memory = u64_to_i64(requested.memory_mib, "memory_mib")?;
        let new_disk = u64_to_i64(requested.disk_mib, "disk_mib")?;
        let mut transaction = self.pool.begin().await?;
        let current = sqlx::query(
            r#"
            SELECT reservation.runtime_id, reservation.cpu_cores,
                   reservation.memory_mib, reservation.disk_mib, runtime.protocol,
                   runtime.reserved_disk_mib AS runtime_disk_mib
            FROM engine_runtime_reservations AS reservation
            JOIN engine_runtimes AS runtime ON runtime.runtime_id = reservation.runtime_id
            WHERE reservation.instance_id = ?1
            "#,
        )
        .bind(instance_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| PlacementRepositoryError::ReservationNotFound(instance_id.to_string()))?;
        let runtime_id: String = current.try_get("runtime_id")?;
        let old_cpu: f64 = current.try_get("cpu_cores")?;
        let old_memory: i64 = current.try_get("memory_mib")?;
        let old_disk: i64 = current.try_get("disk_mib")?;
        let protocol = parse_protocol(current.try_get("protocol")?)?;
        let runtime_disk_mib =
            i64_to_u64(current.try_get("runtime_disk_mib")?, "reserved_disk_mib")?;
        let old_disk_mib = i64_to_u64(old_disk, "disk_mib")?;
        let next_reserved_disk_mib = runtime_disk_mib
            .checked_sub(old_disk_mib)
            .and_then(|remaining| remaining.checked_add(requested.disk_mib))
            .ok_or_else(|| {
                PlacementRepositoryError::InvalidReservation(
                    "shared runtime disk resize overflow".to_string(),
                )
            })?;
        let limit_disk_mib =
            crate::placement::policy::pool_disk_mib(protocol, next_reserved_disk_mib)
                .ok_or(PlacementError::UnsupportedSharedProtocol(protocol))?;
        let limit_disk_mib = u64_to_i64(limit_disk_mib, "limit_disk_mib")?;
        let overhead = crate::placement::policy::runtime_overhead(protocol)
            .ok_or(PlacementError::UnsupportedSharedProtocol(protocol))?;
        let overhead_memory = u64_to_i64(overhead.memory_mib, "overhead_memory_mib")?;
        let now = now_rfc3339();

        let update = sqlx::query(
            r#"
            UPDATE engine_runtimes
            SET reserved_cpu_cores = reserved_cpu_cores - ?1 + ?2,
                reserved_memory_mib = reserved_memory_mib - ?3 + ?4,
                reserved_disk_mib = reserved_disk_mib - ?5 + ?6,
                limit_cpu_cores = reserved_cpu_cores - ?1 + ?2 + ?9,
                limit_memory_mib = reserved_memory_mib - ?3 + ?4 + ?10,
                limit_disk_mib = ?11,
                limits_json = json_set(
                    limits_json,
                    '$.cpu_cores', reserved_cpu_cores - ?1 + ?2 + ?9,
                    '$.memory_mib', reserved_memory_mib - ?3 + ?4 + ?10,
                    '$.disk_mib', ?11
                ),
                updated_at = ?7
            WHERE runtime_id = ?8
              AND deployment_mode = 'shared'
              AND status = 'running'
              AND tenant_count > 0
              AND reserved_cpu_cores >= ?1
              AND reserved_memory_mib >= ?3
              AND reserved_disk_mib >= ?5
              AND reserved_cpu_cores - ?1 + ?2 + ?9 <= ?12
              AND reserved_memory_mib - ?3 + ?4 + ?10 <= ?13
            "#,
        )
        .bind(old_cpu)
        .bind(requested.cpu_cores)
        .bind(old_memory)
        .bind(new_memory)
        .bind(old_disk)
        .bind(new_disk)
        .bind(&now)
        .bind(&runtime_id)
        .bind(overhead.cpu_cores)
        .bind(overhead_memory)
        .bind(limit_disk_mib)
        .bind(crate::shared::limits::MAX_CPU_CORES)
        .bind(u64_to_i64(
            crate::shared::limits::MAX_MEMORY_MIB,
            "max_memory_mib",
        )?)
        .execute(&mut *transaction)
        .await?;
        if update.rows_affected() != 1 {
            return Err(PlacementRepositoryError::CapacityUnavailable(runtime_id));
        }

        let reservation_update = sqlx::query(
            r#"
            UPDATE engine_runtime_reservations
            SET cpu_cores = ?1, memory_mib = ?2, disk_mib = ?3, updated_at = ?4
            WHERE instance_id = ?5
            "#,
        )
        .bind(requested.cpu_cores)
        .bind(new_memory)
        .bind(new_disk)
        .bind(&now)
        .bind(instance_id)
        .execute(&mut *transaction)
        .await?;
        if reservation_update.rows_affected() != 1 {
            return Err(PlacementRepositoryError::ReservationNotFound(
                instance_id.to_string(),
            ));
        }

        let limits_json = serde_json::to_string(requested)?;
        let metadata_update = sqlx::query(
            r#"
            UPDATE instance_metadata
            SET limits_json = ?1,
                metadata_json = json_set(metadata_json, '$.limits', json(?1)),
                updated_at = ?2
            WHERE instance_id = ?3
              AND deployment_mode = 'shared'
              AND runtime_id = ?4
            "#,
        )
        .bind(limits_json)
        .bind(&now)
        .bind(instance_id)
        .bind(&runtime_id)
        .execute(&mut *transaction)
        .await?;
        if metadata_update.rows_affected() != 1 {
            return Err(PlacementRepositoryError::ReservationNotAttached(
                instance_id.to_string(),
            ));
        }
        sync_runtime_capacity(
            &mut transaction,
            &runtime_id,
            protocol,
            overhead,
            overhead_memory,
            &now,
        )
        .await?;
        transaction.commit().await?;

        self.get(&runtime_id)
            .await?
            .ok_or(PlacementRepositoryError::RuntimeNotFound(runtime_id))
    }
}

fn sqlite_write_contention(error: &sqlx::Error) -> bool {
    let sqlx::Error::Database(error) = error else {
        return false;
    };
    let code_is_busy = error
        .code()
        .and_then(|code| code.parse::<u32>().ok())
        .is_some_and(|code| matches!(code & 0xff, 5 | 6));
    let message = error.message().to_ascii_lowercase();
    code_is_busy
        || message.contains("database is locked")
        || message.contains("database table is locked")
}

async fn sync_runtime_capacity(
    transaction: &mut Transaction<'_, Sqlite>,
    runtime_id: &str,
    protocol: Protocol,
    overhead: crate::placement::policy::RuntimeOverhead,
    overhead_memory: i64,
    now: &str,
) -> Result<(), PlacementRepositoryError> {
    let reserved_disk_mib: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(disk_mib), 0)
        FROM engine_runtime_reservations
        WHERE runtime_id = ?1
        "#,
    )
    .bind(runtime_id)
    .fetch_one(&mut **transaction)
    .await?;
    let limit_disk_mib = crate::placement::policy::pool_disk_mib(
        protocol,
        i64_to_u64(reserved_disk_mib, "reserved_disk_mib")?,
    )
    .ok_or(PlacementError::UnsupportedSharedProtocol(protocol))?;
    let limit_disk_mib = u64_to_i64(limit_disk_mib, "limit_disk_mib")?;
    let update = sqlx::query(
        r#"
        UPDATE engine_runtimes
        SET tenant_count = (
                SELECT COUNT(*) FROM engine_runtime_reservations
                WHERE runtime_id = ?1
            ),
            reserved_cpu_cores = COALESCE((
                SELECT SUM(cpu_cores) FROM engine_runtime_reservations
                WHERE runtime_id = ?1
            ), 0.0),
            reserved_memory_mib = COALESCE((
                SELECT SUM(memory_mib) FROM engine_runtime_reservations
                WHERE runtime_id = ?1
            ), 0),
            reserved_disk_mib = COALESCE((
                SELECT SUM(disk_mib) FROM engine_runtime_reservations
                WHERE runtime_id = ?1
            ), 0),
            limit_cpu_cores = ?2 + COALESCE((
                SELECT SUM(cpu_cores) FROM engine_runtime_reservations
                WHERE runtime_id = ?1
            ), 0.0),
            limit_memory_mib = ?3 + COALESCE((
                SELECT SUM(memory_mib) FROM engine_runtime_reservations
                WHERE runtime_id = ?1
            ), 0),
            limit_disk_mib = ?4,
            limits_json = json_set(
                limits_json,
                '$.cpu_cores', ?2 + COALESCE((
                    SELECT SUM(cpu_cores) FROM engine_runtime_reservations
                    WHERE runtime_id = ?1
                ), 0.0),
                '$.memory_mib', ?3 + COALESCE((
                    SELECT SUM(memory_mib) FROM engine_runtime_reservations
                    WHERE runtime_id = ?1
                ), 0),
                '$.disk_mib', ?4
            ),
            updated_at = ?5
        WHERE runtime_id = ?1 AND deployment_mode = 'shared'
        "#,
    )
    .bind(runtime_id)
    .bind(overhead.cpu_cores)
    .bind(overhead_memory)
    .bind(limit_disk_mib)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    if update.rows_affected() != 1 {
        return Err(PlacementRepositoryError::RuntimeNotFound(
            runtime_id.to_string(),
        ));
    }
    Ok(())
}

pub(super) fn check_reservation(limits: &InstanceLimits) -> Result<(), PlacementRepositoryError> {
    crate::shared::limits::validate_runtime_limits(limits.cpu_cores, limits.memory_mib)
        .map_err(|error| PlacementRepositoryError::InvalidReservation(error.to_string()))?;
    if limits.disk_mib == 0 {
        return Err(PlacementRepositoryError::InvalidReservation(
            "disk_mib must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn check_identity(value: &str, field: &'static str) -> Result<(), PlacementRepositoryError> {
    if value.is_empty() || value.trim() != value {
        return Err(PlacementRepositoryError::InvalidValue {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}
