use crate::{
    api::{
        http::{
            response::ApiError,
            router::{AppState, MutationPermit},
        },
        instances::{self, LifecycleAction},
    },
    instances::metadata::DesiredInstanceState,
    jobs::import_export::ImportExportJobPermit,
    placement::{
        DeploymentMigration, EngineRuntime, EngineRuntimeStatus, TenantReservationState, lifecycle,
    },
};
use tokio::sync::OwnedMutexGuard;

/// Lock order: node placement -> nonwaiting job admission -> sorted tenants ->
/// pool. Tenant workers never wait for a pool operation holding their own lock.
pub(super) struct PoolGuard {
    _mutation: MutationPermit,
    _jobs: Vec<ImportExportJobPermit>,
    _tenants: Vec<OwnedMutexGuard<()>>,
    _pool: OwnedMutexGuard<()>,
}

impl PoolGuard {
    pub(super) async fn acquire(
        state: &AppState,
        runtime_id: &str,
    ) -> Result<(EngineRuntime, Self), ApiError> {
        let mutation = state
            .daemon_shutdown
            .try_admit_background_mutation()
            .ok_or_else(|| ApiError::ServiceUnavailable("daemon is shutting down".into()))?;
        let creation = state.instance_locks.lock_creation().await;
        let snapshot = super::load(state, runtime_id).await?;
        if snapshot.owner.is_none() {
            return Err(ApiError::Conflict("pool ownership is unverified".into()));
        }
        let reservations = state
            .placements
            .reservations(runtime_id)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        let mut jobs = Vec::new();
        let mut tenants = Vec::new();
        let mut ids = Vec::new();
        for reservation in reservations {
            if reservation.state != TenantReservationState::Provisioned {
                return Err(ApiError::Conflict(
                    "pool has a database being provisioned".into(),
                ));
            }
            let metadata = state
                .instances
                .get(&reservation.instance_id)
                .await
                .ok_or_else(|| {
                    ApiError::Conflict("pool requires tenant metadata recovery".into())
                })?;
            if metadata.runtime_id() != runtime_id || metadata.owner != snapshot.owner {
                return Err(ApiError::Conflict("pool tenant ownership mismatch".into()));
            }
            jobs.push(
                state
                    .import_export_jobs
                    .try_admit_exclusive(&reservation.instance_id)
                    .map_err(|_| {
                        ApiError::Conflict("pool has queued or running database work".into())
                    })?,
            );
            ids.push(reservation.instance_id);
        }
        drop(creation);
        ids.sort_unstable();
        for id in &ids {
            tenants.push(state.instance_locks.lock(id).await);
        }
        let pool_lock = state.instance_locks.lock(runtime_id).await;
        let current = super::load(state, runtime_id).await?;
        let active = state
            .placements
            .migrations()
            .list_active()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        if active
            .iter()
            .any(|migration| migration_involves_runtime(migration, runtime_id))
        {
            return Err(ApiError::Conflict(
                "pool has an active database migration".into(),
            ));
        }

        let mut current_ids = state
            .placements
            .tenants(runtime_id)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        current_ids.sort_unstable();
        if current.created_at != snapshot.created_at
            || current.owner != snapshot.owner
            || current_ids != ids
        {
            return Err(ApiError::Conflict(
                "pool membership changed; retry the operation".into(),
            ));
        }
        Ok((
            current,
            Self {
                _mutation: mutation,
                _jobs: jobs,
                _tenants: tenants,
                _pool: pool_lock,
            },
        ))
    }
}

fn migration_involves_runtime(migration: &DeploymentMigration, runtime_id: &str) -> bool {
    migration.source_runtime_id == runtime_id
        || migration.target_runtime_id.as_deref() == Some(runtime_id)
        || migration.target_pool_id.as_deref() == Some(runtime_id)
}

fn power_operation_blocked(pool: &EngineRuntime) -> bool {
    pool.pending_image.is_some()
        || matches!(
            pool.status,
            EngineRuntimeStatus::Quarantined
                | EngineRuntimeStatus::Deleting
                | EngineRuntimeStatus::Creating
        )
}

pub(super) async fn change(
    state: &AppState,
    runtime_id: &str,
    action: LifecycleAction,
) -> Result<(), ApiError> {
    let (mut pool, guard) = PoolGuard::acquire(state, runtime_id).await?;
    if power_operation_blocked(&pool) {
        return Err(ApiError::Conflict(
            "pool is not eligible for a power operation".into(),
        ));
    }
    let state = state.clone();
    instances::spawn_owned_mutation_task(async move {
        let _guard = guard;
        match action {
            LifecycleAction::Start | LifecycleAction::Restart => {
                let already_running = pool.status == EngineRuntimeStatus::Running
                    && pool.desired_state == DesiredInstanceState::Running;
                if action == LifecycleAction::Start && already_running {
                    return Ok(());
                }
                pool.desired_state = DesiredInstanceState::Running;
                let recreated = super::image::refresh_logging_locked(&state, &mut pool).await?;
                if !recreated {
                    let restart = action == LifecycleAction::Restart;
                    lifecycle::activate_locked(&state, &mut pool, restart)
                        .await
                        .map_err(|error| ApiError::Runtime(error.to_string()))?;
                }
            }
            LifecycleAction::Stop | LifecycleAction::Kill => {
                stop_locked(&state, &mut pool, action).await?;
            }
        }
        tracing::info!(event = "audit pool_power", runtime_id = %pool.runtime_id, owner = ?pool.owner, ?action);
        Ok(())
    })
    .await
    .map_err(|error| ApiError::Runtime(error.to_string()))?
}

async fn stop_locked(
    state: &AppState,
    pool: &mut EngineRuntime,
    action: LifecycleAction,
) -> Result<(), ApiError> {
    pool.desired_state = DesiredInstanceState::Stopped;
    lifecycle::fence_runtime(state, &pool.runtime_id).await;
    lifecycle::save_runtime(&state.placements, &state.manager, pool.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let stopped = if action == LifecycleAction::Kill {
        state.docker.kill(pool.protocol, &pool.runtime_id).await
    } else {
        state.docker.stop(pool.protocol, &pool.runtime_id).await
    };
    if let Err(error) = stopped
        && !error.is_not_found()
        && !error.is_not_running()
    {
        instances::containment::contain_locked(
            state,
            pool,
            "pool stop failed",
            Some(crate::storage::quarantine::QuarantineKind::ShutdownUnconfirmed),
        )
        .await;
        return Err(ApiError::Runtime(error.to_string()));
    }
    pool.status = EngineRuntimeStatus::Stopped;
    pool.updated_at = crate::shared::time::now_rfc3339();
    lifecycle::save_runtime(&state.placements, &state.manager, pool.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    lifecycle::clear_runtime_caches(state, &pool.runtime_id).await;
    Ok(())
}
