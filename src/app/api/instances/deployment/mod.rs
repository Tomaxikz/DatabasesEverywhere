use axum::extract::State;
use serde::Deserialize;

use crate::{
    api::http::{
        policy::ApiRequestContext,
        response::{ApiError, ApiJson, ApiPath, ApiResponse, ApiResult},
        router::AppState,
    },
    auth::scopes,
    instances::metadata::{DesiredInstanceState, InstanceStatus},
    jobs::import_export::JobAdmissionError,
    placement::{
        DeploymentMigration, DeploymentMigrationError, DeploymentMode, EngineRuntimeStatus,
    },
};

mod worker;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartDeploymentMigrationRequest {
    pub server_id: Option<String>,
    pub pool_id: Option<String>,
    pub limits: Option<crate::api::instances::requests::LimitsRequest>,
    pub target_mode: DeploymentMode,
}

/// Persists the operation before launching an owned worker. The worker keeps
/// the instance mutation lock and exclusive data-job admission until durable
/// completion or a recovery-safe state.
pub async fn start_deployment_migration(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiJson(request): ApiJson<StartDeploymentMigrationRequest>,
) -> ApiResult<DeploymentMigration> {
    auth.require_scope(scopes::INSTANCES_WRITE)?;
    if !state.gateway_supervisor.is_ready() {
        return Err(ApiError::ServiceUnavailable(
            "deployment migrations are unavailable until database gateway recovery completes"
                .to_string(),
        ));
    }
    // Data maintenance acquires exclusive job admission before the instance
    // lock. Use the same order so a password/import worker waiting for this
    // instance cannot deadlock a migration that is waiting for its permit.
    let admission = state
        .import_export_jobs
        .try_admit_exclusive(&instance_id)
        .map_err(|error| migration_admission_error(&instance_id, error))?;
    let creation = state.instance_locks.lock_creation().await;
    let operation = state.instance_locks.lock(&instance_id).await;
    let mut metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    validate_source(&state, &metadata, request.target_mode).await?;
    let previous_owner = metadata.owner.clone();
    if let Some(server_id) = &request.server_id {
        let owner = crate::placement::PoolOwner {
            panel_id: state.config.token_id.clone(),
            server_id: server_id.clone(),
        };
        owner.check().map_err(ApiError::BadRequest)?;
        if metadata
            .owner
            .as_ref()
            .is_some_and(|current| current != &owner)
        {
            return Err(ApiError::Conflict(
                "instance owner cannot be changed during migration".into(),
            ));
        }
        if metadata.owner.is_none() {
            metadata.owner = Some(owner);
        }
    }
    if request.target_mode == DeploymentMode::Shared && metadata.owner.is_none() {
        return Err(ApiError::BadRequest(
            "dedicated-to-shared migration requires server_id".into(),
        ));
    }
    let mut target_pool_guard = None;
    if request.target_mode == DeploymentMode::Shared {
        let id = request.pool_id.as_deref().ok_or_else(|| {
            ApiError::BadRequest("shared target requires pool_id; create the pool first".into())
        })?;
        target_pool_guard = Some(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                state.instance_locks.lock(id),
            )
            .await
            .map_err(|_| ApiError::Conflict("target pool is busy; retry the migration".into()))?,
        );
        let pool = crate::api::pools::load(&state, id).await?;
        if pool.owner != metadata.owner
            || pool.protocol != metadata.protocol
            || pool.status != EngineRuntimeStatus::Running
            || pool.pending_image.is_some()
            || pool.desired_state != DesiredInstanceState::Running
        {
            return Err(ApiError::Conflict(
                "target pool ownership, engine or state does not match".into(),
            ));
        }
    } else if request.pool_id.is_some() {
        return Err(ApiError::BadRequest(
            "dedicated target cannot select a pool".into(),
        ));
    }
    let target_limits = request
        .limits
        .as_ref()
        .map(|limits| {
            if request.target_mode != DeploymentMode::Dedicated {
                return Err(ApiError::BadRequest(
                    "limits is only valid for a dedicated migration target".into(),
                ));
            }
            crate::api::instances::requests::validate_limits(limits)?;
            crate::api::instances::requests::validate_protocol_limits(metadata.protocol, limits)?;
            Ok(crate::api::instances::requests::limits_from_request(limits))
        })
        .transpose()?;

    let mutation = state
        .daemon_shutdown
        .try_admit_background_mutation()
        .ok_or_else(|| {
            ApiError::ServiceUnavailable(
                "daemon shutdown has started; deployment migrations are not accepted".to_string(),
            )
        })?;
    if metadata.owner != previous_owner {
        state
            .manager
            .upsert(metadata.clone())
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    }
    let migration = state
        .placements
        .migrations()
        .start(
            &metadata,
            request.target_mode,
            request.pool_id.as_deref(),
            target_limits.as_ref(),
        )
        .await
        .map_err(migration_error)?;
    let location = format!(
        "/api/instances/{instance_id}/deployment-migrations/{}",
        migration.migration_id
    );
    drop(target_pool_guard);
    worker::spawn(
        state,
        metadata,
        migration.clone(),
        creation,
        operation,
        admission,
        mutation,
    );
    Ok(ApiResponse::accepted_at(migration, location))
}

pub async fn list_deployment_migrations(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<Vec<DeploymentMigration>> {
    auth.require_scope(scopes::INSTANCES_READ)?;
    if state.instances.get(&instance_id).await.is_none() {
        return Err(ApiError::NotFound);
    }
    let migrations = state
        .placements
        .migrations()
        .list_instance(&instance_id)
        .await
        .map_err(migration_error)?;
    Ok(ApiResponse::ok(migrations))
}

pub async fn get_deployment_migration(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, migration_id)): ApiPath<(String, String)>,
) -> ApiResult<DeploymentMigration> {
    auth.require_scope(scopes::INSTANCES_READ)?;
    let migration = state
        .placements
        .migrations()
        .get(&migration_id)
        .await
        .map_err(migration_error)?
        .filter(|migration| migration.instance_id == instance_id)
        .ok_or(ApiError::NotFound)?;
    Ok(ApiResponse::ok(migration))
}

async fn validate_source(
    state: &AppState,
    metadata: &crate::instances::metadata::InstanceMetadata,
    target_mode: DeploymentMode,
) -> Result<(), ApiError> {
    target_mode
        .check(metadata.protocol)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    if metadata.deployment_mode == target_mode {
        return Err(ApiError::Conflict(format!(
            "instance already uses {} deployment",
            target_mode.as_str()
        )));
    }
    let route_fenced = state.instances.routes_fenced(&metadata.instance_id).await;
    if !migration_source_is_live(
        metadata.status,
        metadata.desired_state,
        metadata.disk_limit_blocked,
        route_fenced,
    ) {
        return Err(ApiError::Conflict(
            "deployment migration requires a running, unfenced source instance with an active disk boundary"
                .to_string(),
        ));
    }
    if metadata.tenant_password.is_none() {
        return Err(ApiError::Conflict(
            "deployment migration requires the encrypted current tenant credential; reset the instance password first"
                .to_string(),
        ));
    }
    let runtime = state
        .placements
        .get(metadata.runtime_id())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?
        .ok_or_else(|| {
            ApiError::Conflict(
                "source placement runtime is missing; reconcile it first".to_string(),
            )
        })?;
    if (metadata.deployment_mode == DeploymentMode::Shared
        && (metadata.owner.is_none() || runtime.owner != metadata.owner))
        || runtime.protocol != metadata.protocol
        || runtime.deployment_mode != metadata.deployment_mode
        || !matches!(
            runtime.status,
            EngineRuntimeStatus::Running | EngineRuntimeStatus::Booting
        )
    {
        return Err(ApiError::Conflict(
            "source placement is not a live matching runtime; reconcile it before migration"
                .to_string(),
        ));
    }
    Ok(())
}

fn migration_source_is_live(
    status: InstanceStatus,
    desired_state: DesiredInstanceState,
    disk_limit_blocked: bool,
    route_fenced: bool,
) -> bool {
    status == InstanceStatus::Running
        && desired_state == DesiredInstanceState::Running
        && !disk_limit_blocked
        && !route_fenced
}

pub(super) async fn ensure_no_active_migration(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    let active = state
        .placements
        .migrations()
        .list_instance(instance_id)
        .await
        .map_err(migration_error)?
        .into_iter()
        .find(|migration| migration_blocks_mutation(migration.stage));
    if let Some(migration) = active {
        return Err(ApiError::Conflict(format!(
            "instance {instance_id} has an active deployment migration {} in stage {}; lifecycle mutations remain blocked while its route is fenced",
            migration.migration_id,
            migration.stage.as_str()
        )));
    }
    Ok(())
}

fn migration_blocks_mutation(stage: crate::placement::MigrationStage) -> bool {
    !stage.is_terminal()
}

fn migration_admission_error(instance_id: &str, error: JobAdmissionError) -> ApiError {
    match error {
        JobAdmissionError::ShuttingDown => {
            ApiError::ServiceUnavailable("the daemon is shutting down".to_string())
        }
        JobAdmissionError::GlobalCapacity => ApiError::RateLimited,
        JobAdmissionError::InstanceCapacity => ApiError::Conflict(format!(
            "instance {instance_id} already has queued or running data work"
        )),
    }
}

pub(super) fn migration_error(error: DeploymentMigrationError) -> ApiError {
    match error {
        DeploymentMigrationError::SameMode(mode) => ApiError::Conflict(format!(
            "instance already uses {} deployment",
            mode.as_str()
        )),
        DeploymentMigrationError::ActiveMigration(instance_id) => ApiError::Conflict(format!(
            "instance {instance_id} already has an active deployment migration"
        )),
        DeploymentMigrationError::Placement(error) => ApiError::BadRequest(error.to_string()),
        DeploymentMigrationError::NotFound(_) => ApiError::NotFound,
        error => ApiError::Runtime(error.to_string()),
    }
}

pub(crate) use worker::{fence_active_routes_on_boot, recover_on_boot};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_preflight_never_clears_an_existing_source_fence() {
        assert!(migration_source_is_live(
            InstanceStatus::Running,
            DesiredInstanceState::Running,
            false,
            false,
        ));
        assert!(!migration_source_is_live(
            InstanceStatus::Running,
            DesiredInstanceState::Running,
            false,
            true,
        ));
        assert!(!migration_source_is_live(
            InstanceStatus::Running,
            DesiredInstanceState::Running,
            true,
            false,
        ));
        assert!(!migration_source_is_live(
            InstanceStatus::Running,
            DesiredInstanceState::Stopped,
            false,
            false,
        ));
        assert!(!migration_source_is_live(
            InstanceStatus::Failed,
            DesiredInstanceState::Running,
            false,
            false,
        ));
    }

    #[test]
    fn unresolved_migrations_keep_lifecycle_mutations_blocked() {
        use crate::placement::MigrationStage;

        for stage in [
            MigrationStage::RollingBack,
            MigrationStage::CleanupPending,
            MigrationStage::ManualIntervention,
        ] {
            assert!(migration_blocks_mutation(stage));
        }
        for stage in [
            MigrationStage::Completed,
            MigrationStage::Failed,
            MigrationStage::Cancelled,
        ] {
            assert!(!migration_blocks_mutation(stage));
        }
    }
}
