use crate::{
    api::{
        http::{
            policy::{ApiRequestContext, DestructiveActionPolicy},
            response::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResponse, ApiResult},
            router::AppState,
        },
        instances::{
            self,
            progress::{InstallProgress, InstallProgressStatus},
            requests::{CreateInstanceRequest, LimitsRequest},
        },
    },
    auth::scopes,
    placement::{DeploymentMode, PoolLimits, PoolOwner, PoolSpec},
    shared::protocol::Protocol,
};
use axum::extract::State;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreatePool {
    pub server_id: String,
    pub protocol: Protocol,
    pub image: Option<String>,
    pub limits: PoolLimits,
}

#[derive(Serialize)]
pub(crate) struct PoolAccepted {
    runtime_id: String,
    status: &'static str,
    status_url: String,
}

pub(crate) async fn create(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiJson(request): ApiJson<CreatePool>,
) -> ApiResult<PoolAccepted> {
    auth.require_scope(scopes::POOLS_WRITE)?;
    DeploymentMode::Shared
        .check(request.protocol)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    if !state.config.protocol_enabled(request.protocol) {
        return Err(ApiError::BadRequest("protocol is disabled".into()));
    }
    let owner = PoolOwner {
        panel_id: state.config.token_id.clone(),
        server_id: request.server_id,
    };
    owner.check().map_err(ApiError::BadRequest)?;
    request.limits.check().map_err(ApiError::BadRequest)?;
    instances::requests::validate_protocol_limits(
        request.protocol,
        &LimitsRequest {
            cpu_cores: request.limits.cpu_cores,
            memory_mib: request.limits.memory_mib,
            disk_mib: request.limits.disk_mib,
        },
    )?;
    if crate::placement::policy::engine_disk_overhead(request.protocol)
        .is_none_or(|minimum| request.limits.disk_mib <= minimum)
    {
        return Err(ApiError::BadRequest(
            "pool disk capacity must exceed engine-global overhead".into(),
        ));
    }
    let image = request.image.unwrap_or_else(|| {
        state
            .config
            .images
            .configured_for_protocol(request.protocol)
            .into()
    });
    instances::images::validate_image(&image)?;
    instances::images::check_image_allowed(&state, request.protocol, &image)?;
    let mutation = state
        .daemon_shutdown
        .try_admit_background_mutation()
        .ok_or_else(|| ApiError::ServiceUnavailable("daemon is shutting down".into()))?;
    let runtime_id = crate::placement::policy::runtime_id(request.protocol);
    let permit = state
        .install_progress
        .try_begin_creation(&runtime_id, request.protocol, &image)
        .map_err(|_| {
            ApiError::ServiceUnavailable("pool creation capacity is unavailable".into())
        })?;
    let pool = PoolSpec {
        owner,
        protocol: request.protocol,
        image,
        limits: request.limits,
    };
    let id = runtime_id.clone();
    instances::spawn_owned_mutation_task(async move {
        let _mutation = mutation;
        let _permit = permit;
        let result = async {
            let mut admission = Some(state.instance_locks.lock_creation().await);
            if state
                .placements
                .server_pool(pool.protocol, &pool.owner)
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))?
                .is_some()
            {
                return Err(ApiError::Conflict(
                    "this server already owns a pool for this engine".into(),
                ));
            }
            instances::create::enforce_node_allocation_policy(&state, &pool.limits.limits(), None)
                .await?;
            super::provision::provision_pool(&state, &pool, &id, &mut admission).await?;
            Ok::<_, ApiError>(())
        }
        .await;
        match result {
            Ok(()) => state
                .install_progress
                .complete(&id, "database pool is ready"),
            Err(error) => state
                .install_progress
                .fail_api_error(&id, "pool creation", &error),
        }
    });
    let status_url = format!("/api/pools/{runtime_id}/status");
    Ok(ApiResponse::accepted_at(
        PoolAccepted {
            runtime_id,
            status: "creating",
            status_url: status_url.clone(),
        },
        status_url,
    ))
}

#[derive(Serialize)]
pub(crate) struct PoolStatus {
    runtime_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<InstallProgress>,
}

pub(crate) async fn status(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(runtime_id): ApiPath<String>,
) -> ApiResult<PoolStatus> {
    auth.require_scope(scopes::POOLS_READ)?;
    pool_status(&state, runtime_id).await
}

async fn pool_status(state: &AppState, runtime_id: String) -> ApiResult<PoolStatus> {
    let progress = state.install_progress.get(&runtime_id);
    let status = match super::load(state, &runtime_id).await {
        Ok(pool) => pool.status.as_str().to_string(),
        Err(ApiError::NotFound) => match progress.as_ref() {
            Some(progress) => match progress.status {
                InstallProgressStatus::Running => "creating",
                InstallProgressStatus::Failed => "failed",
                InstallProgressStatus::Completed => "running",
            }
            .into(),
            None => return Err(ApiError::NotFound),
        },
        Err(error) => return Err(error),
    };
    Ok(ApiResponse::ok(PoolStatus {
        runtime_id,
        status,
        progress,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateDatabase {
    instance_id: String,
    database: String,
    username: String,
    password: String,
    public_host: String,
    public_port: Option<u16>,
    disk_mib: u64,
}

pub(crate) async fn create_database(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(runtime_id): ApiPath<String>,
    ApiJson(request): ApiJson<CreateDatabase>,
) -> ApiResult<instances::CreateInstanceAcceptedResponse> {
    auth.require_scope(scopes::INSTANCES_WRITE)?;
    let pool = super::load(&state, &runtime_id).await?;
    let owner = pool
        .owner
        .ok_or_else(|| ApiError::Conflict("pool ownership is not verified".into()))?;
    if owner.panel_id != state.config.token_id {
        return Err(ApiError::Conflict(
            "pool belongs to a different panel identity".into(),
        ));
    }
    let request = CreateInstanceRequest {
        server_id: Some(owner.server_id.clone()),
        owner: Some(owner),
        pool_id: Some(runtime_id),
        instance_id: request.instance_id,
        protocol: pool.protocol,
        deployment_mode: DeploymentMode::Shared,
        database: request.database,
        username: request.username,
        password: request.password,
        public_host: request.public_host,
        public_port: request.public_port,
        project_id: None,
        image: Some(pool.image),
        limits: Some(LimitsRequest {
            cpu_cores: 0.0,
            memory_mib: 0,
            disk_mib: request.disk_mib,
        }),
        purge_stale_resources: false,
        purge_stale_resources_confirmation: None,
    };
    instances::create_instance(State(state), auth, ApiJson(request)).await
}

pub(crate) async fn delete(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(runtime_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<instances::DeleteInstanceQuery>,
) -> ApiResult<serde_json::Value> {
    auth.require_scope(scopes::POOLS_WRITE)?;
    DestructiveActionPolicy::authorize(
        "pool deletion",
        &crate::api::http::policy::DestructiveActionConfirmation {
            confirm: query.confirm,
            reason: query.reason,
        },
    )?;
    let (_pool, guard) = super::power::PoolGuard::acquire(&state, &runtime_id).await?;
    instances::spawn_owned_mutation_task(async move {
        let _guard = guard;
        super::load(&state, &runtime_id).await?;
        if state
            .placements
            .tenant_count(&runtime_id)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?
            != 0
        {
            return Err(ApiError::Conflict(
                "pool is not empty; delete or migrate its databases first".into(),
            ));
        }
        let deleted = instances::delete_empty_pool(&state, &runtime_id).await?;
        Ok(ApiResponse::ok(
            serde_json::json!({"runtime_id":runtime_id,"deleted":deleted}),
        ))
    })
    .await
    .map_err(|error| ApiError::Runtime(error.to_string()))?
}

pub(crate) async fn power(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(runtime_id): ApiPath<String>,
    ApiJson(request): ApiJson<instances::PowerRequest>,
) -> ApiResult<PoolStatus> {
    auth.require_scope(scopes::POOLS_WRITE)?;
    crate::api::pools::power::change(&state, &runtime_id, request.action).await?;
    pool_status(&state, runtime_id).await
}
