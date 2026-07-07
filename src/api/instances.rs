use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, Uri},
};
use bollard::errors::Error as BollardError;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        handlers::{ApiError, ApiResult, authorize_scope},
        images::validate_image,
        instance_create::{
            allocate_loopback_backend_port, backend_endpoint_for_instance,
            create_instance_from_request, launch_container_from_spec, protocol_pids_limit,
            provision_mariadb_tenant_user,
        },
        instance_requests::{
            CreateInstanceRequest, LimitsRequest, limits_from_request, validate_limits,
            validate_protocol_limits,
        },
        routes::AppState,
    },
    auth::scopes,
    databases,
    disk::DiskLimiter,
    instances::paths::InstancePaths,
    instances::{metadata::InstanceMetadata, metadata::InstanceStatus, reconcile},
    runtime::docker::{DockerContainerStatus, DockerError, DockerInstanceSpec},
    shared::{backend::BackendEndpoint, protocol::Protocol, redaction, time::now_rfc3339},
};
use std::{collections::HashMap, time::Duration};

#[derive(Debug, Serialize)]
pub struct InstanceStatusResponse {
    pub instance_id: String,
    pub status: InstanceStatus,
}

#[derive(Debug, Serialize)]
pub struct ReconcileResponse {
    pub instance_id: String,
    pub status: InstanceStatus,
}

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub instance_id: String,
    pub deleted: bool,
    pub purged: bool,
}

#[derive(Debug, Serialize)]
pub struct RuntimeInstanceResponse {
    pub instance_id: String,
    pub protocol: String,
    pub runtime: String,
    pub container_name: String,
    pub status: InstanceStatus,
}

#[derive(Debug, Serialize)]
pub struct LogsResponse {
    pub instance_id: String,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub tail: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateInstanceImageRequest {
    pub image: String,
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateInstanceImageResponse {
    pub instance: InstanceMetadata,
    pub image: String,
    pub recreated: bool,
}

#[derive(Debug, Deserialize)]
pub struct PowerRequest {
    pub action: LifecycleAction,
}

#[derive(Debug, Serialize)]
pub struct PowerResponse {
    pub instance: InstanceMetadata,
    pub action: LifecycleAction,
}

pub async fn list_instances(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Vec<InstanceMetadata>> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_READ)?;
    Ok(Json(state.instances.list().await))
}

pub async fn create_instance(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<CreateInstanceRequest>,
) -> ApiResult<InstanceMetadata> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_WRITE)?;
    create_instance_from_request(&state, request)
        .await
        .map(Json)
}

pub async fn get_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<InstanceMetadata> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_READ)?;
    state
        .instances
        .get(&instance_id)
        .await
        .map(Json)
        .ok_or(ApiError::NotFound)
}

pub async fn get_instance_status(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<InstanceStatusResponse> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    Ok(Json(InstanceStatusResponse {
        instance_id,
        status: metadata.status,
    }))
}

pub async fn reconcile_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<ReconcileResponse> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_WRITE)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let metadata = reconcile::reconcile_one(metadata, &state.docker).await;
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(Json(ReconcileResponse {
        instance_id,
        status: metadata.status,
    }))
}

pub async fn start_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<InstanceMetadata> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_WRITE)?;
    lifecycle_instance(&state, &instance_id, LifecycleAction::Start).await
}

pub async fn stop_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<InstanceMetadata> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_WRITE)?;
    lifecycle_instance(&state, &instance_id, LifecycleAction::Stop).await
}

pub async fn restart_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<InstanceMetadata> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_WRITE)?;
    lifecycle_instance(&state, &instance_id, LifecycleAction::Restart).await
}

pub async fn power_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<PowerRequest>,
) -> ApiResult<PowerResponse> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_WRITE)?;
    let action = request.action;
    let Json(instance) = lifecycle_instance(&state, &instance_id, action).await?;
    Ok(Json(PowerResponse { instance, action }))
}

pub async fn update_instance_image(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<UpdateInstanceImageRequest>,
) -> ApiResult<UpdateInstanceImageResponse> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_WRITE)?;
    let image = validate_image(&request.image)?.to_string();
    let mut metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let container_user = if let Some(user) = state
        .docker
        .rootless_podman_container_user(metadata.protocol)
    {
        tracing::debug!(
            instance_id = metadata.instance_id,
            protocol = %metadata.protocol,
            user,
            "rootless podman detected; using protocol-specific container user for bind mount ownership mapping"
        );
        user.to_string()
    } else {
        paths
            .apply_container_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        paths
            .container_user()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?
    };
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let container_data_path = disk_limiter
        .container_data_path(&paths.data)
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let requested_password = request.password.clone();
    let mut spec = instance_image_update_spec(
        &metadata,
        &paths,
        container_data_path,
        &image,
        request.password,
        protocol_pids_limit(&state, metadata.protocol),
    )
    .await?;
    spec.user = Some(container_user);
    let rootless_podman_backend_port = if state.docker.uses_rootless_podman() {
        let port = match &metadata.backend {
            BackendEndpoint::DockerTcp { host, port } if host == "127.0.0.1" => Some(*port),
            _ => None,
        }
        .unwrap_or(
            allocate_loopback_backend_port()
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))?,
        );
        spec.public_backend_port = Some(port);
        Some(port)
    } else {
        None
    };

    state
        .docker
        .pull_image(&image)
        .await
        .map_err(docker_error)?;
    match state
        .docker
        .delete(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(docker_error(error)),
    }
    launch_container_from_spec(
        &state,
        &spec,
        metadata.protocol,
        &metadata.instance_id,
        &|_| {},
        false,
        || async { Ok(()) },
    )
    .await
    .map_err(|error| error.into_api_error())?;
    if metadata.protocol == Protocol::Mariadb {
        let password = requested_password.as_deref().ok_or_else(|| {
            ApiError::BadRequest(
                "password is required when recreating mariadb database containers".to_string(),
            )
        })?;
        let root_password = metadata.mariadb_root_password.as_deref().ok_or_else(|| {
            ApiError::BadRequest(
                "mariadb internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
            )
        })?;
        provision_mariadb_tenant_user(
            &state,
            &metadata.instance_id,
            &metadata.database.name,
            &metadata.database.username,
            password,
            root_password,
        )
        .await?;
    }
    metadata.backend = backend_endpoint_for_instance(
        &state,
        metadata.protocol,
        &metadata.instance_id,
        rootless_podman_backend_port,
    )
    .await?;
    if metadata.protocol == Protocol::Mariadb
        && let Some(password) = requested_password
    {
        metadata.mariadb_native_password_sha1_stage2 = Some(
            crate::protocols::mariadb::native_password_sha1_stage2_hex(&password),
        );
    }
    metadata.status = InstanceStatus::Running;
    metadata.updated_at = now_rfc3339();
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;

    tracing::info!(
        event = "audit instance_image_updated",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        image,
    );

    Ok(Json(UpdateInstanceImageResponse {
        instance: metadata,
        image,
        recreated: true,
    }))
}

pub async fn delete_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<DeleteResponse> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_WRITE)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let purge = query
        .get("purge")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    match state
        .docker
        .delete(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(docker_error(error)),
    }
    let deleted = state
        .manager
        .delete(&metadata.instance_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    if purge {
        purge_instance_paths(&state, &metadata.instance_id).await?;
    }

    tracing::info!(
        event = "audit instance_deleted",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        purge,
    );

    Ok(Json(DeleteResponse {
        instance_id,
        deleted,
        purged: purge,
    }))
}

pub async fn update_instance_limits(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<LimitsRequest>,
) -> ApiResult<InstanceMetadata> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_WRITE)?;
    validate_limits(&request)?;

    let mut metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    validate_protocol_limits(metadata.protocol, &request)?;
    let limits = limits_from_request(&request);
    if request.disk_mib != metadata.limits.disk_mib {
        let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .update_instance_limit(&metadata.instance_id, &paths.data, limits.disk_mib)
            .await
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    }

    state
        .docker
        .update_limits(
            metadata.protocol,
            &metadata.instance_id,
            limits.cpu_cores,
            limits.memory_mib,
        )
        .await
        .map_err(docker_error)?;

    metadata.limits.cpu_cores = limits.cpu_cores;
    metadata.limits.memory_mib = limits.memory_mib;
    metadata.limits.disk_mib = limits.disk_mib;
    metadata.limits.disk_enforced = state.config.disk.mode.enforced();
    metadata.limits.disk_enforcement_method = state.config.disk.mode.method().to_string();
    metadata.updated_at = now_rfc3339();
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;

    tracing::info!(
        event = "audit instance_limits_updated",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        cpu_cores = metadata.limits.cpu_cores,
        memory_mib = metadata.limits.memory_mib,
        disk_mib = metadata.limits.disk_mib,
    );

    Ok(Json(metadata))
}

pub async fn runtime_instances(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Vec<RuntimeInstanceResponse>> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_READ)?;
    let instances = state.instances.list().await;
    Ok(Json(
        instances
            .into_iter()
            .map(|metadata| RuntimeInstanceResponse {
                instance_id: metadata.instance_id,
                protocol: metadata.protocol.to_string(),
                runtime: metadata.runtime.kind.as_str().to_string(),
                container_name: metadata.runtime.container_name,
                status: metadata.status,
            })
            .collect(),
    ))
}

pub async fn instance_logs(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    Query(query): Query<LogsQuery>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<LogsResponse> {
    authorize_scope(&state, &headers, &uri, scopes::LOGS_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let output = state
        .docker
        .logs(metadata.protocol, &metadata.instance_id, query.tail)
        .await
        .map_err(docker_error)?;
    Ok(Json(LogsResponse {
        instance_id,
        stdout: redaction::redact_connection_url(&output.stdout),
        stderr: redaction::redact_connection_url(&output.stderr),
    }))
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Start,
    Stop,
    Restart,
    Kill,
}

pub(crate) async fn lifecycle_instance(
    state: &AppState,
    instance_id: &str,
    action: LifecycleAction,
) -> ApiResult<InstanceMetadata> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;

    let inspection = state
        .docker
        .inspect_instance(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)?;
    let should_call_docker = match action {
        LifecycleAction::Start => inspection.status != DockerContainerStatus::Running,
        LifecycleAction::Stop => inspection.status == DockerContainerStatus::Running,
        LifecycleAction::Restart => true,
        LifecycleAction::Kill => inspection.status == DockerContainerStatus::Running,
    };

    if should_call_docker {
        if matches!(action, LifecycleAction::Start | LifecycleAction::Restart) {
            let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
                .map_err(|error| ApiError::BadRequest(error.to_string()))?;
            DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
                .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))?;
        }
        match action {
            LifecycleAction::Start => {
                state
                    .docker
                    .start(metadata.protocol, &metadata.instance_id)
                    .await
            }
            LifecycleAction::Stop => {
                state
                    .docker
                    .stop(metadata.protocol, &metadata.instance_id)
                    .await
            }
            LifecycleAction::Restart => {
                state
                    .docker
                    .restart(metadata.protocol, &metadata.instance_id)
                    .await
            }
            LifecycleAction::Kill => {
                state
                    .docker
                    .kill(metadata.protocol, &metadata.instance_id)
                    .await
            }
        }
        .map_err(docker_error)?;
    }

    if matches!(action, LifecycleAction::Start | LifecycleAction::Restart) {
        state
            .docker
            .wait_until_ready(
                metadata.protocol,
                &metadata.instance_id,
                Duration::from_secs(120),
            )
            .await
            .map_err(docker_error)?;
    }

    let metadata = reconcile::reconcile_one(metadata, &state.docker).await;
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;

    Ok(Json(metadata))
}

async fn purge_instance_paths(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
        .purge_instance_data(&paths.data)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    for path in [paths.data, paths.logs, paths.sockets, paths.artifacts] {
        match tokio::fs::remove_dir_all(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ApiError::Runtime(format!(
                    "failed to purge {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

async fn instance_image_update_spec(
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    container_data_path: std::path::PathBuf,
    image: &str,
    password: Option<String>,
    pids_limit: i64,
) -> Result<DockerInstanceSpec, ApiError> {
    let password = match metadata.protocol {
        Protocol::Redis => password.unwrap_or_default(),
        _ => password.ok_or_else(|| {
            ApiError::BadRequest(
                "password is required when recreating non-redis database containers".to_string(),
            )
        })?,
    };
    let password = SecretString::from(password);

    let mut spec = match metadata.protocol {
        Protocol::Postgres => databases::postgres::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            &metadata.database.username,
            password,
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Redis => databases::redis::docker::instance_spec(
            &metadata.instance_id,
            image,
            container_data_path.clone(),
            paths.logs.clone(),
        ),
        Protocol::Mariadb => databases::mariadb::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            &metadata.database.username,
            password,
            SecretString::from(metadata.mariadb_root_password.clone().ok_or_else(|| {
                ApiError::BadRequest(
                    "mariadb internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
                )
            })?),
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mongodb => databases::mongodb::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            &metadata.database.username,
            password,
            container_data_path.clone(),
            paths.logs.clone(),
        ),
        Protocol::Clickhouse => {
            let hosted_config_path = databases::clickhouse::docker::write_hosted_config(&paths.logs)
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))?;
            databases::clickhouse::docker::instance_spec(
                &metadata.instance_id,
                image,
                &metadata.database.name,
                &metadata.database.username,
                password,
                container_data_path,
                paths.logs.clone(),
                hosted_config_path,
            )
        }
        Protocol::Qdrant => databases::qdrant::docker::instance_spec(
            &metadata.instance_id,
            image,
            password,
            container_data_path,
            paths.logs.clone(),
        ),
    };
    spec.cpu_cores = metadata.limits.cpu_cores;
    spec.memory_mib = metadata.limits.memory_mib;
    spec.disk_mib = metadata.limits.disk_mib;
    spec.pids_limit = Some(pids_limit);
    Ok(spec)
}

pub(crate) fn docker_error(error: DockerError) -> ApiError {
    match error {
        DockerError::InvalidId(error) => ApiError::BadRequest(error.to_string()),
        DockerError::Api(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => ApiError::NotFound,
        DockerError::Api(BollardError::DockerResponseServerError {
            status_code: 409,
            message,
            ..
        }) => ApiError::Conflict(message),
        error => ApiError::Runtime(error.to_string()),
    }
}
