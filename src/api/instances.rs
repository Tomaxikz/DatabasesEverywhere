use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, Uri},
};
use bollard::errors::Error as BollardError;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::Mutex,
    time::{Duration as TokioDuration, Instant},
};

use crate::{
    api::{
        handlers::{ApiError, ApiResult, authorize_scope},
        images::{ensure_image_allowed, validate_image},
        instance_create::{
            allocate_loopback_backend_port, backend_endpoint_for_instance,
            create_instance_from_request, launch_container_from_spec, protocol_pids_limit,
            provision_mariadb_tenant_user, provision_mongodb_tenant_user,
            provision_postgres_tenant_role,
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
    instances::{
        metadata::InstanceDatabaseVersion, metadata::InstanceImageStatus,
        metadata::InstanceMetadata, metadata::InstanceStatus, reconcile,
    },
    runtime::docker::{DockerContainerStatus, DockerError, DockerInstanceSpec},
    shared::{backend::BackendEndpoint, protocol::Protocol, redaction, time::now_rfc3339},
};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

const INSTANCE_RUNTIME_INFO_TTL: TokioDuration = TokioDuration::from_secs(60);

#[derive(Debug, Clone, Default)]
pub struct InstanceRuntimeInfoCache {
    inner: Arc<Mutex<HashMap<String, CachedInstanceRuntimeInfo>>>,
}

#[derive(Debug, Clone)]
struct CachedInstanceRuntimeInfo {
    image: InstanceImageStatus,
    database_version: InstanceDatabaseVersion,
    sampled_at: Instant,
}

#[derive(Debug, Clone)]
struct MajorUpgradePrecheck {
    warnings: Vec<String>,
}

impl InstanceRuntimeInfoCache {
    async fn fresh(
        &self,
        instance_id: &str,
        configured_image: &str,
    ) -> Option<(InstanceImageStatus, InstanceDatabaseVersion)> {
        let inner = self.inner.lock().await;
        let cached = inner
            .get(instance_id)
            .filter(|cached| cached.sampled_at.elapsed() < INSTANCE_RUNTIME_INFO_TTL)
            .filter(|cached| cached.image.configured == configured_image)?;
        Some((cached.image.clone(), cached.database_version.clone()))
    }

    async fn store(
        &self,
        instance_id: String,
        image: InstanceImageStatus,
        database_version: InstanceDatabaseVersion,
    ) {
        let mut inner = self.inner.lock().await;
        inner.insert(
            instance_id,
            CachedInstanceRuntimeInfo {
                image,
                database_version,
                sampled_at: Instant::now(),
            },
        );
    }

    pub async fn remove(&self, instance_id: &str) {
        self.inner.lock().await.remove(instance_id);
    }
}

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
    #[serde(default)]
    pub major_upgrade: bool,
}

#[derive(Debug, Serialize)]
pub struct UpdateInstanceImageResponse {
    pub instance: InstanceMetadata,
    pub image: String,
    pub recreated: bool,
    pub strategy: ImageUpdateStrategy,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_artifact_id: Option<String>,
    pub old_volume_backup_retained: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImageUpdateStrategy {
    InPlaceRecreate,
    MajorUpgradeMigration,
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
    let instances = futures::future::join_all(
        state
            .instances
            .list()
            .await
            .into_iter()
            .map(|metadata| enrich_instance_runtime_info(&state, metadata)),
    )
    .await;
    Ok(Json(instances))
}

pub async fn create_instance(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<CreateInstanceRequest>,
) -> ApiResult<InstanceMetadata> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_WRITE)?;
    let instance_id = request.instance_id.clone();
    let creation = tokio::spawn(async move { create_instance_from_request(&state, request).await });
    creation
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "instance creation task failed unexpectedly for {instance_id}: {error}"
            ))
        })?
        .map(Json)
}

pub async fn get_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<InstanceMetadata> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    Ok(Json(enrich_instance_runtime_info(&state, metadata).await))
}

async fn enrich_instance_runtime_info(
    state: &AppState,
    mut metadata: InstanceMetadata,
) -> InstanceMetadata {
    let configured = state
        .config
        .images
        .configured_for_protocol(metadata.protocol);
    if let Some((image, database_version)) = state
        .instance_runtime_cache
        .fresh(&metadata.instance_id, configured)
        .await
    {
        metadata.image = Some(image);
        metadata.database_version = Some(database_version);
        return metadata;
    }

    let current = state
        .docker
        .container_image(metadata.protocol, &metadata.instance_id)
        .await
        .ok()
        .flatten();
    let update_available = current
        .as_deref()
        .is_some_and(|current| current != configured);
    let image = InstanceImageStatus {
        current,
        configured: configured.to_string(),
        update_available,
    };
    let database_version = current_database_version(state, &metadata).await;
    state
        .instance_runtime_cache
        .store(
            metadata.instance_id.clone(),
            image.clone(),
            database_version.clone(),
        )
        .await;
    metadata.image = Some(image);
    metadata.database_version = Some(database_version);
    metadata
}

async fn current_database_version(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> InstanceDatabaseVersion {
    if metadata.status != InstanceStatus::Running {
        return InstanceDatabaseVersion {
            current: None,
            error: Some(format!(
                "instance is {}; version is only probed for running instances",
                metadata.status.as_str()
            )),
        };
    }

    let script = database_version_script(metadata.protocol);
    match state
        .docker
        .exec_shell(metadata.protocol, &metadata.instance_id, script)
        .await
    {
        Ok(output) => {
            let current = normalize_database_version(metadata.protocol, &output.stdout);
            let error = current
                .is_none()
                .then(|| "database version command returned no parseable output".to_string());
            InstanceDatabaseVersion { current, error }
        }
        Err(error) => InstanceDatabaseVersion {
            current: None,
            error: Some(short_error(&error.to_string(), 240)),
        },
    }
}

fn database_version_script(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => "postgres --version 2>/dev/null || psql --version",
        Protocol::Mariadb => "mariadb --version 2>/dev/null || mysqld --version",
        Protocol::Redis => "redis-server --version",
        Protocol::Mongodb => "mongod --version | awk '/db version/ {print $3; exit}'",
        Protocol::Clickhouse => "clickhouse-server --version 2>/dev/null || clickhouse --version",
        Protocol::Qdrant => {
            "if command -v qdrant >/dev/null 2>&1; then qdrant --version; elif [ -x /qdrant/qdrant ]; then /qdrant/qdrant --version; else cat /qdrant/VERSION 2>/dev/null; fi"
        }
    }
}

fn normalize_database_version(protocol: Protocol, stdout: &str) -> Option<String> {
    let line = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    let version = match protocol {
        Protocol::Postgres => line
            .strip_prefix("postgres (PostgreSQL) ")
            .or_else(|| line.strip_prefix("psql (PostgreSQL) "))
            .unwrap_or(line),
        Protocol::Mariadb => line
            .split("Distrib ")
            .nth(1)
            .and_then(|rest| rest.split([',', ' ']).next())
            .unwrap_or(line),
        Protocol::Redis => line
            .split_whitespace()
            .find_map(|part| part.strip_prefix("v="))
            .unwrap_or(line),
        Protocol::Mongodb => line.strip_prefix('v').unwrap_or(line),
        Protocol::Clickhouse => line
            .strip_prefix("ClickHouse server version ")
            .or_else(|| line.strip_prefix("ClickHouse local version "))
            .or_else(|| line.strip_prefix("ClickHouse client version "))
            .unwrap_or(line)
            .split(" (")
            .next()
            .unwrap_or(line),
        Protocol::Qdrant => line
            .strip_prefix("qdrant ")
            .or_else(|| line.strip_prefix("Qdrant "))
            .unwrap_or(line),
    }
    .trim()
    .trim_end_matches('.');

    (!version.is_empty()).then(|| version.to_string())
}

fn short_error(value: &str, max_chars: usize) -> String {
    let mut out = value.trim().replace('\n', "; ");
    if out.chars().count() > max_chars {
        out = out.chars().take(max_chars).collect();
        out.push_str("...");
    }
    out
}

fn fail_image_update_api(state: &AppState, instance_id: &str, error: ApiError) -> ApiError {
    tracing::error!(
        event = "audit instance_image_update_failed",
        instance_id,
        error = %error,
        "instance image update failed"
    );
    state
        .install_progress
        .fail(instance_id, format!("image update failed: {error}"));
    error
}

fn fail_image_update_bad_request(
    state: &AppState,
    instance_id: &str,
    error: impl std::fmt::Display,
) -> ApiError {
    fail_image_update_api(state, instance_id, ApiError::BadRequest(error.to_string()))
}

fn fail_image_update_runtime(
    state: &AppState,
    instance_id: &str,
    error: impl std::fmt::Display,
) -> ApiError {
    fail_image_update_api(state, instance_id, ApiError::Runtime(error.to_string()))
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
    let _operation = state.instance_locks.lock(&instance_id).await;
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
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.resource_cache.remove(&metadata.instance_id).await;
    Ok(Json(ReconcileResponse {
        instance_id,
        status: metadata.status,
    }))
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
    let _operation = state.instance_locks.lock(&instance_id).await;
    let mut metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    if metadata.status == InstanceStatus::Quarantined {
        return Err(ApiError::Conflict(
            "quarantined instances cannot be updated or migrated; inspect the quarantine cause and repair or recover the instance offline"
                .to_string(),
        ));
    }
    ensure_image_allowed(&state, metadata.protocol, &image)?;
    let current_image = state
        .docker
        .container_image(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?
        .ok_or_else(|| {
            fail_image_update_api(
                &state,
                &metadata.instance_id,
                ApiError::BadRequest(
                    "current container image could not be inspected; reconcile the instance before updating the image".to_string(),
                ),
            )
        })?;
    if request.major_upgrade {
        return update_instance_image_by_major_migration(
            &state,
            metadata,
            current_image,
            image,
            request.password,
        )
        .await
        .map(Json);
    }

    let image_change = classify_image_update(metadata.protocol, &current_image, &image)?;
    if image_change == ImageVersionChange::Major {
        return Err(major_upgrade_required_error(
            metadata.protocol,
            &current_image,
            &image,
        ));
    }
    state
        .install_progress
        .begin_image_update(&metadata.instance_id, metadata.protocol, &image);
    state
        .install_progress
        .stage(&metadata.instance_id, "prepare", "preparing image update");
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| fail_image_update_bad_request(&state, &metadata.instance_id, error))?;
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
            .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?;
        paths
            .container_user()
            .await
            .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?
    };
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?;
    let container_data_path = disk_limiter
        .container_data_path(&paths.data)
        .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?;
    let requested_password = request.password.clone();
    let mut spec = instance_image_update_spec(
        &metadata,
        &paths,
        container_data_path,
        &image,
        request.password,
        protocol_pids_limit(&state, metadata.protocol),
    )
    .await
    .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    spec.user = Some(container_user);
    let rootless_podman_backend_port = if state.docker.uses_rootless_podman() {
        let port = match &metadata.backend {
            BackendEndpoint::DockerTcp { host, port } if host == "127.0.0.1" => Some(*port),
            _ => None,
        }
        .unwrap_or(
            allocate_loopback_backend_port()
                .await
                .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?,
        );
        spec.public_backend_port = Some(port);
        Some(port)
    } else {
        None
    };

    let progress = state.install_progress.clone();
    let progress_instance_id = metadata.instance_id.clone();
    let pull_progress = move |event| progress.docker_pull(&progress_instance_id, event);
    state
        .docker
        .pull_image_with_progress(&image, &pull_progress)
        .await
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    state.install_progress.stage(
        &metadata.instance_id,
        "delete_container",
        "removing old container",
    );
    match state
        .docker
        .delete(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => {
            return Err(fail_image_update_api(
                &state,
                &metadata.instance_id,
                docker_error(error),
            ));
        }
    }
    launch_container_from_spec(
        &state,
        &spec,
        metadata.protocol,
        &metadata.instance_id,
        &pull_progress,
        true,
        || async { Ok(()) },
    )
    .await
    .map_err(|error| {
        fail_image_update_api(&state, &metadata.instance_id, error.into_api_error())
    })?;
    if metadata.protocol == Protocol::Postgres {
        provision_postgres_tenant_role(
            &state,
            &metadata.instance_id,
            &metadata.database.name,
            &metadata.database.username,
        )
        .await
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    }
    if metadata.protocol == Protocol::Mariadb {
        let password = requested_password.as_deref().ok_or_else(|| {
            fail_image_update_api(
                &state,
                &metadata.instance_id,
                ApiError::BadRequest(
                    "password is required when recreating mariadb database containers".to_string(),
                ),
            )
        })?;
        let root_password = metadata.mariadb_root_password.as_deref().ok_or_else(|| {
            fail_image_update_api(
                &state,
                &metadata.instance_id,
                ApiError::BadRequest(
                    "mariadb internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
                ),
            )
        })?;
        state.install_progress.stage(
            &metadata.instance_id,
            "provision",
            "re-provisioning MariaDB user",
        );
        provision_mariadb_tenant_user(
            &state,
            &metadata.instance_id,
            &metadata.database.name,
            &metadata.database.username,
            password,
            root_password,
        )
        .await
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    }
    state.install_progress.stage(
        &metadata.instance_id,
        "backend",
        "resolving backend endpoint",
    );
    metadata.backend = backend_endpoint_for_instance(
        &state,
        metadata.protocol,
        &metadata.instance_id,
        rootless_podman_backend_port,
    )
    .await
    .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
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
        .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;

    tracing::info!(
        event = "audit instance_image_updated",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        image,
    );
    state
        .install_progress
        .complete(&metadata.instance_id, "image update completed");

    Ok(Json(UpdateInstanceImageResponse {
        instance: metadata,
        image,
        recreated: true,
        strategy: ImageUpdateStrategy::InPlaceRecreate,
        warnings: Vec::new(),
        export_artifact_id: None,
        old_volume_backup_retained: false,
    }))
}

async fn update_instance_image_by_major_migration(
    state: &AppState,
    mut metadata: InstanceMetadata,
    current_image: String,
    image: String,
    password: Option<String>,
) -> Result<UpdateInstanceImageResponse, ApiError> {
    ensure_major_upgrade_supported(metadata.protocol)
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    let password = password.ok_or_else(|| {
        fail_image_update_api(
            state,
            &metadata.instance_id,
            ApiError::BadRequest(
                "password is required for major upgrade migration because DBE does not store tenant database passwords".to_string(),
            ),
        )
    })?;
    state
        .install_progress
        .begin_major_upgrade(&metadata.instance_id, metadata.protocol, &image);
    let precheck = precheck_major_upgrade(state, &metadata, &current_image, &image)
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    state.install_progress.stage(
        &metadata.instance_id,
        "export",
        "exporting old database before major upgrade",
    );
    let export_artifact = crate::api::import_export::export_instance_to_default_artifact(
        state,
        &metadata.instance_id,
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;

    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| fail_image_update_bad_request(state, &metadata.instance_id, error))?;
    let rollback = MajorUpgradeRollback {
        metadata: metadata.clone(),
        old_image: current_image.clone(),
        password: password.clone(),
        paths: paths.clone(),
    };

    let staged =
        create_staged_replacement_and_import(state, &metadata, &image, &password, &export_artifact)
            .await
            .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;

    state.install_progress.stage(
        &metadata.instance_id,
        "cutover",
        "validated replacement; stopping old container for final cutover",
    );
    let old_volume_backup = old_volume_backup_path(&paths.data)?;
    stop_and_delete_container(state, metadata.protocol, &metadata.instance_id)
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    rename_path(&paths.data, &old_volume_backup)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
        .purge_instance_data(&paths.data)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    if let Err(error) =
        move_staged_replacement_into_place(state, &metadata, &paths, &staged, &image, &password)
            .await
    {
        let rollback_error = rollback
            .restore(state, &old_volume_backup)
            .await
            .err()
            .map(|rollback_error| rollback_error.to_string());
        let message = match rollback_error {
            Some(rollback_error) => {
                format!("major upgrade failed: {error}; rollback also failed: {rollback_error}")
            }
            None => format!("major upgrade failed and old container was restored: {error}"),
        };
        return Err(fail_image_update_runtime(
            state,
            &metadata.instance_id,
            message,
        ));
    }
    metadata.backend = backend_endpoint_for_instance(
        state,
        metadata.protocol,
        &metadata.instance_id,
        rootless_backend_port_for_spec(state, &metadata, true).await?,
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    if metadata.protocol == Protocol::Mariadb {
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
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.install_progress.complete(
        &metadata.instance_id,
        "major upgrade migration completed; old volume retained for rollback",
    );

    tracing::info!(
        event = "audit instance_major_upgrade_completed",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        from_image = %current_image,
        to_image = %image,
        export_artifact = %export_artifact.display(),
        old_volume_backup = %old_volume_backup.display(),
    );

    Ok(UpdateInstanceImageResponse {
        instance: metadata,
        image,
        recreated: true,
        strategy: ImageUpdateStrategy::MajorUpgradeMigration,
        warnings: {
            let mut warnings = precheck.warnings;
            warnings.extend([
                "major upgrade used export/import migration instead of reusing the old data volume"
                    .to_string(),
                "old volume backup was kept on disk for manual rollback until the admin removes it"
                    .to_string(),
            ]);
            warnings
        },
        export_artifact_id: export_artifact
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string),
        old_volume_backup_retained: true,
    })
}

async fn precheck_major_upgrade(
    state: &AppState,
    metadata: &InstanceMetadata,
    current_image: &str,
    requested_image: &str,
) -> Result<MajorUpgradePrecheck, ApiError> {
    state.install_progress.stage(
        &metadata.instance_id,
        "precheck",
        "checking major upgrade compatibility",
    );
    ensure_major_upgrade_supported(metadata.protocol)?;
    let inspection = state
        .docker
        .inspect_instance(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)?;
    if inspection.status != DockerContainerStatus::Running {
        return Err(ApiError::BadRequest(format!(
            "major upgrade requires a running healthy source container; current status is {:?}, health={:?}",
            inspection.status, inspection.health
        )));
    }

    let current_major = image_major_version(current_image).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "{} major upgrade cannot compare current image tag {current_image:?}; use pinned semver-like tags for existing instances",
            metadata.protocol
        ))
    })?;
    let requested_major = image_major_version(requested_image).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "{} major upgrade cannot compare requested image tag {requested_image:?}; use pinned semver-like tags for existing instances",
            metadata.protocol
        ))
    })?;
    validate_major_upgrade_path(metadata.protocol, current_major, requested_major)?;

    let mut warnings = Vec::new();
    if current_major == requested_major {
        warnings.push(format!(
            "requested image has the same major version as current image ({current_major}); DBE still rebuilt the instance because major_upgrade=true"
        ));
    }
    if metadata.protocol == Protocol::Mongodb {
        precheck_mongodb_major_upgrade(state, metadata, current_major, requested_major).await?;
    } else {
        warnings.push(format!(
            "{} major upgrade uses logical dump/import; test application compatibility before upgrading production workloads",
            metadata.protocol
        ));
    }

    tracing::info!(
        event = "audit instance_major_upgrade_precheck_passed",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        current_image,
        requested_image,
        current_major,
        requested_major,
    );
    Ok(MajorUpgradePrecheck { warnings })
}

fn validate_major_upgrade_path(
    protocol: Protocol,
    current_major: u64,
    requested_major: u64,
) -> Result<(), ApiError> {
    if requested_major < current_major {
        return Err(ApiError::BadRequest(format!(
            "{protocol} image downgrade is blocked: current major is {current_major}, requested major is {requested_major}. Restore an older-version backup into a new instance instead."
        )));
    }
    if protocol == Protocol::Mongodb && requested_major > current_major + 1 {
        return Err(ApiError::BadRequest(format!(
            "mongodb major upgrade cannot skip versions: current major is {current_major}, requested major is {requested_major}. Upgrade one major version at a time."
        )));
    }
    Ok(())
}

async fn precheck_mongodb_major_upgrade(
    state: &AppState,
    metadata: &InstanceMetadata,
    current_major: u64,
    requested_major: u64,
) -> Result<(), ApiError> {
    if metadata.mongodb_root_password.is_none() {
        return Err(ApiError::BadRequest(
            "mongodb internal root password is missing; this instance was created before DBE stored MongoDB maintenance credentials, so automatic major upgrades cannot safely dump protected internal collections. Recreate the instance or restore from a manual admin dump.".to_string(),
        ));
    }
    let fcv = mongodb_feature_compatibility_major(state, metadata).await?;
    if requested_major > fcv + 1 {
        return Err(ApiError::BadRequest(format!(
            "mongodb featureCompatibilityVersion blocks this upgrade: FCV major is {fcv}, requested image major is {requested_major}. Upgrade one major version at a time and let FCV advance before the next major upgrade."
        )));
    }
    if fcv > current_major {
        return Err(ApiError::BadRequest(format!(
            "mongodb featureCompatibilityVersion {fcv} is newer than current image major {current_major}; refusing upgrade because the source state is inconsistent"
        )));
    }
    Ok(())
}

async fn mongodb_feature_compatibility_major(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<u64, ApiError> {
    let output = state
        .docker
        .exec_shell(
            Protocol::Mongodb,
            &metadata.instance_id,
            r#"mongosh --quiet --host 127.0.0.1 --username "$DBE_MONGO_ROOT_USER" --password "$DBE_MONGO_ROOT_PASSWORD" --authenticationDatabase admin admin --eval 'const f=db.adminCommand({getParameter:1, featureCompatibilityVersion:1}).featureCompatibilityVersion || {}; print(f.version || f.targetVersion || "")'"#,
        )
        .await
        .map_err(|error| {
            ApiError::BadRequest(format!(
                "failed to read mongodb featureCompatibilityVersion with DBE maintenance credentials: {error}"
            ))
        })?;
    parse_major_version_value(output.stdout.trim()).ok_or_else(|| {
        ApiError::BadRequest(
            "failed to parse mongodb featureCompatibilityVersion from source container".to_string(),
        )
    })
}

async fn create_empty_replacement_and_import(
    state: &AppState,
    metadata: &mut InstanceMetadata,
    paths: &InstancePaths,
    image: &str,
    password: &str,
    export_artifact: &std::path::Path,
    reuse_existing_rootless_backend_port: bool,
) -> Result<(), ApiError> {
    state.install_progress.stage(
        &metadata.instance_id,
        "prepare_replacement",
        "creating fresh data directory for target major version",
    );
    paths
        .create_dirs()
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    let container_user = if let Some(user) = state
        .docker
        .rootless_podman_container_user(metadata.protocol)
    {
        user.to_string()
    } else {
        paths
            .apply_container_owner()
            .await
            .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
        paths
            .container_user()
            .await
            .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?
    };

    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    let disk = disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    let container_data_path = disk.container_data_path.unwrap_or(paths.data.clone());
    let mut spec = instance_image_update_spec(
        metadata,
        paths,
        container_data_path,
        image,
        Some(password.to_string()),
        protocol_pids_limit(state, metadata.protocol),
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    spec.user = Some(container_user);
    let rootless_podman_backend_port =
        rootless_backend_port_for_spec(state, metadata, reuse_existing_rootless_backend_port)
            .await?;
    spec.public_backend_port = rootless_podman_backend_port;

    let progress = state.install_progress.clone();
    let progress_instance_id = metadata.instance_id.clone();
    let pull_progress = move |event| progress.docker_pull(&progress_instance_id, event);
    state
        .docker
        .pull_image_with_progress(image, &pull_progress)
        .await
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    launch_container_from_spec(
        state,
        &spec,
        metadata.protocol,
        &metadata.instance_id,
        &pull_progress,
        true,
        || async {
            if metadata.protocol == Protocol::Mongodb {
                provision_mongodb_tenant_user(
                    state,
                    &metadata.instance_id,
                    &metadata.database.name,
                    &metadata.database.username,
                    password,
                    metadata.mongodb_root_password.as_deref().ok_or_else(|| {
                        ApiError::BadRequest(
                            "mongodb internal root password is missing; this instance was created before DBE stored MongoDB maintenance credentials, so automatic major upgrades cannot dump protected internal collections. Recreate the instance or restore from a manually created admin dump.".to_string(),
                        )
                    })?,
                )
                .await?;
            }
            Ok(())
        },
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error.into_api_error()))?;

    if metadata.protocol == Protocol::Postgres {
        provision_postgres_tenant_role(
            state,
            &metadata.instance_id,
            &metadata.database.name,
            &metadata.database.username,
        )
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    }

    state.install_progress.stage(
        &metadata.instance_id,
        "import",
        "importing exported data into replacement container",
    );
    crate::api::import_export::import_default_artifact_into_metadata(
        state,
        metadata,
        export_artifact,
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    validate_replacement_instance(state, metadata, password).await?;
    metadata.backend = backend_endpoint_for_instance(
        state,
        metadata.protocol,
        &metadata.instance_id,
        rootless_podman_backend_port,
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    if metadata.protocol == Protocol::Mariadb {
        metadata.mariadb_native_password_sha1_stage2 = Some(
            crate::protocols::mariadb::native_password_sha1_stage2_hex(password),
        );
    }
    Ok(())
}

struct StagedMajorUpgrade {
    metadata: InstanceMetadata,
    paths: InstancePaths,
}

async fn create_staged_replacement_and_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    image: &str,
    password: &str,
    export_artifact: &std::path::Path,
) -> Result<StagedMajorUpgrade, ApiError> {
    state.install_progress.stage(
        &metadata.instance_id,
        "prepare_replacement",
        "creating temporary target-version database for major upgrade",
    );
    let temporary_instance_id = temporary_major_upgrade_instance_id(&metadata.instance_id);
    let staged_paths = InstancePaths::new(&state.config.paths, &temporary_instance_id)
        .map_err(|error| fail_image_update_bad_request(state, &metadata.instance_id, error))?;
    cleanup_temporary_replacement(
        state,
        metadata.protocol,
        &temporary_instance_id,
        &staged_paths,
    )
    .await;

    let mut staged_metadata = metadata.clone();
    staged_metadata.instance_id = temporary_instance_id.clone();
    staged_metadata.status = InstanceStatus::Creating;
    staged_metadata.runtime.container_name = state
        .docker
        .container_name(metadata.protocol, &temporary_instance_id)
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    staged_metadata.updated_at = now_rfc3339();

    match create_empty_replacement_and_import(
        state,
        &mut staged_metadata,
        &staged_paths,
        image,
        password,
        export_artifact,
        false,
    )
    .await
    {
        Ok(()) => Ok(StagedMajorUpgrade {
            metadata: staged_metadata,
            paths: staged_paths,
        }),
        Err(error) => {
            cleanup_temporary_replacement(
                state,
                metadata.protocol,
                &temporary_instance_id,
                &staged_paths,
            )
            .await;
            Err(error)
        }
    }
}

async fn move_staged_replacement_into_place(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    staged: &StagedMajorUpgrade,
    image: &str,
    password: &str,
) -> Result<(), ApiError> {
    stop_and_delete_container(
        state,
        staged.metadata.protocol,
        &staged.metadata.instance_id,
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
        .purge_instance_data(&staged.paths.data)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    cleanup_path_if_exists(&paths.data).await?;
    rename_path(&staged.paths.data, &paths.data)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    cleanup_temporary_side_paths(&staged.paths).await;
    create_empty_replacement_and_import_without_import(state, metadata, paths, image, password)
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    Ok(())
}

struct MajorUpgradeRollback {
    metadata: InstanceMetadata,
    old_image: String,
    password: String,
    paths: InstancePaths,
}

impl MajorUpgradeRollback {
    async fn restore(
        self,
        state: &AppState,
        old_volume_backup: &std::path::Path,
    ) -> Result<(), ApiError> {
        tracing::warn!(
            event = "audit instance_major_upgrade_rollback_started",
            instance_id = %self.metadata.instance_id,
            protocol = %self.metadata.protocol,
        );
        let _ =
            stop_and_delete_container(state, self.metadata.protocol, &self.metadata.instance_id)
                .await;
        let disk_limiter =
            DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
        let _ = disk_limiter.purge_instance_data(&self.paths.data).await;
        cleanup_path_if_exists(&self.paths.data).await?;
        rename_path(old_volume_backup, &self.paths.data)
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to restore old volume: {error}")))?;
        create_empty_replacement_and_import_without_import(
            state,
            &self.metadata,
            &self.paths,
            &self.old_image,
            &self.password,
        )
        .await?;
        state
            .manager
            .upsert(self.metadata.clone())
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        tracing::warn!(
            event = "audit instance_major_upgrade_rollback_completed",
            instance_id = %self.metadata.instance_id,
            protocol = %self.metadata.protocol,
        );
        Ok(())
    }
}

async fn create_empty_replacement_and_import_without_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    image: &str,
    password: &str,
) -> Result<(), ApiError> {
    let container_user = if let Some(user) = state
        .docker
        .rootless_podman_container_user(metadata.protocol)
    {
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
    let disk = disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let container_data_path = disk.container_data_path.unwrap_or(paths.data.clone());
    let mut spec = instance_image_update_spec(
        metadata,
        paths,
        container_data_path,
        image,
        Some(password.to_string()),
        protocol_pids_limit(state, metadata.protocol),
    )
    .await?;
    spec.user = Some(container_user);
    spec.public_backend_port = rootless_backend_port_for_spec(state, metadata, true).await?;
    let progress = state.install_progress.clone();
    let progress_instance_id = metadata.instance_id.clone();
    let pull_progress = move |event| progress.docker_pull(&progress_instance_id, event);
    launch_container_from_spec(
        state,
        &spec,
        metadata.protocol,
        &metadata.instance_id,
        &pull_progress,
        true,
        || async { Ok(()) },
    )
    .await
    .map_err(|error| error.into_api_error())
}

async fn rootless_backend_port_for_spec(
    state: &AppState,
    metadata: &InstanceMetadata,
    reuse_existing: bool,
) -> Result<Option<u16>, ApiError> {
    if !state.docker.uses_rootless_podman() {
        return Ok(None);
    }
    if reuse_existing
        && let BackendEndpoint::DockerTcp { host, port } = &metadata.backend
        && host == "127.0.0.1"
    {
        return Ok(Some(*port));
    }
    allocate_loopback_backend_port()
        .await
        .map(Some)
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))
}

fn temporary_major_upgrade_instance_id(instance_id: &str) -> String {
    format!(
        "dbe_upgrade_tmp_{}_{}",
        uuid::Uuid::new_v4().simple(),
        instance_id
    )
}

async fn cleanup_temporary_replacement(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
    paths: &InstancePaths,
) {
    let _ = stop_and_delete_container(state, protocol, instance_id).await;
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    let _ = disk_limiter.purge_instance_data(&paths.data).await;
    let _ = cleanup_path_if_exists(&paths.data).await;
    cleanup_temporary_side_paths(paths).await;
}

async fn cleanup_temporary_side_paths(paths: &InstancePaths) {
    for path in [
        &paths.logs,
        &paths.sockets,
        &paths.artifacts,
        &paths.runtime_config,
    ] {
        let _ = cleanup_path_if_exists(path).await;
    }
}

async fn validate_replacement_instance(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
) -> Result<(), ApiError> {
    state.install_progress.stage(
        &metadata.instance_id,
        "validate",
        "validating replacement database",
    );
    let script = match metadata.protocol {
        Protocol::Postgres => "PGPASSWORD=\"${DBE_POSTGRES_PASSWORD:-$POSTGRES_PASSWORD}\" psql -h 127.0.0.1 -U \"${DBE_POSTGRES_USER:-$POSTGRES_USER}\" -d \"$POSTGRES_DB\" -v ON_ERROR_STOP=1 -c 'select 1' >/dev/null".to_string(),
        Protocol::Mariadb => "mariadb -h 127.0.0.1 -u \"$MARIADB_USER\" -p\"$MARIADB_PASSWORD\" \"$MARIADB_DATABASE\" -e 'select 1' >/dev/null".to_string(),
        Protocol::Mongodb => "mongosh --quiet --host 127.0.0.1 --username \"$DBE_MONGO_USER\" --password \"$DBE_MONGO_PASSWORD\" --authenticationDatabase \"$DBE_MONGO_DATABASE\" \"$DBE_MONGO_DATABASE\" --eval 'db.runCommand({ ping: 1 }).ok' >/dev/null".to_string(),
        Protocol::Clickhouse => "clickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query 'SELECT 1' >/dev/null".to_string(),
        Protocol::Redis | Protocol::Qdrant => {
            return Err(ApiError::BadRequest(format!(
                "{} major upgrade migration is not supported",
                metadata.protocol
            )));
        }
    };
    let script = format!(
        "set -eu\nexport DBE_UPGRADE_PASSWORD={}\n{script}",
        crate::shared::shell::sh_quote(password)
    );
    state
        .docker
        .exec_shell(metadata.protocol, &metadata.instance_id, &script)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    Ok(())
}

async fn stop_and_delete_container(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), ApiError> {
    match state.docker.stop(protocol, instance_id).await {
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(docker_error(error)),
    }
    match state.docker.delete(protocol, instance_id).await {
        Ok(_) => Ok(()),
        Err(error) if error.is_not_found() => Ok(()),
        Err(error) => Err(docker_error(error)),
    }
}

async fn rename_path(from: &std::path::Path, to: &std::path::Path) -> Result<(), std::io::Error> {
    if let Some(parent) = to.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::rename(from, to).await
}

async fn cleanup_path_if_exists(path: &std::path::Path) -> Result<(), ApiError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_dir() => tokio::fs::remove_dir_all(path).await,
        Ok(_) => tokio::fs::remove_file(path).await,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => Err(error),
    }
    .map_err(|error| ApiError::Runtime(format!("failed to remove {}: {error}", path.display())))
}

fn old_volume_backup_path(data_path: &std::path::Path) -> Result<PathBuf, ApiError> {
    let parent = data_path
        .parent()
        .ok_or_else(|| ApiError::Runtime("instance data path has no parent".to_string()))?;
    let name = data_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ApiError::Runtime("instance data path has no valid name".to_string()))?;
    Ok(parent.join(format!(
        ".dbe-major-upgrade-old-{name}-{}",
        uuid::Uuid::new_v4()
    )))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageVersionChange {
    SameMajorOrUnknown,
    Major,
}

fn classify_image_update(
    protocol: Protocol,
    current_image: &str,
    requested_image: &str,
) -> Result<ImageVersionChange, ApiError> {
    if current_image == requested_image {
        return Ok(ImageVersionChange::SameMajorOrUnknown);
    }
    let Some(current_major) = image_major_version(current_image) else {
        return Err(ApiError::BadRequest(format!(
            "{} image update cannot compare current image tag {current_image:?}; use pinned semver-like tags for existing instances",
            protocol
        )));
    };
    let Some(requested_major) = image_major_version(requested_image) else {
        return Err(ApiError::BadRequest(format!(
            "{} image update cannot compare requested image tag {requested_image:?}; use pinned semver-like tags for existing instances",
            protocol
        )));
    };
    if current_major == requested_major {
        Ok(ImageVersionChange::SameMajorOrUnknown)
    } else {
        Ok(ImageVersionChange::Major)
    }
}

fn image_major_version(image: &str) -> Option<u64> {
    let image = image.split('@').next().unwrap_or(image);
    let slash_index = image.rfind('/').map(|index| index + 1).unwrap_or(0);
    let tag_index = image[slash_index..].rfind(':')? + slash_index;
    let tag = &image[tag_index + 1..];
    parse_major_version_value(tag)
}

fn parse_major_version_value(value: &str) -> Option<u64> {
    let major = value
        .split(|character: char| !character.is_ascii_digit())
        .next()?;
    if major.is_empty() {
        None
    } else {
        major.parse().ok()
    }
}

fn major_upgrade_required_error(
    protocol: Protocol,
    current_image: &str,
    requested_image: &str,
) -> ApiError {
    ApiError::BadRequest(format!(
        "{protocol} major image upgrade is blocked for normal image updates. Current image is {current_image}, requested image is {requested_image}. Retry with major_upgrade=true to run DBE's export/import migration workflow, or create a fresh instance and import a dump manually."
    ))
}

fn ensure_major_upgrade_supported(protocol: Protocol) -> Result<(), ApiError> {
    match protocol {
        Protocol::Postgres | Protocol::Mariadb | Protocol::Mongodb | Protocol::Clickhouse => Ok(()),
        Protocol::Redis => Err(ApiError::BadRequest(
            "redis major upgrades are blocked because Redis uses physical archive restore here; create a fresh Redis instance or use a dedicated Redis migration workflow".to_string(),
        )),
        Protocol::Qdrant => Err(ApiError::BadRequest(
            "qdrant major upgrades are blocked because Qdrant snapshot compatibility is version-specific; create a fresh Qdrant instance or use a dedicated Qdrant migration workflow".to_string(),
        )),
    }
}

pub async fn delete_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<DeleteResponse> {
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_WRITE)?;
    let _operation = state.instance_locks.lock(&instance_id).await;
    let mut metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let purge = query
        .get("purge")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    metadata.status = deletion_status(metadata.status);
    metadata.updated_at = now_rfc3339();
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;

    match state
        .docker
        .delete(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(docker_error(error)),
    }
    if purge && let Err(error) = purge_instance_paths(&state, &metadata.instance_id).await {
        tracing::error!(
            event = "audit instance_purge_failed",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            error = %error,
            status = metadata.status.as_str(),
            "instance metadata was retained so purge can be retried"
        );
        return Err(error);
    }
    let deleted = state
        .manager
        .delete(&metadata.instance_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.resource_cache.remove(&metadata.instance_id).await;
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

fn deletion_status(current: InstanceStatus) -> InstanceStatus {
    if current == InstanceStatus::Quarantined {
        InstanceStatus::Quarantined
    } else {
        InstanceStatus::Deleting
    }
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
    let _operation = state.instance_locks.lock(&instance_id).await;

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
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;

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
    authorize_scope(&state, &headers, &uri, scopes::INSTANCES_ADMIN)?;
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
    let _operation = state.instance_locks.lock(instance_id).await;
    lifecycle_instance_locked(state, instance_id, action).await
}

pub(crate) async fn lifecycle_instance_locked(
    state: &AppState,
    instance_id: &str,
    action: LifecycleAction,
) -> ApiResult<InstanceMetadata> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;

    if metadata.status == InstanceStatus::Quarantined
        && matches!(action, LifecycleAction::Start | LifecycleAction::Restart)
    {
        return Err(ApiError::Conflict(
            "instance is quarantined for fail-closed safety; inspect job history and logs, then repair, recover, or delete it before attempting to start it"
                .to_string(),
        ));
    }

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
        if metadata.protocol == Protocol::Postgres {
            provision_postgres_tenant_role(
                state,
                &metadata.instance_id,
                &metadata.database.name,
                &metadata.database.username,
            )
            .await?;
        }
    }

    let metadata = reconcile::reconcile_one(metadata, &state.docker).await;
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;

    Ok(Json(metadata))
}

async fn purge_instance_paths(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
        .purge_instance_data(&paths.data)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    for path in [
        paths.data,
        paths.logs,
        paths.sockets,
        paths.artifacts,
        paths.runtime_config,
    ] {
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
            databases::mongodb::docker::MongodbAuth {
                username: metadata.database.username.clone(),
                password,
                root_password: SecretString::from(
                    metadata.mongodb_root_password.clone().ok_or_else(|| {
                        ApiError::BadRequest(
                            "mongodb internal root password is missing; old MongoDB instances must be recreated or restored from a manual admin dump before image replacement".to_string(),
                        )
                    })?,
                ),
            },
            container_data_path.clone(),
            paths.logs.clone(),
        ),
        Protocol::Clickhouse => {
            let hosted_config_path =
                databases::clickhouse::docker::write_hosted_config(&paths.runtime_config)
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
        error @ DockerError::UntrustedContainerNameCollision { .. } => {
            ApiError::Conflict(error.to_string())
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_preserves_quarantine_to_avoid_claiming_a_duplicate_route() {
        assert_eq!(
            deletion_status(InstanceStatus::Quarantined),
            InstanceStatus::Quarantined
        );
        assert_eq!(
            deletion_status(InstanceStatus::Running),
            InstanceStatus::Deleting
        );
        assert_eq!(
            deletion_status(InstanceStatus::Deleting),
            InstanceStatus::Deleting
        );
    }

    #[test]
    fn parses_major_version_from_common_image_tags() {
        assert_eq!(image_major_version("mongo:7.0.37"), Some(7));
        assert_eq!(
            image_major_version("docker.io/library/postgres:18.4"),
            Some(18)
        );
        assert_eq!(
            image_major_version("registry.example.com:5000/db/mariadb:12.3.2"),
            Some(12)
        );
    }

    #[test]
    fn rejects_unpinned_images_for_existing_instance_updates() {
        assert!(image_major_version("mongo:latest").is_none());
        assert!(image_major_version("mongo@sha256:abc").is_none());
        assert!(image_major_version("mongo").is_none());
    }

    #[test]
    fn parses_major_version_values() {
        assert_eq!(parse_major_version_value("8.3"), Some(8));
        assert_eq!(parse_major_version_value("v7.0"), None);
        assert_eq!(parse_major_version_value("latest"), None);
    }

    #[test]
    fn classifies_major_version_changes() {
        let change =
            classify_image_update(Protocol::Mongodb, "mongo:7.0.37", "mongo:8.3.4").unwrap();
        assert_eq!(change, ImageVersionChange::Major);

        let change =
            classify_image_update(Protocol::Postgres, "postgres:18.3", "postgres:18.4").unwrap();
        assert_eq!(change, ImageVersionChange::SameMajorOrUnknown);
    }

    #[test]
    fn requires_parseable_tags_for_different_existing_images() {
        let error =
            classify_image_update(Protocol::Mongodb, "mongo:7.0.37", "mongo:latest").unwrap_err();
        assert!(error.to_string().contains("cannot compare requested image"));
    }

    #[test]
    fn major_upgrade_path_blocks_downgrades() {
        let error = validate_major_upgrade_path(Protocol::Postgres, 18, 17).unwrap_err();
        assert!(error.to_string().contains("downgrade is blocked"));
    }

    #[test]
    fn mongodb_major_upgrade_path_blocks_skipped_versions() {
        let error = validate_major_upgrade_path(Protocol::Mongodb, 6, 8).unwrap_err();
        assert!(error.to_string().contains("cannot skip versions"));

        assert!(validate_major_upgrade_path(Protocol::Mongodb, 7, 8).is_ok());
    }

    #[test]
    fn non_mongodb_dump_upgrade_path_allows_skipped_versions() {
        assert!(validate_major_upgrade_path(Protocol::Postgres, 14, 18).is_ok());
    }

    #[test]
    fn major_migration_support_is_limited_to_logical_dump_protocols() {
        assert!(ensure_major_upgrade_supported(Protocol::Postgres).is_ok());
        assert!(ensure_major_upgrade_supported(Protocol::Mongodb).is_ok());
        assert!(ensure_major_upgrade_supported(Protocol::Redis).is_err());
        assert!(ensure_major_upgrade_supported(Protocol::Qdrant).is_err());
    }

    #[test]
    fn normalizes_database_version_outputs() {
        assert_eq!(
            normalize_database_version(Protocol::Postgres, "postgres (PostgreSQL) 18.4\n"),
            Some("18.4".to_string())
        );
        assert_eq!(
            normalize_database_version(
                Protocol::Mariadb,
                "mariadb  Ver 15.1 Distrib 12.3.2-MariaDB, for Linux (x86_64)\n"
            ),
            Some("12.3.2-MariaDB".to_string())
        );
        assert_eq!(
            normalize_database_version(
                Protocol::Redis,
                "Redis server v=8.8.0 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64\n"
            ),
            Some("8.8.0".to_string())
        );
        assert_eq!(
            normalize_database_version(Protocol::Mongodb, "v8.3.4\n"),
            Some("8.3.4".to_string())
        );
        assert_eq!(
            normalize_database_version(
                Protocol::Clickhouse,
                "ClickHouse server version 25.8.25.37 (official build).\n"
            ),
            Some("25.8.25.37".to_string())
        );
        assert_eq!(
            normalize_database_version(Protocol::Qdrant, "qdrant 1.18.2\n"),
            Some("1.18.2".to_string())
        );
    }

    #[test]
    fn version_probe_errors_are_shortened() {
        let error = short_error(&format!("first\n{}", "x".repeat(400)), 20);
        assert_eq!(error, "first; xxxxxxxxxxxxx...");
    }
}
