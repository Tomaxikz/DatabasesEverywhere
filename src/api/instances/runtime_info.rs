use super::*;

const INSTANCE_RUNTIME_INFO_TTL: TokioDuration = TokioDuration::from_secs(60);
const INSTANCE_RUNTIME_FANOUT_LIMIT: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct InstanceRuntimeInfoCache {
    inner: Arc<Mutex<InstanceRuntimeInfoCacheInner>>,
}

#[derive(Debug, Default)]
pub(super) struct InstanceRuntimeInfoCacheInner {
    epoch: u64,
    runtime: HashMap<String, CachedInstanceRuntimeInfo>,
    inspections: HashMap<String, CachedInstanceInspection>,
    inspection_locks: HashMap<String, Arc<Mutex<()>>>,
}

#[derive(Debug, Clone)]
pub(super) struct CachedInstanceRuntimeInfo {
    image: InstanceImageStatus,
    sampled_at: Instant,
}

#[derive(Debug, Clone)]
pub(super) struct CachedInstanceInspection {
    inspection: DockerInstanceInspection,
    sampled_at: Instant,
}

#[derive(Debug, Clone)]
pub(super) struct MajorUpgradePrecheck {
    pub(super) warnings: Vec<String>,
}

impl InstanceRuntimeInfoCache {
    pub(super) async fn epoch(&self) -> u64 {
        self.inner.lock().await.epoch
    }

    pub(super) async fn fresh(
        &self,
        instance_id: &str,
        configured_image: &str,
    ) -> Option<InstanceImageStatus> {
        let inner = self.inner.lock().await;
        let cached = inner
            .runtime
            .get(instance_id)
            .filter(|cached| cached.sampled_at.elapsed() < INSTANCE_RUNTIME_INFO_TTL)
            .filter(|cached| cached.image.configured == configured_image)?;
        Some(cached.image.clone())
    }

    pub(super) async fn store_if_epoch(
        &self,
        instance_id: String,
        image: InstanceImageStatus,
        expected_epoch: u64,
    ) -> bool {
        let mut inner = self.inner.lock().await;
        if inner.epoch != expected_epoch {
            return false;
        }
        inner.runtime.insert(
            instance_id,
            CachedInstanceRuntimeInfo {
                image,
                sampled_at: Instant::now(),
            },
        );
        true
    }

    async fn inspect_instance(
        &self,
        docker: &DockerRuntime,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<DockerInstanceInspection, DockerError> {
        loop {
            let requested_at = Instant::now();
            let (refresh_lock, epoch) = {
                let mut inner = self.inner.lock().await;
                let epoch = inner.epoch;
                let lock = inner
                    .inspection_locks
                    .entry(instance_id.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(())))
                    .clone();
                (lock, epoch)
            };
            let refresh = refresh_lock.lock().await;

            {
                let inner = self.inner.lock().await;
                if inner.epoch != epoch {
                    drop(inner);
                    drop(refresh);
                    continue;
                }
                if let Some(cached) = inner
                    .inspections
                    .get(instance_id)
                    .filter(|cached| cached.sampled_at >= requested_at)
                {
                    return Ok(cached.inspection.clone());
                }
            }

            let inspection = match docker.inspect_instance(protocol, instance_id).await {
                Ok(inspection) => inspection,
                Err(error) => {
                    let invalidated = self.inner.lock().await.epoch != epoch;
                    drop(refresh);
                    if invalidated {
                        continue;
                    }
                    return Err(error);
                }
            };
            let mut inner = self.inner.lock().await;
            if inner.epoch != epoch {
                drop(inner);
                drop(refresh);
                continue;
            }
            inner.inspections.insert(
                instance_id.to_string(),
                CachedInstanceInspection {
                    inspection: inspection.clone(),
                    sampled_at: Instant::now(),
                },
            );
            return Ok(inspection);
        }
    }

    pub async fn remove(&self, instance_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.epoch = inner.epoch.wrapping_add(1);
        inner.runtime.remove(instance_id);
        inner.inspections.remove(instance_id);
        inner.inspection_locks.remove(instance_id);
    }
}

#[derive(Debug, Serialize)]
pub struct InstanceStatusResponse {
    pub instance_id: String,
    pub status: InstanceStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<InstallProgress>,
}

#[derive(Debug, Serialize)]
pub struct CreateInstanceAcceptedResponse {
    pub instance_id: String,
    pub status: InstanceStatus,
    pub status_url: String,
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
pub struct LogsResponse {
    pub instance_id: String,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogsQuery {
    pub tail: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct PowerRequest {
    pub action: LifecycleAction,
}

#[derive(Debug, Serialize)]
pub struct PowerResponse {
    pub instance: InstanceMetadata,
    pub action: LifecycleAction,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct DeleteInstanceQuery {
    pub confirm: bool,
    pub reason: String,
}

pub async fn list_instances(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<Vec<InstanceMetadata>> {
    auth.require_scope(scopes::INSTANCES_READ)?;
    let instances = futures::stream::iter(state.instances.list().await)
        .map(|metadata| enrich_instance_runtime_info(&state, metadata))
        .buffered(INSTANCE_RUNTIME_FANOUT_LIMIT)
        .collect()
        .await;
    Ok(ApiResponse::ok(instances))
}

pub async fn create_instance(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiJson(request): ApiJson<CreateInstanceRequest>,
) -> ApiResult<CreateInstanceAcceptedResponse> {
    auth.require_scope(scopes::INSTANCES_WRITE)?;
    validate_create_request(&request)?;
    let instance_id = request.instance_id.clone();
    if state.instances.get(&instance_id).await.is_some() {
        return Err(ApiError::Conflict(format!(
            "instance_id {instance_id} already exists"
        )));
    }
    let image = requested_or_configured_image(&state, &request)?;
    let creation_permit = state
        .install_progress
        .try_begin_creation(&instance_id, request.protocol, &image)
        .map_err(|error| match error {
            BeginCreationError::AlreadyRunning => ApiError::Conflict(format!(
                "instance creation already running for {instance_id}"
            )),
            BeginCreationError::Capacity => ApiError::ServiceUnavailable(
                "instance creation queue is at capacity; retry later".to_string(),
            ),
            BeginCreationError::ShuttingDown => ApiError::ServiceUnavailable(
                "daemon shutdown has started; new instance creations are not accepted".to_string(),
            ),
        })?;

    let task_state = state.clone();
    let task_instance_id = instance_id.clone();
    tokio::spawn(async move {
        let worker_state = task_state.clone();
        let result =
            tokio::spawn(async move { create_instance_from_request(&worker_state, request).await })
                .await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                task_state.install_progress.fail_if_running_api_error(
                    &task_instance_id,
                    "instance creation",
                    &error,
                );
                tracing::warn!(
                    event = "audit instance_create_background_failed",
                    instance_id = %task_instance_id,
                    %error,
                    "background instance creation failed"
                );
            }
            Err(error) => {
                let message = format!("instance creation task failed unexpectedly: {error}");
                task_state.install_progress.fail_if_running_internal(
                    &task_instance_id,
                    "instance creation task",
                    &message,
                );
                tracing::error!(
                    event = "audit instance_create_task_failed",
                    instance_id = %task_instance_id,
                    %error,
                    "background instance creation task failed unexpectedly"
                );
            }
        }
        drop(creation_permit);
    });

    let status_url = format!("/api/instances/{instance_id}/status");
    let location = status_url.clone();
    Ok(ApiResponse::accepted_at(
        CreateInstanceAcceptedResponse {
            status_url,
            instance_id,
            status: InstanceStatus::Creating,
        },
        location,
    ))
}

pub async fn get_instance(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<InstanceMetadata> {
    auth.require_scope(scopes::INSTANCES_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    Ok(ApiResponse::ok(
        enrich_instance_runtime_info(&state, metadata).await,
    ))
}

pub(super) async fn enrich_instance_runtime_info(
    state: &AppState,
    mut metadata: InstanceMetadata,
) -> InstanceMetadata {
    let cache_epoch = state.instance_runtime_cache.epoch().await;
    let inspection = live_instance_inspection(state, &metadata).await;
    metadata.status = if state.instances.routes_fenced(&metadata.instance_id).await {
        InstanceStatus::Booting
    } else {
        classify_live_instance_status(&metadata, inspection.as_ref())
    };
    let configured = state
        .config
        .images
        .configured_for_protocol(metadata.protocol);
    if let Some(image) = state
        .instance_runtime_cache
        .fresh(&metadata.instance_id, configured)
        .await
    {
        metadata.image = Some(image);
        metadata.database_version = Some(current_database_version(state, &metadata).await);
        return metadata;
    }

    let current = match inspection.as_ref() {
        Some(Ok(inspection)) => inspection.image.clone(),
        _ => state
            .docker
            .container_image(metadata.protocol, &metadata.instance_id)
            .await
            .ok()
            .flatten(),
    };
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
        .store_if_epoch(metadata.instance_id.clone(), image.clone(), cache_epoch)
        .await;
    metadata.image = Some(image);
    metadata.database_version = Some(database_version);
    metadata
}

pub(super) async fn live_instance_status(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> InstanceStatus {
    if state.instances.routes_fenced(&metadata.instance_id).await {
        return InstanceStatus::Booting;
    }
    let inspection = live_instance_inspection(state, metadata).await;
    classify_live_instance_status(metadata, inspection.as_ref())
}

pub(super) async fn live_instance_inspection(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Option<Result<DockerInstanceInspection, DockerError>> {
    if matches!(
        metadata.status,
        InstanceStatus::Quarantined | InstanceStatus::Deleting
    ) {
        return None;
    }

    Some(
        state
            .instance_runtime_cache
            .inspect_instance(&state.docker, metadata.protocol, &metadata.instance_id)
            .await,
    )
}

pub(super) fn classify_live_instance_status(
    metadata: &InstanceMetadata,
    inspection: Option<&Result<DockerInstanceInspection, DockerError>>,
) -> InstanceStatus {
    // Durable non-running states are also gateway-publication barriers. A
    // container process may already exist while creation, startup hardening,
    // recovery, or an explicit stop is still in progress; reporting `running`
    // before that state is committed tells clients the route is ready when it
    // deliberately is not.
    if metadata.status != InstanceStatus::Running {
        return metadata.status;
    }
    if metadata.desired_state == DesiredInstanceState::Stopped {
        return InstanceStatus::Stopped;
    }
    match inspection {
        None => metadata.status,
        Some(Ok(inspection)) => reconcile::classify_container_status(inspection.status),
        Some(Err(error)) if error.is_not_found() && metadata.status == InstanceStatus::Creating => {
            InstanceStatus::Creating
        }
        Some(Err(error)) if error.is_not_found() => InstanceStatus::Failed,
        Some(Err(error)) => {
            tracing::warn!(
                %error,
                instance_id = %metadata.instance_id,
                "could not refresh live instance status; returning last known status"
            );
            metadata.status
        }
    }
}

pub(super) async fn current_database_version(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> InstanceDatabaseVersion {
    match crate::compatibility::compatibility_attestation(&state.manager, &state.docker, metadata)
        .await
    {
        Ok(Some(attestation)) => InstanceDatabaseVersion {
            current: Some(attestation.version),
            error: attestation
                .diagnostic
                .map(|message| PublicDiagnostic::public("unsupported_database_version", message)),
        },
        Ok(None) => InstanceDatabaseVersion {
            current: None,
            error: Some(PublicDiagnostic::public(
                "version_not_attested",
                "the database version has not been attested yet; it will be checked at daemon boot or after reconstruction, password reset, or image update",
            )),
        },
        Err(error) => InstanceDatabaseVersion {
            current: None,
            error: Some(PublicDiagnostic::internal(
                "database compatibility attestation",
                error,
            )),
        },
    }
}

pub(super) fn fail_image_update_api(
    state: &AppState,
    instance_id: &str,
    error: ApiError,
) -> ApiError {
    tracing::error!(
        event = "audit instance_image_update_failed",
        instance_id,
        error = %error,
        "instance image update failed"
    );
    state
        .install_progress
        .fail_api_error(instance_id, "instance image update", &error);
    error
}

pub(super) fn fail_image_update_bad_request(
    state: &AppState,
    instance_id: &str,
    error: impl std::fmt::Display,
) -> ApiError {
    fail_image_update_api(state, instance_id, ApiError::BadRequest(error.to_string()))
}

pub(super) fn fail_image_update_runtime(
    state: &AppState,
    instance_id: &str,
    error: impl std::fmt::Display,
) -> ApiError {
    fail_image_update_api(state, instance_id, ApiError::Runtime(error.to_string()))
}

pub async fn get_instance_status(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<InstanceStatusResponse> {
    auth.require_scope(scopes::INSTANCES_READ)?;
    let metadata = state.instances.get(&instance_id).await;
    let progress = state
        .install_progress
        .get(&instance_id)
        .filter(|progress| progress.action == "create");
    let status = match (metadata, progress.as_ref()) {
        (Some(metadata), _) => live_instance_status(&state, &metadata).await,
        (None, Some(progress)) => match progress.status {
            InstallProgressStatus::Running => InstanceStatus::Creating,
            InstallProgressStatus::Failed => InstanceStatus::Failed,
            InstallProgressStatus::Completed => InstanceStatus::Running,
        },
        (None, None) => return Err(ApiError::NotFound),
    };
    Ok(ApiResponse::ok(InstanceStatusResponse {
        instance_id,
        status,
        progress,
    }))
}
