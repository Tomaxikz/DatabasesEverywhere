use super::*;

pub async fn update_instance_limits(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiJson(request): ApiJson<LimitsRequest>,
) -> ApiResult<InstanceMetadata> {
    auth.require_scope(scopes::INSTANCES_WRITE)?;
    if request.disk_mib == 0 || request.disk_mib > u64::MAX / (1024 * 1024) {
        return Err(ApiError::BadRequest("disk_mib must be positive".into()));
    }
    let mutation = state
        .daemon_shutdown
        .try_admit_background_mutation()
        .ok_or_else(|| {
            ApiError::ServiceUnavailable(
                "daemon shutdown has started; limit updates are not accepted".to_string(),
            )
        })?;
    // Waiting for locks is cancellable and changes nothing. Detach only once
    // admitted, so abandoned requests cannot accumulate background waiters.
    let creation = state.instance_locks.lock_creation().await;
    let operation = state.instance_locks.lock(&instance_id).await;
    // The worker owns the locks through commit or ordinary error rollback.
    spawn_owned_mutation_task(async move {
        let _mutation = mutation;
        let _operation = operation;
        let result = resize_instance(&state, &instance_id, request, creation).await;
        if let Err(error) = &result {
            tracing::warn!(event = "audit instance_limits_update_failed", %instance_id, %error,
                "instance limit update failed");
        }
        result
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("limit update worker failed: {error}")))?
}

pub(super) async fn resize_instance(
    state: &AppState,
    instance_id: &str,
    request: LimitsRequest,
    creation: tokio::sync::OwnedMutexGuard<()>,
) -> ApiResult<InstanceMetadata> {
    let mut metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    deployment::ensure_no_active_migration(state, instance_id).await?;
    if metadata.deployment_mode == crate::server::placement::DeploymentMode::Dedicated {
        validate_limits(&request)?;
        validate_protocol_limits(metadata.protocol, &request)?;
    }
    let limits = limits_from_request(&request);
    let previous_limits = metadata.limits.clone();
    if metadata.deployment_mode == crate::server::placement::DeploymentMode::Shared {
        return shared::resize(state, metadata, limits, creation)
            .await
            .map(ApiResponse::ok);
    }
    enforce_node_allocation_policy(state, &limits, Some(&previous_limits)).await?;
    let disk_changed = limits.disk_mib != previous_limits.disk_mib;
    let paths = if disk_changed {
        Some(
            InstancePaths::new(&state.config.paths, &metadata.instance_id)
                .map_err(|error| ApiError::BadRequest(error.to_string()))?,
        )
    } else {
        None
    };
    let effective_disk_limiter = persisted_disk_limiter(state, &metadata);
    if let Some(paths) = paths.as_ref() {
        effective_disk_limiter
            .check_method_change(&metadata.limits.disk_enforcement_method)
            .map_err(|error| ApiError::Conflict(error.to_string()))?;
        if crate::config::DiskLimitMode::from_persisted_method(
            &metadata.limits.disk_enforcement_method,
        ) != Some(effective_disk_limiter.mode())
        {
            return Err(ApiError::Conflict(format!(
                "instance currently uses {} disk enforcement but this node selects {}; restart dbev to reconcile or safely recreate/migrate the container before changing its disk limit",
                metadata.limits.disk_enforcement_method,
                effective_disk_limiter.mode().method(),
            )));
        }
        let expected_data_source = effective_disk_limiter
            .container_data_path(&paths.data)
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        match state
            .docker
            .verify_data_bind(
                metadata.protocol,
                &metadata.instance_id,
                &expected_data_source,
            )
            .await
        {
            Ok(()) => {}
            Err(error @ DockerError::DiskBindSourceMismatch { .. }) => {
                return Err(ApiError::Conflict(error.to_string()));
            }
            Err(error) => return Err(docker_error(error)),
        }
        if let Err(error) = effective_disk_limiter
            .update_instance_limit(&metadata.instance_id, &paths.data, limits.disk_mib)
            .await
        {
            let rollback =
                rollback_disk_limit(state, &metadata, paths, previous_limits.disk_mib).await;
            return Err(ApiError::Runtime(format!(
                "failed to update disk limit: {error}; rollback: {rollback}"
            )));
        }
    }

    if let Err(error) = state
        .docker
        .update_limits(
            metadata.protocol,
            &metadata.instance_id,
            limits.cpu_cores,
            limits.memory_mib,
        )
        .await
    {
        let rollback = rollback_instance_limits(
            state,
            &metadata,
            &previous_limits,
            paths.as_ref(),
            disk_changed,
        )
        .await;
        return Err(ApiError::Runtime(format!(
            "failed to update runtime limits: {error}; rollback: {rollback}"
        )));
    }

    metadata.limits.cpu_cores = limits.cpu_cores;
    metadata.limits.memory_mib = limits.memory_mib;
    metadata.limits.disk_mib = limits.disk_mib;
    if disk_changed {
        let effective_disk_mode = effective_disk_limiter.mode();
        metadata.limits.disk_enforced = effective_disk_mode.enforced();
        if effective_disk_mode == crate::config::DiskLimitMode::SoftScanner
            && metadata.disk_limit_blocked
            && limits.disk_mib > previous_limits.disk_mib
        {
            if let Some(paths) = paths.as_ref()
                && state
                    .soft_disk_limiter
                    .ensure_start_allowed(&crate::server::disk::soft::SoftDiskTarget {
                        instance_id: metadata.instance_id.clone(),
                        created_at: metadata.created_at.clone(),
                        protocol: metadata.protocol,
                        data_path: paths.data.clone(),
                        limit_bytes: mib_to_bytes(limits.disk_mib),
                        durable_blocked: true,
                    })
                    .await
                    .is_ok()
            {
                metadata.disk_limit_blocked = false;
            }
        } else if effective_disk_mode != crate::config::DiskLimitMode::SoftScanner {
            metadata.disk_limit_blocked = false;
        }
    }
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state.manager.upsert(metadata.clone()).await {
        let rollback = rollback_instance_limits(
            state,
            &metadata,
            &previous_limits,
            paths.as_ref(),
            disk_changed,
        )
        .await;
        return Err(ApiError::Runtime(format!(
            "failed to persist updated limits: {error}; rollback: {rollback}"
        )));
    }
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    if metadata.limits.disk_enforcement_method != "soft_scanner"
        && !(metadata.protocol == Protocol::Qdrant
            && metadata.limits.disk_enforcement_method == "fuse_quota")
    {
        state.soft_disk_limiter.remove(&metadata.instance_id).await;
    }

    tracing::info!(
        event = "audit instance_limits_updated",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        cpu_cores = metadata.limits.cpu_cores,
        memory_mib = metadata.limits.memory_mib,
        disk_mib = metadata.limits.disk_mib,
    );

    Ok(ApiResponse::ok(metadata))
}

pub(super) async fn rollback_instance_limits(
    state: &AppState,
    metadata: &InstanceMetadata,
    previous: &crate::utils::limits::InstanceLimits,
    paths: Option<&InstancePaths>,
    disk_changed: bool,
) -> String {
    let mut failures = Vec::new();
    if let Err(error) = state
        .docker
        .update_limits(
            metadata.protocol,
            &metadata.instance_id,
            previous.cpu_cores,
            previous.memory_mib,
        )
        .await
    {
        failures.push(format!("runtime rollback failed: {error}"));
    }
    if disk_changed
        && let Some(paths) = paths
        && let Err(error) = persisted_disk_limiter(state, metadata)
            .update_instance_limit(&metadata.instance_id, &paths.data, previous.disk_mib)
            .await
    {
        failures.push(format!("disk rollback failed: {error}"));
    }
    report_limit_rollback(&metadata.instance_id, failures)
}

pub(super) async fn rollback_disk_limit(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    disk_mib: u64,
) -> String {
    let mut failures = Vec::new();
    if let Err(error) = persisted_disk_limiter(state, metadata)
        .update_instance_limit(&metadata.instance_id, &paths.data, disk_mib)
        .await
    {
        failures.push(format!("disk rollback failed: {error}"));
    }
    report_limit_rollback(&metadata.instance_id, failures)
}

pub(super) fn report_limit_rollback(instance_id: &str, failures: Vec<String>) -> String {
    if failures.is_empty() {
        return "completed".to_string();
    }
    let failures = failures.join("; ");
    tracing::error!(
        event = "audit instance_limits_rollback_failed",
        instance_id,
        failures,
        "external limits may require operator reconciliation"
    );
    failures
}
