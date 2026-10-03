use super::*;

pub(in super::super) async fn reconcile(
    state: &AppState,
    mut metadata: InstanceMetadata,
) -> Result<InstanceMetadata, ApiError> {
    let runtime_id = shared_runtime_id(&metadata)?.to_string();
    let _runtime_operation = state.instance_locks.lock(&runtime_id).await;
    metadata = reload_after_runtime_lock(state, &metadata).await?;
    let route_fenced = state.instances.routes_fenced(&metadata.instance_id).await;
    let runtime = load_runtime(state, &metadata).await?;
    let inspection = state
        .docker
        .inspect_instance(metadata.protocol, &runtime.runtime_id)
        .await
        .map_err(docker_error)?;
    metadata.status = reconciled_tenant_status(
        metadata.status,
        metadata.desired_state,
        runtime.status,
        inspection.status,
        route_fenced,
    );
    if metadata.status != InstanceStatus::Running {
        drain_tenant_sessions(state, &metadata.instance_id).await?;
    }
    metadata.updated_at = now_rfc3339();
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(metadata)
}

pub(super) fn reconciled_tenant_status(
    current: InstanceStatus,
    desired: DesiredInstanceState,
    runtime: EngineRuntimeStatus,
    container: DockerContainerStatus,
    route_fenced: bool,
) -> InstanceStatus {
    if matches!(
        current,
        InstanceStatus::Deleting | InstanceStatus::Quarantined
    ) {
        return current;
    }
    if desired == DesiredInstanceState::Stopped {
        return InstanceStatus::Stopped;
    }
    // A lifecycle or data operation may have deliberately left the route
    // fenced after its session drain or rollback became uncertain. Reconcile
    // must not turn a healthy pool observation into permission to republish
    // that tenant; an explicit Start performs the credential checks needed to
    // reopen it safely.
    if route_fenced {
        return InstanceStatus::Failed;
    }
    if current == InstanceStatus::Running
        && runtime == EngineRuntimeStatus::Running
        && container == DockerContainerStatus::Running
    {
        return InstanceStatus::Running;
    }
    InstanceStatus::Failed
}
