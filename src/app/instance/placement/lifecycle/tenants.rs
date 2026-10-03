use super::*;

pub(super) async fn runtime_tenants(
    placements: &PlacementRepository,
    manager: &InstanceManager,
    runtime_id: &str,
) -> HashMap<String, Option<TenantReservationState>> {
    let mut tenants = store_tenants(manager, runtime_id)
        .await
        .into_iter()
        .map(|instance_id| (instance_id, None))
        .collect::<HashMap<_, _>>();
    match placements.reservations(runtime_id).await {
        Ok(reservations) => {
            for reservation in reservations {
                tenants.insert(reservation.instance_id, Some(reservation.state));
            }
        }
        Err(error) => tracing::error!(
            event = "audit shared_runtime_tenant_lookup_failed",
            runtime_id,
            %error,
            "used the loaded tenant metadata to preserve fail-closed pool state propagation"
        ),
    }
    tenants
}

pub(super) fn report_missing_tenant(
    runtime_id: &str,
    instance_id: &str,
    reservation_state: Option<TenantReservationState>,
) {
    match reservation_state {
        Some(TenantReservationState::Reserved) => {}
        Some(TenantReservationState::Provisioned) => tracing::error!(
            event = "audit shared_runtime_missing_tenant_metadata",
            runtime_id,
            instance_id,
            "a provisioned shared tenant is missing its instance metadata"
        ),
        None => tracing::warn!(
            event = "audit shared_runtime_stale_loaded_tenant",
            runtime_id,
            instance_id,
            "loaded shared tenant metadata disappeared before pool state propagation"
        ),
    }
}

pub(super) async fn store_tenants(manager: &InstanceManager, runtime_id: &str) -> Vec<String> {
    manager
        .store()
        .list()
        .await
        .into_iter()
        .filter(|metadata| {
            metadata.deployment_mode == DeploymentMode::Shared
                && metadata.runtime_id() == runtime_id
        })
        .map(|metadata| metadata.instance_id)
        .collect()
}

pub(super) fn classify_runtime_status(status: DockerContainerStatus) -> EngineRuntimeStatus {
    match status {
        DockerContainerStatus::Running => EngineRuntimeStatus::Running,
        DockerContainerStatus::Created | DockerContainerStatus::Stopped => {
            EngineRuntimeStatus::Stopped
        }
        DockerContainerStatus::Starting => EngineRuntimeStatus::Booting,
        DockerContainerStatus::Failed => EngineRuntimeStatus::Failed,
    }
}

pub(super) fn tenant_status(
    runtime: EngineRuntimeStatus,
    desired: DesiredInstanceState,
    current: InstanceStatus,
) -> InstanceStatus {
    if matches!(
        current,
        InstanceStatus::Deleting | InstanceStatus::Quarantined
    ) {
        return current;
    }
    if runtime == EngineRuntimeStatus::Quarantined {
        return InstanceStatus::Quarantined;
    }
    if desired == DesiredInstanceState::Stopped {
        return InstanceStatus::Stopped;
    }
    match runtime {
        EngineRuntimeStatus::Creating => InstanceStatus::Creating,
        EngineRuntimeStatus::Booting => InstanceStatus::Booting,
        EngineRuntimeStatus::Running => InstanceStatus::Running,
        EngineRuntimeStatus::Stopped => InstanceStatus::Stopped,
        EngineRuntimeStatus::Failed | EngineRuntimeStatus::Deleting => InstanceStatus::Failed,
        EngineRuntimeStatus::Quarantined => InstanceStatus::Quarantined,
    }
}
