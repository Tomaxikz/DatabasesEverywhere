use super::*;

pub(super) fn check_power_state(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if metadata.status == InstanceStatus::Quarantined {
        return Err(ApiError::Conflict(
            "quarantined shared tenants cannot change power state; repair or delete the tenant first"
                .to_string(),
        ));
    }
    if metadata.status == InstanceStatus::Deleting {
        return Err(ApiError::Conflict(
            "deleting shared tenants cannot change power state; retry or finish deletion first"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) fn route_was_open(metadata: &InstanceMetadata, route_fenced: bool) -> bool {
    metadata.status == InstanceStatus::Running
        && metadata.desired_state == DesiredInstanceState::Running
        && !metadata.disk_limit_blocked
        && !route_fenced
}

pub(super) fn same_shared_identity(
    snapshot: &InstanceMetadata,
    current: &InstanceMetadata,
) -> bool {
    current.created_at == snapshot.created_at
        && current.deployment_mode == DeploymentMode::Shared
        && current.runtime_id() == snapshot.runtime_id()
        && current.protocol == snapshot.protocol
        && current.database.name == snapshot.database.name
        && current.database.username == snapshot.database.username
}

pub(super) fn target(metadata: &InstanceMetadata) -> TenantTarget<'_> {
    TenantTarget {
        database: &metadata.database.name,
        username: &metadata.database.username,
    }
}

pub(super) fn placement_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::Runtime(format!("shared runtime storage failed: {error}"))
}

pub(super) fn limits_match(left: &InstanceLimits, right: &InstanceLimits) -> bool {
    left.cpu_cores.to_bits() == right.cpu_cores.to_bits()
        && left.memory_mib == right.memory_mib
        && left.disk_mib == right.disk_mib
        && left.disk_enforced == right.disk_enforced
        && left.disk_enforcement_method == right.disk_enforcement_method
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SharedLifecycleError {
    #[error("the shared tenant credential is unavailable while opening its route")]
    MissingCredential,
    #[error("shared tenant uses {used_bytes} bytes against a {limit_bytes}-byte soft limit")]
    SoftDiskLimit { used_bytes: u64, limit_bytes: u64 },
    #[error("shared tenant storage measurement failed: {0}")]
    StorageUsage(String),
    #[error("shared tenant quota metadata could not be persisted: {0}")]
    Persistence(String),
    #[error("shared runtime root disk quota could not be reconciled: {0}")]
    RootDisk(String),
    #[error(transparent)]
    TenantDisk(#[from] tenant::disk::TenantDiskError),
    #[error(transparent)]
    Tenant(#[from] tenant::TenantEngineError),
    #[error(transparent)]
    Docker(#[from] crate::runtime::docker::DockerError),
}

impl SharedLifecycleError {
    pub(super) fn is_disk_conflict(&self) -> bool {
        matches!(self, Self::SoftDiskLimit { .. })
    }
}
