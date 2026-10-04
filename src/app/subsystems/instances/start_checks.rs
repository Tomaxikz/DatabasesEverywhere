use super::docker_error;
use super::lifecycle::LifecycleAction;
use crate::databases::protocol::Protocol;
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::runtime::docker::DockerError;
use crate::server::disk::DiskLimiter;
use crate::server::metadata::{InstanceMetadata, InstanceStatus};
use crate::server::paths::InstancePaths;
use crate::utils::limits::mib_to_bytes;
use crate::utils::time::now_rfc3339;

pub(super) fn starts_runtime(action: LifecycleAction) -> bool {
    matches!(action, LifecycleAction::Start | LifecycleAction::Restart)
}

pub(super) fn reject_quarantined_start(
    metadata: &InstanceMetadata,
    action: LifecycleAction,
) -> Result<(), ApiError> {
    if metadata.status == InstanceStatus::Quarantined && starts_runtime(action) {
        return Err(ApiError::Conflict(
            "instance is quarantined for fail-closed safety; inspect job history and logs, then repair, recover, or delete it before attempting to start it"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) fn persisted_disk_limiter(state: &AppState, metadata: &InstanceMetadata) -> DiskLimiter {
    DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
        .for_persisted_protocol(metadata.protocol, &metadata.limits.disk_enforcement_method)
}

pub(super) fn soft_scanner_required(state: &AppState, metadata: &InstanceMetadata) -> bool {
    crate::server::disk::soft::SoftDiskLimiter::enforcement_required(
        state.config.disk.mode,
        metadata.protocol,
    ) || (metadata.protocol == Protocol::Qdrant
        && metadata.limits.disk_enforcement_method == "fuse_quota")
}

pub(super) async fn precheck_dedicated_start(
    state: &AppState,
    metadata: &mut InstanceMetadata,
) -> Result<bool, ApiError> {
    let disk_limiter = persisted_disk_limiter(state, metadata);
    disk_limiter
        .check_method_change(&metadata.limits.disk_enforcement_method)
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    check_disk_method(&disk_limiter, metadata)?;
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let expected_data_source = disk_limiter
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
            return Err(ApiError::Conflict(format!(
                "{error}; repair/recreate the managed container before starting it"
            )));
        }
        Err(error) => return Err(docker_error(error)),
    }
    if !soft_scanner_required(state, metadata) {
        return Ok(false);
    }
    let snapshot = state
        .soft_disk_limiter
        .ensure_start_allowed(&crate::server::disk::soft::SoftDiskTarget {
            instance_id: metadata.instance_id.clone(),
            created_at: metadata.created_at.clone(),
            protocol: metadata.protocol,
            data_path: paths.data,
            limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
            durable_blocked: metadata.disk_limit_blocked,
        })
        .await
        .map_err(ApiError::Conflict)?;
    if metadata.disk_limit_blocked && !snapshot.blocked {
        metadata.disk_limit_blocked = false;
        metadata.updated_at = now_rfc3339();
        return Ok(true);
    }
    Ok(false)
}

pub(super) fn check_disk_method(
    limiter: &DiskLimiter,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    if crate::config::DiskLimitMode::from_persisted_method(&metadata.limits.disk_enforcement_method)
        == Some(limiter.mode())
    {
        return Ok(());
    }
    Err(ApiError::Conflict(format!(
        "instance currently uses {} disk enforcement but this node selects {}; restart dbev to reconcile or safely recreate/migrate it before activation",
        metadata.limits.disk_enforcement_method,
        limiter.mode().method(),
    )))
}
