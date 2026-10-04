use super::types::BackupIssue;
use crate::databases::protocol::Protocol;
use crate::routes::http::diagnostics::PublicDiagnostic;
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::server::backup::{BackupLayout, BackupStoreError};
use crate::server::jobs::import_export::{
    ImportExportJobPermit, JobAdmissionError, SchedulerAcquireError,
};
use crate::server::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus};
use crate::server::placement::DeploymentMode;
use crate::utils::ids::validate_instance_id;
use crate::utils::limits::mib_to_bytes;

pub(super) fn intentionally_stopped_backup(metadata: &InstanceMetadata) -> Option<BackupIssue> {
    // Classify only the reconciled, locked state. A failed/quarantined instance,
    // a runtime conflict, or an unexpected stop is a failure, not an exclusion.
    (metadata.status == InstanceStatus::Stopped
        && metadata.desired_state == DesiredInstanceState::Stopped)
        .then(|| BackupIssue {
            instance_id: metadata.instance_id.clone(),
            protocol: metadata.protocol,
            reason: PublicDiagnostic::public(
                "intentionally_stopped",
                "instance is intentionally stopped; backup requires the instance to be running",
            ),
        })
}

pub(super) fn check_backup_ready(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if metadata.status != InstanceStatus::Running {
        return Err(ApiError::BadRequest(format!(
            "instance is not running (status={:?})",
            metadata.status
        )));
    }
    Ok(())
}

pub(super) async fn require_instance(
    state: &AppState,
    instance_id: &str,
) -> Result<InstanceMetadata, ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)
}

pub(super) fn admit_backup(
    state: &AppState,
    instance_id: &str,
) -> Result<ImportExportJobPermit, ApiError> {
    state
        .import_export_jobs
        .try_admit_exclusive(instance_id)
        .map_err(|error| match error {
            JobAdmissionError::GlobalCapacity => ApiError::RateLimited,
            JobAdmissionError::InstanceCapacity => ApiError::Conflict(format!(
                "instance {instance_id} already has the maximum number of queued data operations"
            )),
            JobAdmissionError::ShuttingDown => {
                ApiError::ServiceUnavailable("the daemon is shutting down".to_string())
            }
        })
}

pub(super) fn scheduler_error(error: SchedulerAcquireError) -> ApiError {
    match error {
        SchedulerAcquireError::Closed => {
            ApiError::ServiceUnavailable("the daemon is shutting down".to_string())
        }
        SchedulerAcquireError::InsufficientCapacity => ApiError::Conflict(
            "the estimated backup operation exceeds a fixed dynamic import/export scheduler budget; increase the configured budget or reduce the instance allocation"
                .to_string(),
        ),
    }
}

pub(super) fn check_backup_service(state: &AppState) -> Result<(), ApiError> {
    if state.import_export_jobs.is_accepting() {
        Ok(())
    } else {
        Err(ApiError::ServiceUnavailable(
            "the daemon is shutting down".to_string(),
        ))
    }
}

pub(super) fn check_backup_protocol(
    backup_id: &str,
    backup_protocol: Protocol,
    target_protocol: Protocol,
) -> Result<(), ApiError> {
    if backup_protocol == target_protocol {
        Ok(())
    } else {
        Err(ApiError::Conflict(format!(
            "backup {backup_id} uses {}, but the target instance uses {}",
            backup_protocol.as_str(),
            target_protocol.as_str()
        )))
    }
}

pub(super) const fn backup_layout(mode: DeploymentMode) -> BackupLayout {
    match mode {
        DeploymentMode::Dedicated => BackupLayout::Physical,
        DeploymentMode::Shared => BackupLayout::Logical,
    }
}

pub(super) fn check_backup_layout(
    backup_id: &str,
    actual: BackupLayout,
    mode: DeploymentMode,
) -> Result<(), ApiError> {
    let expected = backup_layout(mode);
    if actual == expected {
        return Ok(());
    }
    Err(ApiError::Conflict(format!(
        "backup {backup_id} uses {actual:?} layout, but this tenant now requires {expected:?} layout"
    )))
}

pub(super) fn restore_input_bytes(layout: BackupLayout, stored_bytes: u64, disk_mib: u64) -> u64 {
    match layout {
        BackupLayout::Logical => stored_bytes.max(1),
        BackupLayout::Physical => stored_bytes.max(
            mib_to_bytes(disk_mib).min(crate::server::jobs::import_export::MAX_DATA_ARCHIVE_BYTES),
        ),
    }
}

pub(super) fn store_error(error: BackupStoreError) -> ApiError {
    match error {
        BackupStoreError::InvalidBackupId => ApiError::BadRequest("invalid backup id".to_string()),
        BackupStoreError::NotFound => ApiError::NotFound,
        error => ApiError::Runtime(error.to_string()),
    }
}
