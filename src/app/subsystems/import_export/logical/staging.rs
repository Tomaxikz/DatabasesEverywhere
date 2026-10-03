use super::{super::MAX_UNARCHIVED_BYTES, prepared_support::staging_reservation_bytes};
use crate::{
    instance::metadata::InstanceMetadata,
    routes::http::{response::ApiError, router::AppState},
    utils::protocol::Protocol,
};
use std::path::Path as FsPath;

const BYTES_PER_MIB: u64 = 1024 * 1024;

#[derive(Clone, Copy, Default)]
pub(super) struct LogicalStagingLimits {
    pub(super) remote_staged_limit: Option<u64>,
    pub(super) max_prepared_bytes: Option<u64>,
    pub(super) max_rollback_bytes: Option<u64>,
    pub(super) max_combined_bytes: Option<u64>,
}

impl LogicalStagingLimits {
    pub(super) fn remote(max_bytes: u64) -> Self {
        Self {
            remote_staged_limit: Some(max_bytes),
            max_combined_bytes: Some(max_bytes),
            ..Self::default()
        }
    }

    pub(super) fn upload(budget: UploadLogicalStagingBudget) -> Self {
        Self {
            max_prepared_bytes: Some(budget.prepared_bytes),
            max_rollback_bytes: Some(budget.rollback_bytes),
            max_combined_bytes: Some(budget.reservation_bytes),
            ..Self::default()
        }
    }
}

pub(in crate::subsystems::import_export) async fn check_remote_staging_space(
    paths: &[&FsPath],
    retained_bytes: u64,
    max_bytes: u64,
) -> Result<u64, ApiError> {
    let mut total = retained_bytes;
    if total > max_bytes {
        return Err(staging_limit_exceeded(max_bytes));
    }
    for path in paths {
        let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
            ApiError::Runtime(format!(
                "failed to inspect remote import staging data: {error}"
            ))
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(ApiError::Runtime(
                "remote import staging data is not a regular file".to_string(),
            ));
        }
        total = total.checked_add(metadata.len()).ok_or_else(|| {
            ApiError::BadRequest("remote import staging size overflowed".to_string())
        })?;
        if total > max_bytes {
            return Err(staging_limit_exceeded(max_bytes));
        }
    }
    Ok(total)
}

fn staging_limit_exceeded(max_bytes: u64) -> ApiError {
    ApiError::BadRequest(format!(
        "remote import source and rollback data exceed the configured {max_bytes}-byte staging limit; reduce the selected source or target data size"
    ))
}

#[derive(Debug, Clone, Copy)]
pub(in crate::subsystems::import_export) struct UploadLogicalStagingBudget {
    pub(in crate::subsystems::import_export) prepared_bytes: u64,
    pub(in crate::subsystems::import_export) rollback_bytes: u64,
    pub(in crate::subsystems::import_export) reservation_bytes: u64,
}

pub(in crate::subsystems::import_export) async fn upload_logical_staging_budget(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared_bytes: u64,
) -> Result<Option<UploadLogicalStagingBudget>, ApiError> {
    if metadata.protocol.engine().is_physical() {
        return Ok(None);
    }
    let prepared_bytes = prepared_bytes
        .max(1)
        .min(state.config.artifacts.import_upload_max_bytes)
        .min(MAX_UNARCHIVED_BYTES);
    let rollback_bytes = super::super::jobs::measure_export_bytes(state, metadata).await?;
    if rollback_bytes == 0 {
        return Err(ApiError::Conflict(
            "logical upload import requires a nonzero rollback staging budget".to_string(),
        ));
    }
    let reservation_bytes =
        staging_reservation_bytes(metadata.deployment_mode, prepared_bytes, rollback_bytes)?;
    Ok(Some(UploadLogicalStagingBudget {
        prepared_bytes,
        rollback_bytes,
        reservation_bytes,
    }))
}

pub(in crate::subsystems::import_export) fn upload_physical_staging_bytes(
    metadata: &InstanceMetadata,
) -> Result<Option<u64>, ApiError> {
    physical_staging_bytes(metadata.protocol, metadata.limits.disk_mib)
}

pub(in crate::subsystems::import_export) fn physical_staging_bytes(
    protocol: Protocol,
    disk_mib: u64,
) -> Result<Option<u64>, ApiError> {
    if !protocol.engine().is_physical() {
        return Ok(None);
    }
    let instance_disk_bytes = disk_mib
        .checked_mul(BYTES_PER_MIB)
        .ok_or_else(|| ApiError::Runtime("instance disk limit overflowed".to_string()))?;
    let bytes =
        instance_disk_bytes.min(crate::instance::jobs::import_export::MAX_DATA_ARCHIVE_BYTES);
    if bytes == 0 {
        return Err(ApiError::Conflict(
            "physical upload import requires a nonzero extraction budget".to_string(),
        ));
    }
    Ok(Some(bytes))
}
