use super::checks::{
    check_backup_layout, check_backup_protocol, check_backup_ready, check_backup_service,
    restore_input_bytes, scheduler_error, store_error,
};
use super::storage::backup_storage;
use super::types::RestoreBackupResponse;
use crate::routes::http::response::{ApiError, ApiResponse, ApiResult};
use crate::routes::http::router::AppState;
use crate::server::backup::{BackupLayout, prepare_private_dir};
use crate::server::jobs::import_export::{
    ImportExportJobPermit, JobEstimateInput, JobResourceCost,
};
use crate::server::metadata::InstanceStatus;
use crate::server::placement::DeploymentMode;
use crate::utils::limits::mib_to_bytes;
use std::path::Path as FsPath;
use std::path::PathBuf;
use std::sync::Arc;

pub(super) async fn restore_backup(
    state: AppState,
    instance_id: String,
    backup_id: String,
    reason: String,
    _admission: ImportExportJobPermit,
) -> ApiResult<RestoreBackupResponse> {
    let _operation = state.instance_locks.lock(&instance_id).await;
    check_backup_service(&state)?;
    let mut metadata =
        crate::subsystems::instances::reconcile_instance_locked(&state, &instance_id).await?;
    let storage = backup_storage(&state)?;
    let stored = storage
        .find(&instance_id, &backup_id)
        .await
        .map_err(store_error)?;
    check_backup_protocol(&stored.backup_id, stored.protocol, metadata.protocol)?;
    check_backup_layout(&stored.backup_id, stored.layout, metadata.deployment_mode)?;
    let logical_rollback_bytes = if stored.layout == BackupLayout::Logical {
        Some(crate::subsystems::import_export::jobs::measure_export_bytes(&state, &metadata).await?)
    } else {
        None
    };
    // Physical archives may expand to the complete instance allocation, but a
    // tenant-logical backup is already a bounded database dump. Charging a
    // shared restore for the tenant's full disk allocation makes a tiny dump
    // impossible to restore into a generously sized tenant.
    let restore_size_bytes =
        restore_input_bytes(stored.layout, stored.size_bytes, metadata.limits.disk_mib);
    let _execution = state
        .import_export_jobs
        .acquire_execution(JobResourceCost::estimate(JobEstimateInput {
            protocol: metadata.protocol,
            input_size_bytes: restore_size_bytes.max(1),
            rollback_size_bytes: logical_rollback_bytes.unwrap_or(0),
            wipe: true,
            compressed: true,
            export: false,
        }))
        .await
        .map_err(scheduler_error)?;
    let _runtime_operation = if metadata.deployment_mode == DeploymentMode::Shared {
        Some(state.instance_locks.lock(metadata.runtime_id()).await)
    } else {
        None
    };
    if metadata.deployment_mode == DeploymentMode::Shared {
        metadata =
            crate::subsystems::instances::reload_after_runtime_lock(&state, &metadata).await?;
        check_backup_ready(&metadata)?;
        if metadata.disk_limit_blocked {
            return Err(ApiError::Conflict(
                "shared tenant writes are blocked by its disk limit; restore cannot continue"
                    .to_string(),
            ));
        }
    }
    let extracted_capacity = mib_to_bytes(metadata.limits.disk_mib).clamp(
        1,
        crate::server::jobs::import_export::MAX_DATA_ARCHIVE_BYTES,
    );
    let physical_paths = if stored.layout == BackupLayout::Physical {
        let paths = crate::server::paths::InstancePaths::new(&state.config.paths, &instance_id)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        crate::subsystems::import_export::check_restore_layout(&state, &metadata, &paths)?;
        Some(paths)
    } else {
        None
    };
    let _extracted_capacity = if let Some(paths) = physical_paths.as_ref() {
        let data_parent = paths.data.parent().ok_or_else(|| {
            ApiError::Runtime("backup restore data directory has no parent".to_string())
        })?;
        Some(
            state
                .import_uploads
                .reserve_output_capacity(data_parent, extracted_capacity)
                .await?,
        )
    } else {
        None
    };
    let _logical_staging_capacity = if let Some(rollback_bytes) = logical_rollback_bytes {
        let staging_root = crate::subsystems::import_export::logical_staging_root(&state).await?;
        let staging_bytes =
            crate::subsystems::import_export::logical::shared_restore_staging_bytes(
                stored.size_bytes.max(1),
                rollback_bytes,
            )?;
        Some(
            state
                .import_uploads
                .reserve_output_capacity(&staging_root, staging_bytes)
                .await?,
        )
    } else {
        None
    };
    let temporary_capacity = if storage.kind() == crate::config::BackupStorageDriver::Local {
        None
    } else {
        let temporary_root = PathBuf::from(state.config.paths.tmp_root());
        prepare_private_dir(&temporary_root, "backup materialization directory")
            .await
            .map_err(store_error)?;
        Some(
            state
                .import_uploads
                .reserve_output_capacity(&temporary_root, stored.size_bytes.max(1))
                .await?,
        )
    };
    let materialized = storage
        .materialize(
            &instance_id,
            &backup_id,
            FsPath::new(&state.config.paths.tmp_root()),
            temporary_capacity,
            Arc::clone(&state.config.budgets.backup_materializations),
        )
        .await
        .map_err(store_error)?;
    let finished = match stored.layout {
        BackupLayout::Physical => {
            let paths = physical_paths.ok_or_else(|| {
                ApiError::Runtime("physical backup restore paths were unavailable".to_string())
            })?;
            let was_running = metadata.status == InstanceStatus::Running;
            if was_running
                && let Err(error) = crate::subsystems::instances::change_instance_state_locked(
                    &state,
                    &instance_id,
                    crate::subsystems::instances::LifecycleAction::Stop,
                )
                .await
            {
                drop(materialized);
                return Err(error);
            }
            crate::subsystems::import_export::restore_bounded_archive(
                &state,
                &instance_id,
                paths,
                &materialized.path,
                was_running,
                extracted_capacity,
            )
            .await
        }
        BackupLayout::Logical => {
            crate::subsystems::import_export::logical::restore_shared_backup(
                &state,
                &metadata,
                &materialized.path,
                stored.size_bytes.max(1),
                logical_rollback_bytes.ok_or_else(|| {
                    ApiError::Runtime(
                        "logical backup rollback capacity was not reserved".to_string(),
                    )
                })?,
            )
            .await
        }
    };
    drop(materialized);
    finished?;
    tracing::info!(
        event = "audit backup_restored",
        instance_id,
        backup_id,
        reason,
        storage = storage.kind().as_str(),
    );
    Ok(ApiResponse::ok(RestoreBackupResponse {
        instance_id,
        backup_id,
        restored: true,
    }))
}
