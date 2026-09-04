use std::future::Future;

use tokio::sync::OwnedMutexGuard;

use super::{
    export::{measure_export_bytes, write_reserved_export},
    supervision::{block_uncertain_upload, update_job_result},
    *,
};

pub(super) async fn run_export_job_locked(
    state: AppState,
    job_id: String,
    metadata: InstanceMetadata,
    artifact_path: PathBuf,
    options: ExportOptions,
    logical_output_capacity: Option<u64>,
) {
    let result =
        match lock_job_target(&state, &metadata.instance_id, ImportExportAction::Export).await {
            Ok((metadata, _runtime_operation)) => {
                write_reserved_export(
                    &state,
                    &metadata,
                    artifact_path.clone(),
                    &options,
                    logical_output_capacity,
                )
                .await
            }
            Err(error) => Err(error),
        };
    if !update_job_result(&state, &job_id, result, Some(artifact_path)).await {
        tracing::error!(%job_id, "export completed but its terminal status remained uncertain during shutdown; startup recovery will reconcile it");
    }
}

pub(super) async fn run_import_job_locked(
    state: AppState,
    job_id: String,
    instance_id: String,
    options: ImportOptions,
) {
    let upload_id = match &options.source {
        ImportSourceOptions::Upload { upload_id, .. } => Some(upload_id.clone()),
        _ => None,
    };
    let artifact_path = match &options.source {
        ImportSourceOptions::Artifact(path) => Some(path.clone()),
        ImportSourceOptions::Upload { .. } => None,
        ImportSourceOptions::Remote(_) => None,
        ImportSourceOptions::RemoteRequest(_) => {
            tracing::error!(%job_id, "validated import job retained an unresolved remote source");
            let persisted = update_job_result(
                &state,
                &job_id,
                Err(ApiError::Runtime(
                    "remote import source was not validated".to_string(),
                )),
                None,
            )
            .await;
            if !persisted
                && let Err(quarantine_error) =
                    quarantine_uncertain_import(&state, &instance_id).await
            {
                tracing::error!(%job_id, %instance_id, %quarantine_error, "failed to quarantine a target after unresolved import status became uncertain");
            }
            return;
        }
    };
    let result = match lock_job_target(&state, &instance_id, ImportExportAction::Import).await {
        Ok((_metadata, _runtime_operation)) => {
            import_instance_source(&state, &instance_id, &options).await
        }
        Err(error) => Err(error),
    };
    let succeeded = result.is_ok();
    let failure = result
        .as_ref()
        .err()
        .map(|error| PublicDiagnostic::from_api_error("import operation", error).message);
    let terminal_status_persisted = update_job_result(&state, &job_id, result, artifact_path).await;
    if !terminal_status_persisted {
        tracing::error!(
            %job_id,
            instance_id,
            "import outcome is uncertain because the terminal job status is not durable"
        );
        if let Some(upload_id) = upload_id.as_deref() {
            block_uncertain_upload(
                &state,
                &instance_id,
                upload_id,
                &job_id,
                "import outcome could not be recorded durably; the upload is blocked and the target was quarantined",
            )
            .await;
        }
        if let Err(error) = quarantine_uncertain_import(&state, &instance_id).await {
            tracing::error!(%job_id, instance_id, %error, "failed to fully quarantine an import with uncertain terminal job persistence");
        }
        return;
    }
    if let Some(upload_id) = upload_id.as_deref() {
        super::uploads::finish_upload_import_job(
            &state,
            &instance_id,
            upload_id,
            &job_id,
            succeeded,
            failure.as_deref(),
        )
        .await;
    }
}

async fn lock_job_target(
    state: &AppState,
    instance_id: &str,
    action: ImportExportAction,
) -> Result<(InstanceMetadata, Option<OwnedMutexGuard<()>>), ApiError> {
    let (snapshot, runtime_operation) = reconcile_then_lock_runtime(
        &state.instance_locks,
        crate::api::instances::reconcile_instance_locked(state, instance_id),
    )
    .await?;
    let current = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    if !same_job_target(&snapshot, &current) {
        return Err(ApiError::Conflict(
            "instance placement changed while the import/export job was waiting for its runtime"
                .to_string(),
        ));
    }
    check_logical_ready(&current)?;
    if action == ImportExportAction::Import && current.disk_limit_blocked {
        return Err(ApiError::Conflict(
            "instance is blocked by its disk limit; free space or increase the tenant limit before importing"
                .to_string(),
        ));
    }
    Ok((current, runtime_operation))
}

async fn reconcile_then_lock_runtime<F>(
    locks: &crate::instances::locks::InstanceLocks,
    reconcile: F,
) -> Result<(InstanceMetadata, Option<OwnedMutexGuard<()>>), ApiError>
where
    F: Future<Output = Result<InstanceMetadata, ApiError>>,
{
    // Shared reconciliation briefly owns the pool lock. Await it before taking
    // the long-lived job lock or the same non-reentrant mutex deadlocks.
    let metadata = reconcile.await?;
    let runtime_operation = if metadata.deployment_mode == DeploymentMode::Shared {
        Some(locks.lock(metadata.runtime_id()).await)
    } else {
        None
    };
    Ok((metadata, runtime_operation))
}

fn same_job_target(snapshot: &InstanceMetadata, current: &InstanceMetadata) -> bool {
    snapshot.instance_id == current.instance_id
        && snapshot.created_at == current.created_at
        && snapshot.deployment_mode == current.deployment_mode
        && snapshot.runtime_id() == current.runtime_id()
        && snapshot.protocol == current.protocol
        && snapshot.database.name == current.database.name
        && snapshot.database.username == current.database.username
}

pub(super) async fn acquire_upload_staging(
    state: &AppState,
    instance_id: &str,
    options: &ImportOptions,
) -> Result<Option<super::uploads::ImportStagingPermit>, ApiError> {
    if let Some(staging) = options.upload_staging.as_ref() {
        return match staging {
            UploadStagingBudget::Logical { budget, .. } => {
                let root = logical_staging_root(state).await?;
                state
                    .import_uploads
                    .acquire_staging(&root, budget.reservation_bytes)
                    .await
                    .map(Some)
            }
            UploadStagingBudget::Physical {
                extracted_bytes, ..
            } => {
                let paths = InstancePaths::new(&state.config.paths, instance_id)
                    .map_err(|error| ApiError::BadRequest(error.to_string()))?;
                let data_parent = paths.data.parent().ok_or_else(|| {
                    ApiError::Runtime("physical import data directory has no parent".to_string())
                })?;
                state
                    .import_uploads
                    .acquire_staging_on_existing_root(data_parent, *extracted_bytes)
                    .await
                    .map(Some)
            }
        };
    }

    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    if !protocol_uses_logical_dumps(metadata.protocol) {
        return match &options.source {
            ImportSourceOptions::Remote(_) => {
                let root = PathBuf::from(state.config.paths.tmp_root());
                state
                    .import_uploads
                    .acquire_staging(
                        &root,
                        state.config.security.remote_import.max_staged_bytes.max(1),
                    )
                    .await
                    .map(Some)
            }
            ImportSourceOptions::Artifact(_) => {
                let paths = InstancePaths::new(&state.config.paths, instance_id)
                    .map_err(|error| ApiError::BadRequest(error.to_string()))?;
                let data_parent = paths.data.parent().ok_or_else(|| {
                    ApiError::Runtime("physical import data directory has no parent".to_string())
                })?;
                let extracted = mib_to_bytes(metadata.limits.disk_mib)
                    .clamp(1, crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES);
                state
                    .import_uploads
                    .acquire_staging_on_existing_root(data_parent, extracted)
                    .await
                    .map(Some)
            }
            ImportSourceOptions::Upload { .. } => Err(ApiError::Runtime(
                "physical upload import is missing its validated staging budget".to_string(),
            )),
            ImportSourceOptions::RemoteRequest(_) => Err(ApiError::Runtime(
                "remote import source was not validated".to_string(),
            )),
        };
    }
    let requested = match &options.source {
        ImportSourceOptions::Artifact(path) => {
            let prepared = if is_compressed_import(metadata.protocol, options) {
                MAX_UNARCHIVED_BYTES
            } else {
                tokio::fs::metadata(path)
                    .await
                    .ok()
                    .filter(|value| value.is_file())
                    .map(|value| value.len().min(MAX_UNARCHIVED_BYTES))
                    .unwrap_or(MAX_UNARCHIVED_BYTES)
            };
            let rollback = measure_export_bytes(state, &metadata).await?;
            super::logical::prepared_support::staging_reservation_bytes(
                metadata.deployment_mode,
                prepared,
                rollback,
            )?
        }
        ImportSourceOptions::Remote(_) => import_staging_bytes(
            metadata.protocol,
            state.config.security.remote_import.max_staged_bytes,
        )?,
        ImportSourceOptions::Upload { .. } => {
            return Err(ApiError::Runtime(
                "upload import is missing its validated staging budget".to_string(),
            ));
        }
        ImportSourceOptions::RemoteRequest(_) => {
            return Err(ApiError::Runtime(
                "remote import source was not validated".to_string(),
            ));
        }
    };
    let root = logical_staging_root(state).await?;
    state
        .import_uploads
        .acquire_staging(&root, requested.max(1))
        .await
        .map(Some)
}

pub(in crate::api::import_export) fn import_staging_bytes(
    protocol: Protocol,
    max_staged_bytes: u64,
) -> Result<u64, ApiError> {
    let copies = u64::from(protocol_uses_logical_dumps(protocol)) + 1;
    max_staged_bytes.max(1).checked_mul(copies).ok_or_else(|| {
        ApiError::Conflict("remote import staging reservation overflowed".to_string())
    })
}

pub(in crate::api::import_export) fn is_compressed_import(
    protocol: Protocol,
    options: &ImportOptions,
) -> bool {
    protocol_uses_native_compression(protocol)
        || options.archive_format.is_some()
        || match &options.source {
            ImportSourceOptions::Artifact(path) | ImportSourceOptions::Upload { path, .. } => path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    let name = name.to_ascii_lowercase();
                    name.ends_with(".gz") || name.ends_with(".bz2") || name.ends_with(".zip")
                }),
            ImportSourceOptions::Remote(_) | ImportSourceOptions::RemoteRequest(_) => false,
        }
}

pub(super) async fn estimate_import_cost(
    state: &AppState,
    metadata: &InstanceMetadata,
    options: &ImportOptions,
) -> JobResourceCost {
    let upload_limit = state.config.artifacts.import_upload_max_bytes;
    let remote_limit = state.config.security.remote_import.max_staged_bytes;
    let source_bytes = match &options.source {
        ImportSourceOptions::Artifact(path) | ImportSourceOptions::Upload { path, .. } => {
            tokio::fs::metadata(path)
                .await
                .ok()
                .filter(|metadata| metadata.is_file())
                .map(|metadata| metadata.len())
                .unwrap_or(upload_limit)
        }
        ImportSourceOptions::Remote(_) | ImportSourceOptions::RemoteRequest(_) => remote_limit,
    };
    let compressed = is_compressed_import(metadata.protocol, options);
    let prepared_ceiling = prepared_import_bytes(options, upload_limit, remote_limit, compressed);
    // A compressed dump has no trustworthy expansion ratio until bounded
    // extraction completes. Charge the configured prepared-data ceiling so a
    // tiny gzip bomb cannot evade resource scheduling.
    let estimated_expanded_bytes = conservative_import_input_bytes(
        metadata.protocol,
        source_bytes,
        prepared_ceiling,
        metadata.limits.disk_mib,
        compressed,
    );
    let rollback_size_bytes = if protocol_uses_logical_dumps(metadata.protocol) {
        if metadata.deployment_mode == DeploymentMode::Shared {
            measure_export_bytes(state, metadata)
                .await
                .unwrap_or_else(|_| estimate_rollback_bytes(metadata))
        } else {
            estimate_rollback_bytes(metadata)
        }
    } else {
        0
    };
    JobResourceCost::estimate(JobEstimateInput {
        protocol: metadata.protocol,
        input_size_bytes: estimated_expanded_bytes.max(1),
        rollback_size_bytes,
        wipe: options.mode == ImportMode::Wipe || rollback_size_bytes != 0,
        compressed,
        export: false,
    })
}

pub(in crate::api::import_export) fn prepared_import_bytes(
    options: &ImportOptions,
    upload_limit: u64,
    remote_limit: u64,
    compressed: bool,
) -> u64 {
    match &options.source {
        ImportSourceOptions::Artifact(_) => MAX_UNARCHIVED_BYTES,
        ImportSourceOptions::Upload { .. } => {
            let validated = match options.upload_staging.as_ref() {
                Some(UploadStagingBudget::Logical { budget, .. }) => budget.prepared_bytes,
                Some(UploadStagingBudget::Physical { .. }) | None => upload_limit,
            };
            if compressed {
                validated.max(upload_limit.min(MAX_UNARCHIVED_BYTES))
            } else {
                validated
            }
        }
        ImportSourceOptions::Remote(_) | ImportSourceOptions::RemoteRequest(_) => remote_limit,
    }
    .max(1)
}

fn estimate_rollback_bytes(metadata: &InstanceMetadata) -> u64 {
    mib_to_bytes(metadata.limits.disk_mib).clamp(1, MAX_UNARCHIVED_BYTES)
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    use crate::instances::test_support::shared_metadata;

    #[tokio::test]
    async fn shared_job_locks_runtime_only_after_reconcile_releases_it() {
        let locks = crate::instances::locks::InstanceLocks::default();
        let _tenant_operation = locks.lock("tenant-a").await;
        let reconcile_locks = locks.clone();
        let metadata = shared_metadata();

        let (_, runtime_operation) = tokio::time::timeout(
            Duration::from_secs(1),
            reconcile_then_lock_runtime(&locks, async move {
                let transient_reconcile_lock = reconcile_locks.lock("pool-a").await;
                drop(transient_reconcile_lock);
                Ok(metadata)
            }),
        )
        .await
        .expect("job lock order must not deadlock shared reconciliation")
        .unwrap();

        assert!(runtime_operation.is_some());
    }

    #[test]
    fn job_target_identity_rejects_pool_or_tenant_replacement() {
        let snapshot = shared_metadata();
        let mut current = snapshot.clone();
        assert!(same_job_target(&snapshot, &current));
        current.runtime_id = "pool-b".to_string();
        assert!(!same_job_target(&snapshot, &current));
        current = snapshot.clone();
        current.database.name = "other_db".to_string();
        assert!(!same_job_target(&snapshot, &current));
    }
}
