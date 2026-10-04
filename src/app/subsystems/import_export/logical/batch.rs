use std::{path::Path as FsPath, time::Duration};

use crate::{
    routes::http::{response::ApiError, router::AppState},
    server::{metadata::InstanceMetadata, placement::DeploymentMode},
};

use super::{
    super::{
        ExportOptions, ImportOptions, ImportSourceOptions,
        files::{cleanup_path, dump_extension, logical_staging_root},
        remote::ImportMode,
    },
    dump::{
        LogicalExportControls, LogicalImportControls, export_logical_dump, import_logical_dump,
        prepare_logical_import,
    },
    prepared_support::{
        LogicalApplyError, PreparedLogicalImport, apply_prepared_logical_import,
        apply_prepared_logical_imports, cleanup_prepared_logical_imports,
    },
    sources::logical_apply_options,
    staging::{LogicalStagingLimits, check_remote_staging_space},
    target::{
        check_shared_rollback_objects, commit_recovery_manifest, fail_quiesced_setup,
        fence_import_target, quarantine_suffix, quarantine_uncertain_import,
        restore_import_target_route, write_logical_recovery_manifest,
    },
};

pub(super) async fn import_logical_batch(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_paths: &[&FsPath],
    options: &ImportOptions,
    source_database: Option<&str>,
    staging: LogicalStagingLimits,
) -> Result<(), ApiError> {
    if artifact_paths.is_empty() {
        return Err(ApiError::Runtime(
            "logical import did not contain any artifacts".to_string(),
        ));
    }
    let remote_exec_timeout = staging.remote_staged_limit.map(|_| {
        Duration::from_secs(
            state
                .config
                .security
                .remote_import
                .operation_timeout_seconds,
        )
    });
    let apply_options = logical_apply_options(options, staging.remote_staged_limit.is_some());
    let controls = LogicalImportControls {
        source_database,
        reuse_staged_artifact: staging.remote_staged_limit.is_some(),
        exec_timeout: remote_exec_timeout,
        remove_uploaded_source_limit: staging.remote_staged_limit,
        max_prepared_bytes: staging.max_prepared_bytes,
        ..LogicalImportControls::default()
    };
    let mut prepared = Vec::with_capacity(artifact_paths.len());
    for artifact_path in artifact_paths {
        match prepare_logical_import(
            state,
            metadata,
            metadata.protocol,
            artifact_path,
            &apply_options,
            controls,
        )
        .await
        {
            Ok(artifact) => prepared.push(artifact),
            Err(error) => {
                cleanup_prepared_logical_imports(state, metadata, &prepared).await;
                return Err(error);
            }
        }
    }
    let (retained_source_bytes, rollback_limit) = match rollback_staging_budget(staging, &prepared)
    {
        Ok(budget) => budget,
        Err(error) => {
            cleanup_prepared_logical_imports(state, metadata, &prepared).await;
            return Err(error);
        }
    };

    if let Err(error) = fence_import_target(state, metadata, remote_exec_timeout).await {
        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
        let quarantine = quarantine_uncertain_import(state, &metadata.instance_id).await;
        return Err(ApiError::Runtime(format!(
            "failed to quiesce the logical import target before taking its rollback snapshot: {error}; target was failed closed{}",
            quarantine_suffix(&quarantine)
        )));
    }
    if let Err(error) = check_shared_rollback_objects(state, metadata).await {
        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
        return Err(fail_quiesced_setup(state, metadata, error).await);
    }

    let rollback_root = match logical_staging_root(state).await {
        Ok(root) => root,
        Err(error) => {
            cleanup_prepared_logical_imports(state, metadata, &prepared).await;
            return Err(fail_quiesced_setup(state, metadata, error).await);
        }
    };
    let recovery_id = uuid::Uuid::new_v4();
    let rollback_path = rollback_root.join(format!(
        ".dbe-import-rollback-{recovery_id}.{}",
        dump_extension(metadata.protocol)
    ));
    let recovery_manifest = rollback_root.join(format!(".dbe-import-recovery-{recovery_id}.json"));
    let rollback_has_database_definition = metadata.deployment_mode == DeploymentMode::Dedicated;
    let export_options = ExportOptions::default();
    if let Err(error) = export_logical_dump(
        state,
        metadata,
        metadata.protocol,
        rollback_path.clone(),
        &export_options,
        LogicalExportControls {
            max_output_bytes: rollback_limit,
            exec_timeout: remote_exec_timeout,
            include_database_definition: rollback_has_database_definition,
        },
    )
    .await
    {
        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
        cleanup_path(&rollback_path).await;
        return Err(fail_quiesced_setup(state, metadata, error).await);
    }
    let rollback_options = ImportOptions {
        source: ImportSourceOptions::Artifact(rollback_path.clone()),
        mode: ImportMode::Wipe,
        ..ImportOptions::default()
    };
    // Prove the exact rollback is accepted before the primary helper can mutate.
    let prepared_rollback = if metadata.deployment_mode == DeploymentMode::Shared {
        match prepare_logical_import(
            state,
            metadata,
            metadata.protocol,
            &rollback_path,
            &rollback_options,
            LogicalImportControls {
                reuse_staged_artifact: true,
                database_definition_in_dump: false,
                exec_timeout: remote_exec_timeout,
                ..LogicalImportControls::default()
            },
        )
        .await
        {
            Ok(prepared) => Some(prepared),
            Err(error) => {
                cleanup_prepared_logical_imports(state, metadata, &prepared).await;
                cleanup_path(&rollback_path).await;
                let conflict = ApiError::Conflict(format!(
                    "shared {} import was refused before mutation because the current tenant contains objects its rollback policy cannot safely replay: {error}",
                    metadata.protocol.as_str()
                ));
                return Err(fail_quiesced_setup(state, metadata, conflict).await);
            }
        }
    } else {
        None
    };
    if let Some(limit) = staging.max_combined_bytes
        && let Err(error) =
            check_remote_staging_space(&[&rollback_path], retained_source_bytes, limit).await
    {
        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
        cleanup_path(&rollback_path).await;
        return Err(fail_quiesced_setup(state, metadata, error).await);
    }
    if let Err(error) =
        write_logical_recovery_manifest(&recovery_manifest, metadata, &rollback_path, options.mode)
            .await
    {
        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
        cleanup_path(&rollback_path).await;
        return Err(fail_quiesced_setup(state, metadata, error).await);
    }

    let primary =
        apply_prepared_logical_imports(state, metadata, &prepared, apply_options.mode).await;
    cleanup_prepared_logical_imports(state, metadata, &prepared).await;
    let primary = match primary {
        Ok(()) => {
            return commit_logical_import(state, metadata, &recovery_manifest, &rollback_path)
                .await;
        }
        Err(primary) => primary,
    };
    if primary.helper_uncertain() {
        let quarantine = quarantine_uncertain_import(state, &metadata.instance_id).await;
        return Err(ApiError::Runtime(format!(
            "{} import failed after restore-command cleanup became uncertain: {primary}; rollback was not attempted because it could race the previous command; target was failed closed{}; rollback dump retained at {} with recovery manifest {}",
            metadata.protocol.as_str(),
            quarantine_suffix(&quarantine),
            rollback_path.display(),
            recovery_manifest.display()
        )));
    }
    if let Err(fence_error) = fence_import_target(state, metadata, remote_exec_timeout).await {
        let quarantine = quarantine_uncertain_import(state, &metadata.instance_id).await;
        return Err(ApiError::Runtime(format!(
            "{} import failed: {primary}; the target process could not be generation-fenced before rollback: {fence_error}; rollback was not attempted to avoid racing an ambiguous import command; target was failed closed{}; rollback dump retained at {} with recovery manifest {}",
            metadata.protocol.as_str(),
            quarantine_suffix(&quarantine),
            rollback_path.display(),
            recovery_manifest.display()
        )));
    }

    let rollback = match prepared_rollback.as_ref() {
        Some(prepared) => {
            apply_prepared_logical_import(state, metadata, prepared, ImportMode::Wipe)
                .await
                .map_err(LogicalApplyError::into_api_error)
        }
        None => {
            import_logical_dump(
                state,
                metadata,
                metadata.protocol,
                &rollback_path,
                &rollback_options,
                LogicalImportControls {
                    reuse_staged_artifact: true,
                    database_definition_in_dump: rollback_has_database_definition,
                    exec_timeout: remote_exec_timeout,
                    ..LogicalImportControls::default()
                },
            )
            .await
        }
    };
    match rollback {
        Ok(()) => {
            if let Err(commit_error) = commit_recovery_manifest(&recovery_manifest).await {
                let quarantine = quarantine_uncertain_import(state, &metadata.instance_id).await;
                return Err(ApiError::Runtime(format!(
                    "{} import failed: {primary}; rollback succeeded, but recovery metadata could not be committed: {commit_error}; target was failed closed{}; rollback data and manifest were retained",
                    metadata.protocol.as_str(),
                    quarantine_suffix(&quarantine)
                )));
            }
            if let Err(route_error) = restore_import_target_route(state, metadata).await {
                let quarantine = quarantine_uncertain_import(state, &metadata.instance_id).await;
                return Err(ApiError::Runtime(format!(
                    "{} import failed: {primary}; rollback succeeded, but the target route could not be restored: {route_error}; target was failed closed{}",
                    metadata.protocol.as_str(),
                    quarantine_suffix(&quarantine)
                )));
            }
            cleanup_path(&rollback_path).await;
            Err(primary.into_api_error())
        }
        Err(rollback) => {
            let quarantine = quarantine_uncertain_import(state, &metadata.instance_id).await;
            Err(ApiError::Runtime(format!(
                "{} import failed: {primary}; rollback failed: {rollback}; target was failed closed{}; rollback dump retained at {} with recovery manifest {}",
                metadata.protocol.as_str(),
                quarantine_suffix(&quarantine),
                rollback_path.display(),
                recovery_manifest.display()
            )))
        }
    }
}

pub(super) fn rollback_staging_budget(
    staging: LogicalStagingLimits,
    prepared: &[PreparedLogicalImport],
) -> Result<(u64, Option<u64>), ApiError> {
    let prepared_source_bytes = prepared.iter().try_fold(0_u64, |total, artifact| {
        total
            .checked_add(artifact.prepared_source_bytes)
            .ok_or_else(|| ApiError::BadRequest("prepared import size overflowed".to_string()))
    })?;
    let retained_source_bytes = match staging.remote_staged_limit {
        Some(limit) => remote_staged_source_bytes(prepared, limit)?,
        None => prepared_source_bytes,
    };
    let remaining_combined_bytes = match staging.max_combined_bytes {
        Some(limit) => match limit.checked_sub(retained_source_bytes) {
            Some(remaining) if remaining > 0 => Some(remaining),
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "prepared import data leaves no room in the configured {limit}-byte staging budget for rollback"
                )));
            }
        },
        None => None,
    };
    let rollback_limit = match (staging.max_rollback_bytes, remaining_combined_bytes) {
        (Some(rollback), Some(remaining)) => Some(rollback.min(remaining)),
        (Some(rollback), None) => Some(rollback),
        (None, remaining) => remaining,
    };
    Ok((retained_source_bytes, rollback_limit))
}

pub(super) fn remote_staged_source_bytes(
    prepared: &[PreparedLogicalImport],
    limit: u64,
) -> Result<u64, ApiError> {
    let mut total = 0_u64;
    for artifact in prepared {
        let Some(source_bytes) = artifact.staged_source_bytes else {
            return Err(ApiError::Runtime(
                "remote import source staging accounting was unavailable".to_string(),
            ));
        };
        total = match total.checked_add(source_bytes) {
            Some(total) if total <= limit => total,
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "remote import sources exceed the configured staging limit of {limit} bytes"
                )));
            }
        };
    }
    Ok(total)
}

pub(super) async fn commit_logical_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    recovery_manifest: &FsPath,
    rollback_path: &FsPath,
) -> Result<(), ApiError> {
    if let Err(error) = commit_recovery_manifest(recovery_manifest).await {
        let quarantine = quarantine_uncertain_import(state, &metadata.instance_id).await;
        return Err(ApiError::Runtime(format!(
            "{} import was applied, but its recovery commit marker could not be removed: {error}; target was failed closed{}; rollback data and manifest were retained for review",
            metadata.protocol.as_str(),
            quarantine_suffix(&quarantine)
        )));
    }
    if let Err(error) = restore_import_target_route(state, metadata).await {
        let quarantine = quarantine_uncertain_import(state, &metadata.instance_id).await;
        return Err(ApiError::Runtime(format!(
            "{} import committed, but the target route could not be restored: {error}; target was failed closed{}",
            metadata.protocol.as_str(),
            quarantine_suffix(&quarantine)
        )));
    }
    cleanup_path(rollback_path).await;
    Ok(())
}
