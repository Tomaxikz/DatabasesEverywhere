//! Logical database import/export, transactional rollback, and recovery fencing.

use super::{archive::*, files::*, physical::*, protocol::*, *};
use crate::instances::credentials::logical_export_env;

pub(super) mod prepared_support;
mod staging;
mod target;
use prepared_support::{
    LogicalApplyError, PreparedLogicalImport, PreparedTarget, apply_prepared_logical_import,
    apply_prepared_logical_imports, cleanup_prepared_logical_import,
    cleanup_prepared_logical_imports, parse_sha256, pin_prepared_source,
};
use staging::LogicalStagingLimits;
pub(super) use staging::{
    UploadLogicalStagingBudget, check_remote_staging_space, physical_staging_bytes,
    upload_logical_staging_budget, upload_physical_staging_bytes,
};
pub(crate) use target::quarantine_uncertain_import;
use target::{
    check_shared_rollback_objects, commit_recovery_manifest, fail_quiesced_setup,
    fence_import_target, quarantine_suffix, restore_import_target_route,
    write_logical_recovery_manifest,
};

pub(super) async fn import_instance_source(
    state: &AppState,
    instance_id: &str,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    check_logical_ready(&metadata)?;
    let upload_staging = validated_upload_staging(&metadata, options)?;
    match &options.source {
        ImportSourceOptions::Artifact(path)
            if !matches!(
                metadata.protocol,
                Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
            ) =>
        {
            import_logical(
                state,
                &metadata,
                path,
                options,
                None,
                LogicalStagingLimits::default(),
            )
            .await
        }
        ImportSourceOptions::Artifact(path) => {
            import_artifact(state, instance_id, &metadata, path, options, None).await
        }
        ImportSourceOptions::Upload { path, .. }
            if !matches!(
                metadata.protocol,
                Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
            ) =>
        {
            let staging = match upload_staging {
                Some(UploadStagingBudget::Logical { budget, .. }) => *budget,
                _ => {
                    return Err(ApiError::Runtime(
                        "logical upload staging was unavailable".to_string(),
                    ));
                }
            };
            import_logical(
                state,
                &metadata,
                path,
                options,
                options.source_database.as_deref(),
                LogicalStagingLimits::upload(staging),
            )
            .await
        }
        ImportSourceOptions::Upload { path, .. } => match metadata.protocol {
            Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => {
                let max_extracted_bytes = match upload_staging {
                    Some(UploadStagingBudget::Physical {
                        extracted_bytes, ..
                    }) => *extracted_bytes,
                    _ => {
                        return Err(ApiError::Runtime(
                            "physical upload staging was unavailable".to_string(),
                        ));
                    }
                };
                import_physical_archive(
                    state,
                    instance_id,
                    metadata.protocol,
                    path,
                    max_extracted_bytes,
                )
                .await
            }
            protocol => {
                let staging = match upload_staging {
                    Some(UploadStagingBudget::Logical { budget, .. }) => *budget,
                    _ => {
                        return Err(ApiError::Runtime(
                            "logical upload staging was unavailable".to_string(),
                        ));
                    }
                };
                import_logical_dump(
                    state,
                    &metadata,
                    protocol,
                    path,
                    options,
                    LogicalImportControls {
                        source_database: options.source_database.as_deref(),
                        max_prepared_bytes: Some(staging.prepared_bytes),
                        ..LogicalImportControls::default()
                    },
                )
                .await
            }
        },
        ImportSourceOptions::Remote(source) => {
            if metadata.status != InstanceStatus::Running {
                return Err(ApiError::BadRequest(format!(
                    "remote import requires a running target instance (status={:?})",
                    metadata.status
                )));
            }
            match metadata.protocol {
                Protocol::Redis => import_redis(state, instance_id, source, options.mode).await,
                Protocol::Valkey => import_valkey(state, instance_id, source, options.mode).await,
                Protocol::Qdrant => {
                    import_qdrant(state, instance_id, source, &options.selection, options.mode)
                        .await
                }
                protocol => {
                    let staged = acquire_logical_dump(
                        state,
                        protocol,
                        source,
                        &options.selection,
                        &metadata.database.username,
                        &metadata.database.name,
                    )
                    .await?;
                    let artifact_paths = staged
                        .paths
                        .iter()
                        .map(PathBuf::as_path)
                        .collect::<Vec<_>>();
                    let result = import_logical_batch(
                        state,
                        &metadata,
                        &artifact_paths,
                        options,
                        staged.source_database.as_deref(),
                        LogicalStagingLimits::remote(
                            state.config.security.remote_import.max_staged_bytes,
                        ),
                    )
                    .await;
                    staged.cleanup().await;
                    result
                }
            }
        }
        ImportSourceOptions::RemoteRequest(_) => Err(ApiError::Runtime(
            "remote import source was not validated".to_string(),
        )),
    }
}

fn validated_upload_staging<'a>(
    metadata: &InstanceMetadata,
    options: &'a ImportOptions,
) -> Result<Option<&'a UploadStagingBudget>, ApiError> {
    if !matches!(&options.source, ImportSourceOptions::Upload { .. }) {
        if options.upload_staging.is_some() {
            return Err(ApiError::Runtime(
                "non-upload import unexpectedly retained upload staging".to_string(),
            ));
        }
        return Ok(None);
    }
    let staging = options.upload_staging.as_ref().ok_or_else(|| {
        ApiError::Runtime("upload import did not retain its staging reservation".to_string())
    })?;
    if !upload_staging_matches_target(staging, &metadata.created_at, metadata.limits.disk_mib) {
        return Err(ApiError::Conflict(
            "the target instance or disk limit changed after import admission; submit the upload import again"
                .to_string(),
        ));
    }
    Ok(Some(staging))
}

pub(super) fn upload_staging_matches_target(
    staging: &UploadStagingBudget,
    current_created_at: &str,
    current_disk_mib: u64,
) -> bool {
    let (target_created_at, disk_mib) = match staging {
        UploadStagingBudget::Logical {
            target_created_at,
            disk_mib,
            ..
        }
        | UploadStagingBudget::Physical {
            target_created_at,
            disk_mib,
            ..
        } => (target_created_at, *disk_mib),
    };
    target_created_at == current_created_at && disk_mib == current_disk_mib
}

pub(super) fn check_logical_ready(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if matches!(
        metadata.protocol,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    ) || metadata.status == InstanceStatus::Running
    {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "instance is not running (status={:?})",
            metadata.status
        )))
    }
}

pub(super) async fn import_artifact(
    state: &AppState,
    instance_id: &str,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
    options: &ImportOptions,
    source_database: Option<&str>,
) -> Result<(), ApiError> {
    let protocol = metadata.protocol;
    match protocol {
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => {
            let max_extracted_bytes = physical_staging_bytes(protocol, metadata.limits.disk_mib)?
                .ok_or_else(|| {
                ApiError::Runtime("physical import extraction budget was unavailable".to_string())
            })?;
            import_physical_archive(
                state,
                instance_id,
                protocol,
                artifact_path,
                max_extracted_bytes,
            )
            .await
        }
        protocol => {
            import_logical_dump(
                state,
                metadata,
                protocol,
                artifact_path,
                options,
                LogicalImportControls {
                    source_database,
                    ..LogicalImportControls::default()
                },
            )
            .await
        }
    }
}

async fn import_logical(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
    options: &ImportOptions,
    source_database: Option<&str>,
    staging: LogicalStagingLimits,
) -> Result<(), ApiError> {
    import_logical_batch(
        state,
        metadata,
        &[artifact_path],
        options,
        source_database,
        staging,
    )
    .await
}

pub(super) fn logical_apply_options(
    options: &ImportOptions,
    remote_dump_was_prefiltered: bool,
) -> ImportOptions {
    let mut apply_options = options.clone();
    if remote_dump_was_prefiltered {
        apply_options.selection = ImportExportSelection::default();
    }
    apply_options
}

async fn import_logical_batch(
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
    let prepared_source_bytes = prepared.iter().try_fold(0_u64, |total, artifact| {
        total
            .checked_add(artifact.prepared_source_bytes)
            .ok_or_else(|| ApiError::BadRequest("prepared import size overflowed".to_string()))
    });
    let prepared_source_bytes = match prepared_source_bytes {
        Ok(total) => total,
        Err(error) => {
            cleanup_prepared_logical_imports(state, metadata, &prepared).await;
            return Err(error);
        }
    };
    let retained_source_bytes = match staging.remote_staged_limit {
        Some(limit) => {
            let mut total = 0_u64;
            for artifact in &prepared {
                let Some(source_bytes) = artifact.staged_source_bytes else {
                    cleanup_prepared_logical_imports(state, metadata, &prepared).await;
                    return Err(ApiError::Runtime(
                        "remote import source staging accounting was unavailable".to_string(),
                    ));
                };
                total = match total.checked_add(source_bytes) {
                    Some(total) if total <= limit => total,
                    _ => {
                        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
                        return Err(ApiError::BadRequest(format!(
                            "remote import sources exceed the configured staging limit of {limit} bytes"
                        )));
                    }
                };
            }
            total
        }
        None => prepared_source_bytes,
    };
    let remaining_combined_bytes = match staging.max_combined_bytes {
        Some(limit) => match limit.checked_sub(retained_source_bytes) {
            Some(remaining) if remaining > 0 => Some(remaining),
            _ => {
                cleanup_prepared_logical_imports(state, metadata, &prepared).await;
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
    if primary.is_ok() {
        if let Err(error) = commit_recovery_manifest(&recovery_manifest).await {
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
        cleanup_path(&rollback_path).await;
        return Ok(());
    }

    let primary = match primary {
        Ok(()) => unreachable!(),
        Err(primary) => primary,
    };
    if primary.helper_uncertain() {
        let quarantine = quarantine_uncertain_import(state, &metadata.instance_id).await;
        return Err(ApiError::Runtime(format!(
            "{} import failed after helper cleanup became uncertain: {primary}; rollback was not attempted because it could race the previous helper; target was failed closed{}; rollback dump retained at {} with recovery manifest {}",
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

#[derive(Clone, Copy, Default)]
pub(super) struct LogicalExportControls {
    max_output_bytes: Option<u64>,
    exec_timeout: Option<Duration>,
    include_database_definition: bool,
}

impl LogicalExportControls {
    pub(super) fn with_max_output_bytes(max_output_bytes: u64) -> Self {
        Self {
            max_output_bytes: Some(max_output_bytes),
            ..Self::default()
        }
    }
}

pub(crate) async fn create_shared_backup(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: PathBuf,
    max_output_bytes: u64,
) -> Result<(), ApiError> {
    if metadata.deployment_mode != DeploymentMode::Shared {
        return Err(ApiError::Runtime(
            "logical shared-backup path received a dedicated instance".to_string(),
        ));
    }
    export_logical_dump(
        state,
        metadata,
        metadata.protocol,
        artifact_path,
        &ExportOptions::default(),
        LogicalExportControls {
            max_output_bytes: Some(max_output_bytes),
            exec_timeout: None,
            include_database_definition: false,
        },
    )
    .await
}

pub(crate) async fn restore_shared_backup(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
    max_source_bytes: u64,
    max_rollback_bytes: u64,
) -> Result<(), ApiError> {
    if metadata.deployment_mode != DeploymentMode::Shared {
        return Err(ApiError::Runtime(
            "logical shared-backup restore received a dedicated instance".to_string(),
        ));
    }
    let options = ImportOptions::recovery_restore(artifact_path, metadata.protocol);
    import_logical_batch(
        state,
        metadata,
        &[artifact_path],
        &options,
        None,
        LogicalStagingLimits {
            remote_staged_limit: Some(max_source_bytes),
            max_prepared_bytes: Some(max_source_bytes),
            max_rollback_bytes: Some(max_rollback_bytes),
            ..LogicalStagingLimits::default()
        },
    )
    .await
}

/// Capacity created below the logical staging root while restoring a source
/// that already exists elsewhere. Shared restores pin the inspected source
/// once, then create and pin one rollback dump before mutation.
pub(crate) fn shared_restore_staging_bytes(
    source_bytes: u64,
    rollback_bytes: u64,
) -> Result<u64, ApiError> {
    rollback_bytes
        .checked_mul(2)
        .and_then(|rollback| source_bytes.checked_add(rollback))
        .ok_or_else(|| ApiError::Conflict("shared restore staging overflowed".to_string()))
}

pub(crate) async fn export_for_deployment_migration(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: PathBuf,
    max_output_bytes: u64,
) -> Result<(), ApiError> {
    export_logical_dump(
        state,
        metadata,
        metadata.protocol,
        artifact_path,
        &ExportOptions::default(),
        LogicalExportControls {
            // The migration worker reserves this exact conservative bound.
            // Keep the writer on the same bound so a stale size estimate can
            // fail closed instead of consuming unreserved host capacity.
            max_output_bytes: Some(max_output_bytes),
            exec_timeout: None,
            include_database_definition: false,
        },
    )
    .await
}

pub(crate) async fn import_for_deployment_migration(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
) -> Result<(), ApiError> {
    let options = ImportOptions::recovery_restore(artifact_path, metadata.protocol);
    // A migration target is provisional and disposable until the placement
    // transaction commits. The migration worker owns target cleanup, so using
    // the ordinary transactional batch path here would be both wasteful and
    // unsafe: its rollback recovery republishes an existing instance route.
    // Reuse the canonical inspected logical importer directly and leave every
    // route decision to the durable migration state machine.
    import_logical_dump(
        state,
        metadata,
        metadata.protocol,
        artifact_path,
        &options,
        LogicalImportControls {
            // The artifact is a daemon-owned export inside the migration's
            // private staging root. Inspect and pin it directly instead of
            // first creating an identical intermediate copy.
            reuse_staged_artifact: true,
            max_prepared_bytes: Some(
                tokio::fs::metadata(artifact_path)
                    .await
                    .map_err(|error| {
                        ApiError::Runtime(format!(
                            "failed to inspect deployment migration artifact: {error}"
                        ))
                    })?
                    .len(),
            ),
            ..LogicalImportControls::default()
        },
    )
    .await
}

pub(super) async fn export_logical_dump(
    state: &AppState,
    metadata: &InstanceMetadata,
    protocol: Protocol,
    artifact_path: PathBuf,
    options: &ExportOptions,
    controls: LogicalExportControls,
) -> Result<(), ApiError> {
    let runtime_id = metadata.runtime_id();
    prepare_private_dir(
        artifact_path
            .parent()
            .ok_or_else(|| ApiError::Runtime("invalid artifact path".to_string()))?,
        "artifact directory",
    )
    .await?;

    let extension = dump_extension(protocol);
    let temp_name = format!(".dbe-export-{}.{}", uuid::Uuid::new_v4(), extension);
    let staging_root = logical_staging_root(state).await?;
    let host_temp = staging_root.join(&temp_name);
    cleanup_path(&host_temp).await;

    let script = export_script(
        metadata,
        "/dev/stdout",
        &options.selection,
        controls.include_database_definition,
    )?;
    let max_output_bytes = controls
        .max_output_bytes
        .unwrap_or(MAX_UNARCHIVED_BYTES)
        .min(MAX_UNARCHIVED_BYTES);
    if max_output_bytes == 0 {
        return Err(ApiError::BadRequest(
            "logical export output limit must be nonzero".to_string(),
        ));
    }
    let credentials =
        logical_export_env(metadata).map_err(|error| ApiError::Conflict(error.to_string()))?;
    let environment = credentials.references();
    let stream_result = state
        .docker
        .exec_shell_to_file(
            protocol,
            runtime_id,
            &script,
            &environment,
            &host_temp,
            max_output_bytes,
            controls.exec_timeout.unwrap_or(LOGICAL_STREAM_EXEC_TIMEOUT),
            logical_exec_recovery(metadata),
        )
        .await;
    if let Err(error) = stream_result {
        cleanup_path(&host_temp).await;
        if metadata.deployment_mode == DeploymentMode::Shared {
            let recovery = async {
                fence_import_target(state, metadata, controls.exec_timeout).await?;
                restore_import_target_route(state, metadata).await
            }
            .await;
            if let Err(recovery_error) = recovery {
                return Err(ApiError::Runtime(format!(
                    "shared {} export failed: {error}; tenant operation recovery also failed: {recovery_error}; target remains fenced",
                    protocol.as_str()
                )));
            }
        }
        return Err(ApiError::Runtime(error.to_string()));
    }
    let result = archive_or_copy_export(&host_temp, &artifact_path, options.archive_format).await;
    cleanup_path(&host_temp).await;
    result
}

#[derive(Clone, Copy, Default)]
pub(super) struct LogicalImportControls<'a> {
    source_database: Option<&'a str>,
    reuse_staged_artifact: bool,
    database_definition_in_dump: bool,
    exec_timeout: Option<Duration>,
    remove_uploaded_source_limit: Option<u64>,
    max_prepared_bytes: Option<u64>,
}

pub(super) async fn import_logical_dump(
    state: &AppState,
    metadata: &InstanceMetadata,
    protocol: Protocol,
    artifact_path: &FsPath,
    options: &ImportOptions,
    controls: LogicalImportControls<'_>,
) -> Result<(), ApiError> {
    let prepared =
        prepare_logical_import(state, metadata, protocol, artifact_path, options, controls).await?;
    let result = apply_prepared_logical_import(state, metadata, &prepared, options.mode).await;
    cleanup_prepared_logical_import(state, metadata, &prepared).await;
    result.map_err(LogicalApplyError::into_api_error)
}

async fn prepare_logical_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    protocol: Protocol,
    artifact_path: &FsPath,
    options: &ImportOptions,
    controls: LogicalImportControls<'_>,
) -> Result<PreparedLogicalImport, ApiError> {
    validate_artifact_selection(protocol, &options.selection)?;
    let extension = dump_extension(protocol);
    let temp_name = format!(".dbe-import-{}.{}", uuid::Uuid::new_v4(), extension);
    let staging_root = logical_staging_root(state).await?;
    let host_temp = if controls.reuse_staged_artifact {
        artifact_path.to_path_buf()
    } else {
        staging_root.join(&temp_name)
    };
    let max_prepared_bytes = controls
        .max_prepared_bytes
        .unwrap_or(MAX_UNARCHIVED_BYTES)
        .min(MAX_UNARCHIVED_BYTES);
    let prepared_source_bytes = if controls.reuse_staged_artifact {
        check_import_file_size(&host_temp).await?
    } else {
        cleanup_path(&host_temp).await;
        if let Err(error) = prepare_import_artifact(
            protocol,
            artifact_path,
            &host_temp,
            &staging_root,
            options,
            max_prepared_bytes,
        )
        .await
        {
            cleanup_path(&host_temp).await;
            return Err(error);
        }
        check_import_file_size(&host_temp).await?
    };
    if prepared_source_bytes > max_prepared_bytes {
        if !controls.reuse_staged_artifact {
            cleanup_path(&host_temp).await;
        }
        return Err(ApiError::BadRequest(format!(
            "prepared import source is {prepared_source_bytes} bytes; configured limit is {max_prepared_bytes} bytes"
        )));
    }
    if let Some(limit) = controls.remove_uploaded_source_limit
        && prepared_source_bytes > limit
    {
        return Err(ApiError::BadRequest(format!(
            "remote import source is {prepared_source_bytes} bytes; configured staging limit is {limit} bytes"
        )));
    }

    let postgres_wrapper_lines = if protocol == Protocol::Postgres {
        match super::postgres_dump::wrapper_lines(&host_temp, prepared_source_bytes).await {
            Ok(lines) => lines,
            Err(error) => {
                if !controls.reuse_staged_artifact {
                    cleanup_path(&host_temp).await;
                }
                return Err(error);
            }
        }
    } else {
        None
    };
    let shared_restore = metadata.deployment_mode == DeploymentMode::Shared;
    let expected_sha256 = if shared_restore {
        use super::inspection::shared_import::{
            SharedImportLayout, SharedImportRequest, validate_shared_import,
        };
        let approval = match validate_shared_import(
            &host_temp,
            SharedImportRequest {
                protocol,
                target_database: &metadata.database.name,
                source_database: controls.source_database,
                layout: SharedImportLayout::LogicalDump,
                archive_format: Some(if protocol == Protocol::Mongodb {
                    "gzip"
                } else {
                    "plain"
                }),
                postgres_wrapper_lines,
            },
        )
        .await
        {
            Ok(approval) => approval,
            Err(error) => {
                if !controls.reuse_staged_artifact {
                    cleanup_path(&host_temp).await;
                }
                return Err(ApiError::BadRequest(format!(
                    "shared import was rejected ({:?}): {error}",
                    error.reason
                )));
            }
        };
        if !approval.requires_isolated_staging || !approval.restore_as_tenant {
            if !controls.reuse_staged_artifact {
                cleanup_path(&host_temp).await;
            }
            return Err(ApiError::Runtime(
                "shared import inspection did not require isolated tenant restore".to_string(),
            ));
        }
        Some(parse_sha256(&approval.sha256).ok_or_else(|| {
            ApiError::Runtime("shared import inspection returned an invalid digest".to_string())
        })?)
    } else {
        None
    };
    let script = match build_import_script(
        metadata,
        "/dev/stdin",
        controls.source_database,
        &options.selection,
        controls.database_definition_in_dump,
        postgres_wrapper_lines,
        if shared_restore {
            super::protocol::ImportConnection::PoolLoopback
        } else {
            super::protocol::ImportConnection::LocalSocket
        },
    ) {
        Ok(script) => script,
        Err(error) => {
            if !controls.reuse_staged_artifact {
                cleanup_path(&host_temp).await;
            }
            return Err(error);
        }
    };
    let pinned_input = pin_prepared_source(
        state,
        &host_temp,
        prepared_source_bytes,
        expected_sha256,
        !controls.reuse_staged_artifact,
    )
    .await?;
    let staged_source_bytes = if controls.remove_uploaded_source_limit.is_some() {
        if !controls.reuse_staged_artifact {
            return Err(ApiError::Runtime(
                "remote import source accounting requires a staged source artifact".to_string(),
            ));
        }
        Some(prepared_source_bytes)
    } else {
        None
    };
    Ok(PreparedLogicalImport {
        protocol,
        host_temp,
        owns_host_temp: !controls.reuse_staged_artifact,
        script,
        exec_timeout: controls.exec_timeout,
        database_definition_in_dump: controls.database_definition_in_dump,
        prepared_source_bytes,
        expected_sha256,
        pinned_input,
        staged_source_bytes,
        target: PreparedTarget::new(metadata),
    })
}
