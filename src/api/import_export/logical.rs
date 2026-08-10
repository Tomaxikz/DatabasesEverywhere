//! Logical database import/export, transactional rollback, and recovery fencing.

use super::{archive::*, files::*, physical::*, protocol::*, *};

const LOGICAL_STREAM_EXEC_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Copy, Default)]
struct LogicalStagingLimits {
    remote_staged_limit: Option<u64>,
    max_prepared_bytes: Option<u64>,
    max_rollback_bytes: Option<u64>,
    max_combined_bytes: Option<u64>,
}

impl LogicalStagingLimits {
    fn remote(max_bytes: u64) -> Self {
        Self {
            remote_staged_limit: Some(max_bytes),
            max_combined_bytes: Some(max_bytes),
            ..Self::default()
        }
    }

    fn upload(budget: UploadLogicalStagingBudget) -> Self {
        Self {
            max_prepared_bytes: Some(budget.prepared_bytes),
            max_rollback_bytes: Some(budget.rollback_bytes),
            max_combined_bytes: Some(budget.reservation_bytes),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct UploadLogicalStagingBudget {
    pub(super) prepared_bytes: u64,
    pub(super) rollback_bytes: u64,
    pub(super) reservation_bytes: u64,
}

pub(super) fn upload_logical_staging_budget(
    state: &AppState,
    metadata: &InstanceMetadata,
    mode: ImportMode,
    prepared_bytes: u64,
) -> Result<Option<UploadLogicalStagingBudget>, ApiError> {
    if matches!(
        metadata.protocol,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    ) {
        return Ok(None);
    }
    let prepared_bytes = prepared_bytes
        .max(1)
        .min(state.config.artifacts.import_upload_max_bytes)
        .min(MAX_UNARCHIVED_BYTES);
    let instance_disk_bytes = metadata
        .limits
        .disk_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| ApiError::Runtime("instance disk limit overflowed".to_string()))?;
    let rollback_bytes = if mode == ImportMode::Wipe {
        MAX_UNARCHIVED_BYTES.min(instance_disk_bytes)
    } else {
        0
    };
    if mode == ImportMode::Wipe && rollback_bytes == 0 {
        return Err(ApiError::Conflict(
            "logical upload import requires a nonzero rollback staging budget".to_string(),
        ));
    }
    let reservation_bytes = prepared_bytes
        .checked_add(rollback_bytes)
        .ok_or_else(|| ApiError::Runtime("logical import staging budget overflowed".to_string()))?;
    Ok(Some(UploadLogicalStagingBudget {
        prepared_bytes,
        rollback_bytes,
        reservation_bytes,
    }))
}

pub(super) fn upload_physical_staging_bytes(
    metadata: &InstanceMetadata,
) -> Result<Option<u64>, ApiError> {
    physical_staging_bytes_for(metadata.protocol, metadata.limits.disk_mib)
}

pub(super) fn physical_staging_bytes_for(
    protocol: Protocol,
    disk_mib: u64,
) -> Result<Option<u64>, ApiError> {
    if !matches!(
        protocol,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    ) {
        return Ok(None);
    }
    let instance_disk_bytes = disk_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| ApiError::Runtime("instance disk limit overflowed".to_string()))?;
    let bytes = instance_disk_bytes.min(crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES);
    if bytes == 0 {
        return Err(ApiError::Conflict(
            "physical upload import requires a nonzero extraction budget".to_string(),
        ));
    }
    Ok(Some(bytes))
}

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
    validate_logical_operation_eligible(&metadata)?;
    let upload_staging = validated_upload_staging(&metadata, options)?;
    match &options.source {
        ImportSourceOptions::Artifact(path)
            if options.mode == ImportMode::Wipe
                && !matches!(
                    metadata.protocol,
                    Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
                ) =>
        {
            import_logical_with_rollback(
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
            import_instance_artifact(state, instance_id, &metadata, path, options, None).await
        }
        ImportSourceOptions::Upload { path, .. }
            if options.mode == ImportMode::Wipe
                && !matches!(
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
            import_logical_with_rollback(
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
                    let result = import_logical_artifacts_with_rollback(
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

pub(super) fn validate_logical_operation_eligible(
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
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

pub(super) async fn import_instance_artifact(
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
            let max_extracted_bytes = physical_staging_bytes_for(
                protocol,
                metadata.limits.disk_mib,
            )?
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

async fn import_logical_with_rollback(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
    options: &ImportOptions,
    source_database: Option<&str>,
    staging: LogicalStagingLimits,
) -> Result<(), ApiError> {
    import_logical_artifacts_with_rollback(
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

async fn import_logical_artifacts_with_rollback(
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

    let rollback_root = match logical_staging_root(state).await {
        Ok(root) => root,
        Err(error) => {
            cleanup_prepared_logical_imports(state, metadata, &prepared).await;
            return Err(error);
        }
    };
    let recovery_id = uuid::Uuid::new_v4();
    let rollback_path = rollback_root.join(format!(
        ".dbe-import-rollback-{recovery_id}.{}",
        dump_extension(metadata.protocol)
    ));
    let recovery_manifest = rollback_root.join(format!(".dbe-import-recovery-{recovery_id}.json"));
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
            include_database_definition: true,
        },
    )
    .await
    {
        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
        cleanup_path(&rollback_path).await;
        return Err(error);
    }
    if let Some(limit) = staging.max_combined_bytes
        && let Err(error) = ensure_remote_import_staging_budget_with_retained_bytes(
            &[&rollback_path],
            retained_source_bytes,
            limit,
        )
        .await
    {
        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
        cleanup_path(&rollback_path).await;
        return Err(error);
    }
    if let Err(error) =
        write_logical_recovery_manifest(&recovery_manifest, metadata, &rollback_path, options.mode)
            .await
    {
        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
        cleanup_path(&rollback_path).await;
        return Err(error);
    }

    let primary =
        apply_prepared_logical_imports(state, metadata, &prepared, apply_options.mode).await;
    cleanup_prepared_logical_imports(state, metadata, &prepared).await;
    if primary.is_ok() {
        if let Err(error) = commit_recovery_manifest(&recovery_manifest).await {
            let quarantine = quarantine_after_uncertain_import(state, &metadata.instance_id).await;
            return Err(ApiError::Runtime(format!(
                "{} import was applied, but its recovery commit marker could not be removed: {error}; target was failed closed{}; rollback data and manifest were retained for review",
                metadata.protocol.as_str(),
                quarantine_result_suffix(&quarantine)
            )));
        }
        cleanup_path(&rollback_path).await;
        return Ok(());
    }

    let primary = match primary {
        Ok(()) => unreachable!(),
        Err(primary) => primary,
    };
    if let Err(fence_error) =
        fence_logical_target_for_rollback(state, metadata, remote_exec_timeout).await
    {
        let quarantine = quarantine_after_uncertain_import(state, &metadata.instance_id).await;
        return Err(ApiError::Runtime(format!(
            "{} import failed: {primary}; the target process could not be generation-fenced before rollback: {fence_error}; rollback was not attempted to avoid racing an ambiguous import command; target was failed closed{}; rollback dump retained at {} with recovery manifest {}",
            metadata.protocol.as_str(),
            quarantine_result_suffix(&quarantine),
            rollback_path.display(),
            recovery_manifest.display()
        )));
    }

    let rollback_options = ImportOptions {
        source: ImportSourceOptions::Artifact(rollback_path.clone()),
        mode: ImportMode::Wipe,
        ..ImportOptions::default()
    };
    let rollback = import_logical_dump(
        state,
        metadata,
        metadata.protocol,
        &rollback_path,
        &rollback_options,
        LogicalImportControls {
            reuse_staged_artifact: true,
            database_definition_in_dump: true,
            exec_timeout: remote_exec_timeout,
            ..LogicalImportControls::default()
        },
    )
    .await;
    match rollback {
        Ok(()) => {
            if let Err(commit_error) = commit_recovery_manifest(&recovery_manifest).await {
                let quarantine =
                    quarantine_after_uncertain_import(state, &metadata.instance_id).await;
                return Err(ApiError::Runtime(format!(
                    "{} import failed: {primary}; rollback succeeded, but recovery metadata could not be committed: {commit_error}; target was failed closed{}; rollback data and manifest were retained",
                    metadata.protocol.as_str(),
                    quarantine_result_suffix(&quarantine)
                )));
            }
            cleanup_path(&rollback_path).await;
            Err(primary)
        }
        Err(rollback) => {
            let quarantine = quarantine_after_uncertain_import(state, &metadata.instance_id).await;
            Err(ApiError::Runtime(format!(
                "{} import failed: {primary}; rollback failed: {rollback}; target was failed closed{}; rollback dump retained at {} with recovery manifest {}",
                metadata.protocol.as_str(),
                quarantine_result_suffix(&quarantine),
                rollback_path.display(),
                recovery_manifest.display()
            )))
        }
    }
}

pub(super) async fn fence_logical_target_for_rollback(
    state: &AppState,
    metadata: &InstanceMetadata,
    operation_timeout: Option<Duration>,
) -> Result<(), ApiError> {
    // A Docker transport/attach failure can leave the command running even after its client future
    // is gone. A confirmed stop is the process-generation fence: rollback is only safe after the
    // old database process is dead and a fresh one has reached startup readiness.
    stop_import_target_process(state, metadata, "before logical import rollback")
        .await
        .map_err(ApiError::Runtime)?;

    tokio::time::timeout(
        FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.start(metadata.protocol, &metadata.instance_id),
    )
    .await
    .map_err(|_| {
        ApiError::Runtime("timed out restarting target before logical import rollback".to_string())
    })?
    .map_err(|error| {
        ApiError::Runtime(format!(
            "failed to restart target before logical import rollback: {error}"
        ))
    })?;

    let readiness_timeout = operation_timeout
        .unwrap_or(LOGICAL_ROLLBACK_READINESS_TIMEOUT)
        .min(LOGICAL_ROLLBACK_READINESS_TIMEOUT);
    state
        .docker
        .wait_until_ready(metadata.protocol, &metadata.instance_id, readiness_timeout)
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "target did not become ready before logical import rollback: {error}"
            ))
        })
        .map(|_| ())
}

pub(crate) async fn quarantine_after_uncertain_import(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    let mut metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    metadata.status = InstanceStatus::Quarantined;
    metadata.desired_state = crate::instances::metadata::DesiredInstanceState::Stopped;
    metadata.updated_at = crate::jobs::import_export::now_rfc3339();

    // Remove gateway routes synchronously in memory before any Docker or SQLite wait. Existing
    // connections are cut off by the stop/kill below; new connections can no longer resolve.
    state.instances.upsert(metadata.clone()).await;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.resource_cache.remove(&metadata.instance_id).await;
    state.monitoring_cache.invalidate().await;

    let (runtime_result, persistence_result) = tokio::join!(
        stop_import_target_process(
            state,
            &metadata,
            "after an import lost durable commit or rollback certainty",
        ),
        state.manager.upsert(metadata.clone()),
    );
    let persistence_result =
        persistence_result.map_err(|error| format!("failed to persist quarantine: {error}"));

    tracing::error!(
        event = "audit uncertain_import_instance_quarantined",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        runtime_stopped = runtime_result.is_ok(),
        quarantine_persisted = persistence_result.is_ok(),
        "an import lost durable commit or rollback certainty; removed gateway routes and quarantined the target"
    );

    match (runtime_result, persistence_result) {
        (Ok(()), Ok(())) => Ok(()),
        (runtime, persistence) => {
            let mut failures = Vec::new();
            if let Err(error) = runtime {
                failures.push(error);
            }
            if let Err(error) = persistence {
                failures.push(error);
            }
            Err(ApiError::Runtime(failures.join("; ")))
        }
    }
}

pub(super) async fn stop_import_target_process(
    state: &AppState,
    metadata: &InstanceMetadata,
    reason: &'static str,
) -> Result<(), String> {
    let stop = tokio::time::timeout(
        FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.stop(metadata.protocol, &metadata.instance_id),
    )
    .await;
    match stop {
        Ok(Ok(_)) => return Ok(()),
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => return Ok(()),
        Ok(Err(error)) => {
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %error,
                %reason,
                "graceful stop failed; forcing target shutdown"
            );
        }
        Err(_) => {
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %reason,
                "graceful stop timed out; forcing target shutdown"
            );
        }
    }

    match tokio::time::timeout(
        FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.kill(metadata.protocol, &metadata.instance_id),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => Ok(()),
        Ok(Err(error)) => Err(format!(
            "failed to stop or kill quarantined target: {error}"
        )),
        Err(_) => Err("timed out stopping and killing quarantined target".to_string()),
    }
}

pub(super) fn quarantine_result_suffix(result: &Result<(), ApiError>) -> String {
    match result {
        Ok(()) => " and quarantined".to_string(),
        Err(error) => format!(
            " in memory and quarantined, but complete shutdown/persistence reported: {error}"
        ),
    }
}

pub(super) async fn commit_recovery_manifest(path: &FsPath) -> Result<(), ApiError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::shared::files::remove_private_file_durable(&path))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to commit import recovery metadata: {error}"
            ))
        })?
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to commit import recovery metadata: {error}"
            ))
        })
}

#[derive(Serialize)]
pub(super) struct LogicalRecoveryManifest<'a> {
    schema_version: u32,
    recovery_kind: &'static str,
    instance_id: &'a str,
    protocol: &'static str,
    import_mode: ImportMode,
    rollback_file: &'a str,
    created_at: String,
}

pub(super) async fn write_logical_recovery_manifest(
    path: &FsPath,
    metadata: &InstanceMetadata,
    rollback_path: &FsPath,
    mode: ImportMode,
) -> Result<(), ApiError> {
    let durable_rollback = rollback_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        crate::shared::files::sync_private_regular_file_durable(&durable_rollback)
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to sync rollback data: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("failed to sync rollback data: {error}")))?;
    let rollback_file = rollback_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ApiError::Runtime("invalid rollback file name".to_string()))?;
    let manifest = serde_json::to_vec_pretty(&LogicalRecoveryManifest {
        schema_version: 1,
        recovery_kind: "logical_remote_import",
        instance_id: &metadata.instance_id,
        protocol: metadata.protocol.as_str(),
        import_mode: mode,
        rollback_file,
        created_at: crate::jobs::import_export::now_rfc3339(),
    })
    .map_err(|error| ApiError::Runtime(format!("failed to encode recovery manifest: {error}")))?;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        crate::shared::files::atomic_write_private(&path, &manifest)
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to write recovery manifest: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("failed to write recovery manifest: {error}")))
}

#[cfg(test)]
pub(super) async fn ensure_remote_import_staging_budget(
    paths: &[&FsPath],
    max_bytes: u64,
) -> Result<u64, ApiError> {
    ensure_remote_import_staging_budget_with_retained_bytes(paths, 0, max_bytes).await
}

pub(super) async fn ensure_remote_import_staging_budget_with_retained_bytes(
    paths: &[&FsPath],
    retained_bytes: u64,
    max_bytes: u64,
) -> Result<u64, ApiError> {
    let mut total = retained_bytes;
    if total > max_bytes {
        return Err(ApiError::BadRequest(format!(
            "remote import source and rollback data exceed the configured {max_bytes}-byte staging limit; reduce the selected source or target data size"
        )));
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
            return Err(ApiError::BadRequest(format!(
                "remote import source and rollback data exceed the configured {max_bytes}-byte staging limit; reduce the selected source or target data size"
            )));
        }
    }
    Ok(total)
}

#[derive(Clone, Copy, Default)]
pub(super) struct LogicalExportControls {
    max_output_bytes: Option<u64>,
    exec_timeout: Option<Duration>,
    include_database_definition: bool,
}

pub(super) async fn export_logical_dump(
    state: &AppState,
    metadata: &InstanceMetadata,
    protocol: Protocol,
    artifact_path: PathBuf,
    options: &ExportOptions,
    controls: LogicalExportControls,
) -> Result<(), ApiError> {
    let instance_id = &metadata.instance_id;
    create_private_directory(
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
    let result = async {
        state
            .docker
            .exec_shell_to_file_with_secret_env(
                protocol,
                instance_id,
                &script,
                &[],
                &host_temp,
                max_output_bytes,
                controls.exec_timeout.unwrap_or(LOGICAL_STREAM_EXEC_TIMEOUT),
            )
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        archive_or_copy_export(&host_temp, &artifact_path, options.archive_format).await
    }
    .await;
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
    result
}

pub(super) struct PreparedLogicalImport {
    protocol: Protocol,
    host_temp: PathBuf,
    owns_host_temp: bool,
    script: String,
    exec_timeout: Option<Duration>,
    database_definition_in_dump: bool,
    prepared_source_bytes: u64,
    staged_source_bytes: Option<u64>,
}

pub(super) async fn prepare_logical_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    protocol: Protocol,
    artifact_path: &FsPath,
    options: &ImportOptions,
    controls: LogicalImportControls<'_>,
) -> Result<PreparedLogicalImport, ApiError> {
    validate_logical_artifact_selection(protocol, &options.selection)?;
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
        ensure_import_file_size(&host_temp).await?
    } else {
        cleanup_path(&host_temp).await;
        if let Err(error) = prepare_logical_import_artifact(
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
        ensure_import_file_size(&host_temp).await?
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

    let script = match import_script(
        metadata,
        "/dev/stdin",
        controls.source_database,
        &options.selection,
        controls.database_definition_in_dump,
    ) {
        Ok(script) => script,
        Err(error) => {
            if !controls.reuse_staged_artifact {
                cleanup_path(&host_temp).await;
            }
            return Err(error);
        }
    };
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
        staged_source_bytes,
    })
}

pub(super) async fn apply_prepared_logical_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared: &PreparedLogicalImport,
    mode: ImportMode,
) -> Result<(), ApiError> {
    apply_prepared_logical_imports(state, metadata, std::slice::from_ref(prepared), mode).await
}

pub(super) async fn apply_prepared_logical_imports(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared: &[PreparedLogicalImport],
    mode: ImportMode,
) -> Result<(), ApiError> {
    let first = prepared.first().ok_or_else(|| {
        ApiError::Runtime("logical import did not contain any prepared artifacts".to_string())
    })?;
    if prepared.iter().any(|artifact| {
        artifact.protocol != metadata.protocol
            || artifact.exec_timeout != first.exec_timeout
            || artifact.database_definition_in_dump != first.database_definition_in_dump
    }) {
        return Err(ApiError::Runtime(
            "logical import artifacts had inconsistent execution controls".to_string(),
        ));
    }
    let instance_id = &metadata.instance_id;
    if mode == ImportMode::Wipe {
        wipe_logical_target(
            state,
            metadata,
            first.exec_timeout,
            first.database_definition_in_dump,
        )
        .await?;
    }
    let credentials = mysql_tenant_import_credentials(metadata, first.database_definition_in_dump)?;
    let import_started = Instant::now();
    for artifact in prepared {
        let timeout = match artifact.exec_timeout {
            Some(total) => total
                .checked_sub(import_started.elapsed())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| {
                    ApiError::Runtime(format!(
                        "{} import timed out while applying multiple artifacts",
                        metadata.protocol.as_str()
                    ))
                })?,
            None => LOGICAL_STREAM_EXEC_TIMEOUT,
        };
        let environment = credentials
            .as_ref()
            .map(MysqlTenantImportCredentials::environment);
        state
            .docker
            .exec_shell_with_file_stdin_and_secret_env(
                artifact.protocol,
                instance_id,
                &artifact.script,
                environment.as_ref().map_or(&[], |value| value.as_slice()),
                &artifact.host_temp,
                artifact.prepared_source_bytes,
                timeout,
            )
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    }
    Ok(())
}

pub(super) async fn cleanup_prepared_logical_import(
    _state: &AppState,
    _metadata: &InstanceMetadata,
    prepared: &PreparedLogicalImport,
) {
    if prepared.owns_host_temp {
        cleanup_path(&prepared.host_temp).await;
    }
}

pub(super) async fn cleanup_prepared_logical_imports(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared: &[PreparedLogicalImport],
) {
    for artifact in prepared {
        cleanup_prepared_logical_import(state, metadata, artifact).await;
    }
}
