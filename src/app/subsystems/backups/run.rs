use super::*;

pub(super) async fn backup_instance(
    state: &AppState,
    instance_id: &str,
) -> Result<BackupAttempt, ApiError> {
    let admission = admit_backup(state, instance_id)?;
    let state = state.clone();
    let instance_id = instance_id.to_string();
    tokio::spawn(async move { run_backup(state, instance_id, admission).await })
        .await
        .map_err(|error| ApiError::Runtime(format!("backup task failed: {error}")))?
}

pub(super) async fn run_backup(
    state: AppState,
    instance_id: String,
    _admission: ImportExportJobPermit,
) -> Result<BackupAttempt, ApiError> {
    let _operation = state.instance_locks.lock(&instance_id).await;
    check_backup_service(&state)?;
    let mut metadata =
        crate::subsystems::instances::reconcile_instance_locked(&state, &instance_id).await?;
    if let Some(issue) = intentionally_stopped_backup(&metadata) {
        return Ok(BackupAttempt::Skipped(issue));
    }
    check_backup_ready(&metadata)?;
    let backup_source_bytes = if metadata.deployment_mode == DeploymentMode::Shared {
        crate::subsystems::import_export::jobs::measure_shared_database_bytes(&state, &metadata)
            .await?
    } else {
        mib_to_bytes(metadata.limits.disk_mib)
    };
    let _execution = state
        .import_export_jobs
        .acquire_execution(JobResourceCost::estimate(JobEstimateInput {
            protocol: metadata.protocol,
            input_size_bytes: backup_source_bytes.max(1),
            rollback_size_bytes: 0,
            wipe: false,
            compressed: true,
            export: true,
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
    }
    let storage = backup_storage(&state)?;
    let layout = backup_layout(metadata.deployment_mode);
    let backup_id = new_backup_id(layout);
    let catalog = if state.config.backups.browsing.enabled {
        Some(
            BackupCatalog::capture(
                &state.docker,
                &metadata,
                &backup_id,
                &state.config.backups.browsing,
            )
            .await
            .encode_bounded(state.config.backups.browsing.max_catalog_bytes)
            .map_err(|error| {
                ApiError::Runtime(format!("failed to encode backup catalog: {error}"))
            })?,
        )
    } else {
        None
    };
    let backups_root = PathBuf::from(state.config.paths.backups_root());
    let bundle = BackupBundle::create(&backups_root, &instance_id, &backup_id)
        .await
        .map_err(store_error)?;
    let output_capacity = if layout == BackupLayout::Logical {
        crate::subsystems::import_export::jobs::measure_export_bytes(&state, &metadata).await?
    } else {
        mib_to_bytes(metadata.limits.disk_mib)
            .saturating_add(PHYSICAL_BACKUP_HEADROOM_BYTES)
            .clamp(
                1,
                crate::instance::jobs::import_export::MAX_DATA_ARCHIVE_BYTES,
            )
    };
    let _output_capacity = match state
        .import_uploads
        .reserve_output_capacity(&backups_root, output_capacity)
        .await
    {
        Ok(reservation) => reservation,
        Err(error) => {
            bundle.cleanup().await;
            return Err(error);
        }
    };
    let committed = write_and_commit_bundle(
        &state,
        &storage,
        &bundle,
        &metadata,
        &instance_id,
        &backup_id,
        layout,
        catalog.as_deref(),
        output_capacity,
    )
    .await;
    bundle.cleanup().await;
    let manifest = committed?;
    if let Err(error) = prune_instance_backups(&state, &storage, &instance_id).await {
        tracing::warn!(
            event = "audit backup_retention_failed",
            instance_id,
            backup_id,
            %error,
            "backup completed but retention could not be fully applied"
        );
    }
    tracing::info!(
        event = "audit backup_completed",
        instance_id,
        protocol = metadata.protocol.as_str(),
        layout = ?layout,
        backup_id,
        storage = storage.kind().as_str(),
        catalog = manifest.catalog_available,
    );
    Ok(BackupAttempt::Completed(backup_info(manifest)))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn write_and_commit_bundle(
    state: &AppState,
    storage: &BackupStorage,
    bundle: &BackupBundle,
    metadata: &InstanceMetadata,
    instance_id: &str,
    backup_id: &str,
    layout: BackupLayout,
    catalog: Option<&[u8]>,
    output_capacity: u64,
) -> Result<StoredBackup, ApiError> {
    if let Some(catalog) = catalog {
        bundle.write_catalog(catalog).await.map_err(store_error)?;
    }
    match layout {
        BackupLayout::Physical => {
            create_physical_archive(state, metadata, &bundle.archive, output_capacity).await?
        }
        BackupLayout::Logical => {
            crate::subsystems::import_export::logical::create_shared_backup(
                state,
                metadata,
                bundle.archive.clone(),
                output_capacity,
            )
            .await?
        }
    }
    let manifest = build_manifest(
        backup_id.to_string(),
        instance_id.to_string(),
        metadata.protocol,
        layout,
        &bundle.archive,
        catalog.is_some(),
    )
    .await
    .map_err(store_error)?;
    bundle
        .write_metadata(&manifest)
        .await
        .map_err(store_error)?;
    storage
        .commit(bundle, &manifest)
        .await
        .map_err(store_error)?;
    Ok(manifest)
}

pub(super) async fn create_physical_archive(
    state: &AppState,
    metadata: &InstanceMetadata,
    archive: &FsPath,
    max_output_bytes: u64,
) -> Result<(), ApiError> {
    let instance_id = &metadata.instance_id;
    let was_running = metadata.status == InstanceStatus::Running;
    if was_running {
        tracing::info!(
            event = "audit physical_backup_pause",
            instance_id,
            protocol = metadata.protocol.as_str(),
            "physical backup is stopping the database for a consistent archive; clients may disconnect"
        );
        crate::subsystems::instances::change_instance_state_locked(
            state,
            instance_id,
            crate::subsystems::instances::LifecycleAction::Stop,
        )
        .await?;
    }
    let paths = crate::instance::paths::InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let archive_policy = if metadata.protocol == Protocol::Mysql {
        DataArchiveSourcePolicy::MysqlDataDirectory
    } else {
        DataArchiveSourcePolicy::Strict
    };
    let result = create_bounded_archive_with_policy(
        paths.data,
        archive.to_path_buf(),
        archive_policy,
        max_output_bytes,
    )
    .await
    .map_err(|error| ApiError::Runtime(error.to_string()));
    if let Err(error) = &result {
        tracing::error!(
            event = "audit backup_archive_failed",
            instance_id,
            protocol = metadata.protocol.as_str(),
            error = %error,
            "failed to archive stopped instance data"
        );
    }
    let result = crate::subsystems::import_export::finish_physical_change(
        state,
        instance_id,
        was_running,
        result,
    )
    .await;
    if was_running && result.is_ok() {
        tracing::info!(
            event = "audit physical_backup_resumed",
            instance_id,
            protocol = metadata.protocol.as_str(),
            "physical backup archive completed and the database was restarted"
        );
    }
    result
}
