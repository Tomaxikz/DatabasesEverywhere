use super::*;

pub(in super::super) async fn import_instance_source(
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
        ImportSourceOptions::Artifact(path) if !metadata.protocol.engine().is_physical() => {
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
        ImportSourceOptions::Upload { path, .. } if !metadata.protocol.engine().is_physical() => {
            let Some(UploadStagingBudget::Logical { budget, .. }) = upload_staging else {
                return Err(ApiError::Runtime(
                    "logical upload staging was unavailable".to_string(),
                ));
            };
            import_logical(
                state,
                &metadata,
                path,
                options,
                options.source_database.as_deref(),
                LogicalStagingLimits::upload(*budget),
            )
            .await
        }
        ImportSourceOptions::Upload { path, .. } => {
            let Some(UploadStagingBudget::Physical {
                extracted_bytes, ..
            }) = upload_staging
            else {
                return Err(ApiError::Runtime(
                    "physical upload staging was unavailable".to_string(),
                ));
            };
            import_physical_archive(
                state,
                instance_id,
                metadata.protocol,
                path,
                *extracted_bytes,
            )
            .await
        }
        ImportSourceOptions::Remote(source) => {
            import_remote_source(state, instance_id, &metadata, source, options).await
        }
        ImportSourceOptions::RemoteRequest(_) => Err(ApiError::Runtime(
            "remote import source was not validated".to_string(),
        )),
    }
}

pub(super) async fn import_remote_source(
    state: &AppState,
    instance_id: &str,
    metadata: &InstanceMetadata,
    source: &RemoteImportSource,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    if metadata.status != InstanceStatus::Running {
        return Err(ApiError::BadRequest(format!(
            "remote import requires a running target instance (status={:?})",
            metadata.status
        )));
    }
    match metadata.protocol.engine().family() {
        EngineFamily::Resp => {
            import_resp(state, instance_id, source, options.mode, metadata.protocol).await
        }
        EngineFamily::Vector => {
            import_qdrant(state, instance_id, source, &options.selection, options.mode).await
        }
        EngineFamily::Postgres
        | EngineFamily::Mysql
        | EngineFamily::Document
        | EngineFamily::Columnar => {
            let protocol = metadata.protocol;
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
                metadata,
                &artifact_paths,
                options,
                staged.source_database.as_deref(),
                LogicalStagingLimits::remote(state.config.security.remote_import.max_staged_bytes),
            )
            .await;
            staged.cleanup().await;
            result
        }
    }
}

pub(super) fn validated_upload_staging<'a>(
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

pub(in super::super) fn upload_staging_matches_target(
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

pub(in super::super) fn check_logical_ready(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if metadata.protocol.engine().is_physical() || metadata.status == InstanceStatus::Running {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "instance is not running (status={:?})",
            metadata.status
        )))
    }
}

pub(in super::super) async fn import_artifact(
    state: &AppState,
    instance_id: &str,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
    options: &ImportOptions,
    source_database: Option<&str>,
) -> Result<(), ApiError> {
    let protocol = metadata.protocol;
    if protocol.engine().is_physical() {
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
    } else {
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

pub(super) async fn import_logical(
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

pub(in super::super) fn logical_apply_options(
    options: &ImportOptions,
    remote_dump_was_prefiltered: bool,
) -> ImportOptions {
    let mut apply_options = options.clone();
    if remote_dump_was_prefiltered {
        apply_options.selection = ImportExportSelection::default();
    }
    apply_options
}
