use super::*;

#[derive(Clone, Copy, Default)]
pub(in super::super) struct LogicalExportControls {
    pub(super) max_output_bytes: Option<u64>,
    pub(super) exec_timeout: Option<Duration>,
    pub(super) include_database_definition: bool,
}

impl LogicalExportControls {
    pub(in super::super) fn with_max_output_bytes(max_output_bytes: u64) -> Self {
        Self {
            max_output_bytes: Some(max_output_bytes),
            ..Self::default()
        }
    }
}

pub(in super::super) async fn export_logical_dump(
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
pub(in super::super) struct LogicalImportControls<'a> {
    pub(super) source_database: Option<&'a str>,
    pub(super) reuse_staged_artifact: bool,
    pub(super) database_definition_in_dump: bool,
    pub(super) exec_timeout: Option<Duration>,
    pub(super) remove_uploaded_source_limit: Option<u64>,
    pub(super) max_prepared_bytes: Option<u64>,
}

pub(in super::super) async fn import_logical_dump(
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

pub(super) async fn prepare_logical_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    protocol: Protocol,
    artifact_path: &FsPath,
    options: &ImportOptions,
    controls: LogicalImportControls<'_>,
) -> Result<PreparedLogicalImport, ApiError> {
    protocol
        .engine()
        .validate_artifact_selection(&options.selection)?;
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
    let owns_host_temp = !controls.reuse_staged_artifact;
    if prepared_source_bytes > max_prepared_bytes {
        discard_owned_temp(&host_temp, owns_host_temp).await;
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

    let postgres_wrapper_lines = if protocol.engine().family().is_postgres() {
        match super::postgres_dump::wrapper_lines(&host_temp, prepared_source_bytes).await {
            Ok(lines) => lines,
            Err(error) => {
                discard_owned_temp(&host_temp, owns_host_temp).await;
                return Err(error);
            }
        }
    } else {
        None
    };
    let shared_restore = metadata.deployment_mode == DeploymentMode::Shared;
    let expected_sha256 = if shared_restore {
        Some(
            inspect_shared_import_digest(
                &host_temp,
                owns_host_temp,
                metadata,
                protocol,
                controls.source_database,
                postgres_wrapper_lines,
            )
            .await?,
        )
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
            discard_owned_temp(&host_temp, owns_host_temp).await;
            return Err(error);
        }
    };
    let pinned_input = pin_prepared_source(
        state,
        &host_temp,
        prepared_source_bytes,
        expected_sha256,
        owns_host_temp,
    )
    .await?;
    let staged_source_bytes = if controls.remove_uploaded_source_limit.is_some() {
        if owns_host_temp {
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
        owns_host_temp,
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

pub(super) async fn discard_owned_temp(host_temp: &FsPath, owns_host_temp: bool) {
    if owns_host_temp {
        cleanup_path(host_temp).await;
    }
}

pub(super) async fn inspect_shared_import_digest(
    host_temp: &FsPath,
    owns_host_temp: bool,
    metadata: &InstanceMetadata,
    protocol: Protocol,
    source_database: Option<&str>,
    postgres_wrapper_lines: Option<(u64, u64)>,
) -> Result<[u8; 32], ApiError> {
    use super::inspection::shared_import::{
        SharedImportLayout, SharedImportRequest, validate_shared_import,
    };
    let archive_format = if protocol.engine().native_gzip_logical_dump() {
        "gzip"
    } else {
        "plain"
    };
    let approval = match validate_shared_import(
        host_temp,
        SharedImportRequest {
            protocol,
            target_database: &metadata.database.name,
            source_database,
            layout: SharedImportLayout::LogicalDump,
            archive_format: Some(archive_format),
            postgres_wrapper_lines,
        },
    )
    .await
    {
        Ok(approval) => approval,
        Err(error) => {
            discard_owned_temp(host_temp, owns_host_temp).await;
            return Err(ApiError::BadRequest(format!(
                "shared import was rejected ({:?}): {error}",
                error.reason
            )));
        }
    };
    if !approval.requires_isolated_staging || !approval.restore_as_tenant {
        discard_owned_temp(host_temp, owns_host_temp).await;
        return Err(ApiError::Runtime(
            "shared import inspection did not require isolated tenant restore".to_string(),
        ));
    }
    parse_sha256(&approval.sha256).ok_or_else(|| {
        ApiError::Runtime("shared import inspection returned an invalid digest".to_string())
    })
}
