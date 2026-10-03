//! Engine-neutral import/export orchestration around per-engine transfer scripts.

use super::{files::*, *};
use crate::{databases::engine::LogicalImportRequest, server::credentials::logical_import_env};

pub(super) use crate::databases::engine::{ImportConnection, SelectionUse};

pub(super) async fn validate_import_source(
    _state: &AppState,
    target_protocol: Protocol,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    match &options.source {
        ImportSourceOptions::Artifact(path) => {
            if path.as_os_str().is_empty() {
                return Err(ApiError::BadRequest(
                    "artifact import requires source.artifact_id".to_string(),
                ));
            }
            target_protocol
                .engine()
                .validate_artifact_selection(&options.selection)?;
            if target_protocol.engine().is_physical() && options.archive_format.is_some() {
                return Err(ApiError::BadRequest(format!(
                    "{} artifact imports consume their physical archive directly; omit archive_format",
                    target_protocol.as_str()
                )));
            }
        }
        ImportSourceOptions::Upload { upload_id, .. } => {
            if upload_id.is_empty() {
                return Err(ApiError::BadRequest(
                    "upload import requires source.upload_id".to_string(),
                ));
            }
            target_protocol
                .engine()
                .validate_artifact_selection(&options.selection)?;
            if options.archive_format.is_some() {
                return Err(ApiError::BadRequest(
                    "upload imports detect their format from the uploaded file; omit archive_format"
                        .to_string(),
                ));
            }
        }
        ImportSourceOptions::RemoteRequest(_) | ImportSourceOptions::Remote(_) => {
            if options.archive_format.is_some() {
                return Err(ApiError::BadRequest(
                    "remote imports create their own native dump; omit archive_format".to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_source_database(
    target_protocol: Protocol,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    if !matches!(&options.source, ImportSourceOptions::Upload { .. }) {
        if options.source_database.is_some() {
            return Err(ApiError::BadRequest(
                "source.source_database is supported only for temporary uploads".to_string(),
            ));
        }
        return Ok(());
    }
    target_protocol
        .engine()
        .validate_upload_source_database(options.source_database.as_deref())
        .map_err(ApiError::from)
}

pub(super) async fn harden_import_options(
    state: &AppState,
    instance_id: &str,
    target_protocol: Protocol,
    mut options: ImportOptions,
) -> Result<ImportOptions, ApiError> {
    validate_import_source(state, target_protocol, &options).await?;
    validate_source_database(target_protocol, &options)?;
    let source = std::mem::take(&mut options.source);
    options.source = match source {
        ImportSourceOptions::Artifact(path) => {
            ImportSourceOptions::Artifact(validate_artifact_path(state, instance_id, &path).await?)
        }
        ImportSourceOptions::Upload { upload_id, .. } => {
            let (source, archive_format) = super::uploads::harden_upload_source(
                state,
                instance_id,
                target_protocol,
                upload_id,
            )
            .await?;
            options.archive_format = archive_format;
            source
        }
        ImportSourceOptions::RemoteRequest(request) => ImportSourceOptions::Remote(
            validate_remote_source(state, target_protocol, request).await?,
        ),
        ImportSourceOptions::Remote(source) => ImportSourceOptions::Remote(source),
    };
    Ok(options)
}

pub(super) fn export_script(
    metadata: &InstanceMetadata,
    output_path: &str,
    selection: &ImportExportSelection,
    include_database_definition: bool,
) -> Result<String, ApiError> {
    if metadata.deployment_mode == DeploymentMode::Shared && include_database_definition {
        return Err(ApiError::BadRequest(
            "shared logical exports cannot include an administrator database definition"
                .to_string(),
        ));
    }
    metadata
        .protocol
        .engine()
        .logical_export_script(
            metadata,
            output_path,
            selection,
            include_database_definition,
        )
        .map_err(ApiError::from)
}

pub(super) fn wipe_logical_script(
    metadata: &InstanceMetadata,
    database_definition_in_dump: bool,
) -> Result<String, ApiError> {
    if metadata.deployment_mode == DeploymentMode::Shared && database_definition_in_dump {
        return Err(ApiError::BadRequest(
            "shared imports cannot replace an engine-level database definition".to_string(),
        ));
    }
    metadata
        .protocol
        .engine()
        .logical_wipe_script(metadata, database_definition_in_dump)
        .map_err(ApiError::from)
}

pub(super) async fn wipe_logical_target(
    state: &AppState,
    metadata: &InstanceMetadata,
    exec_timeout: Option<Duration>,
    database_definition_in_dump: bool,
) -> Result<(), super::shared_restore::RestoreError> {
    let timeout = exec_timeout.unwrap_or(LOGICAL_STREAM_EXEC_TIMEOUT);
    let script = wipe_logical_script(metadata, database_definition_in_dump)?;
    if metadata.deployment_mode == DeploymentMode::Shared
        && metadata.protocol.engine().shared_wipe_uses_admin_runtime()
    {
        return super::shared_restore::wipe_clickhouse(state, metadata, timeout).await;
    }
    let credentials = logical_import_env(metadata, database_definition_in_dump)
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    let environment = credentials.references();
    let result = match logical_exec_recovery(metadata) {
        ExecRecovery::RestartRuntime => {
            state
                .docker
                .exec_shell_with_secrets_timeout(
                    metadata.protocol,
                    metadata.runtime_id(),
                    &script,
                    &environment,
                    timeout,
                )
                .await
        }
        ExecRecovery::CallerHandles => {
            state
                .docker
                .exec_tenant_shell(
                    metadata.protocol,
                    metadata.runtime_id(),
                    &script,
                    &environment,
                    timeout,
                )
                .await
        }
    };
    result.map_err(|error| {
        ApiError::Runtime(format!(
            "failed to wipe {} target before import: {error}",
            metadata.protocol.as_str()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
pub(super) fn import_script(
    metadata: &InstanceMetadata,
    input_path: &str,
    source_database: Option<&str>,
    selection: &ImportExportSelection,
    database_definition_in_dump: bool,
) -> Result<String, ApiError> {
    build_import_script(
        metadata,
        input_path,
        source_database,
        selection,
        database_definition_in_dump,
        None,
        ImportConnection::LocalSocket,
    )
}

pub(super) fn build_import_script(
    metadata: &InstanceMetadata,
    input_path: &str,
    source_database: Option<&str>,
    selection: &ImportExportSelection,
    database_definition_in_dump: bool,
    postgres_wrapper_lines: Option<(u64, u64)>,
    connection: ImportConnection,
) -> Result<String, ApiError> {
    if metadata.deployment_mode == DeploymentMode::Shared && database_definition_in_dump {
        return Err(ApiError::BadRequest(
            "shared imports cannot execute an administrator database definition".to_string(),
        ));
    }
    metadata
        .protocol
        .engine()
        .logical_import_script(&LogicalImportRequest {
            metadata,
            input_path,
            source_database,
            selection,
            database_definition_in_dump,
            postgres_wrapper_lines,
            connection,
        })
        .map_err(ApiError::from)
}
