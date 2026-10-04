use std::path::{Path as FsPath, PathBuf};

use crate::{
    routes::http::{response::ApiError, router::AppState},
    server::{metadata::InstanceMetadata, placement::DeploymentMode},
};

use super::{
    super::{ExportOptions, ImportOptions},
    batch::import_logical_batch,
    dump::{
        LogicalExportControls, LogicalImportControls, export_logical_dump, import_logical_dump,
    },
    staging::LogicalStagingLimits,
};

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
