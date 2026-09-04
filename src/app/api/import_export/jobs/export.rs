use super::*;

const LOGICAL_EXPORT_BASE_ALLOWANCE_BYTES: u64 = 64 * 1024 * 1024;

pub(super) async fn estimate_export_cost(
    state: &AppState,
    metadata: &InstanceMetadata,
    options: &ExportOptions,
) -> JobResourceCost {
    let allocated_bytes = mib_to_bytes(metadata.limits.disk_mib)
        .min(crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES);
    let input_size_bytes = if metadata.deployment_mode == DeploymentMode::Shared {
        measure_shared_database_bytes(state, metadata)
            .await
            .unwrap_or(allocated_bytes)
    } else {
        match InstancePaths::new(&state.config.paths, &metadata.instance_id) {
            Ok(paths) => state
                .resource_cache
                .disk_usage(&state.config, &metadata.instance_id, paths.data)
                .await
                .map(|usage| usage.used_bytes)
                .unwrap_or(allocated_bytes),
            Err(_) => allocated_bytes,
        }
    }
    .clamp(1, crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES);
    JobResourceCost::estimate(JobEstimateInput {
        protocol: metadata.protocol,
        input_size_bytes,
        rollback_size_bytes: 0,
        wipe: false,
        compressed: protocol_uses_native_compression(metadata.protocol)
            || options.archive_format != ExportArchiveFormat::Plain,
        export: true,
    })
}

pub(super) async fn export_artifact(
    state: &AppState,
    instance_id: &str,
    artifact_path: PathBuf,
    options: &ExportOptions,
) -> Result<(), ApiError> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let reservations = reserve_export_capacity(state, &metadata, &artifact_path, options).await?;
    write_reserved_export(
        state,
        &metadata,
        artifact_path,
        options,
        reservations.logical_output_capacity,
    )
    .await
}

pub(super) struct ExportOutputReservations {
    _artifact: super::uploads::DiskCapacityReservation,
    _staging: Option<super::uploads::DiskCapacityReservation>,
    pub(super) logical_output_capacity: Option<u64>,
}

pub(in crate::api::import_export) fn estimate_export_bytes(
    protocol: Protocol,
    database_used_bytes: u64,
) -> u64 {
    let expansion_factor = match protocol {
        Protocol::Mongodb => 2,
        Protocol::Postgres | Protocol::Mariadb | Protocol::Mysql | Protocol::Clickhouse => 4,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => 1,
    };
    database_used_bytes
        .saturating_mul(expansion_factor)
        .saturating_add(LOGICAL_EXPORT_BASE_ALLOWANCE_BYTES)
        .clamp(LOGICAL_EXPORT_BASE_ALLOWANCE_BYTES, MAX_UNARCHIVED_BYTES)
}

pub(in crate::api::import_export) fn needs_separate_export_staging(
    archive_format: ExportArchiveFormat,
    roots_share_filesystem: bool,
) -> bool {
    archive_format != ExportArchiveFormat::Plain || !roots_share_filesystem
}

pub(crate) async fn measure_export_bytes(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<u64, ApiError> {
    if metadata.deployment_mode == DeploymentMode::Shared {
        return Ok(estimate_export_bytes(
            metadata.protocol,
            measure_shared_database_bytes(state, metadata).await?,
        ));
    }
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let database_used_bytes = state
        .resource_cache
        .fresh_disk_usage(&state.config, &metadata.instance_id, paths.data)
        .await
        .map_err(|error| {
            ApiError::ServiceUnavailable(format!(
                "database disk usage is not available for export sizing: {error}; retry shortly"
            ))
        })?
        .used_bytes;
    Ok(estimate_export_bytes(
        metadata.protocol,
        database_used_bytes,
    ))
}

pub(crate) async fn measure_shared_database_bytes(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<u64, ApiError> {
    if metadata.deployment_mode != DeploymentMode::Shared {
        return Err(ApiError::Runtime(
            "shared export sizing received a dedicated instance".to_string(),
        ));
    }
    let runtime = state
        .placements
        .get(metadata.runtime_id())
        .await
        .map_err(|error| {
            ApiError::ServiceUnavailable(format!(
                "shared tenant size runtime is not available: {error}"
            ))
        })?
        .ok_or_else(|| {
            ApiError::ServiceUnavailable("shared tenant size runtime is missing".to_string())
        })?;
    if runtime.deployment_mode != DeploymentMode::Shared
        || runtime.runtime_id != metadata.runtime_id()
        || runtime.protocol != metadata.protocol
        || runtime.status != crate::placement::EngineRuntimeStatus::Running
    {
        return Err(ApiError::ServiceUnavailable(
            "shared tenant size runtime is not an eligible running pool".to_string(),
        ));
    }
    let target = crate::placement::tenant::TenantTarget {
        database: &metadata.database.name,
        username: &metadata.database.username,
    };
    crate::placement::tenant::measure_storage(&state.docker, &runtime, &[target])
        .await
        .map_err(|error| {
            ApiError::ServiceUnavailable(format!(
                "shared tenant size is not available for export sizing: {error}"
            ))
        })?
        .into_iter()
        .next()
        .ok_or_else(|| {
            ApiError::ServiceUnavailable("shared tenant size query returned no result".to_string())
        })
}

pub(super) async fn reserve_export_capacity(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
    options: &ExportOptions,
) -> Result<ExportOutputReservations, ApiError> {
    check_logical_ready(metadata)?;
    if options.delivery.is_client() {
        crate::api::artifacts::check_export_slot(state, &metadata.instance_id).await?;
    }
    let artifact_root = artifact_path
        .parent()
        .ok_or_else(|| ApiError::Runtime("export artifact has no parent directory".to_string()))?;
    let physical = matches!(
        metadata.protocol,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    );
    let logical_output_capacity = if physical {
        None
    } else {
        Some(measure_export_bytes(state, metadata).await?)
    };
    let output_capacity = match logical_output_capacity {
        None => mib_to_bytes(metadata.limits.disk_mib)
            .saturating_add(64 * 1024 * 1024)
            .clamp(1, crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES),
        Some(logical_output_capacity) => {
            export_artifact_capacity_bytes(logical_output_capacity, options.archive_format)
                .ok_or_else(|| {
                    ApiError::Runtime("export artifact capacity calculation overflowed".to_string())
                })?
        }
    };
    let _artifact_capacity = state
        .import_uploads
        .reserve_output_capacity(artifact_root, output_capacity)
        .await?;
    let staging = if let Some(logical_output_capacity) = logical_output_capacity {
        let staging_root = logical_staging_root(state).await?;
        let roots_share_filesystem = state
            .import_uploads
            .output_roots_share_filesystem(artifact_root, &staging_root)
            .await?;
        if needs_separate_export_staging(options.archive_format, roots_share_filesystem) {
            Some(
                state
                    .import_uploads
                    .reserve_output_capacity(&staging_root, logical_output_capacity)
                    .await?,
            )
        } else {
            None
        }
    } else {
        None
    };
    Ok(ExportOutputReservations {
        _artifact: _artifact_capacity,
        _staging: staging,
        logical_output_capacity,
    })
}

pub(super) async fn write_reserved_export(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: PathBuf,
    options: &ExportOptions,
    logical_output_capacity: Option<u64>,
) -> Result<(), ApiError> {
    match metadata.protocol {
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => {
            export_physical_archive(
                state,
                &metadata.instance_id,
                metadata.protocol,
                artifact_path,
                &options.selection,
            )
            .await
        }
        protocol => {
            let controls = logical_output_capacity
                .map(LogicalExportControls::with_max_output_bytes)
                .unwrap_or_default();
            export_logical_dump(state, metadata, protocol, artifact_path, options, controls).await
        }
    }
}

pub(super) async fn export_artifact_path(
    state: &AppState,
    instance_id: &str,
    protocol: Protocol,
    archive_format: ExportArchiveFormat,
    delivery: ExportDelivery,
) -> Result<PathBuf, ApiError> {
    crate::shared::ids::validate_instance_id(instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let export_root = if delivery.is_one_use() {
        crate::api::artifacts::instance_spool_root(state, instance_id)
    } else {
        crate::api::artifacts::instance_export_root(state, instance_id)
    };
    prepare_private_dir(&export_root, "export directory").await?;
    let artifact_id = uuid::Uuid::new_v4();
    Ok(export_root.join(format!(
        "{}.{}{}",
        artifact_id,
        dump_extension(protocol),
        archive_format.suffix()
    )))
}
