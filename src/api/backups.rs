use std::{
    path::{Path as FsPath, PathBuf},
    time::Duration,
};

use axum::extract::State;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::{
    api::{
        api_response::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResponse, ApiResult},
        artifacts::{ArtifactInfo, DeleteArtifactResponse},
        public_diagnostic::PublicDiagnostic,
        routes::AppState,
        security_policy::{
            ApiRequestContext, DestructiveActionConfirmation, DestructiveActionPolicy,
        },
    },
    auth::scopes,
    backups::{
        BackupBundle, BackupStorage, BackupStoreError, MaterializedBackup, StoredBackup,
        build_manifest,
        catalog::{BackupCatalog, BackupCatalogColumn},
        ensure_private_directory, new_backup_id,
    },
    instances::metadata::{InstanceMetadata, InstanceStatus},
    jobs::import_export::{
        ArchiveSymlinkPolicy, DataArchiveSourcePolicy, ImportExportJobPermit, JobAdmissionError,
        JobEstimateInput, JobResourceCost, SchedulerAcquireError,
        create_data_archive_with_policy_bounded,
    },
    shared::{ids::validate_instance_id, protocol::Protocol},
};

#[derive(Debug, Serialize)]
pub struct BackupStatusResponse {
    pub enabled: bool,
    pub interval_minutes: u64,
    pub run_on_startup: bool,
    pub retention_keep_latest_per_instance: usize,
    pub retention_max_age_days: u64,
    pub redis_excluded: bool,
    pub storage_driver: String,
    pub browsing_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct RunBackupResponse {
    pub backups: Vec<ArtifactInfo>,
    pub skipped: Vec<SkippedBackup>,
}

#[derive(Debug, Serialize)]
pub struct RestoreBackupResponse {
    pub instance_id: String,
    pub backup_id: String,
    pub restored: bool,
}

#[derive(Debug, Serialize)]
pub struct SkippedBackup {
    pub instance_id: String,
    pub protocol: Protocol,
    pub reason: PublicDiagnostic,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct BackupContentsQuery {
    pub object: Option<String>,
    pub offset: usize,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct BackupContentsResponse {
    pub backup_id: String,
    pub instance_id: String,
    pub protocol: Protocol,
    pub database_name: String,
    pub captured_at: Option<String>,
    pub consistency: Option<String>,
    pub catalog_available: bool,
    pub truncated: bool,
    pub warnings: Vec<String>,
    pub objects: Vec<BackupObjectSummary>,
    pub selection: Option<BackupObjectSelection>,
}

#[derive(Debug, Serialize)]
pub struct BackupObjectSummary {
    pub id: String,
    pub namespace: String,
    pub name: String,
    pub kind: String,
    pub estimated_rows: Option<u64>,
    pub columns: Vec<BackupCatalogColumn>,
    pub captured_preview_rows: usize,
    pub preview_truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct BackupObjectSelection {
    pub object_id: String,
    pub offset: usize,
    pub limit: usize,
    pub returned: usize,
    pub total_captured: usize,
    pub rows: Vec<serde_json::Value>,
    pub truncated: bool,
}

pub async fn backup_status(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<BackupStatusResponse> {
    auth.require_scope(scopes::BACKUPS_ADMIN)?;
    Ok(ApiResponse::ok(BackupStatusResponse {
        enabled: state.config.backups.enabled,
        interval_minutes: state.config.backups.interval_minutes,
        run_on_startup: state.config.backups.run_on_startup,
        retention_keep_latest_per_instance: state.config.backups.retention_keep_latest_per_instance,
        retention_max_age_days: state.config.backups.retention_max_age_days,
        redis_excluded: false,
        storage_driver: state.config.backups.storage.driver.as_str().to_string(),
        browsing_enabled: state.config.backups.browsing.enabled,
    }))
}

pub async fn list_instance_backups(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<Vec<ArtifactInfo>> {
    auth.require_scope(scopes::BACKUPS_READ)?;
    ensure_instance_exists(&state, &instance_id).await?;
    let storage = backup_storage(&state)?;
    let backups = storage
        .list(&instance_id)
        .await
        .map_err(store_error)?
        .into_iter()
        .map(artifact_info)
        .collect();
    Ok(ApiResponse::ok(backups))
}

pub async fn browse_instance_backup(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, backup_id)): ApiPath<(String, String)>,
    ApiQuery(query): ApiQuery<BackupContentsQuery>,
) -> ApiResult<BackupContentsResponse> {
    auth.require_scope(scopes::BACKUPS_READ)?;
    let metadata = ensure_instance_exists(&state, &instance_id).await?;
    let limit = query.limit.unwrap_or(25);
    if limit == 0 || limit > 100 {
        return Err(ApiError::BadRequest(
            "limit must be between 1 and 100".to_string(),
        ));
    }
    if query
        .object
        .as_ref()
        .is_some_and(|object| object.len() > 1024)
    {
        return Err(ApiError::BadRequest(
            "object is longer than 1024 bytes".to_string(),
        ));
    }

    let storage = backup_storage(&state)?;
    let backup = storage
        .find(&instance_id, &backup_id)
        .await
        .map_err(store_error)?;
    let bytes = storage
        .read_catalog(
            &instance_id,
            &backup_id,
            state.config.backups.browsing.max_catalog_bytes,
            FsPath::new(&state.config.paths.tmp_root()),
        )
        .await
        .map_err(store_error)?;
    let Some(bytes) = bytes else {
        return Ok(ApiResponse::ok(BackupContentsResponse {
            backup_id,
            instance_id,
            protocol: backup.protocol.unwrap_or(metadata.protocol),
            database_name: metadata.database.name,
            captured_at: None,
            consistency: None,
            catalog_available: false,
            truncated: false,
            warnings: vec![
                "this backup predates catalog capture or browsing was disabled when it was created"
                    .to_string(),
            ],
            objects: Vec::new(),
            selection: None,
        }));
    };
    let catalog = BackupCatalog::decode_and_validate(&bytes, &instance_id, &backup_id)
        .map_err(ApiError::Runtime)?;
    let selection = select_catalog_object(&catalog, query.object.as_deref(), query.offset, limit)?;
    let objects = catalog
        .objects
        .iter()
        .map(|object| BackupObjectSummary {
            id: object.id.clone(),
            namespace: object.namespace.clone(),
            name: object.name.clone(),
            kind: object.kind.clone(),
            estimated_rows: object.estimated_rows,
            columns: object.columns.clone(),
            captured_preview_rows: object.preview_rows.len(),
            preview_truncated: object.preview_truncated,
        })
        .collect();
    Ok(ApiResponse::ok(BackupContentsResponse {
        backup_id,
        instance_id,
        protocol: catalog.protocol,
        database_name: catalog.database_name,
        captured_at: Some(catalog.captured_at),
        consistency: Some(catalog.consistency),
        catalog_available: true,
        truncated: catalog.truncated,
        warnings: catalog.warnings,
        objects,
        selection,
    }))
}

pub async fn run_instance_backup(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<ArtifactInfo> {
    auth.require_scope(scopes::BACKUPS_WRITE)?;
    Ok(ApiResponse::ok(
        backup_instance(&state, &instance_id).await?,
    ))
}

pub async fn run_all_backups(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<RunBackupResponse> {
    auth.require_scope(scopes::BACKUPS_ADMIN)?;
    Ok(ApiResponse::ok(backup_all_instances(&state).await))
}

pub async fn delete_instance_backup(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, backup_id)): ApiPath<(String, String)>,
) -> ApiResult<DeleteArtifactResponse> {
    auth.require_scope(scopes::BACKUPS_WRITE)?;
    ensure_instance_exists(&state, &instance_id).await?;
    let storage = backup_storage(&state)?;
    storage
        .delete(&instance_id, &backup_id)
        .await
        .map_err(store_error)?;
    tracing::info!(
        event = "audit backup_deleted",
        instance_id,
        backup_id,
        storage = storage.kind().as_str()
    );
    Ok(ApiResponse::ok(DeleteArtifactResponse {
        id: backup_id,
        deleted: true,
    }))
}

pub async fn restore_instance_backup(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, backup_id)): ApiPath<(String, String)>,
    ApiJson(confirmation): ApiJson<DestructiveActionConfirmation>,
) -> ApiResult<RestoreBackupResponse> {
    auth.require_scope(scopes::RECOVERY_ADMIN)?;
    let authorization = DestructiveActionPolicy::authorize("backup restore", &confirmation)?;
    let admission = admit_backup_operation(&state, &instance_id)?;
    let state = state.clone();
    let reason = authorization.reason().to_string();
    tokio::spawn(async move {
        restore_instance_backup_admitted(state, instance_id, backup_id, reason, admission).await
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("backup restore task failed: {error}")))?
}

async fn restore_instance_backup_admitted(
    state: AppState,
    instance_id: String,
    backup_id: String,
    reason: String,
    _admission: ImportExportJobPermit,
) -> ApiResult<RestoreBackupResponse> {
    let _operation = state.instance_locks.lock(&instance_id).await;
    ensure_operation_can_start(&state)?;
    let metadata = crate::api::instances::reconcile_instance_locked(&state, &instance_id).await?;
    let paths = crate::instances::paths::InstancePaths::new(&state.config.paths, &instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    crate::api::import_export::verify_physical_data_replacement(&state, &metadata, &paths)?;
    let storage = backup_storage(&state)?;
    let stored = storage
        .find(&instance_id, &backup_id)
        .await
        .map_err(store_error)?;
    let restore_size_bytes = stored.size_bytes.max(
        metadata
            .limits
            .disk_mib
            .saturating_mul(1024 * 1024)
            .min(crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES),
    );
    let _execution = state
        .import_export_jobs
        .acquire_execution(JobResourceCost::estimate(JobEstimateInput {
            protocol: metadata.protocol,
            input_size_bytes: restore_size_bytes.max(1),
            rollback_size_bytes: 0,
            wipe: true,
            compressed: true,
            export: false,
        }))
        .await
        .map_err(scheduler_execution_error)?;
    let data_parent = paths.data.parent().ok_or_else(|| {
        ApiError::Runtime("backup restore data directory has no parent".to_string())
    })?;
    let extracted_capacity = metadata
        .limits
        .disk_mib
        .saturating_mul(1024 * 1024)
        .clamp(1, crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES);
    let _extracted_capacity = state
        .import_uploads
        .reserve_output_capacity(data_parent, extracted_capacity)
        .await?;
    let temporary_capacity = if storage.kind() == crate::config::BackupStorageDriver::Local {
        None
    } else {
        let temporary_root = PathBuf::from(state.config.paths.tmp_root());
        ensure_private_directory(&temporary_root, "backup materialization directory")
            .await
            .map_err(store_error)?;
        Some(
            state
                .import_uploads
                .reserve_output_capacity(&temporary_root, stored.size_bytes.max(1))
                .await?,
        )
    };
    let materialized = storage
        .materialize(
            &instance_id,
            &backup_id,
            FsPath::new(&state.config.paths.tmp_root()),
        )
        .await
        .map_err(store_error)?;
    let _temporary_capacity = temporary_capacity;
    let was_running = metadata.status == InstanceStatus::Running;
    if was_running
        && let Err(error) = crate::api::instances::lifecycle_instance_locked(
            &state,
            &instance_id,
            crate::api::instances::LifecycleAction::Stop,
        )
        .await
    {
        materialized.cleanup().await;
        return Err(error);
    }
    let finished = crate::api::import_export::restore_data_from_archive_bounded(
        &state,
        &instance_id,
        paths,
        &materialized.path,
        was_running,
        extracted_capacity,
        ArchiveSymlinkPolicy::PreserveValidated,
    )
    .await;
    materialized.cleanup().await;
    finished?;
    tracing::info!(
        event = "audit backup_restored",
        instance_id,
        backup_id,
        reason,
        storage = storage.kind().as_str(),
    );
    Ok(ApiResponse::ok(RestoreBackupResponse {
        instance_id,
        backup_id,
        restored: true,
    }))
}

pub(crate) async fn backup_instance(
    state: &AppState,
    instance_id: &str,
) -> Result<ArtifactInfo, ApiError> {
    let admission = admit_backup_operation(state, instance_id)?;
    let state = state.clone();
    let instance_id = instance_id.to_string();
    tokio::spawn(async move { backup_instance_admitted(state, instance_id, admission).await })
        .await
        .map_err(|error| ApiError::Runtime(format!("backup task failed: {error}")))?
}

async fn backup_instance_admitted(
    state: AppState,
    instance_id: String,
    _admission: ImportExportJobPermit,
) -> Result<ArtifactInfo, ApiError> {
    let _operation = state.instance_locks.lock(&instance_id).await;
    ensure_operation_can_start(&state)?;
    let metadata = crate::api::instances::reconcile_instance_locked(&state, &instance_id).await?;
    validate_backup_eligible(&metadata)?;
    let _execution = state
        .import_export_jobs
        .acquire_execution(JobResourceCost::estimate(JobEstimateInput {
            protocol: metadata.protocol,
            input_size_bytes: metadata.limits.disk_mib.saturating_mul(1024 * 1024).max(1),
            rollback_size_bytes: 0,
            wipe: false,
            compressed: true,
            export: true,
        }))
        .await
        .map_err(scheduler_execution_error)?;
    let storage = backup_storage(&state)?;
    let backup_id = new_backup_id();
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
    let output_capacity = metadata
        .limits
        .disk_mib
        .saturating_mul(1024 * 1024)
        .saturating_add(64 * 1024 * 1024)
        .clamp(1, crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES);
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
    if let Some(catalog) = catalog.as_deref()
        && let Err(error) = bundle.write_catalog(catalog).await
    {
        bundle.cleanup().await;
        return Err(store_error(error));
    }

    let result = create_physical_archive(&state, &metadata, &bundle.archive, output_capacity).await;
    if let Err(error) = result {
        bundle.cleanup().await;
        return Err(error);
    }
    let manifest = match build_manifest(
        backup_id.clone(),
        instance_id.clone(),
        metadata.protocol,
        &bundle.archive,
        catalog.is_some(),
    )
    .await
    {
        Ok(manifest) => manifest,
        Err(error) => {
            bundle.cleanup().await;
            return Err(store_error(error));
        }
    };
    if let Err(error) = bundle.write_metadata(&manifest).await {
        bundle.cleanup().await;
        return Err(store_error(error));
    }
    if let Err(error) = storage.commit(&bundle, &manifest).await {
        bundle.cleanup().await;
        return Err(store_error(error));
    }
    bundle.cleanup().await;
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
        backup_id,
        storage = storage.kind().as_str(),
        catalog = manifest.catalog_available,
    );
    Ok(artifact_info(manifest))
}

async fn create_physical_archive(
    state: &AppState,
    metadata: &InstanceMetadata,
    archive: &FsPath,
    max_output_bytes: u64,
) -> Result<(), ApiError> {
    let instance_id = &metadata.instance_id;
    let was_running = metadata.status == InstanceStatus::Running;
    if was_running {
        crate::api::instances::lifecycle_instance_locked(
            state,
            instance_id,
            crate::api::instances::LifecycleAction::Stop,
        )
        .await?;
    }
    let paths = crate::instances::paths::InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let archive_policy = if metadata.protocol == Protocol::Mysql {
        DataArchiveSourcePolicy::MysqlDataDirectory
    } else {
        DataArchiveSourcePolicy::Strict
    };
    let result = create_data_archive_with_policy_bounded(
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
    crate::api::import_export::finish_physical_operation(state, instance_id, was_running, result)
        .await
}

pub(crate) async fn backup_all_instances(state: &AppState) -> RunBackupResponse {
    let mut backups = Vec::new();
    let mut skipped = Vec::new();
    for metadata in state.instances.list().await {
        match backup_instance(state, &metadata.instance_id).await {
            Ok(response) => backups.push(response),
            Err(error) => {
                tracing::warn!(
                    event = "audit instance_backup_skipped",
                    instance_id = metadata.instance_id,
                    protocol = metadata.protocol.as_str(),
                    error = %error,
                    "instance backup was skipped"
                );
                skipped.push(SkippedBackup {
                    instance_id: metadata.instance_id,
                    protocol: metadata.protocol,
                    reason: PublicDiagnostic::from_api_error("instance backup", &error),
                });
            }
        }
    }
    tracing::info!(
        event = "audit backups_completed",
        backups = backups.len(),
        skipped = skipped.len(),
    );
    RunBackupResponse { backups, skipped }
}

pub fn start_scheduler(state: AppState) {
    if !state.config.backups.enabled {
        tracing::info!("automatic backups disabled");
        return;
    }
    let interval = Duration::from_secs(state.config.backups.interval_minutes.saturating_mul(60));
    let run_on_startup = state.config.backups.run_on_startup;
    let mut shutdown = state.gateway_supervisor.subscribe_shutdown();
    tokio::spawn(async move {
        tracing::info!(
            interval_minutes = state.config.backups.interval_minutes,
            run_on_startup,
            storage = state.config.backups.storage.driver.as_str(),
            "automatic backups enabled"
        );
        if run_on_startup && !*shutdown.borrow() {
            run_scheduled_backup_pass(&state).await;
        }
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("automatic backup scheduler stopped");
                        break;
                    }
                }
                () = sleep(interval) => run_scheduled_backup_pass(&state).await,
            }
        }
    });
}

pub(crate) async fn materialize_backup_for_download(
    state: &AppState,
    instance_id: &str,
    backup_id: &str,
) -> Result<MaterializedBackup, ApiError> {
    let storage = backup_storage(state)?;
    storage
        .materialize(
            instance_id,
            backup_id,
            FsPath::new(&state.config.paths.tmp_root()),
        )
        .await
        .map_err(store_error)
}

pub(crate) async fn ensure_backup_exists(
    state: &AppState,
    instance_id: &str,
    backup_id: &str,
) -> Result<(), ApiError> {
    backup_storage(state)?
        .find(instance_id, backup_id)
        .await
        .map(|_| ())
        .map_err(store_error)
}

pub(crate) async fn purge_instance_backups(
    state: &AppState,
    instance_id: &str,
) -> Result<usize, ApiError> {
    backup_storage(state)?
        .delete_instance(instance_id)
        .await
        .map_err(store_error)
}

fn backup_storage(state: &AppState) -> Result<BackupStorage, ApiError> {
    BackupStorage::from_config(&state.config).map_err(store_error)
}

async fn prune_instance_backups(
    state: &AppState,
    storage: &BackupStorage,
    instance_id: &str,
) -> Result<(), ApiError> {
    let keep_latest = state.config.backups.retention_keep_latest_per_instance;
    let max_age_seconds = state
        .config
        .backups
        .retention_max_age_days
        .saturating_mul(24 * 60 * 60);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut backups = storage.list(instance_id).await.map_err(store_error)?;
    backups.sort_by_key(|backup| std::cmp::Reverse(backup.created_at_unix));
    let mut deleted = 0_usize;
    for (index, backup) in backups.into_iter().enumerate() {
        let expired = max_age_seconds > 0
            && now.saturating_sub(backup.created_at_unix)
                > i64::try_from(max_age_seconds).unwrap_or(i64::MAX);
        if index >= keep_latest || expired {
            storage
                .delete(instance_id, &backup.backup_id)
                .await
                .map_err(store_error)?;
            deleted += 1;
        }
    }
    tracing::info!(
        event = "audit backup_retention_pruned",
        instance_id,
        keep_latest,
        max_age_days = state.config.backups.retention_max_age_days,
        deleted,
        storage = storage.kind().as_str(),
    );
    Ok(())
}

fn select_catalog_object(
    catalog: &BackupCatalog,
    object_id: Option<&str>,
    offset: usize,
    limit: usize,
) -> Result<Option<BackupObjectSelection>, ApiError> {
    let Some(object_id) = object_id else {
        if offset != 0 {
            return Err(ApiError::BadRequest(
                "offset requires an object selection".to_string(),
            ));
        }
        return Ok(None);
    };
    let object = catalog
        .objects
        .iter()
        .find(|object| object.id == object_id)
        .ok_or(ApiError::NotFound)?;
    let rows = object
        .preview_rows
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    Ok(Some(BackupObjectSelection {
        object_id: object.id.clone(),
        offset,
        limit,
        returned: rows.len(),
        total_captured: object.preview_rows.len(),
        rows,
        truncated: object.preview_truncated
            || offset.saturating_add(limit) < object.preview_rows.len(),
    }))
}

fn artifact_info(backup: StoredBackup) -> ArtifactInfo {
    ArtifactInfo {
        id: backup.backup_id,
        instance_id: backup.instance_id,
        size_bytes: backup.size_bytes,
        modified_at: backup.created_at,
        sha256: backup.sha256,
    }
}

fn validate_backup_eligible(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if metadata.status != InstanceStatus::Running {
        return Err(ApiError::BadRequest(format!(
            "instance is not running (status={:?})",
            metadata.status
        )));
    }
    Ok(())
}

async fn ensure_instance_exists(
    state: &AppState,
    instance_id: &str,
) -> Result<InstanceMetadata, ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)
}

fn admit_backup_operation(
    state: &AppState,
    instance_id: &str,
) -> Result<ImportExportJobPermit, ApiError> {
    state
        .import_export_jobs
        .try_admit_exclusive(instance_id)
        .map_err(|error| match error {
            JobAdmissionError::GlobalCapacity => ApiError::RateLimited,
            JobAdmissionError::InstanceCapacity => ApiError::Conflict(format!(
                "instance {instance_id} already has the maximum number of queued data operations"
            )),
            JobAdmissionError::ShuttingDown => {
                ApiError::ServiceUnavailable("the daemon is shutting down".to_string())
            }
        })
}

fn scheduler_execution_error(error: SchedulerAcquireError) -> ApiError {
    match error {
        SchedulerAcquireError::Closed => {
            ApiError::ServiceUnavailable("the daemon is shutting down".to_string())
        }
        SchedulerAcquireError::InsufficientCapacity => ApiError::Conflict(
            "the estimated backup operation exceeds a fixed dynamic import/export scheduler budget; increase the configured budget or reduce the instance allocation"
                .to_string(),
        ),
    }
}

fn ensure_operation_can_start(state: &AppState) -> Result<(), ApiError> {
    if state.import_export_jobs.is_accepting() {
        Ok(())
    } else {
        Err(ApiError::ServiceUnavailable(
            "the daemon is shutting down".to_string(),
        ))
    }
}

async fn run_scheduled_backup_pass(state: &AppState) {
    let response = backup_all_instances(state).await;
    tracing::info!(
        event = "audit scheduled_backup_pass",
        backups = response.backups.len(),
        skipped = response.skipped.len(),
    );
}

fn store_error(error: BackupStoreError) -> ApiError {
    match error {
        BackupStoreError::InvalidBackupId => ApiError::BadRequest("invalid backup id".to_string()),
        BackupStoreError::NotFound => ApiError::NotFound,
        error => ApiError::Runtime(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_selection_is_bounded_and_object_scoped() {
        let catalog = BackupCatalog {
            schema_version: crate::backups::catalog::BACKUP_CATALOG_SCHEMA_VERSION,
            backup_id: "one.physical.tar.gz".to_string(),
            instance_id: "inst_one".to_string(),
            protocol: Protocol::Postgres,
            database_name: "app".to_string(),
            captured_at: "2024-01-01T00:00:00Z".to_string(),
            consistency: "test".to_string(),
            truncated: false,
            warnings: Vec::new(),
            objects: vec![crate::backups::catalog::BackupCatalogObject {
                id: "public.users".to_string(),
                namespace: "public".to_string(),
                name: "users".to_string(),
                kind: "table".to_string(),
                estimated_rows: Some(3),
                columns: Vec::new(),
                preview_rows: vec![serde_json::json!({"id": 1}), serde_json::json!({"id": 2})],
                preview_truncated: true,
            }],
        };

        let selection = select_catalog_object(&catalog, Some("public.users"), 1, 1)
            .unwrap()
            .unwrap();
        assert_eq!(selection.returned, 1);
        assert_eq!(selection.rows[0]["id"], 2);
        assert!(selection.truncated);
    }
}
