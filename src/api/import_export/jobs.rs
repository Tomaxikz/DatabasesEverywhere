//! HTTP handlers and durable import/export job orchestration.

use super::{files::*, logical::*, physical::*, protocol::*, *};
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

mod supervision;
use supervision::{
    block_uncertain_upload, spawn_export_job_supervisor, spawn_import_job_supervisor,
};

pub(super) const MAX_REPLAY_OPTIONS_BYTES: usize = 64 * 1024;
const IMPORT_WORKER_QUEUED: u8 = 0;
const IMPORT_WORKER_RUNNING: u8 = 1;
const IMPORT_WORKER_FINISHED: u8 = 2;
const MAX_ENQUEUE_READBACK_DELAY_MS: u64 = 1_000;

fn fixed_scheduler_capacity_error() -> ApiError {
    ApiError::Conflict(
        "the estimated operation exceeds a fixed dynamic import/export scheduler budget; increase the configured dynamic memory, I/O, or CPU budget, reduce the operation size, or use a deliberate manual concurrency limit"
            .to_string(),
    )
}

pub async fn export_instance(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiOptionalJson(request): ApiOptionalJson<ExportRequest>,
) -> ApiResult<ImportExportJobResponse> {
    auth.require_scope(scopes::IMPORT_EXPORT_WRITE)?;
    let selection = request
        .as_ref()
        .and_then(|request| request.selection.clone())
        .unwrap_or_default();
    let archive_format = match request.as_ref() {
        Some(request) => ExportArchiveFormat::detect(request.archive_format.as_deref())?,
        None => ExportArchiveFormat::Plain,
    };
    queue_export_instance_with_options(
        &state,
        &instance_id,
        ExportOptions {
            selection,
            archive_format,
        },
    )
    .await
}

pub(crate) async fn export_instance_to_default_artifact(
    state: &AppState,
    instance_id: &str,
) -> Result<PathBuf, ApiError> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let artifact_path = export_artifact_path(
        state,
        &metadata.instance_id,
        metadata.protocol,
        ExportArchiveFormat::Plain,
    )
    .await?;
    export_instance_artifact(
        state,
        &metadata.instance_id,
        artifact_path.clone(),
        &ExportOptions::default(),
    )
    .await?;
    Ok(artifact_path)
}

pub(crate) async fn import_default_artifact_into_metadata(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
) -> Result<(), ApiError> {
    import_instance_artifact(
        state,
        &metadata.instance_id,
        metadata,
        artifact_path,
        &ImportOptions::artifact(artifact_path.to_path_buf()),
        None,
    )
    .await
}

pub(crate) async fn queue_export_instance_with_options(
    state: &AppState,
    instance_id: &str,
    mut options: ExportOptions,
) -> ApiResult<ImportExportJobResponse> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    options.archive_format =
        normalized_export_archive_format(metadata.protocol, options.archive_format);
    if matches!(
        metadata.protocol,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    ) && options.archive_format != ExportArchiveFormat::Plain
    {
        return Err(ApiError::BadRequest(format!(
            "{} exports are already physical archives; omit archive_format",
            metadata.protocol.as_str()
        )));
    }
    validate_selection(metadata.protocol, &options.selection, SelectionUse::Export)?;
    let artifact_path = export_artifact_path(
        state,
        &metadata.instance_id,
        metadata.protocol,
        options.archive_format,
    )
    .await?;
    let replay_options = serialize_replay_descriptor(&ReplayDescriptor::Export {
        selection: options.selection.clone(),
        archive_format: options.archive_format,
    })?;
    let owned_state = state.clone();
    let supervisor = tokio::spawn(async move {
        let (job, admission) = enqueue_job(
            &owned_state,
            metadata.instance_id.clone(),
            ImportExportAction::Export,
            Some(artifact_path.display().to_string()),
            Some(replay_options),
        )
        .await?;
        spawn_export_job_supervisor(
            owned_state,
            job.job_id.clone(),
            metadata.instance_id,
            artifact_path,
            options,
            admission,
        );
        audit_import_export(&job, "queued");
        Ok::<_, ApiError>(job)
    });
    let job = await_enqueue_supervisor(supervisor).await?;
    Ok(accepted_job_response(job).await)
}

pub(crate) async fn queue_import_instance(
    state: &AppState,
    instance_id: &str,
    options: ImportOptions,
) -> ApiResult<ImportExportJobResponse> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let mut options =
        harden_import_options(state, &metadata.instance_id, metadata.protocol, options).await?;
    validate_selection(metadata.protocol, &options.selection, SelectionUse::Import)?;
    let resolved_source_database = super::uploads::resolve_upload_source_database_catalog(
        state,
        &metadata.instance_id,
        &options.source,
        options.source_database.as_deref(),
    )
    .await?;
    options.source_database = resolved_source_database;
    super::uploads::validate_upload_selection_capability(
        state,
        &metadata.instance_id,
        &options.source,
        &options.selection,
    )
    .await?;
    let upload_staging = if matches!(&options.source, ImportSourceOptions::Upload { .. }) {
        let prepared_bytes = upload_prepared_reservation_bytes(state, &options).await;
        match upload_logical_staging_budget(state, &metadata, options.mode, prepared_bytes)? {
            Some(budget) => Some(UploadStagingBudget::Logical {
                budget,
                target_created_at: metadata.created_at.clone(),
                disk_mib: metadata.limits.disk_mib,
            }),
            None => match upload_physical_staging_bytes(&metadata)? {
                Some(bytes) => Some(UploadStagingBudget::Physical {
                    extracted_bytes: bytes,
                    target_created_at: metadata.created_at.clone(),
                    disk_mib: metadata.limits.disk_mib,
                }),
                None => None,
            },
        }
    } else {
        None
    };
    options.upload_staging = upload_staging;
    let artifact_path = match &options.source {
        ImportSourceOptions::Artifact(path) => Some(path.clone()),
        ImportSourceOptions::Upload { .. } => None,
        ImportSourceOptions::Remote(_) => None,
        ImportSourceOptions::RemoteRequest(_) => {
            return Err(ApiError::Runtime(
                "remote import source was not validated".to_string(),
            ));
        }
    };
    let replay_options = match &options.source {
        ImportSourceOptions::Artifact(_) => Some(serialize_replay_descriptor(
            &ReplayDescriptor::ArtifactImport {
                mode: options.mode,
                selection: options.selection.clone(),
                archive_format: options.archive_format.clone(),
            },
        )?),
        ImportSourceOptions::Upload { upload_id, .. } => Some(serialize_replay_descriptor(
            &ReplayDescriptor::UploadImport {
                upload_id: upload_id.clone(),
                source_database: options.source_database.clone(),
                mode: options.mode,
                selection: options.selection.clone(),
            },
        )?),
        ImportSourceOptions::Remote(_) | ImportSourceOptions::RemoteRequest(_) => None,
    };
    let remote_admission = if matches!(&options.source, ImportSourceOptions::Remote(_)) {
        Some(
            try_admit_remote_job(
                &metadata.instance_id,
                state.config.security.remote_import.max_concurrent_jobs,
            )
            .ok_or(ApiError::RateLimited)?,
        )
    } else {
        None
    };
    let owned_state = state.clone();
    let supervisor = tokio::spawn(async move {
        let (job, admission) = enqueue_job(
            &owned_state,
            metadata.instance_id.clone(),
            ImportExportAction::Import,
            artifact_path.map(|path| path.display().to_string()),
            replay_options,
        )
        .await?;
        spawn_import_job_supervisor(
            owned_state,
            job.job_id.clone(),
            metadata.instance_id,
            options,
            admission,
            remote_admission,
        );
        audit_import_export(&job, "queued");
        Ok::<_, ApiError>(job)
    });
    let job = await_enqueue_supervisor(supervisor).await?;
    Ok(accepted_job_response(job).await)
}

async fn await_enqueue_supervisor(
    supervisor: tokio::task::JoinHandle<Result<ImportExportJob, ApiError>>,
) -> Result<ImportExportJob, ApiError> {
    supervisor.await.map_err(|error| {
        ApiError::Runtime(format!("import/export enqueue supervisor failed: {error}"))
    })?
}

async fn upload_prepared_reservation_bytes(state: &AppState, options: &ImportOptions) -> u64 {
    let maximum = state.config.artifacts.import_upload_max_bytes;
    let ImportSourceOptions::Upload { path, .. } = &options.source else {
        return maximum;
    };
    // Container formats may expand up to the validated extraction ceiling;
    // plain logical dumps and MongoDB's directly streamed gzip archive need
    // only their actual source file reserved here.
    if options.archive_format.is_some() {
        return maximum;
    }
    tokio::fs::metadata(path)
        .await
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.len())
        .unwrap_or(maximum)
}

async fn close_unclaimed_upload_job(
    state: &AppState,
    job_id: &str,
    code: &'static str,
    message: &'static str,
) {
    let diagnostic = PublicDiagnostic::public(code, message);
    if let Err(error) = state
        .import_export_jobs
        .update_status(
            job_id,
            ImportExportStatus::Failed,
            None,
            Some(diagnostic.to_storage_string()),
        )
        .await
    {
        tracing::error!(job_id, %error, "failed to close an unclaimed upload import job");
    }
}

pub async fn get_import_export_job(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, job_id)): ApiPath<(String, String)>,
) -> ApiResult<ImportExportJobResponse> {
    auth.require_scope(scopes::IMPORT_EXPORT_READ)?;
    state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let job = state
        .import_export_jobs
        .get(&job_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?
        .ok_or(ApiError::NotFound)?;
    if job.instance_id != instance_id {
        return Err(ApiError::NotFound);
    }
    Ok(ApiResponse::ok(public_job_response(job).await))
}

pub async fn list_import_export_jobs(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<JobListQuery>,
) -> ApiResult<Vec<ImportExportJobResponse>> {
    auth.require_scope(scopes::IMPORT_EXPORT_READ)?;
    state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let status = query
        .status
        .as_deref()
        .map(ImportExportStatus::parse)
        .transpose()
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let jobs = state
        .import_export_jobs
        .list(Some(&instance_id), status, query.limit.unwrap_or(100))
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let mut response = Vec::with_capacity(jobs.len());
    for job in jobs {
        response.push(public_job_response(job).await);
    }
    Ok(ApiResponse::ok(response))
}

pub(super) async fn accepted_job_response(
    job: ImportExportJob,
) -> ApiResponse<ImportExportJobResponse> {
    let response = public_job_response(job).await;
    let location = format!(
        "/api/instances/{}/import-export/jobs/{}",
        response.instance_id, response.job_id
    );
    ApiResponse::accepted_at(response, location)
}

pub(super) async fn enqueue_job(
    state: &AppState,
    instance_id: String,
    action: ImportExportAction,
    artifact_path: Option<String>,
    replay_options: Option<String>,
) -> Result<(ImportExportJob, ImportExportJobPermit), ApiError> {
    let admission = state
        .import_export_jobs
        .try_admit(&instance_id)
        .map_err(|error| match error {
            JobAdmissionError::GlobalCapacity => ApiError::RateLimited,
            JobAdmissionError::InstanceCapacity => ApiError::Conflict(format!(
                "instance {instance_id} already has the maximum number of running or queued import/export jobs"
            )),
            JobAdmissionError::ShuttingDown => {
                ApiError::ServiceUnavailable("the daemon is shutting down".to_string())
            }
        })?;
    let now = crate::jobs::import_export::now_rfc3339();
    let job = ImportExportJob {
        job_id: uuid::Uuid::new_v4().to_string(),
        instance_id,
        action,
        status: ImportExportStatus::Queued,
        artifact_path,
        replay_options,
        error: None,
        created_at: now.clone(),
        updated_at: now,
    };
    if let Err(insert_error) = state.import_export_jobs.insert(job.clone()).await {
        let mut attempt = 0_u32;
        loop {
            attempt = attempt.saturating_add(1);
            match state.import_export_jobs.get(&job.job_id).await {
                Ok(Some(stored)) if stored == job => {
                    state
                        .import_export_jobs
                        .cache_durable_job(job.clone())
                        .await;
                    tracing::warn!(job_id = job.job_id, %insert_error, attempt, "recovered an acknowledged durable import/export enqueue");
                    break;
                }
                Ok(Some(_)) => {
                    tracing::error!(job_id = job.job_id, %insert_error, attempt, "import/export enqueue read-back differed from the intended durable job");
                    return Err(ApiError::Runtime(
                        "import/export job persistence was inconsistent".to_string(),
                    ));
                }
                Ok(None) => return Err(ApiError::Runtime(insert_error.to_string())),
                Err(read_error) if state.import_export_jobs.is_accepting() => {
                    tracing::warn!(job_id = job.job_id, %insert_error, %read_error, attempt, "retrying uncertain import/export enqueue read-back");
                    let exponent = attempt.saturating_sub(1).min(6);
                    let delay_ms = 25_u64
                        .saturating_mul(1_u64 << exponent)
                        .min(MAX_ENQUEUE_READBACK_DELAY_MS);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Err(read_error) => {
                    tracing::error!(job_id = job.job_id, %insert_error, %read_error, attempt, "daemon shutdown interrupted uncertain import/export enqueue classification; startup recovery will reconcile any durable row");
                    return Err(ApiError::Runtime(insert_error.to_string()));
                }
            }
        }
    }
    Ok((job, admission))
}

pub(super) fn serialize_replay_descriptor(
    descriptor: &ReplayDescriptor,
) -> Result<String, ApiError> {
    let encoded = serde_json::to_string(descriptor).map_err(|error| {
        ApiError::Runtime(format!("failed to encode job replay options: {error}"))
    })?;
    if encoded.len() > MAX_REPLAY_OPTIONS_BYTES {
        return Err(ApiError::BadRequest(format!(
            "import/export selection exceeds the {MAX_REPLAY_OPTIONS_BYTES}-byte queued-job limit"
        )));
    }
    Ok(encoded)
}

pub(crate) async fn replay_failed_job(
    state: &AppState,
    job: &ImportExportJob,
) -> ApiResult<ImportExportJobResponse> {
    let replay_options = job.replay_options.as_deref().ok_or_else(|| {
        ApiError::BadRequest(
            "this job cannot be replayed because it used remote credentials or predates safe replay metadata; submit a new request"
                .to_string(),
        )
    })?;
    let descriptor: ReplayDescriptor = serde_json::from_str(replay_options).map_err(|_| {
        ApiError::BadRequest(
            "this job has invalid replay metadata; submit a new request".to_string(),
        )
    })?;
    match (job.action, descriptor) {
        (
            ImportExportAction::Export,
            ReplayDescriptor::Export {
                selection,
                archive_format,
            },
        ) => {
            queue_export_instance_with_options(
                state,
                &job.instance_id,
                ExportOptions {
                    selection,
                    archive_format,
                },
            )
            .await
        }
        (
            ImportExportAction::Import,
            ReplayDescriptor::ArtifactImport {
                mode,
                selection,
                archive_format,
            },
        ) => {
            let artifact_path = job.artifact_path.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "artifact replay metadata is missing its artifact; submit a new request"
                        .to_string(),
                )
            })?;
            queue_import_instance(
                state,
                &job.instance_id,
                ImportOptions::replay_artifact(artifact_path, mode, selection, archive_format),
            )
            .await
        }
        (
            ImportExportAction::Import,
            ReplayDescriptor::UploadImport {
                upload_id,
                source_database,
                mode,
                selection,
            },
        ) => {
            queue_import_instance(
                state,
                &job.instance_id,
                ImportOptions {
                    archive_format: None,
                    source: ImportSourceOptions::Upload {
                        upload_id,
                        path: PathBuf::new(),
                    },
                    source_database,
                    mode,
                    selection,
                    upload_staging: None,
                },
            )
            .await
        }
        _ => Err(ApiError::BadRequest(
            "job replay metadata does not match the original action; submit a new request"
                .to_string(),
        )),
    }
}

pub(super) async fn run_export_job_locked(
    state: AppState,
    job_id: String,
    metadata: InstanceMetadata,
    artifact_path: PathBuf,
    options: ExportOptions,
) {
    let result =
        match crate::api::instances::reconcile_instance_locked(&state, &metadata.instance_id).await
        {
            Ok(_) => {
                export_instance_artifact_reserved(
                    &state,
                    &metadata,
                    artifact_path.clone(),
                    &options,
                )
                .await
            }
            Err(error) => Err(error),
        };
    if !update_job_result(&state, &job_id, result, Some(artifact_path)).await {
        tracing::error!(%job_id, "export completed but its terminal status remained uncertain during shutdown; startup recovery will reconcile it");
    }
}

pub(super) async fn run_import_job_locked(
    state: AppState,
    job_id: String,
    instance_id: String,
    options: ImportOptions,
) {
    let upload_id = match &options.source {
        ImportSourceOptions::Upload { upload_id, .. } => Some(upload_id.clone()),
        _ => None,
    };
    let artifact_path = match &options.source {
        ImportSourceOptions::Artifact(path) => Some(path.clone()),
        ImportSourceOptions::Upload { .. } => None,
        ImportSourceOptions::Remote(_) => None,
        ImportSourceOptions::RemoteRequest(_) => {
            tracing::error!(%job_id, "validated import job retained an unresolved remote source");
            let persisted = update_job_result(
                &state,
                &job_id,
                Err(ApiError::Runtime(
                    "remote import source was not validated".to_string(),
                )),
                None,
            )
            .await;
            if !persisted
                && let Err(quarantine_error) =
                    quarantine_after_uncertain_import(&state, &instance_id).await
            {
                tracing::error!(%job_id, %instance_id, %quarantine_error, "failed to quarantine a target after unresolved import status became uncertain");
            }
            return;
        }
    };
    let result = match crate::api::instances::reconcile_instance_locked(&state, &instance_id).await
    {
        Ok(_) => import_instance_source(&state, &instance_id, &options).await,
        Err(error) => Err(error),
    };
    let succeeded = result.is_ok();
    let failure = result
        .as_ref()
        .err()
        .map(|error| PublicDiagnostic::from_api_error("import operation", error).message);
    let terminal_status_persisted = update_job_result(&state, &job_id, result, artifact_path).await;
    if !terminal_status_persisted {
        tracing::error!(
            %job_id,
            instance_id,
            "import outcome is uncertain because the terminal job status is not durable"
        );
        if let Some(upload_id) = upload_id.as_deref() {
            block_uncertain_upload(
                &state,
                &instance_id,
                upload_id,
                &job_id,
                "import outcome could not be recorded durably; the upload is blocked and the target was quarantined",
            )
            .await;
        }
        if let Err(error) = quarantine_after_uncertain_import(&state, &instance_id).await {
            tracing::error!(%job_id, instance_id, %error, "failed to fully quarantine an import with uncertain terminal job persistence");
        }
        return;
    }
    if let Some(upload_id) = upload_id.as_deref() {
        super::uploads::finish_upload_import_job(
            &state,
            &instance_id,
            upload_id,
            &job_id,
            succeeded,
            failure.as_deref(),
        )
        .await;
    }
}

async fn acquire_upload_staging(
    state: &AppState,
    instance_id: &str,
    options: &ImportOptions,
) -> Result<Option<super::uploads::ImportStagingPermit>, ApiError> {
    if let Some(staging) = options.upload_staging.as_ref() {
        return match staging {
            UploadStagingBudget::Logical { budget, .. } => {
                let root = logical_staging_root(state).await?;
                state
                    .import_uploads
                    .acquire_staging(&root, budget.reservation_bytes)
                    .await
                    .map(Some)
            }
            UploadStagingBudget::Physical {
                extracted_bytes, ..
            } => {
                let paths = InstancePaths::new(&state.config.paths, instance_id)
                    .map_err(|error| ApiError::BadRequest(error.to_string()))?;
                let data_parent = paths.data.parent().ok_or_else(|| {
                    ApiError::Runtime("physical import data directory has no parent".to_string())
                })?;
                state
                    .import_uploads
                    .acquire_staging_on_existing_root(data_parent, *extracted_bytes)
                    .await
                    .map(Some)
            }
        };
    }

    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    if !protocol_uses_logical_dumps(metadata.protocol) {
        return match &options.source {
            ImportSourceOptions::Remote(_) => {
                let root = PathBuf::from(state.config.paths.tmp_root());
                state
                    .import_uploads
                    .acquire_staging(
                        &root,
                        state.config.security.remote_import.max_staged_bytes.max(1),
                    )
                    .await
                    .map(Some)
            }
            ImportSourceOptions::Artifact(_) => {
                let paths = InstancePaths::new(&state.config.paths, instance_id)
                    .map_err(|error| ApiError::BadRequest(error.to_string()))?;
                let data_parent = paths.data.parent().ok_or_else(|| {
                    ApiError::Runtime("physical import data directory has no parent".to_string())
                })?;
                let extracted = metadata
                    .limits
                    .disk_mib
                    .saturating_mul(1024 * 1024)
                    .clamp(1, crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES);
                state
                    .import_uploads
                    .acquire_staging_on_existing_root(data_parent, extracted)
                    .await
                    .map(Some)
            }
            ImportSourceOptions::Upload { .. } => Err(ApiError::Runtime(
                "physical upload import is missing its validated staging budget".to_string(),
            )),
            ImportSourceOptions::RemoteRequest(_) => Err(ApiError::Runtime(
                "remote import source was not validated".to_string(),
            )),
        };
    }
    let requested = match &options.source {
        ImportSourceOptions::Artifact(path) => {
            let prepared = if import_source_is_compressed(metadata.protocol, options) {
                MAX_UNARCHIVED_BYTES
            } else {
                tokio::fs::metadata(path)
                    .await
                    .ok()
                    .filter(|value| value.is_file())
                    .map(|value| value.len().min(MAX_UNARCHIVED_BYTES))
                    .unwrap_or(MAX_UNARCHIVED_BYTES)
            };
            let rollback = if options.mode == ImportMode::Wipe {
                estimated_logical_rollback_bytes(&metadata)
            } else {
                0
            };
            prepared.checked_add(rollback).ok_or_else(|| {
                ApiError::Conflict("logical import staging reservation overflowed".to_string())
            })?
        }
        ImportSourceOptions::Remote(_) => remote_import_staging_reservation_bytes(
            metadata.protocol,
            state.config.security.remote_import.max_staged_bytes,
        )?,
        ImportSourceOptions::Upload { .. } => {
            return Err(ApiError::Runtime(
                "upload import is missing its validated staging budget".to_string(),
            ));
        }
        ImportSourceOptions::RemoteRequest(_) => {
            return Err(ApiError::Runtime(
                "remote import source was not validated".to_string(),
            ));
        }
    };
    let root = logical_staging_root(state).await?;
    state
        .import_uploads
        .acquire_staging(&root, requested.max(1))
        .await
        .map(Some)
}

pub(super) fn remote_import_staging_reservation_bytes(
    protocol: Protocol,
    max_staged_bytes: u64,
) -> Result<u64, ApiError> {
    let copies = if matches!(
        protocol,
        Protocol::Mariadb | Protocol::Mysql | Protocol::Clickhouse
    ) {
        2
    } else {
        1
    };
    max_staged_bytes.max(1).checked_mul(copies).ok_or_else(|| {
        ApiError::Conflict("remote import staging reservation overflowed".to_string())
    })
}

pub(super) fn import_source_is_compressed(protocol: Protocol, options: &ImportOptions) -> bool {
    protocol_uses_native_compression(protocol)
        || options.archive_format.is_some()
        || match &options.source {
            ImportSourceOptions::Artifact(path) | ImportSourceOptions::Upload { path, .. } => path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    let name = name.to_ascii_lowercase();
                    name.ends_with(".gz") || name.ends_with(".bz2") || name.ends_with(".zip")
                }),
            ImportSourceOptions::Remote(_) | ImportSourceOptions::RemoteRequest(_) => false,
        }
}

async fn estimate_export_execution_cost(
    state: &AppState,
    metadata: &InstanceMetadata,
    options: &ExportOptions,
) -> JobResourceCost {
    let allocated_bytes = metadata
        .limits
        .disk_mib
        .saturating_mul(1024 * 1024)
        .min(crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES);
    let input_size_bytes = match InstancePaths::new(&state.config.paths, &metadata.instance_id) {
        Ok(paths) => state
            .resource_cache
            .disk_usage(&state.config, &metadata.instance_id, paths.data)
            .await
            .map(|usage| usage.used_bytes)
            .unwrap_or(allocated_bytes),
        Err(_) => allocated_bytes,
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

async fn estimate_import_execution_cost(
    state: &AppState,
    metadata: &InstanceMetadata,
    options: &ImportOptions,
) -> JobResourceCost {
    let upload_limit = state.config.artifacts.import_upload_max_bytes;
    let remote_limit = state.config.security.remote_import.max_staged_bytes;
    let source_bytes = match &options.source {
        ImportSourceOptions::Artifact(path) | ImportSourceOptions::Upload { path, .. } => {
            tokio::fs::metadata(path)
                .await
                .ok()
                .filter(|metadata| metadata.is_file())
                .map(|metadata| metadata.len())
                .unwrap_or(upload_limit)
        }
        ImportSourceOptions::Remote(_) | ImportSourceOptions::RemoteRequest(_) => remote_limit,
    };
    let compressed = import_source_is_compressed(metadata.protocol, options);
    let prepared_ceiling =
        import_prepared_ceiling_bytes(options, upload_limit, remote_limit, compressed);
    // A compressed dump has no trustworthy expansion ratio until bounded
    // extraction completes. Charge the configured prepared-data ceiling so a
    // tiny gzip bomb cannot evade resource scheduling.
    let estimated_expanded_bytes = conservative_import_input_bytes(
        metadata.protocol,
        source_bytes,
        prepared_ceiling,
        metadata.limits.disk_mib,
        compressed,
    );
    let rollback_size_bytes =
        if options.mode == ImportMode::Wipe && protocol_uses_logical_dumps(metadata.protocol) {
            estimated_logical_rollback_bytes(metadata)
        } else {
            0
        };
    JobResourceCost::estimate(JobEstimateInput {
        protocol: metadata.protocol,
        input_size_bytes: estimated_expanded_bytes.max(1),
        rollback_size_bytes,
        wipe: options.mode == ImportMode::Wipe,
        compressed,
        export: false,
    })
}

pub(super) fn import_prepared_ceiling_bytes(
    options: &ImportOptions,
    upload_limit: u64,
    remote_limit: u64,
    compressed: bool,
) -> u64 {
    match &options.source {
        ImportSourceOptions::Artifact(_) => MAX_UNARCHIVED_BYTES,
        ImportSourceOptions::Upload { .. } => {
            let validated = match options.upload_staging.as_ref() {
                Some(UploadStagingBudget::Logical { budget, .. }) => budget.prepared_bytes,
                Some(UploadStagingBudget::Physical { .. }) | None => upload_limit,
            };
            if compressed {
                validated.max(upload_limit.min(MAX_UNARCHIVED_BYTES))
            } else {
                validated
            }
        }
        ImportSourceOptions::Remote(_) | ImportSourceOptions::RemoteRequest(_) => remote_limit,
    }
    .max(1)
}

fn estimated_logical_rollback_bytes(metadata: &InstanceMetadata) -> u64 {
    metadata
        .limits
        .disk_mib
        .saturating_mul(1024 * 1024)
        .clamp(1, MAX_UNARCHIVED_BYTES)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum JobBeginOutcome {
    Running,
    Closed,
    Uncertain,
}

pub(super) async fn begin_import_export_job(state: &AppState, job_id: &str) -> JobBeginOutcome {
    let mut attempt = 0_u32;
    loop {
        if !state.import_export_jobs.is_accepting() {
            let diagnostic = PublicDiagnostic::public(
                "shutdown",
                "daemon shutdown began before the queued job started",
            );
            return if persist_terminal_job_status(
                state,
                job_id,
                ImportExportStatus::Failed,
                None,
                Some(diagnostic.to_storage_string()),
            )
            .await
            {
                JobBeginOutcome::Closed
            } else {
                JobBeginOutcome::Uncertain
            };
        }
        match state
            .import_export_jobs
            .update_status(job_id, ImportExportStatus::Running, None, None)
            .await
        {
            Ok(()) => return JobBeginOutcome::Running,
            Err(error) => {
                attempt = attempt.saturating_add(1);
                tracing::warn!(%job_id, %error, attempt, "retrying durable running status before import/export execution");
                let delay_ms = 50_u64
                    .saturating_mul(1_u64 << attempt.saturating_sub(1).min(5))
                    .min(1_000);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }
}

pub(super) async fn update_job_result(
    state: &AppState,
    job_id: &str,
    result: Result<(), ApiError>,
    artifact_path: Option<PathBuf>,
) -> bool {
    match result {
        Ok(()) => {
            tracing::info!(%job_id, "audit import_export_job_succeeded");
            persist_terminal_job_status(
                state,
                job_id,
                ImportExportStatus::Succeeded,
                artifact_path.map(|path| path.display().to_string()),
                None,
            )
            .await
        }
        Err(error) => {
            tracing::warn!(%job_id, %error, "audit import_export_job_failed");
            let diagnostic = PublicDiagnostic::from_api_error("import/export operation", &error);
            persist_terminal_job_status(
                state,
                job_id,
                ImportExportStatus::Failed,
                artifact_path.map(|path| path.display().to_string()),
                Some(diagnostic.to_storage_string()),
            )
            .await
        }
    }
}

async fn persist_terminal_job_status(
    state: &AppState,
    job_id: &str,
    status: ImportExportStatus,
    artifact_path: Option<String>,
    error: Option<String>,
) -> bool {
    const SHUTDOWN_ATTEMPTS: u32 = 3;
    let mut attempt = 0_u32;
    loop {
        attempt = attempt.saturating_add(1);
        match state
            .import_export_jobs
            .update_status(job_id, status, artifact_path.clone(), error.clone())
            .await
        {
            Ok(()) => return true,
            Err(storage_error)
                if state.import_export_jobs.is_accepting() || attempt < SHUTDOWN_ATTEMPTS =>
            {
                tracing::warn!(%job_id, %storage_error, attempt, "retrying terminal import/export job persistence");
                let delay_ms = 100_u64
                    .saturating_mul(1_u64 << attempt.saturating_sub(1).min(4))
                    .min(1_000);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            Err(storage_error) => {
                tracing::error!(%job_id, %storage_error, attempt, "import/export operation completed but its terminal status could not be persisted");
                return false;
            }
        }
    }
}

pub(super) async fn export_instance_artifact(
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
    let _reservations =
        acquire_export_output_capacity(state, &metadata, &artifact_path, options).await?;
    export_instance_artifact_reserved(state, &metadata, artifact_path, options).await
}

pub(super) struct ExportOutputReservations {
    _artifact: super::uploads::DiskCapacityReservation,
    _staging: Option<super::uploads::DiskCapacityReservation>,
}

pub(super) async fn acquire_export_output_capacity(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
    options: &ExportOptions,
) -> Result<ExportOutputReservations, ApiError> {
    validate_logical_operation_eligible(metadata)?;
    let artifact_root = artifact_path
        .parent()
        .ok_or_else(|| ApiError::Runtime("export artifact has no parent directory".to_string()))?;
    let physical = matches!(
        metadata.protocol,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    );
    let output_capacity = if physical {
        metadata
            .limits
            .disk_mib
            .saturating_mul(1024 * 1024)
            .saturating_add(64 * 1024 * 1024)
            .clamp(1, crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES)
    } else {
        export_artifact_capacity_bytes(MAX_UNARCHIVED_BYTES, options.archive_format).ok_or_else(
            || ApiError::Runtime("export artifact capacity calculation overflowed".to_string()),
        )?
    };
    let _artifact_capacity = state
        .import_uploads
        .reserve_output_capacity(artifact_root, output_capacity)
        .await?;
    let staging = if physical {
        None
    } else {
        let staging_root = logical_staging_root(state).await?;
        Some(
            state
                .import_uploads
                .reserve_output_capacity(&staging_root, MAX_UNARCHIVED_BYTES)
                .await?,
        )
    };
    Ok(ExportOutputReservations {
        _artifact: _artifact_capacity,
        _staging: staging,
    })
}

pub(super) async fn export_instance_artifact_reserved(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: PathBuf,
    options: &ExportOptions,
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
            export_logical_dump(
                state,
                metadata,
                protocol,
                artifact_path,
                options,
                LogicalExportControls::default(),
            )
            .await
        }
    }
}

pub(super) async fn export_artifact_path(
    state: &AppState,
    instance_id: &str,
    protocol: Protocol,
    archive_format: ExportArchiveFormat,
) -> Result<PathBuf, ApiError> {
    crate::shared::ids::validate_instance_id(instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let export_root = crate::api::artifacts::instance_export_root(state, instance_id);
    create_private_directory(&export_root, "export directory").await?;
    let artifact_id = uuid::Uuid::new_v4();
    Ok(export_root.join(format!(
        "{}.{}{}",
        artifact_id,
        dump_extension(protocol),
        archive_format.suffix()
    )))
}

pub(crate) async fn public_job_response(job: ImportExportJob) -> ImportExportJobResponse {
    let artifact_size_bytes = match job.artifact_path.as_deref() {
        Some(path) => tokio::fs::metadata(path)
            .await
            .ok()
            .map(|metadata| metadata.len()),
        None => None,
    };
    let artifact_id = job
        .artifact_path
        .as_deref()
        .and_then(|path| FsPath::new(path).file_name())
        .and_then(|name| name.to_str())
        .map(str::to_string);
    ImportExportJobResponse {
        job_id: job.job_id,
        instance_id: job.instance_id,
        action: job.action,
        status: job.status,
        artifact_id,
        artifact_size_bytes,
        error: job
            .error
            .as_deref()
            .map(|error| PublicDiagnostic::from_storage("import/export operation", error)),
        created_at: job.created_at,
        updated_at: job.updated_at,
    }
}

pub(super) fn audit_import_export(job: &ImportExportJob, status: &'static str) {
    tracing::info!(
        event = "audit import_export_job",
        action = job.action.as_str(),
        status,
        job_id = %job.job_id,
        instance_id = %job.instance_id,
        artifact_path = ?job.artifact_path,
    );
}
