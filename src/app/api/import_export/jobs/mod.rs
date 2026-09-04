//! HTTP handlers and durable import/export job orchestration.

use super::{files::*, logical::*, physical::*, protocol::*, *};

mod execution;
mod export;
mod supervision;
#[cfg(test)]
pub(super) use execution::{import_staging_bytes, is_compressed_import, prepared_import_bytes};
#[cfg(test)]
pub(super) use export::{estimate_export_bytes, needs_separate_export_staging};
use export::{export_artifact, export_artifact_path};
pub(crate) use export::{measure_export_bytes, measure_shared_database_bytes};
use supervision::{spawn_export_supervisor, spawn_import_supervisor};

pub(super) const MAX_REPLAY_OPTIONS_BYTES: usize = 64 * 1024;
const MAX_ENQUEUE_READBACK_DELAY_MS: u64 = 1_000;

fn scheduler_capacity_error() -> ApiError {
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
    queue_export(
        &state,
        &instance_id,
        ExportOptions {
            selection,
            archive_format,
            delivery: ExportDelivery::default(),
        },
    )
    .await
}

pub(crate) async fn export_default_artifact(
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
        ExportDelivery::InternalRetained,
    )
    .await?;
    export_artifact(
        state,
        &metadata.instance_id,
        artifact_path.clone(),
        &ExportOptions::default(),
    )
    .await?;
    Ok(artifact_path)
}

pub(crate) async fn register_default_artifact(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
) -> Result<(), ApiError> {
    import_artifact(
        state,
        &metadata.instance_id,
        metadata,
        artifact_path,
        &ImportOptions::artifact(artifact_path.to_path_buf()),
        None,
    )
    .await
}

pub(crate) async fn queue_export(
    state: &AppState,
    instance_id: &str,
    mut options: ExportOptions,
) -> ApiResult<ImportExportJobResponse> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    options.archive_format = export_archive_format(metadata.protocol, options.archive_format);
    options.delivery = ExportDelivery::for_client(state);
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
    crate::api::artifacts::check_export_slot(state, &metadata.instance_id).await?;
    let artifact_path = export_artifact_path(
        state,
        &metadata.instance_id,
        metadata.protocol,
        options.archive_format,
        options.delivery,
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
        spawn_export_supervisor(
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
    let job = wait_for_enqueue(supervisor).await?;
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
    let resolved_source_database = super::uploads::resolve_upload_catalog(
        state,
        &metadata.instance_id,
        &options.source,
        options.source_database.as_deref(),
    )
    .await?;
    options.source_database = resolved_source_database;
    super::uploads::check_upload_selection(
        state,
        &metadata.instance_id,
        &options.source,
        &options.selection,
    )
    .await?;
    let upload_staging = if matches!(&options.source, ImportSourceOptions::Upload { .. }) {
        let prepared_bytes = prepared_upload_bytes(state, &options).await;
        match upload_logical_staging_budget(state, &metadata, prepared_bytes).await? {
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
        spawn_import_supervisor(
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
    let job = wait_for_enqueue(supervisor).await?;
    Ok(accepted_job_response(job).await)
}

async fn wait_for_enqueue(
    supervisor: tokio::task::JoinHandle<Result<ImportExportJob, ApiError>>,
) -> Result<ImportExportJob, ApiError> {
    supervisor.await.map_err(|error| {
        ApiError::Runtime(format!("import/export enqueue supervisor failed: {error}"))
    })?
}

async fn prepared_upload_bytes(state: &AppState, options: &ImportOptions) -> u64 {
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
            queue_export(
                state,
                &job.instance_id,
                ExportOptions {
                    selection,
                    archive_format,
                    delivery: ExportDelivery::default(),
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

pub(crate) async fn public_job_response(job: ImportExportJob) -> ImportExportJobResponse {
    let exposes_export_artifact =
        job.action == ImportExportAction::Export && job.status == ImportExportStatus::Succeeded;
    let artifact_size_bytes = match job
        .artifact_path
        .as_deref()
        .filter(|_| exposes_export_artifact)
    {
        Some(path) => tokio::fs::metadata(path)
            .await
            .ok()
            .map(|metadata| metadata.len()),
        None => None,
    };
    let artifact_id = job
        .artifact_path
        .as_deref()
        .filter(|_| exposes_export_artifact)
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
