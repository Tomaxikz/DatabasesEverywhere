//! HTTP handlers and durable import/export job orchestration.

use super::{files::*, logical::*, physical::*, protocol::*, *};

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
    options: ExportOptions,
) -> ApiResult<ImportExportJobResponse> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
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
    let (job, admission) = enqueue_job(
        state,
        metadata.instance_id.clone(),
        ImportExportAction::Export,
        Some(artifact_path.display().to_string()),
        Some(replay_options),
    )
    .await?;

    tokio::spawn(run_export_job(
        state.clone(),
        job.job_id.clone(),
        metadata.instance_id,
        artifact_path,
        options,
        admission,
    ));

    audit_import_export(&job, "queued");
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
    super::uploads::validate_upload_selection_capability(
        state,
        &metadata.instance_id,
        &options.source,
        &options.selection,
    )
    .await?;
    let (staging_permit, upload_staging) =
        if matches!(&options.source, ImportSourceOptions::Upload { .. }) {
            match upload_logical_staging_budget(state, &metadata, options.mode)? {
                Some(budget) => {
                    let root = logical_staging_root(state).await?;
                    let permit = state
                        .import_uploads
                        .acquire_staging(&root, budget.reservation_bytes)
                        .await?;
                    (
                        Some(permit),
                        Some(UploadStagingBudget::Logical {
                            budget,
                            target_created_at: metadata.created_at.clone(),
                            disk_mib: metadata.limits.disk_mib,
                        }),
                    )
                }
                None => match upload_physical_staging_bytes(&metadata)? {
                    Some(bytes) => {
                        let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
                            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
                        let data_parent = paths.data.parent().ok_or_else(|| {
                            ApiError::Runtime(
                                "physical import data directory has no parent".to_string(),
                            )
                        })?;
                        let permit = state
                            .import_uploads
                            .acquire_staging_on_existing_root(data_parent, bytes)
                            .await?;
                        (
                            Some(permit),
                            Some(UploadStagingBudget::Physical {
                                extracted_bytes: bytes,
                                target_created_at: metadata.created_at.clone(),
                                disk_mib: metadata.limits.disk_mib,
                            }),
                        )
                    }
                    None => (None, None),
                },
            }
        } else {
            (None, None)
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
    let (job, admission) = enqueue_job(
        state,
        metadata.instance_id.clone(),
        ImportExportAction::Import,
        artifact_path
            .as_ref()
            .map(|path| path.display().to_string()),
        replay_options,
    )
    .await?;

    if let ImportSourceOptions::Upload { upload_id, .. } = &options.source {
        let claimed = match state
            .import_uploads
            .repository()
            .claim_ready_for_job(
                &metadata.instance_id,
                upload_id,
                &job.job_id,
                &crate::jobs::import_export::now_rfc3339(),
            )
            .await
        {
            Ok(claimed) => claimed,
            Err(error) => {
                close_unclaimed_upload_job(
                    state,
                    &job.job_id,
                    "upload_storage",
                    "the temporary import upload claim could not be persisted",
                )
                .await;
                if let Err(release_error) = state
                    .import_uploads
                    .repository()
                    .release_claim_after_failed_job(
                        &metadata.instance_id,
                        upload_id,
                        &job.job_id,
                        "upload claim acknowledgement was uncertain; submit the import again",
                        &crate::jobs::import_export::now_rfc3339(),
                    )
                    .await
                {
                    tracing::error!(job_id = job.job_id, %release_error, "failed to reconcile an uncertain upload claim");
                }
                return Err(ApiError::Runtime(format!(
                    "failed to claim import upload: {error}"
                )));
            }
        };
        if !claimed {
            close_unclaimed_upload_job(
                state,
                &job.job_id,
                "upload_conflict",
                "the temporary import upload is no longer ready",
            )
            .await;
            return Err(ApiError::Conflict(
                "the temporary import upload changed before the job could claim it".to_string(),
            ));
        }
    }

    tokio::spawn(run_import_job(
        state.clone(),
        job.job_id.clone(),
        metadata.instance_id,
        options,
        admission,
        staging_permit,
    ));

    audit_import_export(&job, "queued");
    Ok(accepted_job_response(job).await)
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
    state
        .import_export_jobs
        .insert(job.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok((job, admission))
}

pub(super) fn serialize_replay_descriptor(
    descriptor: &ReplayDescriptor,
) -> Result<String, ApiError> {
    serde_json::to_string(descriptor)
        .map_err(|error| ApiError::Runtime(format!("failed to encode job replay options: {error}")))
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

pub(super) async fn run_export_job(
    state: AppState,
    job_id: String,
    instance_id: String,
    artifact_path: PathBuf,
    options: ExportOptions,
    _admission: ImportExportJobPermit,
) {
    let _operation = state.instance_locks.lock(&instance_id).await;
    if !begin_import_export_job(&state, &job_id).await {
        return;
    }
    let result = match crate::api::instances::reconcile_instance_locked(&state, &instance_id).await
    {
        Ok(_) => {
            export_instance_artifact(&state, &instance_id, artifact_path.clone(), &options).await
        }
        Err(error) => Err(error),
    };
    let _ = update_job_result(&state, &job_id, result, Some(artifact_path)).await;
}

pub(super) async fn run_import_job(
    state: AppState,
    job_id: String,
    instance_id: String,
    options: ImportOptions,
    _admission: ImportExportJobPermit,
    _staging_permit: Option<super::uploads::ImportStagingPermit>,
) {
    let _operation = state.instance_locks.lock(&instance_id).await;
    let upload_id = match &options.source {
        ImportSourceOptions::Upload { upload_id, .. } => Some(upload_id.clone()),
        _ => None,
    };
    if !begin_import_export_job(&state, &job_id).await {
        if let Some(upload_id) = upload_id.as_deref() {
            super::uploads::finish_upload_import_job(
                &state,
                &instance_id,
                upload_id,
                &job_id,
                false,
                Some("daemon shutdown began before the import started"),
            )
            .await;
        }
        return;
    }
    let artifact_path = match &options.source {
        ImportSourceOptions::Artifact(path) => Some(path.clone()),
        ImportSourceOptions::Upload { .. } => None,
        ImportSourceOptions::Remote(_) => None,
        ImportSourceOptions::RemoteRequest(_) => {
            tracing::error!(%job_id, "validated import job retained an unresolved remote source");
            let _ = update_job_result(
                &state,
                &job_id,
                Err(ApiError::Runtime(
                    "remote import source was not validated".to_string(),
                )),
                None,
            )
            .await;
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
    if let Some(upload_id) = upload_id.as_deref() {
        if !terminal_status_persisted {
            tracing::error!(
                %job_id,
                instance_id,
                upload_id,
                "retaining claimed import upload because the job's terminal status is not durable"
            );
            let reason = "import outcome could not be recorded durably; the upload is blocked and the target was quarantined";
            match state
                .import_uploads
                .repository()
                .reconcile_interrupted_importing(
                    &instance_id,
                    upload_id,
                    &job_id,
                    crate::storage::import_uploads::InterruptedImportDisposition::Failed,
                    reason,
                    &crate::jobs::import_export::now_rfc3339(),
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    tracing::error!(%job_id, instance_id, upload_id, "uncertain terminal job persistence did not match the claimed upload state")
                }
                Err(error) => {
                    tracing::error!(%job_id, instance_id, upload_id, %error, "failed to block an upload with uncertain terminal job persistence")
                }
            }
            if let Err(error) = quarantine_after_uncertain_import(&state, &instance_id).await {
                tracing::error!(%job_id, instance_id, upload_id, %error, "failed to fully quarantine an import with uncertain terminal job persistence");
            }
            return;
        }
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

pub(super) async fn begin_import_export_job(state: &AppState, job_id: &str) -> bool {
    if !state.import_export_jobs.is_accepting() {
        let diagnostic = PublicDiagnostic::public(
            "shutdown",
            "daemon shutdown began before the queued job started",
        );
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
            tracing::error!(%job_id, %error, "failed to persist shutdown cancellation for queued import/export job");
        }
        return false;
    }
    if let Err(error) = state
        .import_export_jobs
        .update_status(job_id, ImportExportStatus::Running, None, None)
        .await
    {
        tracing::error!(%job_id, %error, "refusing to run import/export job because its running status could not be persisted");
        return false;
    }
    true
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
    const ATTEMPTS: u32 = 3;
    for attempt in 1..=ATTEMPTS {
        match state
            .import_export_jobs
            .update_status(job_id, status, artifact_path.clone(), error.clone())
            .await
        {
            Ok(()) => return true,
            Err(storage_error) if attempt < ATTEMPTS => {
                tracing::warn!(%job_id, %storage_error, attempt, "retrying terminal import/export job persistence");
                tokio::time::sleep(Duration::from_millis(100 * u64::from(attempt))).await;
            }
            Err(storage_error) => {
                tracing::error!(%job_id, %storage_error, attempt, "import/export operation completed but its terminal status could not be persisted");
            }
        }
    }
    false
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
    validate_logical_operation_eligible(&metadata)?;
    match metadata.protocol {
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => {
            export_physical_archive(
                state,
                instance_id,
                metadata.protocol,
                artifact_path,
                &options.selection,
            )
            .await
        }
        protocol => {
            export_logical_dump(
                state,
                &metadata,
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
