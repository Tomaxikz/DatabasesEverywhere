use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    path::{Component, Path as FsPath, PathBuf},
    time::{Duration, Instant},
};

use crate::{
    api::{
        api_response::{
            ApiError, ApiJson, ApiOptionalJson, ApiPath, ApiQuery, ApiResponse, ApiResult,
        },
        instances::{LifecycleAction, lifecycle_instance_locked},
        public_diagnostic::PublicDiagnostic,
        remote_import::{
            ImportMode, RemoteImportRequest, RemoteImportSource, acquire_logical_dump,
            import_qdrant, import_redis, validate_remote_source,
        },
        routes::AppState,
        security_policy::ApiRequestContext,
    },
    auth::scopes,
    instances::{
        metadata::{InstanceMetadata, InstanceStatus},
        paths::InstancePaths,
    },
    jobs::import_export::{
        ImportExportAction, ImportExportJob, ImportExportJobPermit, ImportExportStatus,
        JobAdmissionError, create_data_archive, extract_data_archive,
    },
    shared::{files::is_safe_flat_file_name, protocol::Protocol, shell::sh_quote},
};
use axum::extract::State;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

const MAX_UNARCHIVED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4096;
const MAX_ARCHIVE_DEPTH: usize = 32;
const ARCHIVE_OPERATION_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_SELECTION_ITEMS: usize = 512;
const MAX_SELECTION_FIELDS_PER_ITEM: usize = 512;
const FAIL_CLOSED_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const LOGICAL_ROLLBACK_READINESS_TIMEOUT: Duration = Duration::from_secs(120);
pub(crate) const CLICKHOUSE_ENGINE_AWK_PROGRAM: &str = r#"
/^[[:space:]]*ENGINE[[:space:]]*=/ {
  candidate = $0
  sub(/^[[:space:]]*ENGINE[[:space:]]*=[[:space:]]*/, "", candidate)
  if (candidate !~ /^[A-Za-z][A-Za-z0-9_]*([[:space:](]|$)/) {
    invalid = 1
    next
  }
  sub(/[^A-Za-z0-9_].*$/, "", candidate)
  engine = candidate
  count++
}
END {
  if (invalid || count != 1) {
    exit 64
  }
  print engine
}
"#;

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    pub selection: Option<ImportExportSelection>,
    #[serde(default)]
    pub archive_format: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    pub source: ImportSource,
    #[serde(default)]
    pub mode: ImportMode,
    #[serde(default)]
    pub selection: Option<ImportExportSelection>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportSource {
    Artifact {
        artifact_id: String,
        #[serde(default)]
        archive_format: Option<String>,
    },
    Remote(RemoteImportRequest),
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectionMode {
    #[default]
    Full,
    Selective,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ImportExportSelection {
    pub mode: SelectionMode,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    #[serde(deserialize_with = "deserialize_selection_fields")]
    pub fields: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SelectionFieldsInput {
    Map(HashMap<String, Vec<String>>),
    Sequence(Vec<serde::de::IgnoredAny>),
}

fn deserialize_selection_fields<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    match SelectionFieldsInput::deserialize(deserializer)? {
        SelectionFieldsInput::Map(fields) => Ok(fields),
        SelectionFieldsInput::Sequence(fields) if fields.is_empty() => Ok(HashMap::new()),
        SelectionFieldsInput::Sequence(_) => Err(D::Error::custom(
            "selection.fields must be an object or an empty array",
        )),
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ImportOptions {
    archive_format: Option<String>,
    source: ImportSourceOptions,
    mode: ImportMode,
    selection: ImportExportSelection,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ExportOptions {
    selection: ImportExportSelection,
    archive_format: ExportArchiveFormat,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExportArchiveFormat {
    #[default]
    Plain,
    Gzip,
    Bzip2,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ReplayDescriptor {
    Export {
        selection: ImportExportSelection,
        archive_format: ExportArchiveFormat,
    },
    ArtifactImport {
        mode: ImportMode,
        selection: ImportExportSelection,
        archive_format: Option<String>,
    },
}

impl ExportArchiveFormat {
    fn detect(format: Option<&str>) -> Result<Self, ApiError> {
        if format.is_none() {
            return Ok(Self::Plain);
        }
        match format
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "plain" => Ok(Self::Plain),
            "gzip" => Ok(Self::Gzip),
            "bzip2" => Ok(Self::Bzip2),
            other => Err(ApiError::BadRequest(format!(
                "unsupported export archive_format {other}; use plain, gzip, or bzip2"
            ))),
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Plain => "",
            Self::Gzip => ".gz",
            Self::Bzip2 => ".bz2",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ImportSourceOptions {
    Artifact(PathBuf),
    RemoteRequest(RemoteImportRequest),
    Remote(RemoteImportSource),
}

impl Default for ImportSourceOptions {
    fn default() -> Self {
        Self::Artifact(PathBuf::new())
    }
}

impl ImportOptions {
    pub(crate) fn artifact(path: impl Into<PathBuf>) -> Self {
        Self {
            source: ImportSourceOptions::Artifact(path.into()),
            ..Self::default()
        }
    }

    pub(crate) fn recovery_restore(path: impl Into<PathBuf>, protocol: Protocol) -> Self {
        let path = path.into();
        Self {
            archive_format: recovery_archive_format(&path, protocol),
            source: ImportSourceOptions::Artifact(path),
            mode: ImportMode::Wipe,
            selection: ImportExportSelection::default(),
        }
    }

    fn replay_artifact(
        path: impl Into<PathBuf>,
        mode: ImportMode,
        selection: ImportExportSelection,
        archive_format: Option<String>,
    ) -> Self {
        Self {
            archive_format,
            source: ImportSourceOptions::Artifact(path.into()),
            mode,
            selection,
        }
    }
}

fn recovery_archive_format(path: &FsPath, protocol: Protocol) -> Option<String> {
    if matches!(protocol, Protocol::Redis | Protocol::Qdrant) {
        return None;
    }
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if protocol == Protocol::Mongodb
        && (filename.ends_with(".mongodb.archive.gz") || filename.ends_with(".archive.gz"))
    {
        return None;
    }
    [
        (".tar.gz", "tar.gz"),
        (".tgz", "tar.gz"),
        (".tar", "tar"),
        (".zip", "zip"),
        (".gzip", "gzip"),
        (".gz", "gzip"),
        (".bzip2", "bzip2"),
        (".bz2", "bzip2"),
    ]
    .into_iter()
    .find_map(|(suffix, format)| filename.ends_with(suffix).then(|| format.to_string()))
}

impl From<&ImportRequest> for ImportOptions {
    fn from(request: &ImportRequest) -> Self {
        let selection = request.selection.clone().unwrap_or_default();
        match &request.source {
            ImportSource::Artifact {
                artifact_id,
                archive_format,
            } => Self {
                archive_format: archive_format.clone(),
                source: ImportSourceOptions::Artifact(PathBuf::from(artifact_id)),
                mode: request.mode,
                selection,
            },
            ImportSource::Remote(remote) => Self {
                archive_format: None,
                source: ImportSourceOptions::RemoteRequest(remote.clone()),
                mode: request.mode,
                selection,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobListQuery {
    pub status: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ImportExportJobResponse {
    pub job_id: String,
    pub instance_id: String,
    pub action: ImportExportAction,
    pub status: ImportExportStatus,
    pub artifact_id: Option<String>,
    pub artifact_size_bytes: Option<u64>,
    pub error: Option<PublicDiagnostic>,
    pub created_at: String,
    pub updated_at: String,
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
    options: ExportOptions,
) -> ApiResult<ImportExportJobResponse> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Qdrant)
        && options.archive_format != ExportArchiveFormat::Plain
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

pub async fn import_instance(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiJson(request): ApiJson<ImportRequest>,
) -> ApiResult<ImportExportJobResponse> {
    auth.require_scope(scopes::IMPORT_EXPORT_WRITE)?;
    queue_import_instance(&state, &instance_id, ImportOptions::from(&request)).await
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
    let options =
        harden_import_options(state, &metadata.instance_id, metadata.protocol, options).await?;
    validate_selection(metadata.protocol, &options.selection, SelectionUse::Import)?;
    let artifact_path = match &options.source {
        ImportSourceOptions::Artifact(path) => Some(path.clone()),
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

    tokio::spawn(run_import_job(
        state.clone(),
        job.job_id.clone(),
        metadata.instance_id,
        options,
        admission,
    ));

    audit_import_export(&job, "queued");
    Ok(accepted_job_response(job).await)
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

async fn accepted_job_response(job: ImportExportJob) -> ApiResponse<ImportExportJobResponse> {
    let response = public_job_response(job).await;
    let location = format!(
        "/api/instances/{}/import-export/jobs/{}",
        response.instance_id, response.job_id
    );
    ApiResponse::accepted_at(response, location)
}

async fn enqueue_job(
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

fn serialize_replay_descriptor(descriptor: &ReplayDescriptor) -> Result<String, ApiError> {
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
        _ => Err(ApiError::BadRequest(
            "job replay metadata does not match the original action; submit a new request"
                .to_string(),
        )),
    }
}

async fn run_export_job(
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
    update_job_result(&state, &job_id, result, Some(artifact_path)).await;
}

async fn run_import_job(
    state: AppState,
    job_id: String,
    instance_id: String,
    options: ImportOptions,
    _admission: ImportExportJobPermit,
) {
    let _operation = state.instance_locks.lock(&instance_id).await;
    if !begin_import_export_job(&state, &job_id).await {
        return;
    }
    let artifact_path = match &options.source {
        ImportSourceOptions::Artifact(path) => Some(path.clone()),
        ImportSourceOptions::Remote(_) => None,
        ImportSourceOptions::RemoteRequest(_) => {
            tracing::error!(%job_id, "validated import job retained an unresolved remote source");
            update_job_result(
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
    update_job_result(&state, &job_id, result, artifact_path).await;
}

async fn begin_import_export_job(state: &AppState, job_id: &str) -> bool {
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

async fn update_job_result(
    state: &AppState,
    job_id: &str,
    result: Result<(), ApiError>,
    artifact_path: Option<PathBuf>,
) {
    match result {
        Ok(()) => {
            tracing::info!(%job_id, "audit import_export_job_succeeded");
            if let Err(error) = state
                .import_export_jobs
                .update_status(
                    job_id,
                    ImportExportStatus::Succeeded,
                    artifact_path.map(|path| path.display().to_string()),
                    None,
                )
                .await
            {
                tracing::error!(%job_id, %error, "import/export operation succeeded but its terminal status could not be persisted");
            }
        }
        Err(error) => {
            tracing::warn!(%job_id, %error, "audit import_export_job_failed");
            let diagnostic = PublicDiagnostic::from_api_error("import/export operation", &error);
            if let Err(storage_error) = state
                .import_export_jobs
                .update_status(
                    job_id,
                    ImportExportStatus::Failed,
                    artifact_path.map(|path| path.display().to_string()),
                    Some(diagnostic.to_storage_string()),
                )
                .await
            {
                tracing::error!(%job_id, %storage_error, "import/export operation failed and its terminal status could not be persisted");
            }
        }
    }
}

async fn export_instance_artifact(
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
        Protocol::Redis | Protocol::Qdrant => {
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

async fn import_instance_source(
    state: &AppState,
    instance_id: &str,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    validate_logical_operation_eligible(&metadata)?;
    match &options.source {
        ImportSourceOptions::Artifact(path)
            if options.mode == ImportMode::Wipe
                && !matches!(metadata.protocol, Protocol::Redis | Protocol::Qdrant) =>
        {
            import_logical_with_rollback(state, &metadata, path, options, None, None).await
        }
        ImportSourceOptions::Artifact(path) => {
            import_instance_artifact(state, instance_id, &metadata, path, options, None).await
        }
        ImportSourceOptions::Remote(source) => {
            if metadata.status != InstanceStatus::Running {
                return Err(ApiError::BadRequest(format!(
                    "remote import requires a running target instance (status={:?})",
                    metadata.status
                )));
            }
            match metadata.protocol {
                Protocol::Redis => import_redis(state, instance_id, source, options.mode).await,
                Protocol::Qdrant => {
                    import_qdrant(state, instance_id, source, &options.selection, options.mode)
                        .await
                }
                protocol => {
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
                    let result = import_logical_artifacts_with_rollback(
                        state,
                        &metadata,
                        &artifact_paths,
                        options,
                        staged.source_database.as_deref(),
                        Some(state.config.security.remote_import.max_staged_bytes),
                    )
                    .await;
                    staged.cleanup().await;
                    result
                }
            }
        }
        ImportSourceOptions::RemoteRequest(_) => Err(ApiError::Runtime(
            "remote import source was not validated".to_string(),
        )),
    }
}

fn validate_logical_operation_eligible(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Qdrant)
        || metadata.status == InstanceStatus::Running
    {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "instance is not running (status={:?})",
            metadata.status
        )))
    }
}

async fn import_instance_artifact(
    state: &AppState,
    instance_id: &str,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
    options: &ImportOptions,
    source_database: Option<&str>,
) -> Result<(), ApiError> {
    let protocol = metadata.protocol;
    match protocol {
        Protocol::Redis | Protocol::Qdrant => {
            import_physical_archive(state, instance_id, protocol, artifact_path).await
        }
        protocol => {
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
}

async fn import_logical_with_rollback(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
    options: &ImportOptions,
    source_database: Option<&str>,
    staging_limit: Option<u64>,
) -> Result<(), ApiError> {
    import_logical_artifacts_with_rollback(
        state,
        metadata,
        &[artifact_path],
        options,
        source_database,
        staging_limit,
    )
    .await
}

async fn import_logical_artifacts_with_rollback(
    state: &AppState,
    metadata: &InstanceMetadata,
    artifact_paths: &[&FsPath],
    options: &ImportOptions,
    source_database: Option<&str>,
    staging_limit: Option<u64>,
) -> Result<(), ApiError> {
    if artifact_paths.is_empty() {
        return Err(ApiError::Runtime(
            "logical import did not contain any artifacts".to_string(),
        ));
    }
    let remote_exec_timeout = staging_limit.map(|_| {
        Duration::from_secs(
            state
                .config
                .security
                .remote_import
                .operation_timeout_seconds,
        )
    });
    // Remote selective acquisition has already reduced the dump. Applying that
    // native dump is therefore a full artifact import; forwarding the original
    // selection would reject it or filter it a second time.
    let mut apply_options = options.clone();
    apply_options.selection = ImportExportSelection::default();
    let controls = LogicalImportControls {
        source_database,
        reuse_staged_artifact: staging_limit.is_some(),
        exec_timeout: remote_exec_timeout,
        remove_uploaded_source_limit: staging_limit,
        ..LogicalImportControls::default()
    };
    let mut prepared = Vec::with_capacity(artifact_paths.len());
    for artifact_path in artifact_paths {
        match prepare_logical_import(
            state,
            metadata,
            metadata.protocol,
            artifact_path,
            &apply_options,
            controls,
        )
        .await
        {
            Ok(artifact) => prepared.push(artifact),
            Err(error) => {
                cleanup_prepared_logical_imports(state, metadata, &prepared).await;
                return Err(error);
            }
        }
    }
    let retained_source_bytes = match staging_limit {
        Some(limit) => {
            let mut total = 0_u64;
            for artifact in &prepared {
                let Some(source_bytes) = artifact.removed_host_source_bytes else {
                    cleanup_prepared_logical_imports(state, metadata, &prepared).await;
                    return Err(ApiError::Runtime(
                        "remote import source staging accounting was unavailable".to_string(),
                    ));
                };
                total = match total.checked_add(source_bytes) {
                    Some(total) if total <= limit => total,
                    _ => {
                        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
                        return Err(ApiError::BadRequest(format!(
                            "remote import sources exceed the configured staging limit of {limit} bytes"
                        )));
                    }
                };
            }
            total
        }
        None => 0,
    };
    let rollback_limit = staging_limit.map(|limit| limit - retained_source_bytes);

    let rollback_root = match logical_staging_root(state).await {
        Ok(root) => root,
        Err(error) => {
            cleanup_prepared_logical_imports(state, metadata, &prepared).await;
            return Err(error);
        }
    };
    let recovery_id = uuid::Uuid::new_v4();
    let rollback_path = rollback_root.join(format!(
        ".dbe-import-rollback-{recovery_id}.{}",
        dump_extension(metadata.protocol)
    ));
    let recovery_manifest = rollback_root.join(format!(".dbe-import-recovery-{recovery_id}.json"));
    let export_options = ExportOptions::default();
    if let Err(error) = export_logical_dump(
        state,
        metadata,
        metadata.protocol,
        rollback_path.clone(),
        &export_options,
        LogicalExportControls {
            max_output_bytes: rollback_limit,
            exec_timeout: remote_exec_timeout,
            include_database_definition: true,
        },
    )
    .await
    {
        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
        cleanup_path(&rollback_path).await;
        return Err(error);
    }
    if let Some(limit) = staging_limit
        && let Err(error) = ensure_remote_import_staging_budget_with_retained_bytes(
            &[&rollback_path],
            retained_source_bytes,
            limit,
        )
        .await
    {
        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
        cleanup_path(&rollback_path).await;
        return Err(error);
    }
    if let Err(error) =
        write_logical_recovery_manifest(&recovery_manifest, metadata, &rollback_path, options.mode)
            .await
    {
        cleanup_prepared_logical_imports(state, metadata, &prepared).await;
        cleanup_path(&rollback_path).await;
        return Err(error);
    }

    let primary =
        apply_prepared_logical_imports(state, metadata, &prepared, apply_options.mode).await;
    cleanup_prepared_logical_imports(state, metadata, &prepared).await;
    if primary.is_ok() {
        if let Err(error) = commit_recovery_manifest(&recovery_manifest).await {
            let quarantine = quarantine_after_uncertain_import(state, &metadata.instance_id).await;
            return Err(ApiError::Runtime(format!(
                "{} import was applied, but its recovery commit marker could not be removed: {error}; target was failed closed{}; rollback data and manifest were retained for review",
                metadata.protocol.as_str(),
                quarantine_result_suffix(&quarantine)
            )));
        }
        cleanup_path(&rollback_path).await;
        return Ok(());
    }

    let primary = match primary {
        Ok(()) => unreachable!(),
        Err(primary) => primary,
    };
    if let Err(fence_error) =
        fence_logical_target_for_rollback(state, metadata, remote_exec_timeout).await
    {
        let quarantine = quarantine_after_uncertain_import(state, &metadata.instance_id).await;
        return Err(ApiError::Runtime(format!(
            "{} import failed: {primary}; the target process could not be generation-fenced before rollback: {fence_error}; rollback was not attempted to avoid racing an ambiguous import command; target was failed closed{}; rollback dump retained at {} with recovery manifest {}",
            metadata.protocol.as_str(),
            quarantine_result_suffix(&quarantine),
            rollback_path.display(),
            recovery_manifest.display()
        )));
    }

    let rollback_options = ImportOptions {
        source: ImportSourceOptions::Artifact(rollback_path.clone()),
        mode: ImportMode::Wipe,
        ..ImportOptions::default()
    };
    let rollback = import_logical_dump(
        state,
        metadata,
        metadata.protocol,
        &rollback_path,
        &rollback_options,
        LogicalImportControls {
            reuse_staged_artifact: true,
            database_definition_in_dump: true,
            exec_timeout: remote_exec_timeout,
            ..LogicalImportControls::default()
        },
    )
    .await;
    match rollback {
        Ok(()) => {
            if let Err(commit_error) = commit_recovery_manifest(&recovery_manifest).await {
                let quarantine =
                    quarantine_after_uncertain_import(state, &metadata.instance_id).await;
                return Err(ApiError::Runtime(format!(
                    "{} import failed: {primary}; rollback succeeded, but recovery metadata could not be committed: {commit_error}; target was failed closed{}; rollback data and manifest were retained",
                    metadata.protocol.as_str(),
                    quarantine_result_suffix(&quarantine)
                )));
            }
            cleanup_path(&rollback_path).await;
            Err(primary)
        }
        Err(rollback) => {
            let quarantine = quarantine_after_uncertain_import(state, &metadata.instance_id).await;
            Err(ApiError::Runtime(format!(
                "{} import failed: {primary}; rollback failed: {rollback}; target was failed closed{}; rollback dump retained at {} with recovery manifest {}",
                metadata.protocol.as_str(),
                quarantine_result_suffix(&quarantine),
                rollback_path.display(),
                recovery_manifest.display()
            )))
        }
    }
}

async fn fence_logical_target_for_rollback(
    state: &AppState,
    metadata: &InstanceMetadata,
    operation_timeout: Option<Duration>,
) -> Result<(), ApiError> {
    // A Docker transport/attach failure can leave the command running even after its client future
    // is gone. A confirmed stop is the process-generation fence: rollback is only safe after the
    // old database process is dead and a fresh one has reached startup readiness.
    stop_import_target_process(state, metadata, "before logical import rollback")
        .await
        .map_err(ApiError::Runtime)?;

    tokio::time::timeout(
        FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.start(metadata.protocol, &metadata.instance_id),
    )
    .await
    .map_err(|_| {
        ApiError::Runtime("timed out restarting target before logical import rollback".to_string())
    })?
    .map_err(|error| {
        ApiError::Runtime(format!(
            "failed to restart target before logical import rollback: {error}"
        ))
    })?;

    let readiness_timeout = operation_timeout
        .unwrap_or(LOGICAL_ROLLBACK_READINESS_TIMEOUT)
        .min(LOGICAL_ROLLBACK_READINESS_TIMEOUT);
    state
        .docker
        .wait_until_ready(metadata.protocol, &metadata.instance_id, readiness_timeout)
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "target did not become ready before logical import rollback: {error}"
            ))
        })
        .map(|_| ())
}

pub(crate) async fn quarantine_after_uncertain_import(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    let mut metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    metadata.status = InstanceStatus::Quarantined;
    metadata.updated_at = crate::jobs::import_export::now_rfc3339();

    // Remove gateway routes synchronously in memory before any Docker or SQLite wait. Existing
    // connections are cut off by the stop/kill below; new connections can no longer resolve.
    state.instances.upsert(metadata.clone()).await;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.resource_cache.remove(&metadata.instance_id).await;
    state.monitoring_cache.invalidate().await;

    let (runtime_result, persistence_result) = tokio::join!(
        stop_import_target_process(
            state,
            &metadata,
            "after an import lost durable commit or rollback certainty",
        ),
        state.manager.upsert(metadata.clone()),
    );
    let persistence_result =
        persistence_result.map_err(|error| format!("failed to persist quarantine: {error}"));

    tracing::error!(
        event = "audit uncertain_import_instance_quarantined",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        runtime_stopped = runtime_result.is_ok(),
        quarantine_persisted = persistence_result.is_ok(),
        "an import lost durable commit or rollback certainty; removed gateway routes and quarantined the target"
    );

    match (runtime_result, persistence_result) {
        (Ok(()), Ok(())) => Ok(()),
        (runtime, persistence) => {
            let mut failures = Vec::new();
            if let Err(error) = runtime {
                failures.push(error);
            }
            if let Err(error) = persistence {
                failures.push(error);
            }
            Err(ApiError::Runtime(failures.join("; ")))
        }
    }
}

async fn stop_import_target_process(
    state: &AppState,
    metadata: &InstanceMetadata,
    reason: &'static str,
) -> Result<(), String> {
    let stop = tokio::time::timeout(
        FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.stop(metadata.protocol, &metadata.instance_id),
    )
    .await;
    match stop {
        Ok(Ok(_)) => return Ok(()),
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => return Ok(()),
        Ok(Err(error)) => {
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %error,
                %reason,
                "graceful stop failed; forcing target shutdown"
            );
        }
        Err(_) => {
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %reason,
                "graceful stop timed out; forcing target shutdown"
            );
        }
    }

    match tokio::time::timeout(
        FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.kill(metadata.protocol, &metadata.instance_id),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => Ok(()),
        Ok(Err(error)) => Err(format!(
            "failed to stop or kill quarantined target: {error}"
        )),
        Err(_) => Err("timed out stopping and killing quarantined target".to_string()),
    }
}

fn quarantine_result_suffix(result: &Result<(), ApiError>) -> String {
    match result {
        Ok(()) => " and quarantined".to_string(),
        Err(error) => format!(
            " in memory and quarantined, but complete shutdown/persistence reported: {error}"
        ),
    }
}

async fn commit_recovery_manifest(path: &FsPath) -> Result<(), ApiError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::shared::files::remove_private_file_durable(&path))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to commit import recovery metadata: {error}"
            ))
        })?
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to commit import recovery metadata: {error}"
            ))
        })
}

#[derive(Serialize)]
struct LogicalRecoveryManifest<'a> {
    schema_version: u32,
    recovery_kind: &'static str,
    instance_id: &'a str,
    protocol: &'static str,
    import_mode: ImportMode,
    rollback_file: &'a str,
    created_at: String,
}

async fn write_logical_recovery_manifest(
    path: &FsPath,
    metadata: &InstanceMetadata,
    rollback_path: &FsPath,
    mode: ImportMode,
) -> Result<(), ApiError> {
    let durable_rollback = rollback_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        crate::shared::files::sync_private_regular_file_durable(&durable_rollback)
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to sync rollback data: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("failed to sync rollback data: {error}")))?;
    let rollback_file = rollback_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ApiError::Runtime("invalid rollback file name".to_string()))?;
    let manifest = serde_json::to_vec_pretty(&LogicalRecoveryManifest {
        schema_version: 1,
        recovery_kind: "logical_remote_import",
        instance_id: &metadata.instance_id,
        protocol: metadata.protocol.as_str(),
        import_mode: mode,
        rollback_file,
        created_at: crate::jobs::import_export::now_rfc3339(),
    })
    .map_err(|error| ApiError::Runtime(format!("failed to encode recovery manifest: {error}")))?;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        crate::shared::files::atomic_write_private(&path, &manifest)
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to write recovery manifest: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("failed to write recovery manifest: {error}")))
}

#[cfg(test)]
async fn ensure_remote_import_staging_budget(
    paths: &[&FsPath],
    max_bytes: u64,
) -> Result<u64, ApiError> {
    ensure_remote_import_staging_budget_with_retained_bytes(paths, 0, max_bytes).await
}

async fn ensure_remote_import_staging_budget_with_retained_bytes(
    paths: &[&FsPath],
    retained_bytes: u64,
    max_bytes: u64,
) -> Result<u64, ApiError> {
    let mut total = retained_bytes;
    if total > max_bytes {
        return Err(ApiError::BadRequest(format!(
            "remote import source and rollback data exceed the configured {max_bytes}-byte staging limit; reduce the selected source or target data size"
        )));
    }
    for path in paths {
        let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
            ApiError::Runtime(format!(
                "failed to inspect remote import staging data: {error}"
            ))
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(ApiError::Runtime(
                "remote import staging data is not a regular file".to_string(),
            ));
        }
        total = total.checked_add(metadata.len()).ok_or_else(|| {
            ApiError::BadRequest("remote import staging size overflowed".to_string())
        })?;
        if total > max_bytes {
            return Err(ApiError::BadRequest(format!(
                "remote import source and rollback data exceed the configured {max_bytes}-byte staging limit; reduce the selected source or target data size"
            )));
        }
    }
    Ok(total)
}

async fn export_physical_archive(
    state: &AppState,
    instance_id: &str,
    protocol: Protocol,
    artifact_path: PathBuf,
    selection: &ImportExportSelection,
) -> Result<(), ApiError> {
    ensure_full_selection(protocol, selection)?;
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let was_running = metadata.status == InstanceStatus::Running;
    if was_running {
        let _ = lifecycle_instance_locked(state, instance_id, LifecycleAction::Stop).await?;
    }

    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let result = create_data_archive(paths.data, artifact_path)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()));
    finish_physical_operation(state, instance_id, was_running, result).await
}

async fn import_physical_archive(
    state: &AppState,
    instance_id: &str,
    protocol: Protocol,
    artifact_path: &FsPath,
) -> Result<(), ApiError> {
    match protocol {
        Protocol::Redis | Protocol::Qdrant => {}
        protocol => {
            return Err(ApiError::BadRequest(format!(
                "{} is not a physical archive protocol",
                protocol.as_str()
            )));
        }
    }
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let was_running = metadata.status == InstanceStatus::Running;
    if was_running {
        let _ = lifecycle_instance_locked(state, instance_id, LifecycleAction::Stop).await?;
    }

    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let mut result = replace_data_from_archive(paths.clone(), artifact_path).await;
    if result.is_ok() && !state.docker.uses_rootless_podman() {
        result = paths
            .reapply_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()));
    }
    finish_physical_operation(state, instance_id, was_running, result).await
}

#[derive(Clone, Copy, Default)]
struct LogicalExportControls {
    max_output_bytes: Option<u64>,
    exec_timeout: Option<Duration>,
    include_database_definition: bool,
}

async fn export_logical_dump(
    state: &AppState,
    metadata: &InstanceMetadata,
    protocol: Protocol,
    artifact_path: PathBuf,
    options: &ExportOptions,
    controls: LogicalExportControls,
) -> Result<(), ApiError> {
    let instance_id = &metadata.instance_id;
    create_private_directory(
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
    let container_temp = format!("/tmp/{temp_name}");
    cleanup_path(&host_temp).await;

    let mut script = export_script(
        metadata,
        &container_temp,
        &options.selection,
        controls.include_database_definition,
    )?;
    if let Some(max_bytes) = controls.max_output_bytes {
        // POSIX shells differ on whether `ulimit -f` blocks are 512 or 1024 bytes.
        // Dividing by 1024 is conservative on both and bounds the container-side
        // dump before Docker transfer begins.
        let blocks = max_bytes / 1024;
        if blocks == 0 {
            return Err(ApiError::BadRequest(
                "remote import staging limit leaves no room for a rollback dump".to_string(),
            ));
        }
        script = format!("set -eu\nulimit -f {blocks}\n{script}");
    }
    let result = async {
        let output = match controls.exec_timeout {
            Some(timeout) => {
                state
                    .docker
                    .exec_shell_with_timeout(protocol, instance_id, &script, timeout)
                    .await
            }
            None => {
                state
                    .docker
                    .exec_shell(protocol, instance_id, &script)
                    .await
            }
        };
        output.map_err(|error| ApiError::Runtime(error.to_string()))?;
        match controls.max_output_bytes {
            Some(max_bytes) => {
                state
                    .docker
                    .download_file_bounded(
                        protocol,
                        instance_id,
                        &container_temp,
                        &host_temp,
                        max_bytes,
                    )
                    .await
            }
            None => {
                state
                    .docker
                    .download_file(protocol, instance_id, &container_temp, &host_temp)
                    .await
            }
        }
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
        archive_or_copy_export(&host_temp, &artifact_path, options.archive_format).await
    }
    .await;
    cleanup_container_temp(state, protocol, instance_id, &container_temp).await;
    cleanup_path(&host_temp).await;
    result
}

#[derive(Clone, Copy, Default)]
struct LogicalImportControls<'a> {
    source_database: Option<&'a str>,
    reuse_staged_artifact: bool,
    database_definition_in_dump: bool,
    exec_timeout: Option<Duration>,
    remove_uploaded_source_limit: Option<u64>,
}

async fn import_logical_dump(
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
    result
}

struct PreparedLogicalImport {
    protocol: Protocol,
    host_temp: PathBuf,
    owns_host_temp: bool,
    container_temp: String,
    script: String,
    exec_timeout: Option<Duration>,
    database_definition_in_dump: bool,
    removed_host_source_bytes: Option<u64>,
}

async fn prepare_logical_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    protocol: Protocol,
    artifact_path: &FsPath,
    options: &ImportOptions,
    controls: LogicalImportControls<'_>,
) -> Result<PreparedLogicalImport, ApiError> {
    ensure_full_selection(protocol, &options.selection)?;
    let extension = dump_extension(protocol);
    let temp_name = format!(".dbe-import-{}.{}", uuid::Uuid::new_v4(), extension);
    let staging_root = logical_staging_root(state).await?;
    let host_temp = if controls.reuse_staged_artifact {
        artifact_path.to_path_buf()
    } else {
        staging_root.join(&temp_name)
    };
    let container_temp = format!("/tmp/{temp_name}");
    let staged_source_bytes = if controls.reuse_staged_artifact {
        Some(ensure_import_file_size(&host_temp).await?)
    } else {
        cleanup_path(&host_temp).await;
        if let Err(error) = prepare_logical_import_artifact(
            protocol,
            artifact_path,
            &host_temp,
            &staging_root,
            options,
        )
        .await
        {
            cleanup_path(&host_temp).await;
            return Err(error);
        }
        None
    };
    if let (Some(source_bytes), Some(limit)) =
        (staged_source_bytes, controls.remove_uploaded_source_limit)
        && source_bytes > limit
    {
        return Err(ApiError::BadRequest(format!(
            "remote import source is {source_bytes} bytes; configured staging limit is {limit} bytes"
        )));
    }

    let script = match import_script(
        metadata,
        &container_temp,
        controls.source_database,
        controls.database_definition_in_dump,
    ) {
        Ok(script) => script,
        Err(error) => {
            if !controls.reuse_staged_artifact {
                cleanup_path(&host_temp).await;
            }
            return Err(error);
        }
    };
    if let Err(error) = state
        .docker
        .upload_file(protocol, &metadata.instance_id, &host_temp, &container_temp)
        .await
    {
        cleanup_container_temp(state, protocol, &metadata.instance_id, &container_temp).await;
        if !controls.reuse_staged_artifact {
            cleanup_path(&host_temp).await;
        }
        return Err(ApiError::Runtime(error.to_string()));
    }
    let removed_host_source_bytes = if controls.remove_uploaded_source_limit.is_some() {
        let source_bytes = staged_source_bytes.ok_or_else(|| {
            ApiError::Runtime(
                "remote import source removal requires a staged source artifact".to_string(),
            )
        })?;
        let source_path = host_temp.clone();
        if let Err(error) = tokio::task::spawn_blocking(move || {
            crate::shared::files::remove_private_file_durable(&source_path)
        })
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("failed to join remote source cleanup: {error}"))
        })?
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to remove uploaded remote source from host staging: {error}"
            ))
        }) {
            cleanup_container_temp(state, protocol, &metadata.instance_id, &container_temp).await;
            return Err(error);
        }
        Some(source_bytes)
    } else {
        None
    };
    Ok(PreparedLogicalImport {
        protocol,
        host_temp,
        owns_host_temp: !controls.reuse_staged_artifact,
        container_temp,
        script,
        exec_timeout: controls.exec_timeout,
        database_definition_in_dump: controls.database_definition_in_dump,
        removed_host_source_bytes,
    })
}

async fn apply_prepared_logical_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared: &PreparedLogicalImport,
    mode: ImportMode,
) -> Result<(), ApiError> {
    apply_prepared_logical_imports(state, metadata, std::slice::from_ref(prepared), mode).await
}

async fn apply_prepared_logical_imports(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared: &[PreparedLogicalImport],
    mode: ImportMode,
) -> Result<(), ApiError> {
    let first = prepared.first().ok_or_else(|| {
        ApiError::Runtime("logical import did not contain any prepared artifacts".to_string())
    })?;
    if prepared.iter().any(|artifact| {
        artifact.protocol != metadata.protocol
            || artifact.exec_timeout != first.exec_timeout
            || artifact.database_definition_in_dump != first.database_definition_in_dump
    }) {
        return Err(ApiError::Runtime(
            "logical import artifacts had inconsistent execution controls".to_string(),
        ));
    }
    let instance_id = &metadata.instance_id;
    if mode == ImportMode::Wipe {
        wipe_logical_target(
            state,
            metadata,
            first.exec_timeout,
            first.database_definition_in_dump,
        )
        .await?;
    }
    let import_started = Instant::now();
    for artifact in prepared {
        let result = match artifact.exec_timeout {
            Some(timeout) => {
                let remaining = timeout
                    .checked_sub(import_started.elapsed())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or_else(|| {
                        ApiError::Runtime(format!(
                            "{} import timed out while applying multiple artifacts",
                            metadata.protocol.as_str()
                        ))
                    })?;
                state
                    .docker
                    .exec_shell_with_timeout(
                        artifact.protocol,
                        instance_id,
                        &artifact.script,
                        remaining,
                    )
                    .await
            }
            None => {
                state
                    .docker
                    .exec_shell(artifact.protocol, instance_id, &artifact.script)
                    .await
            }
        };
        result.map_err(|error| ApiError::Runtime(error.to_string()))?;
    }
    Ok(())
}

async fn cleanup_prepared_logical_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared: &PreparedLogicalImport,
) {
    cleanup_container_temp(
        state,
        prepared.protocol,
        &metadata.instance_id,
        &prepared.container_temp,
    )
    .await;
    if prepared.owns_host_temp {
        cleanup_path(&prepared.host_temp).await;
    }
}

async fn cleanup_prepared_logical_imports(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared: &[PreparedLogicalImport],
) {
    for artifact in prepared {
        cleanup_prepared_logical_import(state, metadata, artifact).await;
    }
}

async fn prepare_logical_import_artifact(
    protocol: Protocol,
    artifact_path: &FsPath,
    host_temp: &FsPath,
    staging_root: &FsPath,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    let Some(requested_format) = options.archive_format.as_deref() else {
        ensure_import_file_size(artifact_path).await?;
        copy_file(artifact_path, host_temp).await?;
        return Ok(());
    };

    let format = ImportArchiveFormat::parse(requested_format)?;
    match format {
        ImportArchiveFormat::Plain => {
            ensure_import_file_size(artifact_path).await?;
            copy_file(artifact_path, host_temp).await
        }
        ImportArchiveFormat::Gzip => decompress_gzip(artifact_path, host_temp).await,
        ImportArchiveFormat::Bzip2 => decompress_bzip2(artifact_path, host_temp).await,
        ImportArchiveFormat::Tar | ImportArchiveFormat::TarGzip => {
            let staging = staging_root.join(format!(".dbe-unarchive-{}", uuid::Uuid::new_v4()));
            let result = match extract_tar_archive(
                artifact_path,
                &staging,
                format == ImportArchiveFormat::TarGzip,
            )
            .await
            {
                Ok(()) => copy_selected_dump(protocol, &staging, host_temp).await,
                Err(error) => Err(error),
            };
            cleanup_dir(&staging).await;
            result
        }
        ImportArchiveFormat::Zip => {
            let staging = staging_root.join(format!(".dbe-unarchive-{}", uuid::Uuid::new_v4()));
            let result = match extract_zip_archive(artifact_path, &staging).await {
                Ok(()) => copy_selected_dump(protocol, &staging, host_temp).await,
                Err(error) => Err(error),
            };
            cleanup_dir(&staging).await;
            result
        }
    }
}

async fn decompress_gzip(source: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "decompress gzip",
        true,
        move |deadline| -> Result<(), std::io::Error> {
            let input = std::fs::File::open(source)?;
            let mut decoder = flate2::read::GzDecoder::new(input);
            write_new_private_file(&target, |mut output| {
                copy_limited_until(&mut decoder, &mut output, MAX_UNARCHIVED_BYTES, deadline)?;
                output.flush()
            })
        },
    )
    .await
}

async fn decompress_bzip2(source: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "decompress bzip2",
        true,
        move |deadline| -> Result<(), std::io::Error> {
            let input = std::fs::File::open(source)?;
            let mut decoder = bzip2::read::BzDecoder::new(input);
            write_new_private_file(&target, |mut output| {
                copy_limited_until(&mut decoder, &mut output, MAX_UNARCHIVED_BYTES, deadline)?;
                output.flush()
            })
        },
    )
    .await
}

async fn extract_tar_archive(
    source: &FsPath,
    target_dir: &FsPath,
    gzipped: bool,
) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target_dir = target_dir.to_path_buf();
    tokio::task::spawn_blocking(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let deadline = archive_operation_deadline();
            create_private_directory_blocking(&target_dir)?;
            let input = std::fs::File::open(source)?;
            if gzipped {
                let decoder = flate2::read::GzDecoder::new(input);
                let mut archive = tar::Archive::new(decoder);
                unpack_tar_safely(&mut archive, &target_dir, deadline)?;
            } else {
                let mut archive = tar::Archive::new(input);
                unpack_tar_safely(&mut archive, &target_dir, deadline)?;
            }
            Ok(())
        },
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to extract tar archive: {error}")))?
    .map_err(|error| ApiError::BadRequest(format!("failed to extract tar archive: {error}")))
}

async fn extract_zip_archive(source: &FsPath, target_dir: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target_dir = target_dir.to_path_buf();
    tokio::task::spawn_blocking(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let deadline = archive_operation_deadline();
            create_private_directory_blocking(&target_dir)?;
            let input = std::fs::File::open(source)?;
            let mut archive = zip::ZipArchive::new(input)?;
            if archive.len() > MAX_ARCHIVE_ENTRIES {
                return Err(format!("archive has more than {MAX_ARCHIVE_ENTRIES} entries").into());
            }
            let mut total = 0_u64;
            for index in 0..archive.len() {
                ensure_archive_deadline(deadline)?;
                let mut file = archive.by_index(index)?;
                let enclosed = file
                    .enclosed_name()
                    .ok_or_else(|| format!("zip entry {} has unsafe path", file.name()))?
                    .to_path_buf();
                validate_relative_archive_path(&enclosed)?;
                total = total
                    .checked_add(file.size())
                    .ok_or("archive uncompressed size overflow")?;
                if total > MAX_UNARCHIVED_BYTES {
                    return Err(
                        format!("archive expands beyond {MAX_UNARCHIVED_BYTES} bytes").into(),
                    );
                }
                let size = file.size();
                let target = target_dir.join(enclosed);
                if file.is_dir() {
                    create_private_directory_blocking(&target)?;
                    continue;
                }
                if let Some(parent) = target.parent() {
                    create_private_directory_blocking(parent)?;
                }
                let mut output = create_private_file_blocking(&target)?;
                copy_limited_until(&mut file, &mut output, size, deadline)?;
            }
            Ok(())
        },
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to extract zip archive: {error}")))?
    .map_err(|error| ApiError::BadRequest(format!("failed to extract zip archive: {error}")))
}

fn unpack_tar_safely<R: Read>(
    archive: &mut tar::Archive<R>,
    target_dir: &FsPath,
    deadline: Instant,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut total = 0_u64;
    let mut entries = 0_usize;
    for entry in archive.entries()? {
        ensure_archive_deadline(deadline)?;
        entries += 1;
        if entries > MAX_ARCHIVE_ENTRIES {
            return Err(format!("archive has more than {MAX_ARCHIVE_ENTRIES} entries").into());
        }
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err("archive contains unsupported link/device/special entry".into());
        }
        let path = entry.path()?.to_path_buf();
        validate_relative_archive_path(&path)?;
        let size = entry.header().size()?;
        total = total
            .checked_add(size)
            .ok_or("archive uncompressed size overflow")?;
        if total > MAX_UNARCHIVED_BYTES {
            return Err(format!("archive expands beyond {MAX_UNARCHIVED_BYTES} bytes").into());
        }
        let target = target_dir.join(&path);
        if kind.is_dir() {
            create_private_directory_blocking(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            create_private_directory_blocking(parent)?;
        }
        let mut output = create_private_file_blocking(&target)?;
        copy_limited_until(&mut entry, &mut output, size, deadline)?;
    }
    Ok(())
}

fn validate_relative_archive_path(
    path: &FsPath,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut depth = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(_) => {
                depth += 1;
                if depth > MAX_ARCHIVE_DEPTH {
                    return Err(format!("archive path depth exceeds {MAX_ARCHIVE_DEPTH}").into());
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("archive contains unsafe path {}", path.display()).into());
            }
        }
    }
    if depth == 0 {
        return Err("archive contains empty path".into());
    }
    Ok(())
}

fn archive_operation_deadline() -> Instant {
    Instant::now() + ARCHIVE_OPERATION_TIMEOUT
}

fn ensure_archive_deadline(deadline: Instant) -> Result<(), std::io::Error> {
    if Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "archive operation exceeded time limit",
        ));
    }
    Ok(())
}

fn copy_limited_until<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
    deadline: Instant,
) -> Result<u64, std::io::Error> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        ensure_archive_deadline(deadline)?;
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(total);
        }
        total = total.saturating_add(read as u64);
        if total > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed data exceeded configured limit",
            ));
        }
        writer.write_all(&buffer[..read])?;
    }
}

async fn copy_selected_dump(
    protocol: Protocol,
    staging_dir: &FsPath,
    host_temp: &FsPath,
) -> Result<(), ApiError> {
    let staging_dir = staging_dir.to_path_buf();
    let candidate =
        tokio::task::spawn_blocking(move || find_dump_candidate(protocol, &staging_dir))
            .await
            .map_err(|error| {
                ApiError::Runtime(format!("failed to inspect archive contents: {error}"))
            })?
            .map_err(ApiError::BadRequest)?;
    copy_file(&candidate, host_temp).await
}

fn find_dump_candidate(protocol: Protocol, root: &FsPath) -> Result<PathBuf, String> {
    let mut files = Vec::new();
    collect_regular_files(root, &mut files).map_err(|error| error.to_string())?;
    files.sort();
    let suffixes = dump_candidate_suffixes(protocol);
    for suffix in suffixes {
        let matches: Vec<_> = files
            .iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.to_ascii_lowercase().ends_with(suffix))
            })
            .cloned()
            .collect();
        match matches.len() {
            1 => return Ok(matches[0].clone()),
            0 => {}
            _ => {
                return Err(format!(
                    "archive contains multiple candidate dump files ending with {suffix}"
                ));
            }
        }
    }
    Err(format!(
        "archive does not contain a supported {} dump file",
        protocol.as_str()
    ))
}

fn collect_regular_files(dir: &FsPath, files: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_regular_files(&path, files)?;
        } else if metadata.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn dump_candidate_suffixes(protocol: Protocol) -> &'static [&'static str] {
    match protocol {
        Protocol::Postgres => &[".postgres.sql", ".pgsql.sql", ".sql"],
        Protocol::Redis => &[".redis.tar.gz", ".tar.gz"],
        Protocol::Mariadb => &[".mariadb.sql", ".mysql.sql", ".sql"],
        Protocol::Mysql => &[".mysql.sql", ".sql"],
        Protocol::Mongodb => &[".mongodb.archive.gz", ".archive.gz"],
        Protocol::Clickhouse => &[".clickhouse.sql", ".sql"],
        Protocol::Qdrant => &[".qdrant.tar.gz", ".tar.gz"],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportArchiveFormat {
    Plain,
    Gzip,
    Bzip2,
    Tar,
    TarGzip,
    Zip,
}

impl ImportArchiveFormat {
    fn parse(value: &str) -> Result<Self, ApiError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plain" => Ok(Self::Plain),
            "gzip" => Ok(Self::Gzip),
            "bzip2" => Ok(Self::Bzip2),
            "tar" => Ok(Self::Tar),
            "tar.gz" => Ok(Self::TarGzip),
            "zip" => Ok(Self::Zip),
            other => Err(ApiError::BadRequest(format!(
                "unsupported archive_format {other}; use plain, gzip, bzip2, tar, tar.gz, or zip"
            ))),
        }
    }
}

async fn validate_import_source(
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
            if matches!(target_protocol, Protocol::Redis | Protocol::Qdrant) {
                ensure_full_selection(target_protocol, &options.selection)?;
                if options.archive_format.is_some() {
                    return Err(ApiError::BadRequest(format!(
                        "{} artifact imports consume their physical archive directly; omit archive_format",
                        target_protocol.as_str()
                    )));
                }
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

async fn harden_import_options(
    state: &AppState,
    instance_id: &str,
    target_protocol: Protocol,
    mut options: ImportOptions,
) -> Result<ImportOptions, ApiError> {
    validate_import_source(state, target_protocol, &options).await?;
    options.source = match options.source {
        ImportSourceOptions::Artifact(path) => {
            ImportSourceOptions::Artifact(validate_artifact_path(state, instance_id, &path).await?)
        }
        ImportSourceOptions::RemoteRequest(request) => ImportSourceOptions::Remote(
            validate_remote_source(state, target_protocol, request).await?,
        ),
        ImportSourceOptions::Remote(source) => ImportSourceOptions::Remote(source),
    };
    Ok(options)
}

#[derive(Debug, Clone, Copy)]
enum SelectionUse {
    Export,
    Import,
}

fn validate_selection(
    protocol: Protocol,
    selection: &ImportExportSelection,
    use_case: SelectionUse,
) -> Result<(), ApiError> {
    if selection.include.len() > MAX_SELECTION_ITEMS
        || selection.exclude.len() > MAX_SELECTION_ITEMS
    {
        return Err(ApiError::BadRequest(format!(
            "selection include/exclude may contain at most {MAX_SELECTION_ITEMS} items"
        )));
    }
    if selection.fields.len() > MAX_SELECTION_ITEMS {
        return Err(ApiError::BadRequest(format!(
            "selection fields may contain at most {MAX_SELECTION_ITEMS} objects"
        )));
    }
    for fields in selection.fields.values() {
        if fields.len() > MAX_SELECTION_FIELDS_PER_ITEM {
            return Err(ApiError::BadRequest(format!(
                "selection fields for one object may contain at most {MAX_SELECTION_FIELDS_PER_ITEM} fields"
            )));
        }
    }

    if selection.mode == SelectionMode::Full {
        if !selection.include.is_empty()
            || !selection.exclude.is_empty()
            || !selection.fields.is_empty()
        {
            return Err(ApiError::BadRequest(
                "selection.mode=full must not include include/exclude/fields".to_string(),
            ));
        }
        return Ok(());
    }

    if selection.include.is_empty() {
        return Err(ApiError::BadRequest(
            "selection.mode=selective requires at least one include item".to_string(),
        ));
    }
    if let Some(overlap) = selection
        .include
        .iter()
        .find(|item| selection.exclude.contains(*item))
    {
        return Err(ApiError::BadRequest(format!(
            "selection cannot both include and exclude {overlap}"
        )));
    }

    match protocol {
        Protocol::Postgres | Protocol::Mariadb | Protocol::Mysql => {
            for item in selection.include.iter().chain(selection.exclude.iter()) {
                validate_sql_object_name(protocol, item)?;
            }
            if !selection.fields.is_empty() {
                return Err(ApiError::NotImplemented(format!(
                    "{} column-level selective {} is not implemented yet; use table-level selection",
                    protocol.as_str(),
                    selection_use_name(use_case)
                )));
            }
        }
        Protocol::Mongodb => {
            for item in selection.include.iter().chain(selection.exclude.iter()) {
                validate_simple_identifier("mongodb collection", item)?;
            }
            let mut included_collections = HashSet::with_capacity(selection.include.len());
            if let Some(duplicate) = selection
                .include
                .iter()
                .find(|collection| !included_collections.insert(collection.as_str()))
            {
                return Err(ApiError::BadRequest(format!(
                    "mongodb selection includes collection {duplicate} more than once"
                )));
            }
            if matches!(use_case, SelectionUse::Export) && selection.include.len() != 1 {
                return Err(ApiError::NotImplemented(format!(
                    "mongodb selective {} currently supports exactly one included collection",
                    selection_use_name(use_case)
                )));
            }
            if !selection.fields.is_empty() {
                return Err(ApiError::NotImplemented(
                    "mongodb field projection is not implemented yet; use collection-level selection".to_string(),
                ));
            }
        }
        Protocol::Clickhouse => {
            for item in selection.include.iter().chain(selection.exclude.iter()) {
                validate_simple_identifier("clickhouse table", item)?;
            }
            for (table, fields) in &selection.fields {
                validate_simple_identifier("clickhouse table", table)?;
                for field in fields {
                    validate_simple_identifier("clickhouse column", field)?;
                }
            }
        }
        Protocol::Redis => {
            return Err(ApiError::NotImplemented(
                "redis selective import/export requires a logical key dump format and is not implemented yet".to_string(),
            ));
        }
        Protocol::Qdrant => {
            for item in selection.include.iter().chain(selection.exclude.iter()) {
                validate_simple_identifier("qdrant collection", item)?;
            }
            if !selection.fields.is_empty() {
                return Err(ApiError::NotImplemented(
                    "qdrant field-level selection is not implemented; use collection-level selection"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn selection_use_name(use_case: SelectionUse) -> &'static str {
    match use_case {
        SelectionUse::Export => "export",
        SelectionUse::Import => "import",
    }
}

fn ensure_full_selection(
    protocol: Protocol,
    selection: &ImportExportSelection,
) -> Result<(), ApiError> {
    if selection.mode == SelectionMode::Full
        && selection.include.is_empty()
        && selection.exclude.is_empty()
        && selection.fields.is_empty()
    {
        return Ok(());
    }
    Err(ApiError::BadRequest(format!(
        "{} artifact import/export path only accepts selection.mode=full; create a selective export artifact or use remote selective import",
        protocol.as_str()
    )))
}

fn validate_sql_object_name(protocol: Protocol, value: &str) -> Result<(), ApiError> {
    let parts: Vec<_> = value.split('.').collect();
    let valid = match protocol {
        Protocol::Postgres => (1..=2).contains(&parts.len()),
        Protocol::Mariadb => (1..=2).contains(&parts.len()),
        Protocol::Mysql => (1..=2).contains(&parts.len()),
        _ => false,
    } && parts
        .iter()
        .all(|part| !part.is_empty() && simple_identifier(part));
    if valid {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "invalid {} object name {value}; use ascii identifiers like table or schema.table",
            protocol.as_str()
        )))
    }
}

fn validate_simple_identifier(kind: &str, value: &str) -> Result<(), ApiError> {
    if simple_identifier(value) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "invalid {kind} {value}; use ascii letters, digits, underscore, or dash"
        )))
    }
}

fn simple_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn postgres_dump_selection_args(selection: &ImportExportSelection) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(String::new());
    }
    let mut args = String::new();
    for item in &selection.include {
        args.push_str(" --table=");
        args.push_str(&sh_quote(item));
    }
    for item in &selection.exclude {
        args.push_str(" --exclude-table=");
        args.push_str(&sh_quote(item));
    }
    Ok(args)
}

fn mariadb_local_dump_selection_args(
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(" -- \"$MARIADB_DATABASE\"".to_string());
    }
    let mut args = String::new();
    for item in &selection.exclude {
        let table = item
            .rsplit_once('.')
            .map(|(_, table)| table)
            .unwrap_or(item);
        args.push_str(&format!(" --ignore-table=\"$MARIADB_DATABASE.{table}\""));
    }
    args.push_str(" -- \"$MARIADB_DATABASE\"");
    for item in &selection.include {
        let table = item
            .rsplit_once('.')
            .map(|(_, table)| table)
            .unwrap_or(item);
        args.push(' ');
        args.push_str(&sh_quote(table));
    }
    Ok(args)
}

fn mysql_local_dump_selection_args(selection: &ImportExportSelection) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(" -- \"$MYSQL_DATABASE\"".to_string());
    }
    let mut args = String::new();
    for item in &selection.exclude {
        let table = item
            .rsplit_once('.')
            .map(|(_, table)| table)
            .unwrap_or(item);
        args.push_str(&format!(" --ignore-table=\"$MYSQL_DATABASE.{table}\""));
    }
    args.push_str(" -- \"$MYSQL_DATABASE\"");
    for item in &selection.include {
        let table = item
            .rsplit_once('.')
            .map(|(_, table)| table)
            .unwrap_or(item);
        args.push(' ');
        args.push_str(&sh_quote(table));
    }
    Ok(args)
}

fn mongodb_dump_selection_args(selection: &ImportExportSelection) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(String::new());
    }
    let mut args = String::new();
    let collection = selection.include.first().ok_or_else(|| {
        ApiError::BadRequest(
            "mongodb selective export requires one included collection".to_string(),
        )
    })?;
    args.push_str(" --collection=");
    args.push_str(&sh_quote(collection));
    Ok(args)
}

fn clickhouse_table_source(selection: &ImportExportSelection) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(r#"clickhouse-client \
  --host 127.0.0.1 \
  --user "$CLICKHOUSE_USER" \
  --password "$CLICKHOUSE_PASSWORD" \
  --database "$CLICKHOUSE_DB" \
  --query "SHOW TABLES FORMAT TSV""#
            .to_string());
    }
    Ok(format!(
        "printf '%s\\n' {}",
        sh_quote(&selection.include.join("\n"))
    ))
}

fn clickhouse_column_expr_function(selection: &ImportExportSelection) -> Result<String, ApiError> {
    if selection.fields.is_empty() {
        return Ok(r#"printf '*'"#.to_string());
    }
    let mut cases = String::from("case \"$table\" in\n");
    for (table, fields) in &selection.fields {
        let columns = fields
            .iter()
            .map(|field| format!("`{field}`"))
            .collect::<Vec<_>>()
            .join(", ");
        cases.push_str(&format!(
            "  {}) printf '%s' {} ;;\n",
            sh_quote(table),
            sh_quote(&columns)
        ));
    }
    cases.push_str("  *) printf '*' ;;\nesac");
    Ok(cases)
}

fn ensure_mongodb_root_password(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if metadata.protocol == Protocol::Mongodb && metadata.mongodb_root_password.is_none() {
        return Err(ApiError::BadRequest(
            "mongodb internal root password is missing; this instance was created before DBE stored MongoDB maintenance credentials, so DBE cannot export/import protected internal collections such as time-series buckets. Recreate the instance or use a manual admin dump.".to_string(),
        ));
    }
    Ok(())
}

fn ensure_mysql_root_password(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if metadata.protocol == Protocol::Mysql && metadata.mysql_root_password.is_none() {
        return Err(ApiError::BadRequest(
            "mysql internal root password is missing; recreate or repair this instance before exporting or importing"
                .to_string(),
        ));
    }
    Ok(())
}

fn export_script(
    metadata: &InstanceMetadata,
    output_path: &str,
    selection: &ImportExportSelection,
    include_database_definition: bool,
) -> Result<String, ApiError> {
    let protocol = metadata.protocol;
    let script = match protocol {
        Protocol::Postgres => {
            let filters = postgres_dump_selection_args(selection)?;
            format!(
                r#"set -eu
PGPASSWORD="${{DBE_POSTGRES_PASSWORD:-$POSTGRES_PASSWORD}}" pg_dump \
  -h /var/run/postgresql \
  -U "${{DBE_POSTGRES_USER:-$POSTGRES_USER}}" \
  -d "$POSTGRES_DB" \
  --clean --if-exists --no-owner --no-privileges{filters} \
  > {output_path}
"#
            )
        }
        Protocol::Mariadb => {
            let filters = mariadb_local_dump_selection_args(selection)?;
            let database_definition = if include_database_definition {
                " --databases"
            } else {
                ""
            };
            format!(
                r#"set -eu
mariadb-dump \
  --protocol=socket \
  --socket=/run/mysqld/mysqld.sock \
  -u "$MARIADB_USER" \
  -p"$MARIADB_PASSWORD" \
  --single-transaction --quick --routines --events --triggers \
  --hex-blob --add-drop-table{database_definition}{filters} \
  > {output_path}
"#
            )
        }
        Protocol::Mysql => {
            ensure_mysql_root_password(metadata)?;
            let filters = mysql_local_dump_selection_args(selection)?;
            let database_definition = if include_database_definition {
                " --databases"
            } else {
                ""
            };
            format!(
                r#"set -eu
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump \
  --protocol=socket \
  --socket=/var/run/mysqld/mysqld.sock \
  -u root \
  --single-transaction --quick --routines --events --triggers \
  --hex-blob --add-drop-table --no-tablespaces --set-gtid-purged=OFF{database_definition}{filters} \
  > {output_path}
"#
            )
        }
        Protocol::Mongodb => {
            ensure_mongodb_root_password(metadata)?;
            let filters = mongodb_dump_selection_args(selection)?;
            format!(
                r#"set -eu
mongodump \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_ROOT_USER" \
  --password "$DBE_MONGO_ROOT_PASSWORD" \
  --authenticationDatabase "admin" \
  --db "$DBE_MONGO_DATABASE" \
  {filters} \
  --archive={output_path} \
  --gzip
"#
            )
        }
        Protocol::Clickhouse => {
            let table_source = clickhouse_table_source(selection)?;
            let column_expr = clickhouse_column_expr_function(selection)?;
            let engine_parser = sh_quote(CLICKHOUSE_ENGINE_AWK_PROGRAM);
            format!(
                r#"set -eu
out={output_path}
printf '%s\n' '-- DatabasesEverywhere ClickHouse logical dump' > "$out"
{table_source} | while IFS= read -r table; do
    [ -n "$table" ] || continue
    case "$table" in *[!A-Za-z0-9_-]*)
      echo 'target clickhouse contains a non-portable table name' >&2
      exit 42
    ;; esac
    create=$(clickhouse-client \
      --host 127.0.0.1 \
      --user "$CLICKHOUSE_USER" \
      --password "$CLICKHOUSE_PASSWORD" \
      --database "$CLICKHOUSE_DB" \
      --query "SHOW CREATE TABLE \`$table\` FORMAT TabSeparatedRaw")
    engine=$(printf '%s\n' "$create" | awk {engine_parser}) || {{
      echo 'target clickhouse SHOW CREATE must contain exactly one valid ENGINE clause' >&2
      exit 43
    }}
    case "$engine" in
      MergeTree|ReplacingMergeTree|SummingMergeTree|AggregatingMergeTree|CollapsingMergeTree|VersionedCollapsingMergeTree|GraphiteMergeTree|CoalescingMergeTree|Log|TinyLog|StripeLog|Memory) ;;
      *)
        echo 'target clickhouse table uses an unsupported or non-portable table engine' >&2
        exit 43
      ;;
    esac
    columns=$({column_expr})
    printf 'DROP TABLE IF EXISTS `%s`;\n' "$table" >> "$out"
    printf '%s\n' "$create" >> "$out"
    printf ';\n' >> "$out"
    clickhouse-client \
      --host 127.0.0.1 \
      --user "$CLICKHOUSE_USER" \
      --password "$CLICKHOUSE_PASSWORD" \
      --database "$CLICKHOUSE_DB" \
      --output_format_sql_insert_table_name="$table" \
      --query "SELECT $columns FROM \`$table\` FORMAT SQLInsert" >> "$out"
    printf '\n' >> "$out"
  done
"#
            )
        }
        Protocol::Redis => {
            return Err(ApiError::BadRequest(
                "redis uses physical archive export".to_string(),
            ));
        }
        Protocol::Qdrant => {
            return Err(ApiError::NotImplemented(
                "qdrant snapshot export is not implemented yet".to_string(),
            ));
        }
    };
    Ok(script)
}

fn wipe_logical_script(
    metadata: &InstanceMetadata,
    database_definition_in_dump: bool,
) -> Result<String, ApiError> {
    let script = match metadata.protocol {
        Protocol::Postgres => r#"set -eu
PGPASSWORD="${DBE_POSTGRES_PASSWORD:-$POSTGRES_PASSWORD}" psql \
  -h /var/run/postgresql \
  -U "${DBE_POSTGRES_USER:-$POSTGRES_USER}" \
  -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 <<'DBEV_SQL'
DO $dbev$
DECLARE schema_name text;
BEGIN
  FOR schema_name IN
    SELECT nspname
    FROM pg_namespace
    WHERE nspname <> 'information_schema'
      AND nspname NOT LIKE 'pg_%'
  LOOP
    EXECUTE format('DROP SCHEMA %I CASCADE', schema_name);
  END LOOP;
END
$dbev$;
CREATE SCHEMA public AUTHORIZATION CURRENT_USER;
DBEV_SQL
"#
        .to_string(),
        Protocol::Mariadb if database_definition_in_dump => r#"set -eu
mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock \
  -u root -p"$MARIADB_ROOT_PASSWORD" \
  -e "DROP DATABASE IF EXISTS \`$MARIADB_DATABASE\`;"
"#
        .to_string(),
        Protocol::Mariadb => r#"set -eu
settings=$(mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock \
  -u root -p"$MARIADB_ROOT_PASSWORD" \
  --batch --skip-column-names "$MARIADB_DATABASE" \
  -e 'SELECT @@character_set_database, @@collation_database')
set -- $settings
[ "$#" -eq 2 ] || {
  echo 'failed to read the target database charset and collation' >&2
  exit 43
}
case "$1" in ''|*[!A-Za-z0-9_]*)
  echo 'target database returned an invalid character set name' >&2
  exit 43
;; esac
case "$2" in ''|*[!A-Za-z0-9_]*)
  echo 'target database returned an invalid collation name' >&2
  exit 43
;; esac
mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock \
  -u root -p"$MARIADB_ROOT_PASSWORD" \
  -e "DROP DATABASE IF EXISTS \`$MARIADB_DATABASE\`; CREATE DATABASE \`$MARIADB_DATABASE\` CHARACTER SET $1 COLLATE $2;"
"#
        .to_string(),
        Protocol::Mysql if database_definition_in_dump => {
            ensure_mysql_root_password(metadata)?;
            r#"set -eu
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql \
  --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root \
  -e "DROP DATABASE IF EXISTS \`$MYSQL_DATABASE\`;"
"#
            .to_string()
        }
        Protocol::Mysql => {
            ensure_mysql_root_password(metadata)?;
            r#"set -eu
settings=$(MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql \
  --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root \
  --batch --skip-column-names "$MYSQL_DATABASE" \
  -e 'SELECT @@character_set_database, @@collation_database')
set -- $settings
[ "$#" -eq 2 ] || {
  echo 'failed to read the target database charset and collation' >&2
  exit 43
}
case "$1" in ''|*[!A-Za-z0-9_]*)
  echo 'target database returned an invalid character set name' >&2
  exit 43
;; esac
case "$2" in ''|*[!A-Za-z0-9_]*)
  echo 'target database returned an invalid collation name' >&2
  exit 43
;; esac
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql \
  --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root \
  -e "DROP DATABASE IF EXISTS \`$MYSQL_DATABASE\`; CREATE DATABASE \`$MYSQL_DATABASE\` CHARACTER SET $1 COLLATE $2;"
"#
            .to_string()
        }
        Protocol::Mongodb => {
            ensure_mongodb_root_password(metadata)?;
            r#"set -eu
mongosh --quiet \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_ROOT_USER" \
  --password "$DBE_MONGO_ROOT_PASSWORD" \
  --authenticationDatabase admin \
  "$DBE_MONGO_DATABASE" \
  --eval 'db.dropDatabase()'
"#
            .to_string()
        }
        Protocol::Clickhouse => r#"set -eu
clickhouse-client \
  --host 127.0.0.1 \
  --user "$CLICKHOUSE_USER" \
  --password "$CLICKHOUSE_PASSWORD" \
  --database "$CLICKHOUSE_DB" \
  --query 'SHOW TABLES FORMAT TSVRaw' | while IFS= read -r table; do
  [ -n "$table" ] || continue
  case "$table" in *[!A-Za-z0-9_-]*)
    echo 'target clickhouse contains a non-portable table name' >&2
    exit 42
  ;; esac
  clickhouse-client \
    --host 127.0.0.1 \
    --user "$CLICKHOUSE_USER" \
    --password "$CLICKHOUSE_PASSWORD" \
    --database "$CLICKHOUSE_DB" \
    --query "DROP TABLE IF EXISTS \`$table\` SYNC"
done
"#
        .to_string(),
        Protocol::Redis | Protocol::Qdrant => {
            return Err(ApiError::BadRequest(format!(
                "{} does not use the logical wipe path",
                metadata.protocol.as_str()
            )));
        }
    };
    Ok(script)
}

async fn wipe_logical_target(
    state: &AppState,
    metadata: &InstanceMetadata,
    exec_timeout: Option<Duration>,
    database_definition_in_dump: bool,
) -> Result<(), ApiError> {
    let script = wipe_logical_script(metadata, database_definition_in_dump)?;
    let result = match exec_timeout {
        Some(timeout) => {
            state
                .docker
                .exec_shell_with_timeout(metadata.protocol, &metadata.instance_id, &script, timeout)
                .await
        }
        None => {
            state
                .docker
                .exec_shell(metadata.protocol, &metadata.instance_id, &script)
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

fn mongodb_namespace_pattern(database: &str) -> String {
    let mut pattern = String::with_capacity(database.len() + 2);
    for character in database.chars() {
        match character {
            '\\' => pattern.push_str(r"\\"),
            '*' => pattern.push_str(r"\*"),
            _ => pattern.push(character),
        }
    }
    pattern.push_str(".*");
    pattern
}

fn import_script(
    metadata: &InstanceMetadata,
    input_path: &str,
    source_database: Option<&str>,
    database_definition_in_dump: bool,
) -> Result<String, ApiError> {
    let protocol = metadata.protocol;
    let script = match protocol {
        Protocol::Postgres => format!(
            r#"set -eu
PGPASSWORD="${{DBE_POSTGRES_PASSWORD:-$POSTGRES_PASSWORD}}" psql \
  -h /var/run/postgresql \
  -U "${{DBE_POSTGRES_USER:-$POSTGRES_USER}}" \
  -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 \
  -f {input_path}
"#
        ),
        Protocol::Mariadb if database_definition_in_dump => format!(
            r#"set -eu
mariadb \
  --protocol=socket \
  --socket=/run/mysqld/mysqld.sock \
  -u root \
  -p"$MARIADB_ROOT_PASSWORD" \
  < {input_path}
"#
        ),
        Protocol::Mariadb => format!(
            r#"set -eu
mariadb \
  --protocol=socket \
  --socket=/run/mysqld/mysqld.sock \
  -u "$MARIADB_USER" \
  -p"$MARIADB_PASSWORD" \
  "$MARIADB_DATABASE" \
  < {input_path}
"#
        ),
        Protocol::Mysql if database_definition_in_dump => {
            ensure_mysql_root_password(metadata)?;
            format!(
                r#"set -eu
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql \
  --protocol=socket \
  --socket=/var/run/mysqld/mysqld.sock \
  -u root \
  < {input_path}
"#
            )
        }
        Protocol::Mysql => {
            ensure_mysql_root_password(metadata)?;
            format!(
                r#"set -eu
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql \
  --protocol=socket \
  --socket=/var/run/mysqld/mysqld.sock \
  -u root \
  "$MYSQL_DATABASE" \
  < {input_path}
"#
            )
        }
        Protocol::Mongodb => {
            ensure_mongodb_root_password(metadata)?;
            let namespaces = match source_database {
                Some(source_database) => {
                    let source_pattern = mongodb_namespace_pattern(source_database);
                    format!(
                        "--nsInclude {} \\\n  --nsFrom {} \\\n  --nsTo \"$DBE_MONGO_DATABASE.*\"",
                        sh_quote(&source_pattern),
                        sh_quote(&source_pattern),
                    )
                }
                None => "--nsInclude \"$DBE_MONGO_DATABASE.*\"".to_string(),
            };
            format!(
                r#"set -eu
mongorestore \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_ROOT_USER" \
  --password "$DBE_MONGO_ROOT_PASSWORD" \
  --authenticationDatabase "admin" \
  --drop \
  {namespaces} \
  --archive={input_path} \
  --gzip
"#
            )
        }
        Protocol::Clickhouse => format!(
            r#"set -eu
clickhouse-client \
  --host 127.0.0.1 \
  --user "$CLICKHOUSE_USER" \
  --password "$CLICKHOUSE_PASSWORD" \
  --database "$CLICKHOUSE_DB" \
  --multiquery \
  < {input_path}
"#
        ),
        Protocol::Redis => {
            return Err(ApiError::BadRequest(
                "redis uses physical archive import".to_string(),
            ));
        }
        Protocol::Qdrant => {
            return Err(ApiError::NotImplemented(
                "qdrant snapshot import is not implemented yet".to_string(),
            ));
        }
    };
    Ok(script)
}

async fn logical_staging_root(state: &AppState) -> Result<PathBuf, ApiError> {
    let root = PathBuf::from(state.config.paths.tmp_root()).join("import-export");
    create_private_directory(&root, "logical import/export staging directory").await?;
    Ok(root)
}

async fn cleanup_container_temp(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
    path: &str,
) {
    let script = format!("rm -f -- {}", sh_quote(path));
    if let Err(error) = state
        .docker
        .exec_shell(protocol, instance_id, &script)
        .await
    {
        tracing::warn!(
            instance_id,
            %protocol,
            %error,
            "failed to remove container import/export temporary file"
        );
    }
}

fn dump_extension(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => "postgres.sql",
        Protocol::Redis => "redis.tar.gz",
        Protocol::Mariadb => "mariadb.sql",
        Protocol::Mysql => "mysql.sql",
        Protocol::Mongodb => "mongodb.archive.gz",
        Protocol::Clickhouse => "clickhouse.sql",
        Protocol::Qdrant => "qdrant.tar.gz",
    }
}

async fn copy_file(from: &FsPath, to: &FsPath) -> Result<(), ApiError> {
    if let Some(parent) = to.parent() {
        create_private_directory(parent, "file parent directory").await?;
    }
    let from = from.to_path_buf();
    let to = to.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(), std::io::Error> {
        let mut input = std::fs::File::open(&from)?;
        write_new_private_file(&to, |mut output| {
            std::io::copy(&mut input, &mut output)?;
            output.flush()
        })
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to join file copy task: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("failed to copy file: {error}")))
}

async fn archive_or_copy_export(
    from: &FsPath,
    to: &FsPath,
    format: ExportArchiveFormat,
) -> Result<(), ApiError> {
    match format {
        ExportArchiveFormat::Plain => move_or_copy_file(from, to).await,
        ExportArchiveFormat::Gzip => compress_gzip(from, to).await,
        ExportArchiveFormat::Bzip2 => compress_bzip2(from, to).await,
    }
}

async fn move_or_copy_file(from: &FsPath, to: &FsPath) -> Result<(), ApiError> {
    match tokio::fs::rename(from, to).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
            copy_file(from, to).await?;
            tokio::fs::remove_file(from).await.map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to remove export staging file after copying it: {error}"
                ))
            })
        }
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to install export artifact: {error}"
        ))),
    }
}

async fn compress_gzip(source: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "compress gzip",
        false,
        move |deadline| -> Result<(), std::io::Error> {
            if let Some(parent) = target.parent() {
                create_private_directory_blocking(parent)?;
            }
            let mut input = std::fs::File::open(source)?;
            write_new_private_file(&target, |output| {
                let mut encoder =
                    flate2::write::GzEncoder::new(output, flate2::Compression::new(3));
                copy_limited_until(&mut input, &mut encoder, u64::MAX, deadline)?;
                encoder.finish()?;
                Ok(())
            })
        },
    )
    .await
}

async fn compress_bzip2(source: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "compress bzip2",
        false,
        move |deadline| -> Result<(), std::io::Error> {
            if let Some(parent) = target.parent() {
                create_private_directory_blocking(parent)?;
            }
            let mut input = std::fs::File::open(source)?;
            write_new_private_file(&target, |output| {
                let mut encoder =
                    bzip2::write::BzEncoder::new(output, bzip2::Compression::default());
                copy_limited_until(&mut input, &mut encoder, u64::MAX, deadline)?;
                encoder.finish()?;
                Ok(())
            })
        },
    )
    .await
}

async fn run_archive_file_operation(
    failure_label: &'static str,
    io_error_is_bad_request: bool,
    task: impl FnOnce(Instant) -> Result<(), std::io::Error> + Send + 'static,
) -> Result<(), ApiError> {
    let result = tokio::task::spawn_blocking(move || task(archive_operation_deadline()))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to {failure_label}: {error}")))?;

    match result {
        Ok(()) => Ok(()),
        Err(error) if io_error_is_bad_request => Err(ApiError::BadRequest(format!(
            "failed to {failure_label}: {error}"
        ))),
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to {failure_label}: {error}"
        ))),
    }
}

async fn ensure_import_file_size(path: &FsPath) -> Result<u64, ApiError> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        ApiError::Runtime(format!(
            "failed to read import artifact metadata {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ApiError::BadRequest(
            "import artifact must be a real regular file".to_string(),
        ));
    }
    if metadata.len() > MAX_UNARCHIVED_BYTES {
        return Err(ApiError::BadRequest(format!(
            "import artifact is too large: {} bytes exceeds {} bytes",
            metadata.len(),
            MAX_UNARCHIVED_BYTES
        )));
    }
    Ok(metadata.len())
}

pub(crate) async fn replace_data_from_archive(
    paths: InstancePaths,
    artifact_path: &FsPath,
) -> Result<(), ApiError> {
    let import_id = uuid::Uuid::new_v4();
    let expected_root = paths
        .data
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ApiError::Runtime("invalid data path".to_string()))?
        .to_string();
    tokio::fs::create_dir_all(&paths.data)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to create data directory: {error}")))?;

    let data_parent = paths
        .data
        .parent()
        .ok_or_else(|| ApiError::Runtime("data directory has no parent".to_string()))?;
    let workspace = data_parent.join(format!(".dbe-restore-{}-{import_id}", paths.instance_id));
    create_private_directory(&workspace, "physical restore workspace").await?;
    let staging_dir = workspace.join("staging");
    let staged_data = staging_dir.join(&expected_root);
    let backup_dir = workspace.join("previous-data");
    if let Err(error) =
        create_private_directory(&staging_dir, "physical import staging directory").await
    {
        cleanup_dir(&workspace).await;
        return Err(error);
    }
    if let Err(error) = extract_data_archive(
        artifact_path.to_path_buf(),
        staging_dir.clone(),
        expected_root,
    )
    .await
    {
        cleanup_dir(&workspace).await;
        return Err(ApiError::BadRequest(error.to_string()));
    }

    if let Err(error) =
        create_private_directory(&backup_dir, "physical import rollback directory").await
    {
        cleanup_dir(&workspace).await;
        return Err(error);
    }

    if let Err(error) = move_directory_entries(&paths.data, &backup_dir).await {
        if let Err(rollback_error) = move_directory_entries(&backup_dir, &paths.data).await {
            return Err(ApiError::Runtime(format!(
                "failed to move existing data contents aside: {error}; rollback also failed: {rollback_error}; recovery data was retained at {}",
                workspace.display()
            )));
        }
        cleanup_dir(&workspace).await;
        return Err(ApiError::Runtime(format!(
            "failed to move existing data contents aside: {error}"
        )));
    }

    if let Err(error) = move_directory_entries(&staged_data, &paths.data).await {
        cleanup_dir_contents(&paths.data).await;
        if let Err(rollback_error) = move_directory_entries(&backup_dir, &paths.data).await {
            return Err(ApiError::Runtime(format!(
                "failed to install imported data contents: {error}; rollback also failed: {rollback_error}; recovery data was retained at {}",
                workspace.display()
            )));
        }
        cleanup_dir(&workspace).await;
        return Err(ApiError::Runtime(format!(
            "failed to install imported data contents: {error}"
        )));
    }

    cleanup_dir(&workspace).await;
    Ok(())
}

async fn move_directory_entries(from: &FsPath, to: &FsPath) -> Result<(), std::io::Error> {
    move_directory_entries_except(from, to, &[]).await
}

async fn move_directory_entries_except(
    from: &FsPath,
    to: &FsPath,
    exclude: &[&FsPath],
) -> Result<(), std::io::Error> {
    let mut entries = match tokio::fs::read_dir(from).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    tokio::fs::create_dir_all(to).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if exclude.iter().any(|excluded| path == **excluded) {
            continue;
        }
        let target = to.join(entry.file_name());
        tokio::fs::rename(path, target).await?;
    }
    Ok(())
}

async fn cleanup_dir_contents(path: &FsPath) {
    let Ok(mut entries) = tokio::fs::read_dir(path).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        cleanup_path(&path).await;
    }
}

pub(crate) async fn finish_physical_operation(
    state: &AppState,
    instance_id: &str,
    was_running: bool,
    primary_result: Result<(), ApiError>,
) -> Result<(), ApiError> {
    if !was_running {
        return primary_result;
    }

    let restart_result = lifecycle_instance_locked(state, instance_id, LifecycleAction::Start)
        .await
        .map(|_| ());
    if let (Err(primary_error), Err(restart_error)) = (&primary_result, &restart_result) {
        tracing::error!(
            instance_id,
            error = %primary_error,
            restart_error = %restart_error,
            "physical operation failed and the originally-running instance could not be restarted"
        );
    }
    preserve_primary_error(primary_result, restart_result)
}

fn preserve_primary_error(
    primary_result: Result<(), ApiError>,
    recovery_result: Result<(), ApiError>,
) -> Result<(), ApiError> {
    match (primary_result, recovery_result) {
        (Err(primary_error), _) => Err(primary_error),
        (Ok(()), recovery_result) => recovery_result,
    }
}

async fn export_artifact_path(
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

fn audit_import_export(job: &ImportExportJob, status: &'static str) {
    tracing::info!(
        event = "audit import_export_job",
        action = job.action.as_str(),
        status,
        job_id = %job.job_id,
        instance_id = %job.instance_id,
        artifact_path = ?job.artifact_path,
    );
}

async fn cleanup_dir(path: &FsPath) {
    cleanup_path(path).await;
}

async fn cleanup_path(path: &FsPath) {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => {
            if let Err(error) = tokio::fs::remove_file(path).await {
                tracing::warn!(path = %path.display(), %error, "failed to clean import workspace");
            }
        }
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "failed to clean import workspace");
        }
    }
}

async fn create_private_directory(path: &FsPath, label: &str) -> Result<(), ApiError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || create_private_directory_blocking(&path))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to secure {label}: {error}")))?
        .map_err(|error| ApiError::Runtime(format!("failed to secure {label}: {error}")))
}

fn create_private_directory_blocking(path: &FsPath) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a real directory", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_private_file_blocking(path: &FsPath) -> Result<std::fs::File, std::io::Error> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    options.open(path)
}

fn write_new_private_file<T>(
    path: &FsPath,
    operation: impl FnOnce(std::fs::File) -> Result<T, std::io::Error>,
) -> Result<T, std::io::Error> {
    let file = create_private_file_blocking(path)?;
    let result = operation(file);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

async fn validate_artifact_path(
    state: &AppState,
    instance_id: &str,
    path: &FsPath,
) -> Result<PathBuf, ApiError> {
    crate::shared::ids::validate_instance_id(instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let artifact_id = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| is_safe_flat_file_name(name))
        .ok_or_else(|| ApiError::BadRequest("invalid artifact_id".to_string()))?;
    if !path.is_absolute() && path.to_str() != Some(artifact_id) {
        return Err(ApiError::BadRequest("invalid artifact_id".to_string()));
    }

    let base_roots = [
        PathBuf::from(state.config.paths.exports_root()),
        PathBuf::from(state.config.paths.imports_root()),
    ];
    let mut instance_roots = Vec::with_capacity(base_roots.len());
    for base_root in base_roots {
        create_private_directory(&base_root, "artifact root").await?;
        let instance_root = base_root.join(instance_id);
        create_private_directory(&instance_root, "instance artifact directory").await?;
        instance_roots.push(
            tokio::fs::canonicalize(&instance_root)
                .await
                .map_err(|error| {
                    ApiError::Runtime(format!("failed to resolve instance artifact root: {error}"))
                })?,
        );
    }

    let artifact_path = if path.is_absolute() {
        let source_metadata = tokio::fs::symlink_metadata(path)
            .await
            .map_err(|error| ApiError::BadRequest(format!("artifact_id is invalid: {error}")))?;
        if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
            return Err(ApiError::BadRequest(
                "artifact_id must name a real regular file".to_string(),
            ));
        }
        let canonical = tokio::fs::canonicalize(path)
            .await
            .map_err(|error| ApiError::BadRequest(format!("artifact_id is invalid: {error}")))?;
        let belongs_to_instance = canonical
            .parent()
            .is_some_and(|parent| instance_roots.iter().any(|root| parent == root));
        if !belongs_to_instance {
            return Err(ApiError::BadRequest(
                "artifact does not belong to the requested instance".to_string(),
            ));
        }
        canonical
    } else {
        let mut resolved = None;
        for root in &instance_roots {
            let candidate = root.join(artifact_id);
            let metadata = match tokio::fs::symlink_metadata(&candidate).await {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(ApiError::Runtime(format!(
                        "failed to inspect import artifact: {error}"
                    )));
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ApiError::BadRequest(
                    "artifact_id must name a real regular file".to_string(),
                ));
            }
            resolved = Some(tokio::fs::canonicalize(candidate).await.map_err(|error| {
                ApiError::Runtime(format!("failed to resolve import artifact: {error}"))
            })?);
            break;
        }
        resolved.ok_or(ApiError::NotFound)?
    };

    if !artifact_has_allowed_extension(&artifact_path) {
        return Err(ApiError::BadRequest(
            "artifact_id extension is not allowed for import".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(&artifact_path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|error| {
                ApiError::Runtime(format!("failed to secure import artifact: {error}"))
            })?;
    }
    Ok(artifact_path)
}

fn artifact_has_allowed_extension(path: &FsPath) -> bool {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    [
        ".sql",
        ".archive.gz",
        ".snapshot",
        ".tar.gz",
        ".tgz",
        ".tar",
        ".zip",
        ".gz",
        ".gzip",
        ".bz2",
        ".bzip2",
    ]
    .iter()
    .any(|suffix| filename.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, sync::Arc};

    use super::*;
    use crate::{
        auth::api_token::ApiToken,
        config::Config,
        instances::{manager::InstanceManager, state::InstanceStore},
        jobs::import_export::ImportExportJobs,
        runtime::docker::DockerRuntime,
        storage::{repositories::InstanceRepository, sqlite},
    };

    #[tokio::test]
    async fn public_job_response_never_exposes_a_host_path() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = dir.path().join("dump.postgres.sql");
        tokio::fs::write(&artifact, b"select 1").await.unwrap();
        let job = ImportExportJob {
            job_id: "job-1".to_string(),
            instance_id: "instance-1".to_string(),
            action: ImportExportAction::Export,
            status: ImportExportStatus::Succeeded,
            artifact_path: Some(artifact.display().to_string()),
            replay_options: None,
            error: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let response = serde_json::to_value(public_job_response(job).await).unwrap();

        assert_eq!(response["artifact_id"], "dump.postgres.sql");
        assert_eq!(response["artifact_size_bytes"], 8);
        assert!(response.get("artifact_path").is_none());
        assert!(
            !response
                .to_string()
                .contains(&dir.path().display().to_string())
        );
    }

    #[tokio::test]
    async fn public_job_response_redacts_legacy_internal_failure_text() {
        let job = ImportExportJob {
            job_id: "job-legacy".to_string(),
            instance_id: "instance-1".to_string(),
            action: ImportExportAction::Import,
            status: ImportExportStatus::Failed,
            artifact_path: None,
            replay_options: None,
            error: Some("password=hunter2 /var/lib/private".to_string()),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let response = serde_json::to_string(&public_job_response(job).await).unwrap();
        assert!(response.contains("internal_error"));
        assert!(!response.contains("hunter2"));
        assert!(!response.contains("/var/lib/private"));
    }

    #[test]
    fn archive_copy_stops_at_expired_deadline() {
        let mut input = Cursor::new(b"contents".as_slice());
        let mut output = Vec::new();
        let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();

        let error = copy_limited_until(&mut input, &mut output, u64::MAX, expired).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(output.is_empty());
    }

    #[test]
    fn physical_operation_preserves_primary_error_over_restart_error() {
        let result = preserve_primary_error(
            Err(ApiError::BadRequest("restore failed".to_string())),
            Err(ApiError::Runtime("restart failed".to_string())),
        );

        assert!(
            matches!(result, Err(ApiError::BadRequest(message)) if message == "restore failed")
        );
    }

    #[test]
    fn physical_operation_returns_restart_error_after_primary_success() {
        let result =
            preserve_primary_error(Ok(()), Err(ApiError::Runtime("restart failed".to_string())));

        assert!(matches!(result, Err(ApiError::Runtime(message)) if message == "restart failed"));
    }

    #[test]
    fn allows_only_supported_import_artifact_extensions() {
        assert!(artifact_has_allowed_extension(FsPath::new(
            "instance-1.postgres.sql"
        )));
        assert!(artifact_has_allowed_extension(FsPath::new(
            "instance-1.redis.tar.gz"
        )));
        assert!(artifact_has_allowed_extension(FsPath::new(
            "instance-1.mongodb.archive.gz"
        )));
        assert!(artifact_has_allowed_extension(FsPath::new(
            "instance-1.qdrant.tar.gz"
        )));
        assert!(!artifact_has_allowed_extension(FsPath::new(
            "instance-1.sh"
        )));
        assert!(!artifact_has_allowed_extension(FsPath::new(
            "instance-1.sql.exe"
        )));
    }

    #[test]
    fn recovery_restore_is_destructive_and_infers_only_real_wrapper_formats() {
        let postgres =
            ImportOptions::recovery_restore("export.postgres.sql.gz", Protocol::Postgres);
        assert_eq!(postgres.mode, ImportMode::Wipe);
        assert_eq!(postgres.archive_format.as_deref(), Some("gzip"));

        let mongo_native =
            ImportOptions::recovery_restore("export.mongodb.archive.gz", Protocol::Mongodb);
        assert_eq!(mongo_native.mode, ImportMode::Wipe);
        assert_eq!(mongo_native.archive_format, None);

        let mongo_wrapped =
            ImportOptions::recovery_restore("export.mongodb.archive.gz.gz", Protocol::Mongodb);
        assert_eq!(mongo_wrapped.archive_format.as_deref(), Some("gzip"));

        let redis_physical =
            ImportOptions::recovery_restore("export.redis.tar.gz", Protocol::Redis);
        assert_eq!(redis_physical.archive_format, None);
    }

    #[test]
    fn rar_is_rejected_instead_of_being_advertised_but_unimplemented() {
        let error = ImportArchiveFormat::parse("rar").unwrap_err();
        assert!(error.to_string().contains("unsupported archive_format"));
    }

    #[tokio::test]
    async fn remote_import_staging_budget_is_aggregate() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let rollback = directory.path().join("rollback");
        tokio::fs::write(&source, [0_u8; 4]).await.unwrap();
        tokio::fs::write(&rollback, [0_u8; 5]).await.unwrap();

        ensure_remote_import_staging_budget(&[&source, &rollback], 9)
            .await
            .unwrap();
        let error = ensure_remote_import_staging_budget(&[&source, &rollback], 8)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("configured 8-byte staging limit")
        );

        tokio::fs::remove_file(&source).await.unwrap();
        assert_eq!(
            ensure_remote_import_staging_budget_with_retained_bytes(&[&rollback], 4, 9)
                .await
                .unwrap(),
            9
        );
        let error = ensure_remote_import_staging_budget_with_retained_bytes(&[&rollback], 4, 8)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("configured 8-byte staging limit")
        );
    }

    #[test]
    fn qdrant_uses_physical_archive_extension() {
        assert_eq!(dump_extension(Protocol::Qdrant), "qdrant.tar.gz");
        assert!(dump_candidate_suffixes(Protocol::Qdrant).contains(&".qdrant.tar.gz"));
    }

    #[test]
    fn mongodb_namespace_pattern_escapes_literal_database_wildcards() {
        assert_eq!(mongodb_namespace_pattern("analytics"), "analytics.*");
        assert_eq!(
            mongodb_namespace_pattern("tenant*archive"),
            r"tenant\*archive.*"
        );
        assert_eq!(mongodb_namespace_pattern(r"legacy\name"), r"legacy\\name.*");
        assert_eq!(
            sh_quote(&mongodb_namespace_pattern("tenant*archive")),
            r"'tenant\*archive.*'"
        );
    }

    #[test]
    fn managed_logical_scripts_use_unix_sockets_and_scoped_credentials() {
        use crate::{
            instances::metadata::{
                DatabaseIdentity, PublicEndpoint, RuntimeKind, RuntimeMetadata, SCHEMA_VERSION,
            },
            shared::{backend::BackendEndpoint, limits::InstanceLimits},
        };

        let metadata = InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: "inst_mysql_1".to_string(),
            protocol: Protocol::Mysql,
            status: InstanceStatus::Running,
            public: PublicEndpoint {
                host: "db.example.com".to_string(),
                port: 3308,
            },
            backend: BackendEndpoint::UnixSocket {
                socket_path: "/run/dbev/sockets/inst_mysql_1/mysqld.sock".to_string(),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: "dbe-mysql-inst-mysql-1".to_string(),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: "mysql_1".to_string(),
                username: "app_mysql_1".to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mysql_native_password_sha1_stage2: Some(
                "0123456789abcdef0123456789abcdef01234567".to_string(),
            ),
            mysql_root_password: Some("internal-root-password".to_string()),
            mongodb_root_password: None,
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let export = export_script(
            &metadata,
            "/tmp/export.mysql.sql",
            &ImportExportSelection::default(),
            false,
        )
        .unwrap();
        let rollback_export = export_script(
            &metadata,
            "/tmp/rollback.mysql.sql",
            &ImportExportSelection::default(),
            true,
        )
        .unwrap();
        let import = import_script(&metadata, "/tmp/import.mysql.sql", None, false).unwrap();
        let rollback_import =
            import_script(&metadata, "/tmp/rollback.mysql.sql", None, true).unwrap();
        let wipe = wipe_logical_script(&metadata, false).unwrap();
        let rollback_wipe = wipe_logical_script(&metadata, true).unwrap();

        assert_eq!(dump_extension(Protocol::Mysql), "mysql.sql");
        assert!(dump_candidate_suffixes(Protocol::Mysql).contains(&".mysql.sql"));
        assert!(export.contains("mysqldump"));
        assert!(export.contains("--socket=/var/run/mysqld/mysqld.sock"));
        assert!(export.contains("--single-transaction"));
        assert!(export.contains("--events"));
        assert!(export.contains("--hex-blob"));
        assert!(export.contains("MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\""));
        assert!(import.contains("mysql \\"));
        assert!(import.contains("--socket=/var/run/mysqld/mysqld.sock"));
        assert!(import.contains("MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\""));
        assert!(import.contains("-u root"));
        assert!(wipe.contains("--socket=/var/run/mysqld/mysqld.sock"));
        assert!(wipe.contains("-u root"));
        assert!(wipe.contains("SELECT @@character_set_database, @@collation_database"));
        assert!(wipe.contains("CHARACTER SET $1 COLLATE $2"));
        assert!(rollback_wipe.contains("DROP DATABASE IF EXISTS"));
        assert!(!rollback_wipe.contains("CREATE DATABASE"));
        assert!(!rollback_import.contains("\"$MYSQL_DATABASE\""));
        assert!(rollback_import.contains("-u root"));
        assert!(!export.contains("--databases"));
        assert!(rollback_export.contains("--databases"));
        assert!(!export.contains("internal-root-password"));
        assert!(!import.contains("internal-root-password"));

        let mut postgres = metadata.clone();
        postgres.protocol = Protocol::Postgres;
        let postgres_export = export_script(
            &postgres,
            "/tmp/export.postgres.sql",
            &ImportExportSelection::default(),
            false,
        )
        .unwrap();
        let postgres_import =
            import_script(&postgres, "/tmp/import.postgres.sql", None, false).unwrap();
        let postgres_wipe = wipe_logical_script(&postgres, false).unwrap();
        for script in [&postgres_export, &postgres_import, &postgres_wipe] {
            assert!(script.contains("-h /var/run/postgresql"));
            assert!(!script.contains("-h 127.0.0.1"));
        }

        let mut mariadb = metadata.clone();
        mariadb.protocol = Protocol::Mariadb;
        let mariadb_export = export_script(
            &mariadb,
            "/tmp/export.mariadb.sql",
            &ImportExportSelection::default(),
            false,
        )
        .unwrap();
        let mariadb_rollback_export = export_script(
            &mariadb,
            "/tmp/rollback.mariadb.sql",
            &ImportExportSelection::default(),
            true,
        )
        .unwrap();
        let mariadb_import =
            import_script(&mariadb, "/tmp/import.mariadb.sql", None, false).unwrap();
        let mariadb_rollback_import =
            import_script(&mariadb, "/tmp/rollback.mariadb.sql", None, true).unwrap();
        let mariadb_wipe = wipe_logical_script(&mariadb, false).unwrap();
        let mariadb_rollback_wipe = wipe_logical_script(&mariadb, true).unwrap();
        for script in [&mariadb_export, &mariadb_import, &mariadb_wipe] {
            assert!(script.contains("--protocol=socket"));
            assert!(script.contains("--socket=/run/mysqld/mysqld.sock"));
            assert!(!script.contains("-h 127.0.0.1"));
        }
        assert!(mariadb_export.contains("-u \"$MARIADB_USER\""));
        assert!(mariadb_import.contains("-u \"$MARIADB_USER\""));
        assert!(mariadb_wipe.contains("-u root"));
        assert!(mariadb_wipe.contains("SELECT @@character_set_database, @@collation_database"));
        assert!(mariadb_wipe.contains("CHARACTER SET $1 COLLATE $2"));
        assert!(mariadb_rollback_wipe.contains("DROP DATABASE IF EXISTS"));
        assert!(!mariadb_rollback_wipe.contains("CREATE DATABASE"));
        assert!(!mariadb_rollback_import.contains("\"$MARIADB_DATABASE\""));
        assert!(mariadb_rollback_import.contains("-u root"));
        assert!(!mariadb_export.contains("--databases"));
        assert!(mariadb_rollback_export.contains("--databases"));
    }

    #[tokio::test]
    async fn artifact_imports_are_scoped_to_the_requested_instance() {
        let dir = tempfile::tempdir().unwrap();
        let artifacts = dir.path().join("artifacts");
        let exports = artifacts.join("exports").join("instance-1");
        let foreign_exports = artifacts.join("exports").join("instance-2");
        std::fs::create_dir_all(&exports).unwrap();
        std::fs::create_dir_all(&foreign_exports).unwrap();
        let allowed = exports.join("dump.postgres.sql");
        let outside = foreign_exports.join("dump.postgres.sql");
        std::fs::write(&allowed, b"select 1").unwrap();
        std::fs::write(&outside, b"select 1").unwrap();
        let state = test_state_with_config(Config {
            paths: crate::config::PathConfig {
                artifacts: artifacts.display().to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;

        assert_eq!(
            validate_artifact_path(&state, "instance-1", FsPath::new("dump.postgres.sql"))
                .await
                .unwrap(),
            allowed.canonicalize().unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                std::fs::metadata(&allowed).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&exports).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let error = validate_artifact_path(&state, "instance-1", &outside)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("requested instance"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn artifact_import_rejects_symlinks_inside_allowed_root() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let artifacts = dir.path().join("artifacts");
        let exports = artifacts.join("exports").join("instance-1");
        std::fs::create_dir_all(&exports).unwrap();
        let real = exports.join("real.postgres.sql");
        let link = exports.join("linked.postgres.sql");
        std::fs::write(&real, b"select 1").unwrap();
        symlink(&real, &link).unwrap();
        let state = test_state_with_config(Config {
            paths: crate::config::PathConfig {
                artifacts: artifacts.display().to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;

        let error = validate_artifact_path(&state, "instance-1", &link)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("real regular file"));
    }

    #[tokio::test]
    async fn artifact_import_rejects_relative_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let artifacts = dir.path().join("missing-artifacts");
        let state = test_state_with_config(Config {
            paths: crate::config::PathConfig {
                artifacts: artifacts.display().to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;

        let error = validate_artifact_path(&state, "instance-1", FsPath::new("../../etc/passwd"))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("invalid artifact_id"));
    }

    #[tokio::test]
    async fn artifact_import_rejects_outside_absolute_path_when_exports_root_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let artifacts = dir.path().join("artifacts");
        let outside = dir.path().join("outside.postgres.sql");
        std::fs::write(&outside, b"select 1").unwrap();
        let state = test_state_with_config(Config {
            paths: crate::config::PathConfig {
                artifacts: artifacts.display().to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;

        let error = validate_artifact_path(&state, "instance-1", &outside)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("requested instance"));
        assert!(artifacts.join("exports").join("instance-1").is_dir());
    }

    #[test]
    fn remote_import_source_is_typed_and_does_not_accept_a_protocol_override() {
        let request = serde_json::from_value::<ImportRequest>(serde_json::json!({
            "source": {
                "type": "remote",
                "host": "db.example.com",
                "port": 5432,
                "tls": true,
                "database": "app",
                "username": "operator",
                "password": "secret"
            },
            "mode": "wipe"
        }))
        .unwrap();
        assert_eq!(request.mode, ImportMode::Wipe);
        assert!(matches!(request.source, ImportSource::Remote(_)));

        let override_attempt = serde_json::from_value::<ImportRequest>(serde_json::json!({
            "source": {
                "type": "remote",
                "protocol": "postgres",
                "host": "db.example.com",
                "database": "app",
                "username": "operator",
                "password": "secret"
            }
        }));
        assert!(override_attempt.is_err());
    }

    #[test]
    fn import_archive_settings_are_rejected_at_the_top_level() {
        let request = serde_json::from_value::<ImportRequest>(serde_json::json!({
            "source": {
                "type": "artifact",
                "artifact_id": "dump.postgres.sql.gz"
            },
            "unarchive": true,
            "archive_format": "gzip"
        }));

        assert!(request.is_err());
    }

    #[test]
    fn legacy_archive_flags_are_rejected_instead_of_ignored() {
        let export = serde_json::from_value::<ExportRequest>(serde_json::json!({
            "archive": true,
            "archive_format": "gzip"
        }));
        assert!(export.is_err());

        let import = serde_json::from_value::<ImportRequest>(serde_json::json!({
            "source": {
                "type": "artifact",
                "artifact_id": "dump.postgres.sql.gz",
                "unarchive": true,
                "archive_format": "gzip"
            }
        }));
        assert!(import.is_err());
    }

    #[test]
    fn export_selection_accepts_legacy_empty_fields_array() {
        let request = serde_json::from_value::<ExportRequest>(serde_json::json!({
            "selection": {
                "mode": "selective",
                "include": ["users"],
                "exclude": [],
                "fields": []
            }
        }))
        .unwrap();

        assert!(request.selection.unwrap().fields.is_empty());
    }

    #[test]
    fn export_selection_rejects_nonempty_fields_array() {
        let error = serde_json::from_value::<ExportRequest>(serde_json::json!({
            "selection": {
                "mode": "selective",
                "include": ["users"],
                "exclude": [],
                "fields": ["id"]
            }
        }))
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("selection.fields must be an object or an empty array")
        );
    }

    #[test]
    fn selective_import_cannot_exclude_an_included_object() {
        let selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["orders".to_string()],
            exclude: vec!["orders".to_string()],
            ..ImportExportSelection::default()
        };

        for protocol in [
            Protocol::Postgres,
            Protocol::Mariadb,
            Protocol::Mysql,
            Protocol::Mongodb,
            Protocol::Clickhouse,
            Protocol::Qdrant,
        ] {
            let error = validate_selection(protocol, &selection, SelectionUse::Import).unwrap_err();
            assert!(error.to_string().contains("both include and exclude"));
        }
    }

    #[test]
    fn mongodb_dump_selection_uses_supported_collection_flags() {
        let selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["orders".to_string()],
            exclude: vec!["audit".to_string()],
            ..ImportExportSelection::default()
        };

        let args = mongodb_dump_selection_args(&selection).unwrap();

        assert!(args.contains("--collection='orders'"));
        assert!(!args.contains("--excludeCollection"));
        assert!(!args.contains("--nsInclude"));
        assert!(!args.contains("--nsExclude"));
    }

    #[test]
    fn mongodb_remote_import_accepts_multiple_collections_but_export_stays_single_collection() {
        let selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["orders".to_string(), "customers".to_string()],
            ..ImportExportSelection::default()
        };

        validate_selection(Protocol::Mongodb, &selection, SelectionUse::Import).unwrap();
        let export_error =
            validate_selection(Protocol::Mongodb, &selection, SelectionUse::Export).unwrap_err();
        assert!(
            export_error
                .to_string()
                .contains("exactly one included collection")
        );
    }

    #[test]
    fn mongodb_selection_rejects_duplicate_included_collections() {
        let selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["orders".to_string(), "orders".to_string()],
            ..ImportExportSelection::default()
        };

        let error =
            validate_selection(Protocol::Mongodb, &selection, SelectionUse::Import).unwrap_err();
        assert!(error.to_string().contains("more than once"));
    }

    #[tokio::test]
    async fn qdrant_artifact_selection_must_be_full_but_remote_may_be_selective() {
        let state = test_state_with_config(Config::default()).await;
        let selection = ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["events".to_string()],
            ..ImportExportSelection::default()
        };
        let artifact = ImportOptions {
            source: ImportSourceOptions::Artifact(PathBuf::from("backup.qdrant.tar.gz")),
            selection: selection.clone(),
            ..ImportOptions::default()
        };

        let error = validate_import_source(&state, Protocol::Qdrant, &artifact)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("selection.mode=full"));

        let request: RemoteImportRequest = serde_json::from_value(serde_json::json!({
            "host": "qdrant.example.com",
            "port": 6333,
            "tls": true
        }))
        .unwrap();
        let remote = ImportOptions {
            source: ImportSourceOptions::RemoteRequest(request),
            selection,
            ..ImportOptions::default()
        };
        validate_import_source(&state, Protocol::Qdrant, &remote)
            .await
            .unwrap();
    }

    async fn test_state_with_config(config: Config) -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let store = InstanceStore::default();
        let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool));
        test_state_with_store(store, manager, config)
    }

    fn test_state_with_store(
        store: InstanceStore,
        manager: InstanceManager,
        config: Config,
    ) -> AppState {
        AppState::new(crate::api::routes::AppStateData {
            config: Arc::new(config),
            config_path: std::path::PathBuf::from("/tmp/dbev-test-config.yml"),
            config_patches: crate::api::config_admin::ConfigPatchCoordinator::default(),
            api_token: ApiToken::new("secret"),
            instances: store,
            manager,
            docker: DockerRuntime::new(&Default::default(), false).unwrap(),
            import_export_jobs: ImportExportJobs::default(),
            api_rate_limiter: crate::api::security::ApiRateLimiter::default(),
            install_progress: crate::api::progress::InstallProgressStore::default(),
            artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
            resource_cache: crate::api::resources::ResourceCache::default(),
            monitoring_cache: crate::api::websocket::MonitoringSnapshotCache::default(),
            instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
            instance_locks: crate::instances::locks::InstanceLocks::default(),
            gateway_supervisor: crate::gateway::supervisor::GatewaySupervisor::default(),
            daemon_shutdown: crate::api::routes::DaemonShutdown::default(),
        })
    }
}
