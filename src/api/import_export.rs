use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{IpAddr, ToSocketAddrs},
    path::{Component, Path as FsPath, PathBuf},
    time::Duration,
};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, Uri},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::time::timeout;

use crate::{
    api::{
        handlers::{ApiError, ApiResult, authorize_scope},
        instances::{LifecycleAction, lifecycle_instance},
        routes::AppState,
    },
    auth::scopes,
    instances::{
        metadata::{InstanceMetadata, InstanceStatus},
        paths::InstancePaths,
    },
    jobs::import_export::{
        ImportExportAction, ImportExportJob, ImportExportStatus, create_data_archive,
        extract_data_archive,
    },
    shared::{protocol::Protocol, shell::sh_quote},
};

const MAX_UNARCHIVED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4096;
const MAX_ARCHIVE_DEPTH: usize = 32;
const ARCHIVE_OPERATION_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_SELECTION_ITEMS: usize = 512;
const MAX_SELECTION_FIELDS_PER_ITEM: usize = 512;

#[derive(Debug, Deserialize, Default)]
pub struct ExportRequest {
    pub selection: Option<ImportExportSelection>,
    #[serde(default)]
    pub archive: Option<bool>,
    #[serde(default)]
    pub archive_format: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    #[serde(default)]
    pub source: Option<ImportSource>,
    #[serde(default)]
    pub artifact_path: String,
    #[serde(default)]
    pub unarchive: Option<bool>,
    #[serde(default)]
    pub archive_format: Option<String>,
    #[serde(default)]
    pub selection: Option<ImportExportSelection>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ImportSource {
    Artifact {
        artifact_path: String,
        #[serde(default)]
        unarchive: Option<bool>,
        #[serde(default)]
        archive_format: Option<String>,
    },
    Remote(RemoteImportSource),
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteImportSource {
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<SecretString>,
    #[serde(default)]
    pub tls: bool,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectionMode {
    #[default]
    Full,
    Selective,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ImportExportSelection {
    pub mode: SelectionMode,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub fields: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ImportOptions {
    unarchive: bool,
    archive_format: Option<String>,
    source: ImportSourceOptions,
    selection: ImportExportSelection,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ExportOptions {
    selection: ImportExportSelection,
    archive_format: ExportArchiveFormat,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ExportArchiveFormat {
    #[default]
    Plain,
    Gzip,
    Bzip2,
}

impl ExportArchiveFormat {
    fn detect(archive: Option<bool>, format: Option<&str>) -> Result<Self, ApiError> {
        if archive != Some(true) && format.is_none() {
            return Ok(Self::Plain);
        }
        match format
            .unwrap_or("gzip")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "plain" | "none" => Ok(Self::Plain),
            "gz" | "gzip" => Ok(Self::Gzip),
            "bz" | "bz2" | "bzip" | "bzip2" => Ok(Self::Bzip2),
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
}

impl From<&ImportRequest> for ImportOptions {
    fn from(request: &ImportRequest) -> Self {
        let selection = request.selection.clone().unwrap_or_default();
        match &request.source {
            Some(ImportSource::Artifact {
                artifact_path,
                unarchive,
                archive_format,
            }) => Self {
                unarchive: unarchive.unwrap_or(request.unarchive.unwrap_or(false)),
                archive_format: archive_format
                    .clone()
                    .or_else(|| request.archive_format.clone()),
                source: ImportSourceOptions::Artifact(PathBuf::from(artifact_path)),
                selection,
            },
            Some(ImportSource::Remote(remote)) => Self {
                unarchive: false,
                archive_format: None,
                source: ImportSourceOptions::Remote(remote.clone()),
                selection,
            },
            None => Self {
                unarchive: request.unarchive.unwrap_or(false),
                archive_format: request.archive_format.clone(),
                source: ImportSourceOptions::Artifact(PathBuf::from(&request.artifact_path)),
                selection,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct JobListQuery {
    pub instance_id: Option<String>,
    pub status: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ImportExportJobResponse {
    #[serde(flatten)]
    pub job: ImportExportJob,
    pub artifact_size_bytes: Option<u64>,
}

pub async fn export_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    request: Option<Json<ExportRequest>>,
) -> ApiResult<ImportExportJobResponse> {
    authorize_scope(&state, &headers, &uri, scopes::IMPORT_EXPORT_WRITE)?;
    let selection = request
        .as_ref()
        .and_then(|Json(request)| request.selection.clone())
        .unwrap_or_default();
    let archive_format = match request.as_ref() {
        Some(Json(request)) => {
            ExportArchiveFormat::detect(request.archive, request.archive_format.as_deref())?
        }
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

pub(crate) async fn queue_export_instance(
    state: &AppState,
    instance_id: &str,
) -> ApiResult<ImportExportJobResponse> {
    queue_export_instance_with_options(state, instance_id, ExportOptions::default()).await
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
    validate_selection(metadata.protocol, &options.selection, SelectionUse::Export)?;
    let artifact_path = export_artifact_path(
        state,
        &metadata.instance_id,
        metadata.protocol,
        options.archive_format,
    )
    .await?;
    let job = enqueue_job(
        state,
        metadata.instance_id.clone(),
        ImportExportAction::Export,
        Some(artifact_path.display().to_string()),
    )
    .await;

    tokio::spawn(run_export_job(
        state.clone(),
        job.job_id.clone(),
        metadata.instance_id,
        artifact_path,
        options,
    ));

    audit_import_export(&job, "queued");
    Ok(Json(public_job_response(job).await))
}

pub async fn import_instance(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<ImportRequest>,
) -> ApiResult<ImportExportJobResponse> {
    authorize_scope(&state, &headers, &uri, scopes::IMPORT_EXPORT_WRITE)?;
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
    let options = harden_import_options(state, metadata.protocol, options).await?;
    validate_selection(metadata.protocol, &options.selection, SelectionUse::Import)?;
    let artifact_path = match &options.source {
        ImportSourceOptions::Artifact(path) => Some(path.clone()),
        ImportSourceOptions::Remote(_) => None,
    };
    let job = enqueue_job(
        state,
        metadata.instance_id.clone(),
        ImportExportAction::Import,
        artifact_path
            .as_ref()
            .map(|path| path.display().to_string()),
    )
    .await;

    tokio::spawn(run_import_job(
        state.clone(),
        job.job_id.clone(),
        metadata.instance_id,
        options,
    ));

    audit_import_export(&job, "queued");
    Ok(Json(public_job_response(job).await))
}

pub async fn get_import_export_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<ImportExportJobResponse> {
    authorize_scope(&state, &headers, &uri, scopes::IMPORT_EXPORT_READ)?;
    let job = state
        .import_export_jobs
        .get(&job_id)
        .await
        .ok_or(ApiError::NotFound)?;
    Ok(Json(public_job_response(job).await))
}

pub async fn list_import_export_jobs(
    State(state): State<AppState>,
    Query(query): Query<JobListQuery>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Vec<ImportExportJobResponse>> {
    authorize_scope(&state, &headers, &uri, scopes::IMPORT_EXPORT_READ)?;
    let status = query
        .status
        .as_deref()
        .map(ImportExportStatus::parse)
        .transpose()
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let jobs = state
        .import_export_jobs
        .list(
            query.instance_id.as_deref(),
            status,
            query.limit.unwrap_or(100),
        )
        .await;
    let mut response = Vec::with_capacity(jobs.len());
    for job in jobs {
        response.push(public_job_response(job).await);
    }
    Ok(Json(response))
}

async fn enqueue_job(
    state: &AppState,
    instance_id: String,
    action: ImportExportAction,
    artifact_path: Option<String>,
) -> ImportExportJob {
    let now = crate::jobs::import_export::now_rfc3339();
    let job = ImportExportJob {
        job_id: uuid::Uuid::new_v4().to_string(),
        instance_id,
        action,
        status: ImportExportStatus::Queued,
        artifact_path,
        error: None,
        created_at: now.clone(),
        updated_at: now,
    };
    state.import_export_jobs.insert(job.clone()).await;
    job
}

async fn run_export_job(
    state: AppState,
    job_id: String,
    instance_id: String,
    artifact_path: PathBuf,
    options: ExportOptions,
) {
    state
        .import_export_jobs
        .update_status(&job_id, ImportExportStatus::Running, None, None)
        .await;
    let result =
        export_instance_artifact(&state, &instance_id, artifact_path.clone(), &options).await;
    update_job_result(&state, &job_id, result, Some(artifact_path)).await;
}

async fn run_import_job(
    state: AppState,
    job_id: String,
    instance_id: String,
    options: ImportOptions,
) {
    state
        .import_export_jobs
        .update_status(&job_id, ImportExportStatus::Running, None, None)
        .await;
    let artifact_path = match &options.source {
        ImportSourceOptions::Artifact(path) => Some(path.clone()),
        ImportSourceOptions::Remote(_) => None,
    };
    let result = import_instance_source(&state, &instance_id, &options).await;
    update_job_result(&state, &job_id, result, artifact_path).await;
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
            state
                .import_export_jobs
                .update_status(
                    job_id,
                    ImportExportStatus::Succeeded,
                    artifact_path.map(|path| path.display().to_string()),
                    None,
                )
                .await;
        }
        Err(error) => {
            tracing::warn!(%job_id, %error, "audit import_export_job_failed");
            state
                .import_export_jobs
                .update_status(
                    job_id,
                    ImportExportStatus::Failed,
                    artifact_path.map(|path| path.display().to_string()),
                    Some(error.to_string()),
                )
                .await;
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
        protocol => export_logical_dump(state, &metadata, protocol, artifact_path, options).await,
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
    match &options.source {
        ImportSourceOptions::Artifact(path) => {
            import_instance_artifact(state, instance_id, &metadata, path, options).await
        }
        ImportSourceOptions::Remote(remote) => {
            import_remote_source(state, instance_id, &metadata, remote, &options.selection).await
        }
    }
}

async fn import_instance_artifact(
    state: &AppState,
    instance_id: &str,
    metadata: &InstanceMetadata,
    artifact_path: &FsPath,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    let protocol = metadata.protocol;
    match protocol {
        Protocol::Redis | Protocol::Qdrant => {
            import_physical_archive(state, instance_id, protocol, artifact_path).await
        }
        protocol => import_logical_dump(state, metadata, protocol, artifact_path, options).await,
    }
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
        let _ = lifecycle_instance(state, instance_id, LifecycleAction::Stop).await?;
    }

    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let result = create_data_archive(paths.data, artifact_path)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()));

    if was_running {
        restart_after_job(state, instance_id).await?;
    }
    result
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
        let _ = lifecycle_instance(state, instance_id, LifecycleAction::Stop).await?;
    }

    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let result = replace_data_from_archive(paths.clone(), artifact_path).await;
    if result.is_ok() && !state.docker.uses_rootless_podman() {
        paths
            .apply_container_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    }

    if was_running {
        restart_after_job(state, instance_id).await?;
    }
    result
}

async fn export_logical_dump(
    state: &AppState,
    metadata: &InstanceMetadata,
    protocol: Protocol,
    artifact_path: PathBuf,
    options: &ExportOptions,
) -> Result<(), ApiError> {
    let instance_id = &metadata.instance_id;
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    tokio::fs::create_dir_all(
        artifact_path
            .parent()
            .ok_or_else(|| ApiError::Runtime("invalid artifact path".to_string()))?,
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to create artifact dir: {error}")))?;

    let extension = dump_extension(protocol);
    let temp_name = format!(".dbe-export-{}.{}", uuid::Uuid::new_v4(), extension);
    let host_temp = paths.data.join(&temp_name);
    let container_temp = format!("{}/{}", container_data_path(protocol), temp_name);
    cleanup_path(&host_temp).await;

    let script = export_script(metadata, &container_temp, &options.selection)?;
    if let Err(error) = state
        .docker
        .exec_shell(protocol, instance_id, &script)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))
    {
        cleanup_path(&host_temp).await;
        return Err(error);
    }

    archive_or_copy_export(&host_temp, &artifact_path, options.archive_format).await?;
    cleanup_path(&host_temp).await;
    Ok(())
}

async fn import_logical_dump(
    state: &AppState,
    metadata: &InstanceMetadata,
    protocol: Protocol,
    artifact_path: &FsPath,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    let instance_id = &metadata.instance_id;
    ensure_full_selection(protocol, &options.selection)?;
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let extension = dump_extension(protocol);
    let temp_name = format!(".dbe-import-{}.{}", uuid::Uuid::new_v4(), extension);
    let host_temp = paths.data.join(&temp_name);
    let container_temp = format!("{}/{}", container_data_path(protocol), temp_name);
    cleanup_path(&host_temp).await;
    prepare_logical_import_artifact(protocol, artifact_path, &host_temp, &paths.data, options)
        .await?;

    let script = import_script(metadata, &container_temp)?;
    let result = state
        .docker
        .exec_shell(protocol, instance_id, &script)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))
        .map(|_| ());
    cleanup_path(&host_temp).await;
    result
}

async fn prepare_logical_import_artifact(
    protocol: Protocol,
    artifact_path: &FsPath,
    host_temp: &FsPath,
    data_dir: &FsPath,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    if !options.unarchive {
        ensure_import_file_size(artifact_path).await?;
        copy_file(artifact_path, host_temp).await?;
        return Ok(());
    }

    let format = ImportArchiveFormat::detect(artifact_path, options.archive_format.as_deref())?;
    match format {
        ImportArchiveFormat::Plain => {
            ensure_import_file_size(artifact_path).await?;
            copy_file(artifact_path, host_temp).await
        }
        ImportArchiveFormat::Gzip => decompress_gzip(artifact_path, host_temp).await,
        ImportArchiveFormat::Bzip2 => decompress_bzip2(artifact_path, host_temp).await,
        ImportArchiveFormat::Tar | ImportArchiveFormat::TarGzip => {
            let staging = data_dir.join(format!(".dbe-unarchive-{}", uuid::Uuid::new_v4()));
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
            let staging = data_dir.join(format!(".dbe-unarchive-{}", uuid::Uuid::new_v4()));
            let result = match extract_zip_archive(artifact_path, &staging).await {
                Ok(()) => copy_selected_dump(protocol, &staging, host_temp).await,
                Err(error) => Err(error),
            };
            cleanup_dir(&staging).await;
            result
        }
        ImportArchiveFormat::Rar => Err(ApiError::BadRequest(
            "rar import is disabled by the hardened extractor; use zip, tar, tar.gz, gzip, bzip2, or plain dumps".to_string(),
        )),
    }
}

async fn decompress_gzip(source: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "gzip decompression",
        "decompress gzip",
        true,
        move || -> Result<(), std::io::Error> {
            let input = std::fs::File::open(source)?;
            let mut decoder = flate2::read::GzDecoder::new(input);
            let mut output = std::fs::File::create(target)?;
            copy_limited(&mut decoder, &mut output, MAX_UNARCHIVED_BYTES)?;
            Ok(())
        },
    )
    .await
}

async fn decompress_bzip2(source: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "bzip2 decompression",
        "decompress bzip2",
        true,
        move || -> Result<(), std::io::Error> {
            let input = std::fs::File::open(source)?;
            let mut decoder = bzip2::read::BzDecoder::new(input);
            let mut output = std::fs::File::create(target)?;
            copy_limited(&mut decoder, &mut output, MAX_UNARCHIVED_BYTES)?;
            Ok(())
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
    timeout(
        ARCHIVE_OPERATION_TIMEOUT,
        tokio::task::spawn_blocking(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                std::fs::create_dir_all(&target_dir)?;
                let input = std::fs::File::open(source)?;
                if gzipped {
                    let decoder = flate2::read::GzDecoder::new(input);
                    let mut archive = tar::Archive::new(decoder);
                    unpack_tar_safely(&mut archive, &target_dir)?;
                } else {
                    let mut archive = tar::Archive::new(input);
                    unpack_tar_safely(&mut archive, &target_dir)?;
                }
                Ok(())
            },
        ),
    )
    .await
    .map_err(|_| ApiError::BadRequest("tar extraction exceeded time limit".to_string()))?
    .map_err(|error| ApiError::Runtime(format!("failed to extract tar archive: {error}")))?
    .map_err(|error| ApiError::BadRequest(format!("failed to extract tar archive: {error}")))
}

async fn extract_zip_archive(source: &FsPath, target_dir: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target_dir = target_dir.to_path_buf();
    timeout(
        ARCHIVE_OPERATION_TIMEOUT,
        tokio::task::spawn_blocking(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                std::fs::create_dir_all(&target_dir)?;
                let input = std::fs::File::open(source)?;
                let mut archive = zip::ZipArchive::new(input)?;
                if archive.len() > MAX_ARCHIVE_ENTRIES {
                    return Err(
                        format!("archive has more than {MAX_ARCHIVE_ENTRIES} entries").into(),
                    );
                }
                let mut total = 0_u64;
                for index in 0..archive.len() {
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
                        std::fs::create_dir_all(&target)?;
                        continue;
                    }
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    let mut output = std::fs::File::create(target)?;
                    copy_limited(&mut file, &mut output, size)?;
                }
                Ok(())
            },
        ),
    )
    .await
    .map_err(|_| ApiError::BadRequest("zip extraction exceeded time limit".to_string()))?
    .map_err(|error| ApiError::Runtime(format!("failed to extract zip archive: {error}")))?
    .map_err(|error| ApiError::BadRequest(format!("failed to extract zip archive: {error}")))
}

fn unpack_tar_safely<R: Read>(
    archive: &mut tar::Archive<R>,
    target_dir: &FsPath,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut total = 0_u64;
    let mut entries = 0_usize;
    for entry in archive.entries()? {
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
            std::fs::create_dir_all(target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut output = std::fs::File::create(target)?;
        copy_limited(&mut entry, &mut output, size)?;
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

fn copy_limited<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
) -> Result<u64, std::io::Error> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
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
    Rar,
}

impl ImportArchiveFormat {
    fn detect(path: &FsPath, requested: Option<&str>) -> Result<Self, ApiError> {
        if let Some(requested) = requested {
            return Self::parse(requested);
        }
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
            Ok(Self::TarGzip)
        } else if filename.ends_with(".tar") {
            Ok(Self::Tar)
        } else if filename.ends_with(".zip") {
            Ok(Self::Zip)
        } else if filename.ends_with(".rar") {
            Ok(Self::Rar)
        } else if filename.ends_with(".bz2")
            || filename.ends_with(".bzip2")
            || filename.ends_with(".gzip2")
        {
            Ok(Self::Bzip2)
        } else if filename.ends_with(".gz") || filename.ends_with(".gzip") {
            Ok(Self::Gzip)
        } else {
            Ok(Self::Plain)
        }
    }

    fn parse(value: &str) -> Result<Self, ApiError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plain" | "none" | "raw" => Ok(Self::Plain),
            "gz" | "gzip" => Ok(Self::Gzip),
            "bz" | "bz2" | "bzip" | "bzip2" | "gzip2" => Ok(Self::Bzip2),
            "tar" => Ok(Self::Tar),
            "tar.gz" | "tgz" | "targz" => Ok(Self::TarGzip),
            "zip" => Ok(Self::Zip),
            "rar" => Ok(Self::Rar),
            other => Err(ApiError::BadRequest(format!(
                "unsupported archive_format {other}; use plain, gzip, bzip2, tar, tar.gz, zip, or rar"
            ))),
        }
    }
}

async fn validate_import_source(
    state: &AppState,
    target_protocol: Protocol,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    match &options.source {
        ImportSourceOptions::Artifact(path) => {
            if path.as_os_str().is_empty() {
                return Err(ApiError::BadRequest(
                    "artifact import requires source.artifact_path or artifact_path".to_string(),
                ));
            }
            Ok(())
        }
        ImportSourceOptions::Remote(remote) => {
            if remote.protocol != target_protocol {
                return Err(ApiError::BadRequest(format!(
                    "remote protocol {} does not match target instance protocol {}",
                    remote.protocol, target_protocol
                )));
            }
            if matches!(target_protocol, Protocol::Redis | Protocol::Qdrant) {
                return Err(ApiError::NotImplemented(format!(
                    "{} remote credential import is not implemented yet",
                    target_protocol.as_str()
                )));
            }
            required_remote_database(remote)?;
            required_remote_username(remote)?;
            required_remote_password(remote)?;
            resolve_validated_remote_host(state, remote)
                .await
                .map(|_| ())
        }
    }
}

async fn harden_import_options(
    state: &AppState,
    target_protocol: Protocol,
    mut options: ImportOptions,
) -> Result<ImportOptions, ApiError> {
    validate_import_source(state, target_protocol, &options).await?;
    match &mut options.source {
        ImportSourceOptions::Artifact(path) => {
            *path = validate_artifact_path(state, path).await?;
        }
        ImportSourceOptions::Remote(remote) => {
            let resolved_host = resolve_validated_remote_host(state, remote).await?;
            if !remote.tls {
                remote.host = resolved_host;
            }
        }
    }
    Ok(options)
}

async fn resolve_validated_remote_host(
    state: &AppState,
    remote: &RemoteImportSource,
) -> Result<String, ApiError> {
    if remote.port == 0 {
        return Err(ApiError::BadRequest(
            "remote import port must be greater than zero".to_string(),
        ));
    }
    let host = remote.host.trim();
    if host.is_empty()
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
        || host.contains(':') && host.parse::<IpAddr>().is_err()
    {
        return Err(ApiError::BadRequest(
            "remote import host must be a hostname or IP address".to_string(),
        ));
    }

    let host_is_allowlisted = state
        .config
        .security
        .remote_import_allowed_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host));

    let addresses = (host, remote.port)
        .to_socket_addrs()
        .map_err(|error| ApiError::BadRequest(format!("failed to resolve remote host: {error}")))?;
    let mut saw_address = false;
    let mut selected_ip = None;
    for address in addresses {
        saw_address = true;
        if !host_is_allowlisted
            && !state.config.security.allow_private_remote_imports
            && private_or_sensitive_ip(address.ip())
        {
            return Err(ApiError::BadRequest(format!(
                "remote import host resolves to blocked address {}; add it to security.remote_import_allowed_hosts or enable allow_private_remote_imports",
                address.ip()
            )));
        }
        selected_ip.get_or_insert(address.ip());
    }
    if !saw_address {
        return Err(ApiError::BadRequest(
            "remote import host did not resolve to any address".to_string(),
        ));
    }
    selected_ip.map(|ip| ip.to_string()).ok_or_else(|| {
        ApiError::BadRequest("remote import host did not resolve to any address".to_string())
    })
}

fn private_or_sensitive_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.octets() == [169, 254, 169, 254]
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.segments()[0] & 0xfe00 == 0xfc00
                || ip.segments()[0] & 0xffc0 == 0xfe80
        }
    }
}

async fn import_remote_source(
    state: &AppState,
    instance_id: &str,
    metadata: &InstanceMetadata,
    remote: &RemoteImportSource,
    selection: &ImportExportSelection,
) -> Result<(), ApiError> {
    let protocol = metadata.protocol;
    if state.config.daemon.internal_network {
        return Err(ApiError::BadRequest(
            "remote credential import is disabled while daemon.internal_network is true because database containers have no outbound network access".to_string(),
        ));
    }
    if matches!(protocol, Protocol::Redis | Protocol::Qdrant) {
        return Err(ApiError::NotImplemented(format!(
            "{} remote credential import is not implemented yet",
            protocol.as_str()
        )));
    }
    let script = remote_import_script(metadata, remote, selection)?;
    state
        .docker
        .exec_shell(protocol, instance_id, &script)
        .await
        .map_err(|error| ApiError::Runtime(redact_remote_error(error.to_string(), remote)))?;
    Ok(())
}

fn redact_remote_error(mut error: String, remote: &RemoteImportSource) -> String {
    if let Some(password) = &remote.password {
        error = error.replace(password.expose_secret(), "[redacted]");
    }
    error
}

fn remote_import_script(
    metadata: &InstanceMetadata,
    remote: &RemoteImportSource,
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    let protocol = metadata.protocol;
    match protocol {
        Protocol::Postgres => remote_postgres_import_script(remote, selection),
        Protocol::Mariadb => remote_mariadb_import_script(remote, selection),
        Protocol::Mongodb => remote_mongodb_import_script(metadata, remote, selection),
        Protocol::Clickhouse => remote_clickhouse_import_script(remote, selection),
        Protocol::Redis | Protocol::Qdrant => Err(ApiError::NotImplemented(format!(
            "{} remote credential import is not implemented yet",
            protocol.as_str()
        ))),
    }
}

fn remote_postgres_import_script(
    remote: &RemoteImportSource,
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    let database = required_remote_database(remote)?;
    let username = required_remote_username(remote)?;
    let password = required_remote_password(remote)?;
    let filters = postgres_dump_selection_args(selection)?;
    let sslmode = if remote.tls { "require" } else { "disable" };
    Ok(format!(
        r#"set -eu
PGPASSWORD={remote_password} PGSSLMODE={sslmode} pg_dump \
  -h {remote_host} \
  -p {remote_port} \
  -U {remote_user} \
  -d {remote_database} \
  --clean --if-exists --no-owner --no-privileges{filters} \
| PGPASSWORD="$POSTGRES_PASSWORD" psql \
  -h 127.0.0.1 \
  -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1
"#,
        remote_password = sh_quote(password.expose_secret()),
        sslmode = sh_quote(sslmode),
        remote_host = sh_quote(&remote.host),
        remote_port = remote.port,
        remote_user = sh_quote(username),
        remote_database = sh_quote(database),
        filters = filters,
    ))
}

fn remote_mariadb_import_script(
    remote: &RemoteImportSource,
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    let database = required_remote_database(remote)?;
    let username = required_remote_username(remote)?;
    let password = required_remote_password(remote)?;
    let filters = mariadb_dump_selection_args(selection, database)?;
    let ssl = if remote.tls { " --ssl" } else { " --skip-ssl" };
    Ok(format!(
        r#"set -eu
mariadb-dump \
  -h {remote_host} \
  -P {remote_port} \
  -u {remote_user} \
  -p{remote_password}{ssl} \
  --single-transaction --routines --triggers{filters} \
| mariadb \
  -h 127.0.0.1 \
  -u "$MARIADB_USER" \
  -p"$MARIADB_PASSWORD" \
  "$MARIADB_DATABASE"
"#,
        remote_host = sh_quote(&remote.host),
        remote_port = remote.port,
        remote_user = sh_quote(username),
        remote_password = sh_quote(password.expose_secret()),
        ssl = ssl,
        filters = filters,
    ))
}

fn remote_mongodb_import_script(
    metadata: &InstanceMetadata,
    remote: &RemoteImportSource,
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    ensure_mongodb_root_password(metadata)?;
    let database = required_remote_database(remote)?;
    let username = required_remote_username(remote)?;
    let password = required_remote_password(remote)?;
    let filters = mongodb_dump_selection_args(selection, database)?;
    let remote_namespace = format!("{database}.*");
    let tls = if remote.tls { " --tls" } else { "" };
    Ok(format!(
        r#"set -eu
mongodump \
  --host {remote_host} \
  --port {remote_port} \
  --username {remote_user} \
  --password {remote_password} \
  --authenticationDatabase {remote_database} \
  --db {remote_database}{tls} \
  {filters} \
  --archive \
  --gzip \
| mongorestore \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_ROOT_USER" \
  --password "$DBE_MONGO_ROOT_PASSWORD" \
  --authenticationDatabase "admin" \
  --drop \
  --nsFrom {remote_namespace} \
  --nsTo "$DBE_MONGO_DATABASE.*" \
  --archive \
  --gzip
"#,
        remote_host = sh_quote(&remote.host),
        remote_port = remote.port,
        remote_user = sh_quote(username),
        remote_password = sh_quote(password.expose_secret()),
        remote_database = sh_quote(database),
        remote_namespace = sh_quote(&remote_namespace),
        tls = tls,
        filters = filters,
    ))
}

fn remote_clickhouse_import_script(
    remote: &RemoteImportSource,
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    let database = required_remote_database(remote)?;
    let username = required_remote_username(remote)?;
    let password = required_remote_password(remote)?;
    let secure = if remote.tls { " --secure" } else { "" };
    let table_source = clickhouse_remote_table_source(remote, selection)?;
    let column_expr = clickhouse_column_expr_function(selection)?;
    Ok(format!(
        r#"set -eu
remote_host={remote_host}
remote_port={remote_port}
remote_user={remote_user}
remote_password={remote_password}
remote_database={remote_database}
{table_source} | while IFS= read -r table; do
  [ -n "$table" ] || continue
  columns=$({column_expr})
  if [ "$columns" = "*" ]; then
    insert_query="INSERT INTO \`$table\` FORMAT Native"
  else
    insert_query="INSERT INTO \`$table\` ($columns) FORMAT Native"
  fi
  clickhouse-client \
    --host "$remote_host" \
    --port "$remote_port" \
    --user "$remote_user" \
    --password "$remote_password" \
    --database "$remote_database"{secure} \
    --query "SHOW CREATE TABLE \`$table\` FORMAT TabSeparatedRaw" \
  | sed "s/CREATE TABLE /CREATE TABLE IF NOT EXISTS /" \
  | clickhouse-client \
    --host 127.0.0.1 \
    --user "$CLICKHOUSE_USER" \
    --password "$CLICKHOUSE_PASSWORD" \
    --database "$CLICKHOUSE_DB" \
    --multiquery
  clickhouse-client \
    --host "$remote_host" \
    --port "$remote_port" \
    --user "$remote_user" \
    --password "$remote_password" \
    --database "$remote_database"{secure} \
    --query "SELECT $columns FROM \`$table\` FORMAT Native" \
  | clickhouse-client \
    --host 127.0.0.1 \
    --user "$CLICKHOUSE_USER" \
    --password "$CLICKHOUSE_PASSWORD" \
    --database "$CLICKHOUSE_DB" \
    --query "$insert_query"
done
"#,
        remote_host = sh_quote(&remote.host),
        remote_port = remote.port,
        remote_user = sh_quote(username),
        remote_password = sh_quote(password.expose_secret()),
        remote_database = sh_quote(database),
        table_source = table_source,
        column_expr = column_expr,
        secure = secure,
    ))
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

    match protocol {
        Protocol::Postgres | Protocol::Mariadb => {
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
            return Err(ApiError::NotImplemented(
                "qdrant selective import/export is not implemented yet".to_string(),
            ));
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

fn mariadb_dump_selection_args(
    selection: &ImportExportSelection,
    database: &str,
) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(format!(" {}", sh_quote(database)));
    }
    let mut args = String::new();
    for item in &selection.exclude {
        let table = item
            .rsplit_once('.')
            .map(|(_, table)| table)
            .unwrap_or(item);
        args.push_str(" --ignore-table=");
        args.push_str(&sh_quote(&format!("{database}.{table}")));
    }
    args.push(' ');
    args.push_str(&sh_quote(database));
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

fn mariadb_local_dump_selection_args(
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(" \"$MARIADB_DATABASE\"".to_string());
    }
    let mut args = String::new();
    for item in &selection.exclude {
        let table = item
            .rsplit_once('.')
            .map(|(_, table)| table)
            .unwrap_or(item);
        args.push_str(&format!(" --ignore-table=\"$MARIADB_DATABASE.{table}\""));
    }
    args.push_str(" \"$MARIADB_DATABASE\"");
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

fn mongodb_dump_selection_args(
    selection: &ImportExportSelection,
    database: &str,
) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(String::new());
    }
    let mut args = String::new();
    for item in &selection.include {
        args.push_str(" --nsInclude ");
        args.push_str(&sh_quote(&format!("{database}.{item}")));
    }
    for item in &selection.exclude {
        args.push_str(" --nsExclude ");
        args.push_str(&sh_quote(&format!("{database}.{item}")));
    }
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

fn clickhouse_remote_table_source(
    remote: &RemoteImportSource,
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Selective {
        return Ok(format!(
            "printf '%s\\n' {}",
            sh_quote(&selection.include.join("\n"))
        ));
    }
    let secure = if remote.tls { " --secure" } else { "" };
    Ok(format!(
        r#"clickhouse-client \
  --host "$remote_host" \
  --port "$remote_port" \
  --user "$remote_user" \
  --password "$remote_password" \
  --database "$remote_database"{secure} \
  --query "SHOW TABLES FORMAT TSV""#
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

fn required_remote_database(remote: &RemoteImportSource) -> Result<&str, ApiError> {
    remote
        .database
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::BadRequest("remote import requires database".to_string()))
}

fn required_remote_username(remote: &RemoteImportSource) -> Result<&str, ApiError> {
    remote
        .username
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::BadRequest("remote import requires username".to_string()))
}

fn required_remote_password(remote: &RemoteImportSource) -> Result<&SecretString, ApiError> {
    remote
        .password
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("remote import requires password".to_string()))
}

fn ensure_mongodb_root_password(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if metadata.protocol == Protocol::Mongodb && metadata.mongodb_root_password.is_none() {
        return Err(ApiError::BadRequest(
            "mongodb internal root password is missing; this instance was created before DBE stored MongoDB maintenance credentials, so DBE cannot export/import protected internal collections such as time-series buckets. Recreate the instance or use a manual admin dump.".to_string(),
        ));
    }
    Ok(())
}

fn export_script(
    metadata: &InstanceMetadata,
    output_path: &str,
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    let protocol = metadata.protocol;
    let script = match protocol {
        Protocol::Postgres => {
            let filters = postgres_dump_selection_args(selection)?;
            format!(
                r#"set -eu
PGPASSWORD="$POSTGRES_PASSWORD" pg_dump \
  -h 127.0.0.1 \
  -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  --clean --if-exists --no-owner --no-privileges{filters} \
  > {output_path}
"#
            )
        }
        Protocol::Mariadb => {
            let filters = mariadb_local_dump_selection_args(selection)?;
            format!(
                r#"set -eu
mariadb-dump \
  -h 127.0.0.1 \
  -u "$MARIADB_USER" \
  -p"$MARIADB_PASSWORD" \
  --single-transaction --routines --triggers{filters} \
  > {output_path}
"#
            )
        }
        Protocol::Mongodb => {
            ensure_mongodb_root_password(metadata)?;
            let filters = mongodb_dump_selection_args(selection, "$DBE_MONGO_DATABASE")?;
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
            format!(
                r#"set -eu
out={output_path}
: > "$out"
{table_source} | while IFS= read -r table; do
    [ -n "$table" ] || continue
    columns=$({column_expr})
    printf 'DROP TABLE IF EXISTS `%s`;\n' "$table" >> "$out"
    clickhouse-client \
      --host 127.0.0.1 \
      --user "$CLICKHOUSE_USER" \
      --password "$CLICKHOUSE_PASSWORD" \
      --database "$CLICKHOUSE_DB" \
      --query "SHOW CREATE TABLE \`$table\` FORMAT TabSeparatedRaw" >> "$out"
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

fn import_script(metadata: &InstanceMetadata, input_path: &str) -> Result<String, ApiError> {
    let protocol = metadata.protocol;
    let script = match protocol {
        Protocol::Postgres => format!(
            r#"set -eu
PGPASSWORD="$POSTGRES_PASSWORD" psql \
  -h 127.0.0.1 \
  -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 \
  -f {input_path}
"#
        ),
        Protocol::Mariadb => format!(
            r#"set -eu
mariadb \
  -h 127.0.0.1 \
  -u "$MARIADB_USER" \
  -p"$MARIADB_PASSWORD" \
  "$MARIADB_DATABASE" \
  < {input_path}
"#
        ),
        Protocol::Mongodb => {
            ensure_mongodb_root_password(metadata)?;
            format!(
                r#"set -eu
mongorestore \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_ROOT_USER" \
  --password "$DBE_MONGO_ROOT_PASSWORD" \
  --authenticationDatabase "admin" \
  --drop \
  --nsInclude "$DBE_MONGO_DATABASE.*" \
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

fn container_data_path(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => "/var/lib/postgresql",
        Protocol::Redis => "/data",
        Protocol::Mariadb => "/var/lib/mysql",
        Protocol::Mongodb => "/data/db",
        Protocol::Clickhouse => "/var/lib/clickhouse",
        Protocol::Qdrant => "/dbe-qdrant/storage",
    }
}

fn dump_extension(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => "postgres.sql",
        Protocol::Redis => "redis.tar.gz",
        Protocol::Mariadb => "mariadb.sql",
        Protocol::Mongodb => "mongodb.archive.gz",
        Protocol::Clickhouse => "clickhouse.sql",
        Protocol::Qdrant => "qdrant.tar.gz",
    }
}

async fn copy_file(from: &FsPath, to: &FsPath) -> Result<(), ApiError> {
    if let Some(parent) = to.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|error| {
            ApiError::Runtime(format!(
                "failed to create parent directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    tokio::fs::copy(from, to).await.map_err(|error| {
        ApiError::Runtime(format!(
            "failed to copy {} to {}: {error}",
            from.display(),
            to.display()
        ))
    })?;
    Ok(())
}

async fn archive_or_copy_export(
    from: &FsPath,
    to: &FsPath,
    format: ExportArchiveFormat,
) -> Result<(), ApiError> {
    match format {
        ExportArchiveFormat::Plain => copy_file(from, to).await,
        ExportArchiveFormat::Gzip => compress_gzip(from, to).await,
        ExportArchiveFormat::Bzip2 => compress_bzip2(from, to).await,
    }
}

async fn compress_gzip(source: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "gzip compression",
        "compress gzip",
        false,
        move || -> Result<(), std::io::Error> {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut input = std::fs::File::open(source)?;
            let output = std::fs::File::create(target)?;
            let mut encoder = flate2::write::GzEncoder::new(output, flate2::Compression::new(3));
            std::io::copy(&mut input, &mut encoder)?;
            encoder.finish()?;
            Ok(())
        },
    )
    .await
}

async fn compress_bzip2(source: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "bzip2 compression",
        "compress bzip2",
        false,
        move || -> Result<(), std::io::Error> {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut input = std::fs::File::open(source)?;
            let output = std::fs::File::create(target)?;
            let mut encoder = bzip2::write::BzEncoder::new(output, bzip2::Compression::default());
            std::io::copy(&mut input, &mut encoder)?;
            encoder.finish()?;
            Ok(())
        },
    )
    .await
}

async fn run_archive_file_operation(
    timeout_label: &'static str,
    failure_label: &'static str,
    io_error_is_bad_request: bool,
    task: impl FnOnce() -> Result<(), std::io::Error> + Send + 'static,
) -> Result<(), ApiError> {
    let result = timeout(ARCHIVE_OPERATION_TIMEOUT, tokio::task::spawn_blocking(task))
        .await
        .map_err(|_| ApiError::BadRequest(format!("{timeout_label} exceeded time limit")))?
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

async fn ensure_import_file_size(path: &FsPath) -> Result<(), ApiError> {
    let metadata = tokio::fs::metadata(path).await.map_err(|error| {
        ApiError::Runtime(format!(
            "failed to read import artifact metadata {}: {error}",
            path.display()
        ))
    })?;
    if metadata.len() > MAX_UNARCHIVED_BYTES {
        return Err(ApiError::BadRequest(format!(
            "import artifact is too large: {} bytes exceeds {} bytes",
            metadata.len(),
            MAX_UNARCHIVED_BYTES
        )));
    }
    Ok(())
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

    let staging_dir = paths.data.join(format!(".dbe-import-{import_id}"));
    let staged_data = staging_dir.join(&expected_root);
    let backup_dir = paths.data.join(format!(".dbe-backup-{import_id}"));
    tokio::fs::create_dir_all(&staging_dir)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to create import staging: {error}")))?;
    if let Err(error) = extract_data_archive(
        artifact_path.to_path_buf(),
        staging_dir.clone(),
        expected_root,
    )
    .await
    {
        cleanup_dir(&staging_dir).await;
        return Err(ApiError::BadRequest(error.to_string()));
    }

    tokio::fs::create_dir_all(&backup_dir)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to create import backup: {error}")))?;

    if let Err(error) =
        move_directory_entries_except(&paths.data, &backup_dir, &[&staging_dir, &backup_dir]).await
    {
        cleanup_dir(&staging_dir).await;
        cleanup_dir(&backup_dir).await;
        return Err(ApiError::Runtime(format!(
            "failed to move existing data contents aside: {error}"
        )));
    }

    if let Err(error) = move_directory_entries(&staged_data, &paths.data).await {
        cleanup_dir_contents_except(&paths.data, &[&staging_dir, &backup_dir]).await;
        let _ = move_directory_entries(&backup_dir, &paths.data).await;
        cleanup_dir(&staging_dir).await;
        cleanup_dir(&backup_dir).await;
        return Err(ApiError::Runtime(format!(
            "failed to install imported data contents: {error}"
        )));
    }

    cleanup_dir(&backup_dir).await;
    cleanup_dir(&staging_dir).await;
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

async fn cleanup_dir_contents_except(path: &FsPath, exclude: &[&FsPath]) {
    let Ok(mut entries) = tokio::fs::read_dir(path).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if exclude.iter().any(|excluded| path == **excluded) {
            continue;
        }
        cleanup_path(&path).await;
    }
}

async fn restart_after_job(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    let _ = lifecycle_instance(state, instance_id, LifecycleAction::Start).await?;
    Ok(())
}

async fn export_artifact_path(
    state: &AppState,
    instance_id: &str,
    protocol: Protocol,
    archive_format: ExportArchiveFormat,
) -> Result<PathBuf, ApiError> {
    let export_root = PathBuf::from(state.config.paths.exports_root());
    tokio::fs::create_dir_all(&export_root)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to create export dir: {error}")))?;
    Ok(export_root.join(format!(
        "{}-{}.{}{}",
        instance_id,
        OffsetDateTime::now_utc().unix_timestamp(),
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
    ImportExportJobResponse {
        job,
        artifact_size_bytes,
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

async fn validate_artifact_path(state: &AppState, path: &FsPath) -> Result<PathBuf, ApiError> {
    if !path.is_absolute() {
        return Err(ApiError::BadRequest(
            "artifact_path must be an absolute path under configured artifacts exports or imports root"
                .to_string(),
        ));
    }
    let export_root_path = PathBuf::from(state.config.paths.exports_root());
    let import_root_path = PathBuf::from(state.config.paths.imports_root());
    tokio::fs::create_dir_all(&export_root_path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to create exports root: {error}")))?;
    tokio::fs::create_dir_all(&import_root_path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to create imports root: {error}")))?;
    let exports_root = tokio::fs::canonicalize(&export_root_path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to read exports root: {error}")))?;
    let imports_root = tokio::fs::canonicalize(&import_root_path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to read imports root: {error}")))?;
    let artifact_path = tokio::fs::canonicalize(path)
        .await
        .map_err(|error| ApiError::BadRequest(format!("artifact_path is invalid: {error}")))?;
    if !artifact_path.starts_with(&exports_root) && !artifact_path.starts_with(&imports_root) {
        return Err(ApiError::BadRequest(
            "artifact_path must be under configured artifacts exports or imports root".to_string(),
        ));
    }
    if !artifact_has_allowed_extension(&artifact_path) {
        return Err(ApiError::BadRequest(
            "artifact_path extension is not allowed for import".to_string(),
        ));
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
    use std::sync::Arc;

    use super::*;
    use crate::{
        auth::api_token::ApiToken,
        config::Config,
        instances::{manager::InstanceManager, state::InstanceStore},
        jobs::import_export::ImportExportJobs,
        runtime::docker::DockerRuntime,
        storage::{repositories::InstanceRepository, sqlite},
    };

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
    fn qdrant_uses_physical_archive_extension() {
        assert_eq!(dump_extension(Protocol::Qdrant), "qdrant.tar.gz");
        assert!(dump_candidate_suffixes(Protocol::Qdrant).contains(&".qdrant.tar.gz"));
    }

    #[tokio::test]
    async fn artifact_imports_must_be_under_exports_root() {
        let dir = tempfile::tempdir().unwrap();
        let artifacts = dir.path().join("artifacts");
        let exports = artifacts.join("exports");
        std::fs::create_dir_all(&exports).unwrap();
        let allowed = exports.join("instance.postgres.sql");
        let outside = artifacts.join("outside.postgres.sql");
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
            validate_artifact_path(&state, &allowed).await.unwrap(),
            allowed.canonicalize().unwrap()
        );
        assert!(validate_artifact_path(&state, &outside).await.is_err());
    }

    #[tokio::test]
    async fn artifact_import_rejects_relative_paths_before_reading_exports_root() {
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

        let error = validate_artifact_path(&state, FsPath::new("../../etc/passwd"))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("absolute path"));
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

        let error = validate_artifact_path(&state, &outside).await.unwrap_err();

        assert!(error.to_string().contains("under configured artifacts"));
        assert!(artifacts.join("exports").is_dir());
    }

    #[tokio::test]
    async fn rejects_remote_imports_resolving_to_private_ips_by_default() {
        let state = test_state(false, Vec::new()).await;
        let remote = remote_source("127.0.0.1");

        let error = resolve_validated_remote_host(&state, &remote)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("blocked address"));
    }

    #[tokio::test]
    async fn resolves_allowed_remote_host_to_ip_for_import_execution() {
        let state = test_state(true, Vec::new()).await;
        let remote = remote_source("localhost");

        let host = resolve_validated_remote_host(&state, &remote)
            .await
            .unwrap();

        assert!(host.parse::<IpAddr>().is_ok());
        assert_ne!(host, "localhost");
    }

    #[tokio::test]
    async fn preserves_tls_remote_hostname_for_certificate_verification() {
        let state = test_state(true, Vec::new()).await;
        let mut remote = remote_source("localhost");
        remote.tls = true;
        let options = ImportOptions {
            source: ImportSourceOptions::Remote(remote),
            ..Default::default()
        };

        let options = harden_import_options(&state, Protocol::Postgres, options)
            .await
            .unwrap();

        match options.source {
            ImportSourceOptions::Remote(remote) => assert_eq!(remote.host, "localhost"),
            ImportSourceOptions::Artifact(_) => panic!("expected remote source"),
        }
    }

    fn remote_source(host: &str) -> RemoteImportSource {
        RemoteImportSource {
            protocol: Protocol::Postgres,
            host: host.to_string(),
            port: 5432,
            database: Some("app".to_string()),
            username: Some("user".to_string()),
            password: Some(SecretString::from("secret".to_string())),
            tls: false,
        }
    }

    async fn test_state(
        allow_private_remote_imports: bool,
        remote_import_allowed_hosts: Vec<String>,
    ) -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let store = InstanceStore::default();
        let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool));
        test_state_with_store(
            store,
            manager,
            Config {
                security: crate::config::SecurityConfig {
                    allow_private_remote_imports,
                    remote_import_allowed_hosts,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
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
        AppState {
            config: Arc::new(config),
            config_path: std::path::PathBuf::from("/tmp/dbev-test-config.yml"),
            api_token: ApiToken::new("secret"),
            instances: store,
            manager,
            docker: DockerRuntime::new(&Default::default(), false).unwrap(),
            import_export_jobs: ImportExportJobs::default(),
            api_rate_limiter: crate::api::security::ApiRateLimiter::default(),
            install_progress: crate::api::progress::InstallProgressStore::default(),
            artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
            resource_cache: crate::api::resources::ResourceCache::default(),
            instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
        }
    }
}
