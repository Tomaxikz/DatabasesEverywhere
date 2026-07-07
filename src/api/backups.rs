use std::{
    cmp::Reverse,
    path::{Path as FsPath, PathBuf},
    time::{Duration, SystemTime},
};

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Uri, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::time::sleep;
use tokio_util::io::ReaderStream;

use crate::{
    api::{
        artifacts::{ArtifactInfo, DeleteArtifactResponse},
        handlers::{ApiError, ApiResult, authorize_scope},
        import_export::ImportExportJobResponse,
        routes::AppState,
    },
    auth::scopes,
    instances::metadata::{InstanceMetadata, InstanceStatus},
    jobs::import_export::create_data_archive,
    shared::{
        files::{is_safe_flat_file_name, safe_header_filename},
        protocol::Protocol,
    },
};

#[derive(Debug, Deserialize)]
pub struct RunBackupRequest {
    pub instance_id: Option<String>,
    pub all: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct DownloadBackupQuery {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct RestoreBackupRequest {
    pub instance_id: String,
}

#[derive(Debug, Serialize)]
pub struct BackupStatusResponse {
    pub enabled: bool,
    pub interval_minutes: u64,
    pub run_on_startup: bool,
    pub retention_keep_latest_per_instance: usize,
    pub retention_max_age_days: u64,
    pub redis_excluded: bool,
}

#[derive(Debug, Serialize)]
pub struct RunBackupResponse {
    pub jobs: Vec<ImportExportJobResponse>,
    pub skipped: Vec<SkippedBackup>,
}

#[derive(Debug, Serialize)]
pub struct SkippedBackup {
    pub instance_id: String,
    pub protocol: Protocol,
    pub reason: String,
}

pub async fn backup_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<BackupStatusResponse> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_READ)?;
    Ok(Json(BackupStatusResponse {
        enabled: state.config.backups.enabled,
        interval_minutes: state.config.backups.interval_minutes,
        run_on_startup: state.config.backups.run_on_startup,
        retention_keep_latest_per_instance: state.config.backups.retention_keep_latest_per_instance,
        retention_max_age_days: state.config.backups.retention_max_age_days,
        redis_excluded: false,
    }))
}

pub async fn list_backups(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Vec<ArtifactInfo>> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_READ)?;
    Ok(Json(read_backups(&state).await?))
}

pub async fn run_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<RunBackupRequest>,
) -> ApiResult<RunBackupResponse> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_WRITE)?;
    if let Some(instance_id) = request.instance_id.as_deref() {
        let job = queue_backup_instance(&state, instance_id).await?;
        return Ok(Json(RunBackupResponse {
            jobs: vec![job],
            skipped: Vec::new(),
        }));
    }
    if request.all.unwrap_or(false) {
        return Ok(Json(queue_all_backups(&state).await));
    }
    Err(ApiError::BadRequest(
        "set instance_id or all=true".to_string(),
    ))
}

pub async fn delete_backup(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<DeleteArtifactResponse> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_WRITE)?;
    delete_backup_by_name(&state, name).await
}

pub async fn download_backup_query(
    State(state): State<AppState>,
    Query(query): Query<DownloadBackupQuery>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, ApiError> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_READ)?;
    download_backup_by_name(&state, &query.name).await
}

pub async fn download_backup_path(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, ApiError> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_READ)?;
    download_backup_by_name(&state, &name).await
}

pub async fn restore_backup(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<RestoreBackupRequest>,
) -> ApiResult<ImportExportJobResponse> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_WRITE)?;
    let instance_id = request.instance_id.trim();
    if instance_id.is_empty() {
        return Err(ApiError::BadRequest(
            "instance_id must not be empty".to_string(),
        ));
    }
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let path = verified_backup_path_for_instance(&state, &name, instance_id).await?;
    let was_running = metadata.status == InstanceStatus::Running;
    if was_running {
        let _ = crate::api::instances::lifecycle_instance(
            &state,
            instance_id,
            crate::api::instances::LifecycleAction::Stop,
        )
        .await?;
    }
    let paths = crate::instances::paths::InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let result = crate::api::import_export::replace_data_from_archive(paths.clone(), &path).await;
    if result.is_ok() && !state.docker.uses_rootless_podman() {
        paths
            .apply_container_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    }
    if was_running {
        let _ = crate::api::instances::lifecycle_instance(
            &state,
            instance_id,
            crate::api::instances::LifecycleAction::Start,
        )
        .await?;
    }
    result?;
    let now = crate::jobs::import_export::now_rfc3339();
    Ok(Json(ImportExportJobResponse {
        job: crate::jobs::import_export::ImportExportJob {
            job_id: uuid::Uuid::new_v4().to_string(),
            instance_id: instance_id.to_string(),
            action: crate::jobs::import_export::ImportExportAction::Import,
            status: crate::jobs::import_export::ImportExportStatus::Succeeded,
            artifact_path: Some(path.display().to_string()),
            error: None,
            created_at: now.clone(),
            updated_at: now,
        },
        artifact_size_bytes: tokio::fs::metadata(&path).await.ok().map(|m| m.len()),
    }))
}

async fn delete_backup_by_name(
    state: &AppState,
    name: String,
) -> ApiResult<DeleteArtifactResponse> {
    let path = backup_path_by_name(state, &name).await?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => {
            tracing::info!(event = "audit backup_deleted", backup = %name);
            Ok(Json(DeleteArtifactResponse {
                name,
                deleted: true,
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(ApiError::NotFound),
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to delete backup: {error}"
        ))),
    }
}

async fn download_backup_by_name(state: &AppState, name: &str) -> Result<Response, ApiError> {
    let path = backup_path_by_name(state, name).await?;
    let file = File::open(&path)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ApiError::NotFound,
            _ => ApiError::Runtime(format!("failed to open backup: {error}")),
        })?;
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    tracing::info!(event = "audit backup_downloaded", backup = %name);
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", safe_header_filename(name)),
            ),
        ],
        body,
    )
        .into_response())
}

pub(crate) async fn queue_backup_instance(
    state: &AppState,
    instance_id: &str,
) -> Result<ImportExportJobResponse, ApiError> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    validate_backup_eligible(&metadata)?;
    let artifact_path = backup_artifact_path(state, &metadata.instance_id).await?;
    let was_running = metadata.status == InstanceStatus::Running;
    if was_running {
        let _ = crate::api::instances::lifecycle_instance(
            state,
            instance_id,
            crate::api::instances::LifecycleAction::Stop,
        )
        .await?;
    }
    let paths = crate::instances::paths::InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let result = create_data_archive(paths.data, artifact_path.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()));
    if was_running {
        let _ = crate::api::instances::lifecycle_instance(
            state,
            instance_id,
            crate::api::instances::LifecycleAction::Start,
        )
        .await?;
    }
    result?;
    prune_instance_backups(state, &metadata.instance_id).await?;
    let job = crate::jobs::import_export::ImportExportJob {
        job_id: uuid::Uuid::new_v4().to_string(),
        instance_id: metadata.instance_id.clone(),
        action: crate::jobs::import_export::ImportExportAction::Export,
        status: crate::jobs::import_export::ImportExportStatus::Succeeded,
        artifact_path: Some(artifact_path.display().to_string()),
        error: None,
        created_at: crate::jobs::import_export::now_rfc3339(),
        updated_at: crate::jobs::import_export::now_rfc3339(),
    };
    tracing::info!(
        event = "audit backup_queued",
        instance_id,
        protocol = metadata.protocol.as_str(),
    );
    Ok(crate::api::import_export::public_job_response(job).await)
}

pub(crate) async fn queue_all_backups(state: &AppState) -> RunBackupResponse {
    let mut jobs = Vec::new();
    let mut skipped = Vec::new();
    for metadata in state.instances.list().await {
        match validate_backup_eligible(&metadata) {
            Ok(()) => match queue_backup_instance(state, &metadata.instance_id).await {
                Ok(response) => jobs.push(response),
                Err(error) => skipped.push(SkippedBackup {
                    instance_id: metadata.instance_id,
                    protocol: metadata.protocol,
                    reason: error.to_string(),
                }),
            },
            Err(error) => skipped.push(SkippedBackup {
                instance_id: metadata.instance_id,
                protocol: metadata.protocol,
                reason: error.to_string(),
            }),
        }
    }
    tracing::info!(
        event = "audit backups_queued",
        jobs = jobs.len(),
        skipped = skipped.len(),
    );
    RunBackupResponse { jobs, skipped }
}

pub fn start_scheduler(state: AppState) {
    if !state.config.backups.enabled {
        tracing::info!("automatic backups disabled");
        return;
    }

    let interval = Duration::from_secs(state.config.backups.interval_minutes.saturating_mul(60));
    let run_on_startup = state.config.backups.run_on_startup;
    tokio::spawn(async move {
        tracing::info!(
            interval_minutes = state.config.backups.interval_minutes,
            run_on_startup,
            "automatic backups enabled"
        );
        if run_on_startup {
            run_scheduled_backup_pass(&state).await;
        }
        loop {
            sleep(interval).await;
            run_scheduled_backup_pass(&state).await;
        }
    });
}

async fn run_scheduled_backup_pass(state: &AppState) {
    let response = queue_all_backups(state).await;
    tracing::info!(
        event = "audit scheduled_backup_pass",
        jobs = response.jobs.len(),
        skipped = response.skipped.len(),
    );
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

pub(crate) async fn read_backups(state: &AppState) -> Result<Vec<ArtifactInfo>, ApiError> {
    let root = backup_root(state);
    let mut backups = Vec::new();
    read_backup_dir(&root, &mut backups).await?;
    backups.sort_by(|left, right| right.modified_at.cmp(&left.modified_at));
    Ok(backups)
}

pub(crate) async fn verified_backup_path_for_instance(
    state: &AppState,
    name: &str,
    instance_id: &str,
) -> Result<PathBuf, ApiError> {
    validate_backup_name(name)?;
    let path = backup_root(state).join(instance_id).join(name);
    verify_backup_path(state, &path).await
}

async fn backup_path_by_name(state: &AppState, name: &str) -> Result<PathBuf, ApiError> {
    validate_backup_name(name)?;
    let mut matches = Vec::new();
    for backup in read_backups(state).await? {
        if backup.name == name {
            matches.push(PathBuf::from(backup.path));
        }
    }
    match matches.len() {
        0 => Err(ApiError::NotFound),
        1 => verify_backup_path(state, &matches[0]).await,
        _ => Err(ApiError::BadRequest(
            "backup name is ambiguous; request a signed token with instance_id".to_string(),
        )),
    }
}

async fn backup_artifact_path(state: &AppState, instance_id: &str) -> Result<PathBuf, ApiError> {
    let dir = backup_root(state).join(instance_id);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to create backup dir: {error}")))?;
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    Ok(dir.join(format!(
        "{}-{}-{}.physical.tar.gz",
        instance_id,
        time::OffsetDateTime::now_utc().unix_timestamp(),
        &suffix[..8],
    )))
}

fn backup_root(state: &AppState) -> PathBuf {
    PathBuf::from(state.config.paths.backups_root())
}

#[derive(Debug)]
struct BackupFile {
    path: PathBuf,
    name: String,
    modified: SystemTime,
}

async fn prune_instance_backups(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    let keep_latest = state.config.backups.retention_keep_latest_per_instance;
    let max_age_days = state.config.backups.retention_max_age_days;
    let dir = backup_root(state).join(instance_id);
    let mut backups = read_instance_backup_files(&dir).await?;
    backups.sort_by_key(|backup| Reverse(backup.modified));

    let mut deleted = 0usize;
    if max_age_days > 0 {
        let max_age = Duration::from_secs(max_age_days.saturating_mul(24 * 60 * 60));
        let now = SystemTime::now();
        let mut kept = Vec::with_capacity(backups.len());
        for backup in backups {
            let expired = now
                .duration_since(backup.modified)
                .map(|age| age > max_age)
                .unwrap_or(false);
            if expired {
                delete_pruned_backup(&backup).await?;
                deleted += 1;
            } else {
                kept.push(backup);
            }
        }
        backups = kept;
    }

    if backups.len() > keep_latest {
        let old_backups = backups.split_off(keep_latest);
        for backup in old_backups {
            delete_pruned_backup(&backup).await?;
            deleted += 1;
        }
    }

    tracing::info!(
        event = "audit backup_retention_pruned",
        instance_id,
        keep_latest,
        max_age_days,
        deleted,
    );
    Ok(())
}

async fn read_instance_backup_files(dir: &FsPath) -> Result<Vec<BackupFile>, ApiError> {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(ApiError::Runtime(format!(
                "failed to read backup directory {}: {error}",
                dir.display()
            )));
        }
    };
    let mut backups = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to read backup entry: {error}")))?
    {
        let path = entry.path();
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to stat backup entry: {error}")))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if validate_backup_name(name).is_err() {
            continue;
        }
        let name = name.to_string();
        backups.push(BackupFile {
            path,
            name,
            modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        });
    }
    Ok(backups)
}

async fn delete_pruned_backup(backup: &BackupFile) -> Result<(), ApiError> {
    match tokio::fs::remove_file(&backup.path).await {
        Ok(()) => {
            tracing::info!(event = "audit backup_retention_deleted", backup = %backup.name);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to delete old backup {}: {error}",
            backup.path.display()
        ))),
    }
}

async fn verify_backup_path(state: &AppState, path: &FsPath) -> Result<PathBuf, ApiError> {
    let root = backup_root(state);
    tokio::fs::create_dir_all(&root)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to create backup root: {error}")))?;
    let root = tokio::fs::canonicalize(&root)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to resolve backup root: {error}")))?;
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ApiError::NotFound,
            _ => ApiError::Runtime(format!("failed to inspect backup: {error}")),
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ApiError::BadRequest(
            "backup is not a regular file".to_string(),
        ));
    }
    let canonical = tokio::fs::canonicalize(path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to resolve backup: {error}")))?;
    if !canonical.starts_with(&root) {
        return Err(ApiError::BadRequest(
            "backup resolves outside backup root".to_string(),
        ));
    }
    Ok(canonical)
}

async fn read_backup_dir(root: &FsPath, backups: &mut Vec<ArtifactInfo>) -> Result<(), ApiError> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(ApiError::Runtime(format!(
                    "failed to read backup directory {}: {error}",
                    dir.display()
                )));
            }
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to read backup entry: {error}")))?
        {
            let metadata = entry.metadata().await.map_err(|error| {
                ApiError::Runtime(format!("failed to stat backup entry: {error}"))
            })?;
            if metadata.is_dir() {
                stack.push(entry.path());
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| ApiError::Runtime("invalid backup name".to_string()))?
                .to_string();
            backups.push(ArtifactInfo {
                name,
                path: path.display().to_string(),
                size_bytes: metadata.len(),
                modified_at: crate::api::artifacts::system_time_rfc3339(
                    metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                ),
                sha256: crate::api::artifacts::sha256_file(path).await?,
            });
        }
    }
    Ok(())
}

fn validate_backup_name(name: &str) -> Result<(), ApiError> {
    if !is_safe_flat_file_name(name) {
        Err(ApiError::BadRequest("invalid backup name".to_string()))
    } else {
        Ok(())
    }
}
