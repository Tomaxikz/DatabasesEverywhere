use std::{
    cmp::Reverse,
    path::{Path as FsPath, PathBuf},
    time::{Duration, SystemTime},
};

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, Uri},
};
use serde::Serialize;
use tokio::time::sleep;

use crate::{
    api::{
        artifacts::{ArtifactInfo, DeleteArtifactResponse},
        handlers::{ApiError, ApiResult, authorize_scope},
        routes::AppState,
    },
    auth::scopes,
    instances::metadata::{InstanceMetadata, InstanceStatus},
    jobs::import_export::create_data_archive,
    shared::{files::is_safe_flat_file_name, ids::validate_instance_id, protocol::Protocol},
};

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
    pub reason: String,
}

pub async fn backup_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<BackupStatusResponse> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_ADMIN)?;
    Ok(Json(BackupStatusResponse {
        enabled: state.config.backups.enabled,
        interval_minutes: state.config.backups.interval_minutes,
        run_on_startup: state.config.backups.run_on_startup,
        retention_keep_latest_per_instance: state.config.backups.retention_keep_latest_per_instance,
        retention_max_age_days: state.config.backups.retention_max_age_days,
        redis_excluded: false,
    }))
}

pub async fn list_instance_backups(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Vec<ArtifactInfo>> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_READ)?;
    ensure_instance_exists(&state, &instance_id).await?;
    Ok(Json(read_instance_backups(&state, &instance_id).await?))
}

pub async fn run_instance_backup(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<ArtifactInfo> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_WRITE)?;
    Ok(Json(backup_instance(&state, &instance_id).await?))
}

pub async fn run_all_backups(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<RunBackupResponse> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_ADMIN)?;
    Ok(Json(backup_all_instances(&state).await))
}

pub async fn delete_instance_backup(
    State(state): State<AppState>,
    Path((instance_id, backup_id)): Path<(String, String)>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<DeleteArtifactResponse> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_WRITE)?;
    ensure_instance_exists(&state, &instance_id).await?;
    delete_instance_backup_by_id(&state, &instance_id, backup_id).await
}

pub async fn restore_instance_backup(
    State(state): State<AppState>,
    Path((instance_id, backup_id)): Path<(String, String)>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<RestoreBackupResponse> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_WRITE)?;
    let _operation = state.instance_locks.lock(&instance_id).await;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let path = verified_backup_path_for_instance(&state, &backup_id, &instance_id).await?;
    let was_running = metadata.status == InstanceStatus::Running;
    if was_running {
        let _ = crate::api::instances::lifecycle_instance_locked(
            &state,
            &instance_id,
            crate::api::instances::LifecycleAction::Stop,
        )
        .await?;
    }
    let paths = crate::instances::paths::InstancePaths::new(&state.config.paths, &instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let mut result =
        crate::api::import_export::replace_data_from_archive(paths.clone(), &path).await;
    if result.is_ok() && !state.docker.uses_rootless_podman() {
        result = paths
            .apply_container_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()));
    }
    crate::api::import_export::finish_physical_operation(&state, &instance_id, was_running, result)
        .await?;
    tracing::info!(event = "audit backup_restored", instance_id, backup_id);
    Ok(Json(RestoreBackupResponse {
        instance_id,
        backup_id,
        restored: true,
    }))
}

async fn delete_instance_backup_by_id(
    state: &AppState,
    instance_id: &str,
    backup_id: String,
) -> ApiResult<DeleteArtifactResponse> {
    let path = verified_backup_path_for_instance(state, &backup_id, instance_id).await?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => {
            crate::api::artifacts::remove_checksum_sidecar(&path).await;
            tracing::info!(event = "audit backup_deleted", instance_id, backup_id);
            Ok(Json(DeleteArtifactResponse {
                id: backup_id,
                deleted: true,
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(ApiError::NotFound),
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to delete backup: {error}"
        ))),
    }
}

pub(crate) async fn backup_instance(
    state: &AppState,
    instance_id: &str,
) -> Result<ArtifactInfo, ApiError> {
    let _operation = state.instance_locks.lock(instance_id).await;
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    validate_backup_eligible(&metadata)?;
    let artifact_path = backup_artifact_path(state, &metadata.instance_id).await?;
    let was_running = metadata.status == InstanceStatus::Running;
    if was_running {
        let _ = crate::api::instances::lifecycle_instance_locked(
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
    crate::api::import_export::finish_physical_operation(state, instance_id, was_running, result)
        .await?;
    prune_instance_backups(state, &metadata.instance_id).await?;
    let backup = backup_info(&metadata.instance_id, artifact_path).await?;
    tracing::info!(
        event = "audit backup_completed",
        instance_id,
        protocol = metadata.protocol.as_str(),
        backup_id = %backup.id,
    );
    Ok(backup)
}

pub(crate) async fn backup_all_instances(state: &AppState) -> RunBackupResponse {
    let mut backups = Vec::new();
    let mut skipped = Vec::new();
    for metadata in state.instances.list().await {
        match validate_backup_eligible(&metadata) {
            Ok(()) => match backup_instance(state, &metadata.instance_id).await {
                Ok(response) => backups.push(response),
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
    let response = backup_all_instances(state).await;
    tracing::info!(
        event = "audit scheduled_backup_pass",
        backups = response.backups.len(),
        skipped = response.skipped.len(),
    );
}

async fn backup_info(instance_id: &str, path: PathBuf) -> Result<ArtifactInfo, ApiError> {
    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to stat backup: {error}")))?;
    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ApiError::Runtime("invalid backup name".to_string()))?
        .to_string();
    Ok(ArtifactInfo {
        id,
        instance_id: instance_id.to_string(),
        size_bytes: metadata.len(),
        modified_at: crate::api::artifacts::system_time_rfc3339(
            metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        ),
        sha256: crate::api::artifacts::sha256_file(path).await?,
    })
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

async fn ensure_instance_exists(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    state
        .instances
        .get(instance_id)
        .await
        .map(|_| ())
        .ok_or(ApiError::NotFound)
}

async fn read_instance_backups(
    state: &AppState,
    instance_id: &str,
) -> Result<Vec<ArtifactInfo>, ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let files = read_instance_backup_files(&backup_root(state).join(instance_id)).await?;
    let mut backups = Vec::with_capacity(files.len());
    for backup in files {
        let metadata = tokio::fs::metadata(&backup.path)
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to stat backup: {error}")))?;
        backups.push(ArtifactInfo {
            id: backup.name,
            instance_id: instance_id.to_string(),
            size_bytes: metadata.len(),
            modified_at: crate::api::artifacts::system_time_rfc3339(backup.modified),
            sha256: crate::api::artifacts::sha256_file(backup.path).await?,
        });
    }
    backups.sort_by(|left, right| right.modified_at.cmp(&left.modified_at));
    Ok(backups)
}

pub(crate) async fn verified_backup_path_for_instance(
    state: &AppState,
    name: &str,
    instance_id: &str,
) -> Result<PathBuf, ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    validate_backup_name(name)?;
    let path = backup_root(state).join(instance_id).join(name);
    verify_backup_path(state, instance_id, &path).await
}

async fn backup_artifact_path(state: &AppState, instance_id: &str) -> Result<PathBuf, ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let root = backup_root(state);
    create_private_directory(&root, "backup root").await?;
    let dir = root.join(instance_id);
    create_private_directory(&dir, "backup instance directory").await?;
    Ok(dir.join(format!("{}.physical.tar.gz", uuid::Uuid::new_v4())))
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
    match tokio::fs::symlink_metadata(dir).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ApiError::Runtime(
                "instance backup root must be a real directory".to_string(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(ApiError::Runtime(format!(
                "failed to inspect backup directory {}: {error}",
                dir.display()
            )));
        }
    }
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
        if crate::api::artifacts::is_checksum_sidecar(&path) {
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
            crate::api::artifacts::remove_checksum_sidecar(&backup.path).await;
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

async fn verify_backup_path(
    state: &AppState,
    instance_id: &str,
    path: &FsPath,
) -> Result<PathBuf, ApiError> {
    let root = backup_root(state).join(instance_id);
    let root_metadata =
        tokio::fs::symlink_metadata(&root)
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => ApiError::NotFound,
                _ => ApiError::Runtime(format!("failed to inspect instance backup root: {error}")),
            })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(ApiError::Runtime(
            "instance backup root must be a real directory".to_string(),
        ));
    }
    let root = tokio::fs::canonicalize(&root).await.map_err(|error| {
        ApiError::Runtime(format!("failed to resolve instance backup root: {error}"))
    })?;
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

fn validate_backup_name(name: &str) -> Result<(), ApiError> {
    if !is_safe_flat_file_name(name) {
        Err(ApiError::BadRequest("invalid backup name".to_string()))
    } else {
        Ok(())
    }
}

async fn create_private_directory(path: &FsPath, label: &str) -> Result<(), ApiError> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to create {label}: {error}")))?;
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to inspect {label}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ApiError::Runtime(format!(
            "{label} must be a real directory"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|error| {
                ApiError::Runtime(format!("failed to secure {label} permissions: {error}"))
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_names_reject_path_traversal() {
        for name in ["../backup.tar.gz", "nested/backup.tar.gz", "", "."] {
            assert!(validate_backup_name(name).is_err(), "{name}");
        }
        assert!(validate_backup_name("backup.physical.tar.gz").is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_reader_rejects_a_symlinked_instance_root() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        let link = temp.path().join("instance-1");
        tokio::fs::create_dir(&real).await.unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let error = read_instance_backup_files(&link).await.unwrap_err();

        assert!(error.to_string().contains("real directory"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backup_reader_ignores_symlinked_files() {
        let temp = tempfile::tempdir().unwrap();
        let instance_root = temp.path().join("instance-1");
        tokio::fs::create_dir(&instance_root).await.unwrap();
        let outside = temp.path().join("outside.physical.tar.gz");
        tokio::fs::write(&outside, b"outside").await.unwrap();
        std::os::unix::fs::symlink(&outside, instance_root.join("link.physical.tar.gz")).unwrap();

        let backups = read_instance_backup_files(&instance_root).await.unwrap();

        assert!(backups.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn private_backup_directory_overrides_process_umask_defaults() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("backups");

        create_private_directory(&path, "test backups")
            .await
            .unwrap();

        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
