use super::*;

pub(super) async fn require_instance(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    state
        .instances
        .get(instance_id)
        .await
        .map(|_| ())
        .ok_or(ApiError::NotFound)
}

pub(super) async fn remove_artifact_files(path: &FsPath) -> Result<bool, std::io::Error> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {
            remove_checksum_sidecar(path).await;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub(super) async fn read_real_directory(
    root: &FsPath,
) -> Result<Option<tokio::fs::ReadDir>, ApiError> {
    match tokio::fs::symlink_metadata(root).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Err(
            ApiError::Runtime("artifact root must be a real directory".to_string()),
        ),
        Ok(_) => match tokio::fs::read_dir(root).await {
            Ok(entries) => Ok(Some(entries)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ApiError::Runtime(format!(
                "failed to read artifact root: {error}"
            ))),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to inspect artifact root: {error}"
        ))),
    }
}

pub(super) async fn read_instance_artifacts(
    state: &AppState,
    instance_id: &str,
) -> Result<Vec<ArtifactInfo>, ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let instance_root = instance_export_root(state, instance_id);
    let Some(mut entries) = read_real_directory(&instance_root).await? else {
        return Ok(Vec::new());
    };

    let mut artifacts = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to read artifact entry: {error}")))?
    {
        let metadata = tokio::fs::symlink_metadata(entry.path())
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to stat artifact: {error}")))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        let path = entry.path();
        if is_checksum_sidecar(&path) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ApiError::Runtime("invalid artifact name".to_string()))?
            .to_string();
        artifacts.push(ArtifactInfo {
            id: name,
            instance_id: instance_id.to_string(),
            size_bytes: metadata.len(),
            modified_at: system_time_rfc3339(metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH)),
            sha256: sha256_file(path).await?,
        });
    }
    artifacts.sort_by(|left, right| right.modified_at.cmp(&left.modified_at));
    Ok(artifacts)
}

pub(super) fn export_root(state: &AppState) -> PathBuf {
    PathBuf::from(state.config.paths.exports_root())
}

pub(crate) fn instance_export_root(state: &AppState, instance_id: &str) -> PathBuf {
    export_root(state).join(instance_id)
}

pub(super) fn validate_artifact_name(name: &str) -> Result<(), ApiError> {
    if !is_safe_flat_file_name(name) {
        return Err(ApiError::BadRequest("invalid artifact name".to_string()));
    }
    Ok(())
}

pub(crate) async fn verified_artifact_path(
    state: &AppState,
    name: &str,
    instance_id: &str,
) -> Result<PathBuf, ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    validate_artifact_name(name)?;
    let root = instance_export_root(state, instance_id);
    verified_path_in_root(&root, name).await
}

pub(super) async fn downloadable_artifact_path(
    state: &AppState,
    name: &str,
    instance_id: &str,
) -> Result<DownloadableArtifact, ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    validate_artifact_name(name)?;
    let retained = verified_path_in_root(&instance_export_root(state, instance_id), name).await;
    let one_use = verified_path_in_root(&instance_spool_root(state, instance_id), name).await;
    match (retained, one_use) {
        (Ok(_), Ok(_)) => Err(ApiError::Conflict(
            "artifact identifier exists in both retained and one-use storage".to_string(),
        )),
        (Ok(path), Err(ApiError::NotFound)) => Ok(DownloadableArtifact {
            path,
            one_use: false,
        }),
        (Err(ApiError::NotFound), Ok(path)) => Ok(DownloadableArtifact {
            path,
            one_use: true,
        }),
        (Err(ApiError::NotFound), Err(ApiError::NotFound)) => Err(ApiError::NotFound),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

pub(super) async fn verified_path_in_root(root: &FsPath, name: &str) -> Result<PathBuf, ApiError> {
    let root_metadata =
        tokio::fs::symlink_metadata(&root)
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => ApiError::NotFound,
                _ => ApiError::Runtime(format!("failed to inspect artifact root: {error}")),
            })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(ApiError::Runtime(
            "instance artifact root must be a real directory".to_string(),
        ));
    }
    let root = tokio::fs::canonicalize(&root)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to resolve artifact root: {error}")))?;
    let path = root.join(name);
    let metadata =
        tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => ApiError::NotFound,
                _ => ApiError::Runtime(format!("failed to inspect artifact: {error}")),
            })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ApiError::BadRequest(
            "artifact is not a regular file".to_string(),
        ));
    }
    let canonical = tokio::fs::canonicalize(&path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to resolve artifact: {error}")))?;
    if !canonical.starts_with(&root) {
        return Err(ApiError::BadRequest(
            "artifact resolves outside artifact root".to_string(),
        ));
    }
    Ok(canonical)
}
