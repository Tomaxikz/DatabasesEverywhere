use super::*;

const ONE_USE_EXPORT_TTL: std::time::Duration = std::time::Duration::from_secs(60 * 60);
const ONE_USE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
const MAX_SWEEP_ENTRIES: usize = 10_000;

pub(crate) fn one_use_export_root(state: &AppState) -> PathBuf {
    PathBuf::from(state.config.paths.tmp_root()).join("export-downloads")
}

pub(crate) fn instance_one_use_export_root(state: &AppState, instance_id: &str) -> PathBuf {
    one_use_export_root(state).join(instance_id)
}

pub(crate) async fn ensure_client_export_slot(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let active = active_one_use_export_paths(state).await;
    sweep_instance_one_use_exports(state, instance_id, &active).await?;
    let retained = count_regular_exports(&instance_export_root(state, instance_id)).await?;
    let pending = count_regular_exports(&instance_one_use_export_root(state, instance_id)).await?;
    let total = retained
        .checked_add(pending)
        .ok_or_else(|| ApiError::Conflict("artifact count overflowed".to_string()))?;
    let maximum = state.config.artifacts.max_artifacts_per_instance;
    if total >= maximum {
        return Err(ApiError::Conflict(format!(
            "instance already has the configured maximum of {maximum} artifacts or pending one-use exports; download or delete an existing export before creating another"
        )));
    }
    Ok(())
}

pub(crate) async fn reconcile_one_use_exports_once(state: &AppState) -> Result<usize, ApiError> {
    let root = one_use_export_root(state);
    let active = active_one_use_export_paths(state).await;
    let Some(mut entries) = read_real_directory(&root).await? else {
        return Ok(0);
    };
    let mut examined = 0_usize;
    let mut removed = 0_usize;
    while let Some(entry) = entries.next_entry().await.map_err(|error| {
        ApiError::Runtime(format!("failed to read one-use export root: {error}"))
    })? {
        examined = examined.saturating_add(1);
        if examined > MAX_SWEEP_ENTRIES {
            return Err(ApiError::Runtime(
                "one-use export sweep entry limit exceeded".to_string(),
            ));
        }
        let name = match entry.file_name().to_str() {
            Some(name) if validate_instance_id(name).is_ok() => name.to_string(),
            _ => continue,
        };
        let metadata = tokio::fs::symlink_metadata(entry.path())
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to inspect one-use export directory: {error}"
                ))
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        removed =
            removed.saturating_add(sweep_instance_one_use_exports(state, &name, &active).await?);
    }
    Ok(removed)
}

pub(crate) async fn run_one_use_export_sweeper(state: AppState) {
    let mut shutdown = state.daemon_shutdown.subscribe();
    if *shutdown.borrow() {
        return;
    }
    let mut interval = tokio::time::interval(ONE_USE_SWEEP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {
                match reconcile_one_use_exports_once(&state).await {
                    Ok(removed) if removed > 0 => tracing::info!(removed, "expired one-use exports removed"),
                    Ok(_) => {}
                    Err(error) => tracing::error!(%error, "one-use export sweep failed"),
                }
            }
        }
    }
}

async fn sweep_instance_one_use_exports(
    state: &AppState,
    instance_id: &str,
    active: &std::collections::HashSet<PathBuf>,
) -> Result<usize, ApiError> {
    let root = instance_one_use_export_root(state, instance_id);
    let Some(mut entries) = read_real_directory(&root).await? else {
        return Ok(0);
    };
    let cutoff = SystemTime::now()
        .checked_sub(ONE_USE_EXPORT_TTL)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut examined = 0_usize;
    let mut removed = 0_usize;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to read one-use exports: {error}")))?
    {
        examined = examined.saturating_add(1);
        if examined > MAX_SWEEP_ENTRIES {
            return Err(ApiError::Runtime(
                "one-use instance export sweep entry limit exceeded".to_string(),
            ));
        }
        let path = entry.path();
        let metadata = tokio::fs::symlink_metadata(&path).await.map_err(|error| {
            ApiError::Runtime(format!("failed to inspect one-use export: {error}"))
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || is_checksum_sidecar(&path)
            || active.contains(&path)
            || metadata.modified().unwrap_or(SystemTime::now()) > cutoff
        {
            continue;
        }
        remove_download_spool(path).await?;
        removed = removed.saturating_add(1);
    }
    Ok(removed)
}

async fn active_one_use_export_paths(state: &AppState) -> std::collections::HashSet<PathBuf> {
    let paths = state
        .import_export_jobs
        .active_export_artifact_paths()
        .await;
    let root = one_use_export_root(state);
    paths
        .into_iter()
        .map(PathBuf::from)
        .filter(|path| path.starts_with(&root))
        .collect()
}

async fn count_regular_exports(root: &FsPath) -> Result<usize, ApiError> {
    let Some(mut entries) = read_real_directory(root).await? else {
        return Ok(0);
    };
    let mut count = 0_usize;
    let mut examined = 0_usize;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to count artifacts: {error}")))?
    {
        examined = examined.saturating_add(1);
        if examined > MAX_SWEEP_ENTRIES {
            return Err(ApiError::Runtime(
                "artifact count entry limit exceeded".to_string(),
            ));
        }
        let path = entry.path();
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to inspect artifact: {error}")))?;
        if metadata.is_file() && !metadata.file_type().is_symlink() && !is_checksum_sidecar(&path) {
            count = count
                .checked_add(1)
                .ok_or_else(|| ApiError::Conflict("artifact count overflowed".to_string()))?;
        }
    }
    Ok(count)
}

async fn read_real_directory(root: &FsPath) -> Result<Option<tokio::fs::ReadDir>, ApiError> {
    match tokio::fs::symlink_metadata(root).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Err(
            ApiError::Runtime("artifact root must be a real directory".to_string()),
        ),
        Ok(_) => tokio::fs::read_dir(root)
            .await
            .map(Some)
            .map_err(|error| ApiError::Runtime(format!("failed to read artifact root: {error}"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to inspect artifact root: {error}"
        ))),
    }
}

async fn remove_download_spool(path: PathBuf) -> Result<(), ApiError> {
    tokio::task::spawn_blocking(move || remove_download_spool_blocking(&path))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to join export cleanup: {error}")))?
        .map_err(|error| ApiError::Runtime(format!("failed to remove one-use export: {error}")))
}

pub(super) fn remove_download_spool_blocking(path: &FsPath) -> Result<(), std::io::Error> {
    match crate::shared::files::remove_private_file_durable(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if let Some(sidecar) = checksum_sidecar_path(path) {
        match crate::shared::files::remove_private_file_durable(&sidecar) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
