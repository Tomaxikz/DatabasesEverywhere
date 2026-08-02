//! Physical archive workflows for Redis, Qdrant, and backup restoration.

use super::{files::*, protocol::*, *};

pub(super) async fn export_physical_archive(
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

pub(super) async fn import_physical_archive(
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
    if result.is_ok() {
        result = reapply_instance_data_owner(state, &paths).await;
    }
    finish_physical_operation(state, instance_id, was_running, result).await
}

pub(crate) async fn reapply_instance_data_owner(
    state: &AppState,
    paths: &InstancePaths,
) -> Result<(), ApiError> {
    if let Some((uid, gid)) = state.docker.rootless_podman_host_owner() {
        paths
            .reapply_rootless_podman_data_owner(uid, gid)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))
    } else {
        paths
            .reapply_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))
    }
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

pub(super) async fn move_directory_entries(
    from: &FsPath,
    to: &FsPath,
) -> Result<(), std::io::Error> {
    move_directory_entries_except(from, to, &[]).await
}

pub(super) async fn move_directory_entries_except(
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

pub(super) async fn cleanup_dir_contents(path: &FsPath) {
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

pub(super) fn preserve_primary_error(
    primary_result: Result<(), ApiError>,
    recovery_result: Result<(), ApiError>,
) -> Result<(), ApiError> {
    match (primary_result, recovery_result) {
        (Err(primary_error), _) => Err(primary_error),
        (Ok(()), recovery_result) => recovery_result,
    }
}
