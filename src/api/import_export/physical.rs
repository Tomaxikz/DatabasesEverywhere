//! Physical archive workflows for Redis, Valkey, Qdrant, and backup restoration.

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
    max_extracted_bytes: u64,
) -> Result<(), ApiError> {
    match protocol {
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => {}
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
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    verify_physical_data_replacement(state, &metadata, &paths)?;
    let was_running = metadata.status == InstanceStatus::Running;
    if was_running {
        let _ = lifecycle_instance_locked(state, instance_id, LifecycleAction::Stop).await?;
    }
    restore_data_from_archive_bounded(
        state,
        instance_id,
        paths,
        artifact_path,
        was_running,
        max_extracted_bytes,
    )
    .await
}

pub(crate) fn verify_physical_data_replacement(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
) -> Result<(), ApiError> {
    crate::disk::DiskLimiter::with_fuse_root(
        state.config.disk.clone(),
        state.config.paths.fuse_root(),
    )
    .for_persisted_method(&metadata.limits.disk_enforcement_method)
    .verify_physical_data_replacement(&paths.data)
    .map_err(|error| ApiError::Conflict(error.to_string()))
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

#[derive(Debug)]
struct DataReplacementPreparationError {
    error: ApiError,
    original_restored: bool,
}

impl DataReplacementPreparationError {
    fn safe(error: ApiError) -> Self {
        Self {
            error,
            original_restored: true,
        }
    }

    fn uncertain(error: ApiError) -> Self {
        Self {
            error,
            original_restored: false,
        }
    }
}

#[derive(Debug)]
#[must_use = "a pending physical data replacement must be committed or rolled back"]
struct PendingDataReplacement {
    data_dir: PathBuf,
    workspace: PathBuf,
    backup_dir: PathBuf,
}

impl PendingDataReplacement {
    async fn commit(self) {
        cleanup_dir(&self.workspace).await;
    }

    async fn rollback(self) -> Result<(), ApiError> {
        remove_directory_contents(&self.data_dir)
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to clear rejected restored data: {error}; previous data was retained at {}",
                    self.backup_dir.display()
                ))
            })?;
        move_directory_entries(&self.backup_dir, &self.data_dir)
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to roll previous data back into place: {error}; recovery data was retained at {}",
                    self.workspace.display()
                ))
            })?;
        cleanup_dir(&self.workspace).await;
        Ok(())
    }
}

pub(crate) async fn restore_data_from_archive(
    state: &AppState,
    instance_id: &str,
    paths: InstancePaths,
    artifact_path: &FsPath,
    should_be_running: bool,
) -> Result<(), ApiError> {
    restore_data_from_archive_bounded(
        state,
        instance_id,
        paths,
        artifact_path,
        should_be_running,
        crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES,
    )
    .await
}

pub(crate) async fn restore_data_from_archive_bounded(
    state: &AppState,
    instance_id: &str,
    paths: InstancePaths,
    artifact_path: &FsPath,
    should_be_running: bool,
    max_extracted_bytes: u64,
) -> Result<(), ApiError> {
    restore_data_from_archive_with_policy(
        state,
        instance_id,
        paths,
        artifact_path,
        should_be_running,
        true,
        max_extracted_bytes,
    )
    .await
}

pub(crate) async fn rollback_data_from_archive(
    state: &AppState,
    instance_id: &str,
    paths: InstancePaths,
    artifact_path: &FsPath,
) -> Result<(), ApiError> {
    restore_data_from_archive_with_policy(
        state,
        instance_id,
        paths,
        artifact_path,
        true,
        false,
        crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES,
    )
    .await
}

async fn restore_data_from_archive_with_policy(
    state: &AppState,
    instance_id: &str,
    paths: InstancePaths,
    artifact_path: &FsPath,
    should_be_running: bool,
    recover_current_after_preparation_failure: bool,
    max_extracted_bytes: u64,
) -> Result<(), ApiError> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    verify_physical_data_replacement(state, &metadata, &paths)?;
    let disk_limiter = persisted_physical_disk_limiter(state, &metadata);
    let detached_fuse = physical_replacement_requires_mount_detach(&disk_limiter);
    if detached_fuse
        && let Err(detach_error) = disk_limiter.teardown_instance_mount(&paths.data).await
    {
        let recovery = recover_detached_physical_runtime(
            state,
            &metadata,
            &paths,
            should_be_running,
            &disk_limiter,
        )
        .await;
        return Err(physical_recovery_error(
            ApiError::Runtime(format!(
                "failed to detach FuseQuota before physical data replacement: {detach_error}"
            )),
            recovery,
            "the original runtime",
        ));
    }
    let replacement =
        match prepare_data_replacement(paths.clone(), artifact_path, max_extracted_bytes).await {
            Ok(replacement) => replacement,
            Err(failure)
                if failure.original_restored && recover_current_after_preparation_failure =>
            {
                if detached_fuse {
                    let recovery = recover_detached_physical_runtime(
                        state,
                        &metadata,
                        &paths,
                        should_be_running,
                        &disk_limiter,
                    )
                    .await;
                    return Err(physical_recovery_error(
                        failure.error,
                        recovery,
                        "the original runtime",
                    ));
                }
                return finish_physical_operation(
                    state,
                    instance_id,
                    should_be_running,
                    Err(failure.error),
                )
                .await;
            }
            Err(failure) => return Err(failure.error),
        };

    let validation = async {
        reapply_instance_data_owner(state, &paths).await?;
        validate_replaced_instance(state, instance_id, &paths, should_be_running).await
    }
    .await;

    match validation {
        Ok(()) => {
            replacement.commit().await;
            Ok(())
        }
        Err(primary_error) => {
            rollback_rejected_replacement(
                state,
                instance_id,
                &paths,
                should_be_running,
                replacement,
                primary_error,
            )
            .await
        }
    }
}

fn persisted_physical_disk_limiter(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> crate::disk::DiskLimiter {
    crate::disk::DiskLimiter::with_fuse_root(
        state.config.disk.clone(),
        state.config.paths.fuse_root(),
    )
    .for_persisted_method(&metadata.limits.disk_enforcement_method)
}

fn physical_replacement_requires_mount_detach(limiter: &crate::disk::DiskLimiter) -> bool {
    limiter.mode() == crate::config::DiskLimitMode::FuseQuota
}

async fn recover_detached_physical_runtime(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    should_be_running: bool,
    limiter: &crate::disk::DiskLimiter,
) -> Result<(), ApiError> {
    if should_be_running {
        return lifecycle_instance_locked(state, &metadata.instance_id, LifecycleAction::Start)
            .await
            .map(|_| ());
    }

    limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map(|_| ())
        .map_err(|error| ApiError::Runtime(error.to_string()))
}

fn physical_recovery_error(
    primary: ApiError,
    recovery: Result<(), ApiError>,
    recovery_subject: &str,
) -> ApiError {
    match recovery {
        Ok(()) => primary,
        Err(recovery_error) => ApiError::Runtime(format!(
            "{primary}; failed to recover {recovery_subject}: {recovery_error}"
        )),
    }
}

async fn prepare_data_replacement(
    paths: InstancePaths,
    artifact_path: &FsPath,
    max_extracted_bytes: u64,
) -> Result<PendingDataReplacement, DataReplacementPreparationError> {
    let import_id = uuid::Uuid::new_v4();
    let expected_root = paths
        .data
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            DataReplacementPreparationError::safe(ApiError::Runtime(
                "invalid data path".to_string(),
            ))
        })?
        .to_string();
    tokio::fs::create_dir_all(&paths.data)
        .await
        .map_err(|error| {
            DataReplacementPreparationError::safe(ApiError::Runtime(format!(
                "failed to create data directory: {error}"
            )))
        })?;

    let data_parent = paths.data.parent().ok_or_else(|| {
        DataReplacementPreparationError::safe(ApiError::Runtime(
            "data directory has no parent".to_string(),
        ))
    })?;
    let workspace = data_parent.join(format!(".dbe-restore-{}-{import_id}", paths.instance_id));
    create_private_directory(&workspace, "physical restore workspace")
        .await
        .map_err(DataReplacementPreparationError::safe)?;
    let staging_dir = workspace.join("staging");
    let staged_data = staging_dir.join(&expected_root);
    let backup_dir = workspace.join("previous-data");
    if let Err(error) =
        create_private_directory(&staging_dir, "physical import staging directory").await
    {
        cleanup_dir(&workspace).await;
        return Err(DataReplacementPreparationError::safe(error));
    }
    if let Err(error) = extract_data_archive_bounded(
        artifact_path.to_path_buf(),
        staging_dir.clone(),
        expected_root,
        max_extracted_bytes,
    )
    .await
    {
        cleanup_dir(&workspace).await;
        return Err(DataReplacementPreparationError::safe(ApiError::BadRequest(
            error.to_string(),
        )));
    }

    if let Err(error) =
        create_private_directory(&backup_dir, "physical import rollback directory").await
    {
        cleanup_dir(&workspace).await;
        return Err(DataReplacementPreparationError::safe(error));
    }

    if let Err(error) = move_directory_entries(&paths.data, &backup_dir).await {
        if let Err(rollback_error) = move_directory_entries(&backup_dir, &paths.data).await {
            return Err(DataReplacementPreparationError::uncertain(
                ApiError::Runtime(format!(
                    "failed to move existing data contents aside: {error}; rollback also failed: {rollback_error}; recovery data was retained at {}",
                    workspace.display()
                )),
            ));
        }
        cleanup_dir(&workspace).await;
        return Err(DataReplacementPreparationError::safe(ApiError::Runtime(
            format!("failed to move existing data contents aside: {error}"),
        )));
    }

    if let Err(error) = move_directory_entries(&staged_data, &paths.data).await {
        if let Err(cleanup_error) = remove_directory_contents(&paths.data).await {
            return Err(DataReplacementPreparationError::uncertain(
                ApiError::Runtime(format!(
                    "failed to install imported data contents: {error}; failed to clear the partial replacement: {cleanup_error}; recovery data was retained at {}",
                    workspace.display()
                )),
            ));
        }
        if let Err(rollback_error) = move_directory_entries(&backup_dir, &paths.data).await {
            return Err(DataReplacementPreparationError::uncertain(
                ApiError::Runtime(format!(
                    "failed to install imported data contents: {error}; rollback also failed: {rollback_error}; recovery data was retained at {}",
                    workspace.display()
                )),
            ));
        }
        cleanup_dir(&workspace).await;
        return Err(DataReplacementPreparationError::safe(ApiError::Runtime(
            format!("failed to install imported data contents: {error}"),
        )));
    }

    Ok(PendingDataReplacement {
        data_dir: paths.data,
        workspace,
        backup_dir,
    })
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

async fn remove_directory_contents(path: &FsPath) -> Result<(), std::io::Error> {
    let mut entries = match tokio::fs::read_dir(path).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let file_type = entry.file_type().await?;
        if file_type.is_dir() && !file_type.is_symlink() {
            tokio::fs::remove_dir_all(path).await?;
        } else {
            tokio::fs::remove_file(path).await?;
        }
    }
    Ok(())
}

async fn validate_replaced_instance(
    state: &AppState,
    instance_id: &str,
    paths: &InstancePaths,
    should_be_running: bool,
) -> Result<(), ApiError> {
    if should_be_running {
        return lifecycle_instance_locked(state, instance_id, LifecycleAction::Start)
            .await
            .map(|_| ());
    }

    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    crate::disk::DiskLimiter::with_fuse_root(
        state.config.disk.clone(),
        state.config.paths.fuse_root(),
    )
    .for_persisted_protocol(metadata.protocol, &metadata.limits.disk_enforcement_method)
    .apply_instance_limit(instance_id, &paths.data, metadata.limits.disk_mib)
    .await
    .map_err(|error| ApiError::Runtime(error.to_string()))?;
    state
        .docker
        .start(metadata.protocol, instance_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let readiness = state
        .docker
        .wait_until_ready(metadata.protocol, instance_id, Duration::from_secs(120))
        .await
        .map(|_| ())
        .map_err(|error| ApiError::Runtime(error.to_string()));
    let stopped = lifecycle_instance_locked(state, instance_id, LifecycleAction::Stop)
        .await
        .map(|_| ());
    preserve_primary_error(readiness, stopped)
}

async fn rollback_rejected_replacement(
    state: &AppState,
    instance_id: &str,
    paths: &InstancePaths,
    should_be_running: bool,
    replacement: PendingDataReplacement,
    primary_error: ApiError,
) -> Result<(), ApiError> {
    if let Err(stop_error) =
        lifecycle_instance_locked(state, instance_id, LifecycleAction::Stop).await
    {
        return Err(ApiError::Runtime(format!(
            "physical restore failed: {primary_error}; rejected database could not be stopped safely: {stop_error}; previous data was retained at {}",
            replacement.backup_dir.display()
        )));
    }
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let disk_limiter = persisted_physical_disk_limiter(state, &metadata);
    let detached_fuse = physical_replacement_requires_mount_detach(&disk_limiter);
    if detached_fuse
        && let Err(detach_error) = disk_limiter.teardown_instance_mount(&paths.data).await
    {
        return Err(ApiError::Runtime(format!(
            "physical restore failed: {primary_error}; rejected database was stopped, but its FuseQuota mount could not be detached before rollback: {detach_error}; previous data was retained at {}",
            replacement.backup_dir.display()
        )));
    }
    if let Err(rollback_error) = replacement.rollback().await {
        return Err(ApiError::Runtime(format!(
            "physical restore failed: {primary_error}; rollback failed: {rollback_error}"
        )));
    }
    if let Err(owner_error) = reapply_instance_data_owner(state, paths).await {
        return Err(ApiError::Runtime(format!(
            "physical restore failed: {primary_error}; previous data was restored but its ownership could not be reapplied: {owner_error}"
        )));
    }

    let recovery = if detached_fuse {
        recover_detached_physical_runtime(state, &metadata, paths, should_be_running, &disk_limiter)
            .await
    } else if should_be_running {
        lifecycle_instance_locked(state, instance_id, LifecycleAction::Start)
            .await
            .map(|_| ())
    } else {
        lifecycle_instance_locked(state, instance_id, LifecycleAction::Stop)
            .await
            .map(|_| ())
    };
    if let Err(recovery_error) = recovery {
        return Err(ApiError::Runtime(format!(
            "physical restore failed: {primary_error}; previous data was restored, but the original runtime state could not be recovered: {recovery_error}"
        )));
    }

    tracing::warn!(
        event = "audit physical_restore_rolled_back",
        instance_id,
        error = %primary_error,
        "rejected physical restore was rolled back to the previous data"
    );
    Err(primary_error)
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

#[cfg(test)]
mod transaction_tests {
    use super::*;

    #[test]
    fn raw_physical_replacement_detaches_only_fuse_runtime() {
        for (mode, expected) in [
            (crate::config::DiskLimitMode::FuseQuota, true),
            (crate::config::DiskLimitMode::ProjectQuota, false),
            (crate::config::DiskLimitMode::SoftScanner, false),
        ] {
            let limiter = crate::disk::DiskLimiter::new(crate::config::DiskConfig {
                mode,
                ..crate::config::DiskConfig::default()
            });
            assert_eq!(
                physical_replacement_requires_mount_detach(&limiter),
                expected,
                "unexpected mount-detach policy for {mode:?}"
            );
        }
    }

    #[test]
    fn failed_mount_recovery_is_reported_with_the_primary_failure() {
        let error = physical_recovery_error(
            ApiError::Runtime("replacement failed".to_string()),
            Err(ApiError::Runtime("remount failed".to_string())),
            "the original runtime",
        );

        let message = error.to_string();
        assert!(message.contains("replacement failed"));
        assert!(message.contains("remount failed"));
    }

    #[tokio::test]
    async fn pending_replacement_rolls_previous_data_back_into_place() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let workspace = temp.path().join("restore-workspace");
        let backup_dir = workspace.join("previous-data");
        tokio::fs::create_dir_all(&data_dir).await.unwrap();
        tokio::fs::create_dir_all(&backup_dir).await.unwrap();
        tokio::fs::write(data_dir.join("new.rdb"), b"rejected")
            .await
            .unwrap();
        tokio::fs::write(backup_dir.join("old.rdb"), b"healthy")
            .await
            .unwrap();
        let replacement = PendingDataReplacement {
            data_dir: data_dir.clone(),
            workspace: workspace.clone(),
            backup_dir,
        };

        replacement.rollback().await.unwrap();

        assert_eq!(
            tokio::fs::read(data_dir.join("old.rdb")).await.unwrap(),
            b"healthy"
        );
        assert!(!data_dir.join("new.rdb").exists());
        assert!(!workspace.exists());
    }

    #[tokio::test]
    async fn pending_replacement_deletes_previous_data_only_on_commit() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let workspace = temp.path().join("restore-workspace");
        let backup_dir = workspace.join("previous-data");
        tokio::fs::create_dir_all(&data_dir).await.unwrap();
        tokio::fs::create_dir_all(&backup_dir).await.unwrap();
        tokio::fs::write(data_dir.join("new.rdb"), b"validated")
            .await
            .unwrap();
        tokio::fs::write(backup_dir.join("old.rdb"), b"healthy")
            .await
            .unwrap();
        let replacement = PendingDataReplacement {
            data_dir: data_dir.clone(),
            workspace: workspace.clone(),
            backup_dir,
        };

        assert!(workspace.join("previous-data/old.rdb").exists());
        replacement.commit().await;

        assert_eq!(
            tokio::fs::read(data_dir.join("new.rdb")).await.unwrap(),
            b"validated"
        );
        assert!(!workspace.exists());
    }
}
