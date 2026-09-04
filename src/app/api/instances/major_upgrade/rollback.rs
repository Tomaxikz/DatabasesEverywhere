use super::staging::{StagedMajorUpgrade, recreate_empty_instance};
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::api::instances) enum MajorUpgradeRollbackLocation {
    OriginalDataInPlace,
    OldVolumeBackup,
}

pub(in crate::api::instances) async fn classify_upgrade_rollback(
    data_path: &std::path::Path,
    old_volume_backup: &std::path::Path,
) -> Result<MajorUpgradeRollbackLocation, ApiError> {
    let data_exists = path_exists(data_path).await?;
    let backup_exists = path_exists(old_volume_backup).await?;
    match (data_exists, backup_exists) {
        (true, false) => Ok(MajorUpgradeRollbackLocation::OriginalDataInPlace),
        (false, true) => Ok(MajorUpgradeRollbackLocation::OldVolumeBackup),
        (true, true) => Err(ApiError::Runtime(format!(
            "both the original data path {} and rollback backup {} exist",
            data_path.display(),
            old_volume_backup.display()
        ))),
        (false, false) => Err(ApiError::Runtime(format!(
            "neither the original data path {} nor rollback backup {} exists",
            data_path.display(),
            old_volume_backup.display()
        ))),
    }
}

async fn path_exists(path: &std::path::Path) -> Result<bool, ApiError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to inspect {}: {error}",
            path.display()
        ))),
    }
}

pub(super) async fn rollback_failed_upgrade(
    state: &AppState,
    previous_metadata: &InstanceMetadata,
    rollback: MajorUpgradeRollback,
    old_volume_backup: &std::path::Path,
    location: MajorUpgradeRollbackLocation,
    staged: &StagedMajorUpgrade,
    original_error: ApiError,
) -> ApiError {
    cleanup_failed_staging(state, staged).await;
    let original_message = original_error.to_string();
    let rollback_error = rollback_major_upgrade(rollback, state, old_volume_backup, location)
        .await
        .err()
        .map(|error| error.to_string());
    let message = if let Some(rollback_error) = rollback_error {
        let quarantine = quarantine_image_update(
            state,
            previous_metadata,
            "major-upgrade cutover rollback failed",
        )
        .await;
        format!(
            "major upgrade failed ({original_message}); rollback also failed ({rollback_error}); {}",
            image_quarantine_summary(&quarantine)
        )
    } else {
        format!("major upgrade failed and the old container was restored: {original_message}")
    };
    fail_image_update_runtime(state, &previous_metadata.instance_id, message)
}

pub(super) async fn cleanup_failed_staging(state: &AppState, staged: &StagedMajorUpgrade) {
    cleanup_temp_replacement(
        state,
        staged.metadata.protocol,
        &staged.metadata.limits.disk_enforcement_method,
        &staged.metadata.instance_id,
        &staged.paths,
    )
    .await;
}

pub(super) async fn rollback_major_upgrade(
    rollback: MajorUpgradeRollback,
    state: &AppState,
    old_volume_backup: &std::path::Path,
    location: MajorUpgradeRollbackLocation,
) -> Result<(), ApiError> {
    let instance_id = rollback.metadata.instance_id.clone();
    tokio::time::timeout(
        IMAGE_UPDATE_ROLLBACK_TIMEOUT,
        rollback.restore(state, old_volume_backup, location),
    )
    .await
    .map_err(|_| {
        ApiError::Runtime(format!(
            "major-upgrade rollback exceeded its {} second deadline",
            IMAGE_UPDATE_ROLLBACK_TIMEOUT.as_secs()
        ))
    })??;
    state
        .manager
        .delete_compatibility(&instance_id)
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "major-upgrade rollback restored the old container but could not invalidate the replacement compatibility attestation: {error}"
            ))
        })?;
    Ok(())
}

pub(super) struct MajorUpgradeRollback {
    pub(super) metadata: InstanceMetadata,
    pub(super) old_image: String,
    pub(super) password: String,
    pub(super) paths: InstancePaths,
}

impl MajorUpgradeRollback {
    async fn restore(
        self,
        state: &AppState,
        old_volume_backup: &std::path::Path,
        location: MajorUpgradeRollbackLocation,
    ) -> Result<(), ApiError> {
        tracing::warn!(
            event = "audit instance_major_upgrade_rollback_started",
            instance_id = %self.metadata.instance_id,
            protocol = %self.metadata.protocol,
        );
        remove_container(state, self.metadata.protocol, &self.metadata.instance_id).await?;
        if location == MajorUpgradeRollbackLocation::OldVolumeBackup {
            let disk_limiter = DiskLimiter::with_fuse_root(
                state.config.disk.clone(),
                state.config.paths.fuse_root(),
            )
            .for_persisted_protocol(
                self.metadata.protocol,
                &self.metadata.limits.disk_enforcement_method,
            );
            disk_limiter
                .purge_instance_data(&self.paths.data)
                .await
                .map_err(|error| {
                    ApiError::Runtime(format!(
                        "failed to tear down replacement data before rollback: {error}"
                    ))
                })?;
            remove_path_if_exists(&self.paths.data).await?;
            rename_path(old_volume_backup, &self.paths.data)
                .await
                .map_err(|error| {
                    ApiError::Runtime(format!("failed to restore old volume: {error}"))
                })?;
        } else if classify_upgrade_rollback(&self.paths.data, old_volume_backup).await?
            != MajorUpgradeRollbackLocation::OriginalDataInPlace
        {
            return Err(ApiError::Runtime(
                "old volume moved while an in-place rollback was starting".to_string(),
            ));
        }
        recreate_empty_instance(
            state,
            &self.metadata,
            &self.paths,
            &self.old_image,
            &self.password,
        )
        .await?;
        state
            .manager
            .upsert(self.metadata.clone())
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        tracing::warn!(
            event = "audit instance_major_upgrade_rollback_completed",
            instance_id = %self.metadata.instance_id,
            protocol = %self.metadata.protocol,
        );
        Ok(())
    }
}

pub(super) fn upgrade_temp_instance_id(instance_id: &str) -> String {
    format!(
        "dbe_upgrade_tmp_{}_{}",
        uuid::Uuid::new_v4().simple(),
        instance_id
    )
}

pub(super) async fn cleanup_temp_replacement(
    state: &AppState,
    protocol: Protocol,
    disk_enforcement_method: &str,
    instance_id: &str,
    paths: &InstancePaths,
) {
    if let Err(error) = remove_container(state, protocol, instance_id).await {
        tracing::error!(
            instance_id,
            %protocol,
            %error,
            "temporary major-upgrade container could not be removed; retaining its data rather than mutating a potentially live backing path"
        );
        return;
    }
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_persisted_protocol(protocol, disk_enforcement_method);
    if let Err(error) = disk_limiter.purge_instance_data(&paths.data).await {
        tracing::error!(
            instance_id,
            %protocol,
            %error,
            "temporary major-upgrade disk teardown failed; retaining its paths for operator recovery"
        );
        return;
    }
    let _ = remove_path_if_exists(&paths.data).await;
    cleanup_temp_paths(paths).await;
}

pub(super) async fn cleanup_temp_paths(paths: &InstancePaths) {
    for path in [
        &paths.logs,
        &paths.sockets,
        &paths.artifacts,
        &paths.exports,
        &paths.imports,
        &paths.backups,
        &paths.runtime_config,
    ] {
        let _ = remove_path_if_exists(path).await;
    }
}

pub(super) async fn remove_container(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), ApiError> {
    match state.docker.stop(protocol, instance_id).await {
        Ok(_) => {}
        Err(error) if error.is_not_found() || error.is_not_running() => {}
        Err(error) => return Err(docker_error(error)),
    }
    match state.docker.delete(protocol, instance_id).await {
        Ok(_) => Ok(()),
        Err(error) if error.is_not_found() => Ok(()),
        Err(error) => Err(docker_error(error)),
    }
}

pub(super) async fn rename_path(
    from: &std::path::Path,
    to: &std::path::Path,
) -> Result<(), std::io::Error> {
    if let Some(parent) = to.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::rename(from, to).await
}

pub(crate) async fn remove_path_if_exists(path: &std::path::Path) -> Result<(), ApiError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_dir() => tokio::fs::remove_dir_all(path).await,
        Ok(_) => tokio::fs::remove_file(path).await,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => Err(error),
    }
    .map_err(|error| ApiError::Runtime(format!("failed to remove {}: {error}", path.display())))
}

pub(super) fn old_volume_backup_path(data_path: &std::path::Path) -> Result<PathBuf, ApiError> {
    let parent = data_path
        .parent()
        .ok_or_else(|| ApiError::Runtime("instance data path has no parent".to_string()))?;
    let name = data_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ApiError::Runtime("instance data path has no valid name".to_string()))?;
    Ok(parent.join(format!(
        ".dbe-major-upgrade-old-{name}-{}",
        uuid::Uuid::new_v4()
    )))
}
