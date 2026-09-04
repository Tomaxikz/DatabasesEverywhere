use super::*;

mod rollback;
mod source_quiesce;
mod staging;
mod supervisor;
mod version;

pub(crate) use rollback::remove_path_if_exists;
use rollback::{
    MajorUpgradeRollback, cleanup_failed_staging, old_volume_backup_path, remove_container,
    rename_path, rollback_failed_upgrade, rollback_major_upgrade,
};
pub(super) use rollback::{MajorUpgradeRollbackLocation, classify_upgrade_rollback};
#[cfg(test)]
pub(super) use staging::replacement_check_command;
pub(super) use staging::{MajorUpgradeCommitResolution, classify_upgrade_commit};
use staging::{commit_staged_replacement, resolve_upgrade_commit, stage_replacement};
pub(super) use supervisor::run_upgrade_supervisor;
#[cfg(test)]
pub(super) use supervisor::spawn_upgrade_task;
use version::precheck_major_upgrade;
pub(super) use version::upgrade_required_error;
pub(crate) use version::{ImageVersionChange, check_major_upgrade, classify_image_update};
#[cfg(test)]
pub(super) use version::{image_major_version, parse_major_version, validate_upgrade_path};

use source_quiesce::{harden_upgrade_target, quiesce_upgrade_source, restore_upgrade_route};

async fn run_major_upgrade(
    state: &AppState,
    mut metadata: InstanceMetadata,
    current_image: String,
    image: String,
    password: Option<String>,
) -> Result<UpdateInstanceImageResponse, ApiError> {
    check_major_upgrade(metadata.protocol)
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    let password = metadata.tenant_password.clone().or(password).ok_or_else(|| {
        fail_image_update_api(
            state,
            &metadata.instance_id,
            ApiError::BadRequest(
                "password is required for major upgrade migration of legacy instances without a stored encrypted tenant credential".to_string(),
            ),
        )
    })?;
    let previous_metadata = metadata.clone();
    let rollback_image = state
        .docker
        .container_immutable_image_id(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?
        .ok_or_else(|| {
            fail_image_update_api(
                state,
                &metadata.instance_id,
                ApiError::Conflict(
                    "the source container image ID could not be captured; refusing a destructive major upgrade without an exact rollback image"
                        .to_string(),
                ),
            )
        })?;
    state
        .install_progress
        .begin_major_upgrade(&metadata.instance_id, metadata.protocol, &image);
    let precheck = precheck_major_upgrade(state, &metadata, &current_image, &image)
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    if let Err(error) = quiesce_upgrade_source(state, &metadata, &password).await {
        let quarantine = quarantine_image_update(
            state,
            &previous_metadata,
            "major-upgrade source could not be quiesced safely before export",
        )
        .await;
        return Err(fail_image_update_runtime(
            state,
            &metadata.instance_id,
            format!(
                "failed to establish a write-free major-upgrade source ({error}); {}",
                image_quarantine_summary(&quarantine)
            ),
        ));
    }
    state.install_progress.stage(
        &metadata.instance_id,
        "export",
        "exporting quiesced old database before major upgrade",
    );
    let export_artifact = match crate::api::import_export::export_default_artifact(
        state,
        &metadata.instance_id,
    )
    .await
    {
        Ok(artifact) => artifact,
        Err(error) => {
            return Err(restore_upgrade_route(state, &previous_metadata, &password, error).await);
        }
    };
    metadata.runtime.network_mode = "none".to_string();

    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| fail_image_update_bad_request(state, &metadata.instance_id, error))?;
    let rollback = MajorUpgradeRollback {
        metadata: metadata.clone(),
        old_image: rollback_image,
        password: password.clone(),
        paths: paths.clone(),
    };

    let staged = match stage_replacement(state, &metadata, &image, &password, &export_artifact)
        .await
    {
        Ok(staged) => staged,
        Err(error) => {
            return Err(restore_upgrade_route(state, &previous_metadata, &password, error).await);
        }
    };

    state.install_progress.stage(
        &metadata.instance_id,
        "cutover",
        "validated replacement; stopping old container for final cutover",
    );
    tracing::info!(
        event = "audit instance_route_fenced",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        operation = "major_image_upgrade",
        "gateway route removed for the destructive cutover and will return only after compatibility and durable commit"
    );
    let old_volume_backup = old_volume_backup_path(&paths.data)
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    if let Err(error) = remove_container(state, metadata.protocol, &metadata.instance_id).await {
        return Err(rollback_failed_upgrade(
            state,
            &previous_metadata,
            rollback,
            &old_volume_backup,
            MajorUpgradeRollbackLocation::OriginalDataInPlace,
            &staged,
            error,
        )
        .await);
    }
    if let Err(error) = rename_path(&paths.data, &old_volume_backup).await {
        let location = match classify_upgrade_rollback(&paths.data, &old_volume_backup).await {
            Ok(location) => location,
            Err(location_error) => {
                cleanup_failed_staging(state, &staged).await;
                let quarantine = quarantine_image_update(
                    state,
                    &previous_metadata,
                    "major-upgrade volume rename outcome is uncertain",
                )
                .await;
                return Err(fail_image_update_runtime(
                    state,
                    &metadata.instance_id,
                    format!(
                        "failed to move the old volume into rollback staging ({error}) and its location could not be proven ({location_error}); {}",
                        image_quarantine_summary(&quarantine)
                    ),
                ));
            }
        };
        return Err(rollback_failed_upgrade(
            state,
            &previous_metadata,
            rollback,
            &old_volume_backup,
            location,
            &staged,
            ApiError::Runtime(format!(
                "failed to move the old volume into rollback staging: {error}"
            )),
        )
        .await);
    }
    let cutover_result: Result<(), ApiError> = async {
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_persisted_protocol(metadata.protocol, &metadata.limits.disk_enforcement_method)
            .purge_instance_data(&paths.data)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        commit_staged_replacement(state, &metadata, &paths, &staged, &image, &password).await?;
        metadata.backend = backend_endpoint(state, metadata.protocol, &metadata.instance_id)?;
        metadata.runtime.network_mode = "none".to_string();
        harden_upgrade_target(state, &metadata, &password).await?;
        if metadata.protocol == Protocol::Mariadb {
            metadata.mariadb_native_password_sha1_stage2 = Some(
                crate::protocols::mariadb::native_password_sha1_stage2_hex(&password),
            );
        }
        if metadata.protocol == Protocol::Mysql {
            metadata.mysql_native_password_sha1_stage2 = Some(
                crate::protocols::mariadb::native_password_sha1_stage2_hex(&password),
            );
        }
        metadata.tenant_password = Some(password.clone());
        state.install_progress.stage(
            &metadata.instance_id,
            "compatibility",
            "attesting migrated database engine",
        );
        let compatibility = crate::compatibility::probe_instance_compatibility(
            &state.manager,
            &state.docker,
            &metadata,
            true,
        )
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "migrated database compatibility probe failed: {error}"
            ))
        })?;
        if !compatibility.compatible {
            return Err(ApiError::Conflict(compatibility.diagnostic.unwrap_or_else(
                || "migrated database version is unsupported".to_string(),
            )));
        }
        metadata.status = InstanceStatus::Running;
        metadata.updated_at = now_rfc3339();
        Ok(())
    }
    .await;
    if let Err(error) = cutover_result {
        return Err(rollback_failed_upgrade(
            state,
            &previous_metadata,
            rollback,
            &old_volume_backup,
            MajorUpgradeRollbackLocation::OldVolumeBackup,
            &staged,
            error,
        )
        .await);
    }
    if let Err(error) = state.manager.upsert(metadata.clone()).await {
        let commit_error = error.to_string();
        match resolve_upgrade_commit(state, &previous_metadata, &metadata).await {
            MajorUpgradeCommitResolution::Committed => {
                // `InstanceManager` updates the route store only after the
                // repository returns `Ok`. Rebuild that in-memory side of the
                // commit after verifying SQLite contains the intended row.
                state.instances.upsert(metadata.clone()).await;
                tracing::warn!(
                    event = "audit instance_major_upgrade_commit_ack_lost",
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    error = %commit_error,
                    "major-upgrade metadata was durably committed despite a failed commit acknowledgement"
                );
            }
            MajorUpgradeCommitResolution::NotCommitted => {
                let rollback_error = rollback_major_upgrade(
                    rollback,
                    state,
                    &old_volume_backup,
                    MajorUpgradeRollbackLocation::OldVolumeBackup,
                )
                .await
                .err()
                .map(|rollback_error| rollback_error.to_string());
                let message = if let Some(rollback_error) = rollback_error {
                    let quarantine = quarantine_image_update(
                        state,
                        &previous_metadata,
                        "major-upgrade metadata was not committed and rollback failed",
                    )
                    .await;
                    format!(
                        "failed to persist major-upgrade metadata ({commit_error}); rollback also failed ({rollback_error}); {}",
                        image_quarantine_summary(&quarantine)
                    )
                } else {
                    format!(
                        "failed to persist major-upgrade metadata ({commit_error}); durable metadata was unchanged and the old container was restored"
                    )
                };
                return Err(fail_image_update_runtime(
                    state,
                    &metadata.instance_id,
                    message,
                ));
            }
            MajorUpgradeCommitResolution::Uncertain(reason) => {
                let quarantine = quarantine_image_update(
                    state,
                    &previous_metadata,
                    "major-upgrade metadata commit could not be classified",
                )
                .await;
                return Err(fail_image_update_runtime(
                    state,
                    &metadata.instance_id,
                    format!(
                        "major-upgrade runtime cutover completed, but metadata persistence returned {commit_error} and durable commit state is uncertain ({reason}); {}; the old volume backup was retained",
                        image_quarantine_summary(&quarantine)
                    ),
                ));
            }
        }
    }
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.install_progress.complete(
        &metadata.instance_id,
        "major upgrade migration completed; old volume retained for rollback",
    );

    tracing::info!(
        event = "audit instance_major_upgrade_completed",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        from_image = %current_image,
        to_image = %image,
        export_artifact = %export_artifact.display(),
        old_volume_backup = %old_volume_backup.display(),
    );

    Ok(UpdateInstanceImageResponse {
        instance: metadata,
        image,
        recreated: true,
        strategy: ImageUpdateStrategy::MajorUpgradeMigration,
        warnings: {
            let mut warnings = precheck.warnings;
            warnings.extend([
                "major upgrade used export/import migration instead of reusing the old data volume"
                    .to_string(),
                "old volume backup was kept on disk for manual rollback until the admin removes it"
                    .to_string(),
            ]);
            warnings
        },
        export_artifact_id: export_artifact
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string),
        old_volume_backup_retained: true,
    })
}
