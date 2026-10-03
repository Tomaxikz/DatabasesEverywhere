use super::*;

/// Move a pre-exclusion Qdrant instance from its FuseQuota bind source to the
/// raw backing directory. Every destructive runtime step has a remount/recreate
/// rollback; the backing data directory is never renamed or deleted.
pub(super) async fn migrate_qdrant_storage(
    config: &Config,
    docker: &DockerRuntime,
    disk_limiter: &DiskLimiter,
    metadata: &crate::instance::metadata::InstanceMetadata,
    paths: &InstancePaths,
) -> anyhow::Result<bool> {
    if metadata.desired_state == crate::instance::metadata::DesiredInstanceState::Running
        && let Err(error) = docker.check_autostart(&metadata.instance_id).await
    {
        tracing::warn!(instance_id = %metadata.instance_id, %error,
            "deferred automatic storage migration while startup is blocked");
        return Ok(false);
    }
    let legacy_mount = disk_limiter.legacy_fuse_container_path(&paths.data)?;
    let legacy_mount_present = disk_limiter.has_legacy_fuse_mount(&paths.data)?;
    let bound_source = match docker
        .container_bind_source(metadata.protocol, &metadata.instance_id, "/dbe-qdrant")
        .await
    {
        Ok(source) => source,
        Err(error) if error.is_not_found() => None,
        Err(error) => return Err(error.into()),
    };
    if !legacy_qdrant_uses_fuse(bound_source.as_deref(), &legacy_mount) {
        if legacy_mount_present {
            disk_limiter.unmount_legacy_fuse(&paths.data).await?;
            tracing::info!(
                event = "audit qdrant_stale_fuse_mount_removed",
                instance_id = %metadata.instance_id,
                bound_source = bound_source.as_ref().map(|path| path.display().to_string()),
                legacy_mount = %legacy_mount.display(),
                "removed a stale legacy Qdrant FuseQuota mount without recreating a container that did not use it"
            );
        }
        return Ok(true);
    }
    let migration_target_mode = disk_limiter.mode_for_protocol(metadata.protocol);
    if !qdrant_migration_is_safe(migration_target_mode) {
        tracing::error!(
            event = "audit qdrant_fuse_migration_deferred",
            instance_id = %metadata.instance_id,
            target_mode = migration_target_mode.method(),
            "legacy Qdrant FuseQuota storage cannot be adopted transactionally by a native project-quota backend; temporarily select disk.mode=soft_scanner to migrate it to raw storage, or use a backup/create/import migration"
        );
        return Ok(false);
    }
    let Some(api_key) = metadata.tenant_password.clone() else {
        tracing::error!(
            event = "audit qdrant_fuse_migration_deferred",
            instance_id = %metadata.instance_id,
            "legacy Qdrant FuseQuota mount was retained because encrypted tenant credential metadata is unavailable; reset the instance password, then restart dbev to retry safe migration"
        );
        return Ok(false);
    };
    let image = match docker
        .container_immutable_image_id(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(Some(image)) => image,
        Ok(None) => {
            tracing::error!(
                event = "audit qdrant_fuse_migration_deferred",
                instance_id = %metadata.instance_id,
                "legacy Qdrant FuseQuota mount was retained because its immutable container image ID is unavailable"
            );
            return Ok(false);
        }
        Err(error) if error.is_not_found() => {
            tracing::error!(
                event = "audit qdrant_fuse_migration_deferred",
                instance_id = %metadata.instance_id,
                "legacy Qdrant FuseQuota mount was retained because its managed container is missing"
            );
            return Ok(false);
        }
        Err(error) => return Err(error.into()),
    };
    let inspection = docker
        .inspect_instance(metadata.protocol, &metadata.instance_id)
        .await?;
    let (stop_existing, should_run) =
        qdrant_migration_actions(inspection.status, metadata.desired_state);
    let container_user = crate::subsystems::instances::create::prepare_instance_container_user(
        docker,
        paths,
        metadata.protocol,
    )
    .await?;
    let project_id = docker
        .container_project_id(metadata.protocol, &metadata.instance_id)
        .await?;
    let raw_spec = qdrant_migration_spec(
        config,
        metadata,
        paths,
        QdrantMigrationContainer {
            data_path: paths.data.clone(),
            image: &image,
            api_key: &api_key,
            container_user: &container_user,
            project_id: project_id.clone(),
        },
    );
    let legacy_spec = qdrant_migration_spec(
        config,
        metadata,
        paths,
        QdrantMigrationContainer {
            data_path: legacy_mount,
            image: &image,
            api_key: &api_key,
            container_user: &container_user,
            project_id,
        },
    );

    if stop_existing {
        docker
            .stop(metadata.protocol, &metadata.instance_id)
            .await?;
    }

    let migration = async {
        // Deletion is part of the rollback-covered transaction. An engine
        // response can be lost after it removed the container; either outcome
        // is safe because rollback tolerates not-found and recreates exactly
        // the immutable image/spec captured above.
        docker
            .delete(metadata.protocol, &metadata.instance_id)
            .await?;
        disk_limiter.unmount_legacy_fuse(&paths.data).await?;
        disk_limiter
            .for_protocol(metadata.protocol)
            .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
            .await?;
        docker.create(&raw_spec).await?;
        if should_run {
            start_migrated_qdrant(docker, metadata).await?;
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Err(migration_error) = migration {
        let rollback = async {
            match docker
                .delete(metadata.protocol, &metadata.instance_id)
                .await
            {
                Ok(_) => {}
                Err(error) if error.is_not_found() => {}
                Err(error) => return Err(anyhow::Error::from(error)),
            }
            disk_limiter.unmount_legacy_fuse(&paths.data).await?;
            disk_limiter
                .set_legacy_fuse_limit(&paths.data, metadata.limits.disk_mib)
                .await?;
            docker.create(&legacy_spec).await?;
            if should_run {
                start_migrated_qdrant(docker, metadata).await?;
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        match rollback {
            Ok(()) => {
                tracing::error!(
                    event = "audit qdrant_fuse_migration_rolled_back",
                    instance_id = %metadata.instance_id,
                    error = %migration_error,
                    "Qdrant migration to native storage failed; restored its previous FuseQuota container and retained truthful hard-enforcement metadata"
                );
                return Ok(false);
            }
            Err(rollback_error) => {
                anyhow::bail!(
                    "Qdrant FuseQuota migration failed ({migration_error}) and rollback failed ({rollback_error})"
                );
            }
        }
    }

    tracing::info!(
        event = "audit qdrant_fuse_migration_completed",
        instance_id = %metadata.instance_id,
        running = should_run,
        "migrated legacy Qdrant storage from FuseQuota to raw filesystem storage governed by the selected non-FUSE enforcement"
    );
    Ok(true)
}

pub(super) async fn start_migrated_qdrant(
    docker: &DockerRuntime,
    metadata: &crate::instance::metadata::InstanceMetadata,
) -> anyhow::Result<()> {
    docker
        .start(metadata.protocol, &metadata.instance_id)
        .await?;
    docker
        .wait_until_ready(
            metadata.protocol,
            &metadata.instance_id,
            QDRANT_MIGRATION_READY_TIMEOUT,
        )
        .await?;
    Ok(())
}

pub(in super::super) fn qdrant_migration_actions(
    observed: DockerContainerStatus,
    desired: crate::instance::metadata::DesiredInstanceState,
) -> (bool, bool) {
    let stop_existing = matches!(
        observed,
        DockerContainerStatus::Running | DockerContainerStatus::Starting
    );
    let start_replacement = desired == crate::instance::metadata::DesiredInstanceState::Running;
    (stop_existing, start_replacement)
}

pub(in super::super) fn qdrant_migration_is_safe(mode: crate::config::DiskLimitMode) -> bool {
    mode != crate::config::DiskLimitMode::ProjectQuota
}

pub(in super::super) fn legacy_qdrant_uses_fuse(
    bound_source: Option<&Path>,
    legacy_mount: &Path,
) -> bool {
    bound_source == Some(legacy_mount)
}

pub(in super::super) struct QdrantMigrationContainer<'a> {
    pub(in super::super) data_path: PathBuf,
    pub(in super::super) image: &'a str,
    pub(in super::super) api_key: &'a str,
    pub(in super::super) container_user: &'a str,
    pub(in super::super) project_id: Option<String>,
}

pub(in super::super) fn qdrant_migration_spec(
    config: &Config,
    metadata: &crate::instance::metadata::InstanceMetadata,
    paths: &InstancePaths,
    container: QdrantMigrationContainer<'_>,
) -> crate::runtime::docker::DockerInstanceSpec {
    let mut spec =
        Protocol::Qdrant
            .engine()
            .dedicated_spec(crate::databases::engine::DedicatedSpecInput {
                instance_id: &metadata.instance_id,
                image: container.image,
                database: &metadata.database.name,
                username: &metadata.database.username,
                password: secrecy::SecretString::from(container.api_key.to_string()),
                maintenance_password: secrecy::SecretString::from(String::new()),
                data_path: container.data_path,
                sockets: paths.sockets.clone(),
                hosted_config: None,
                socket_bridge_binary: paths.socket_bridge_binary.clone(),
            });
    spec.project_id = container.project_id;
    spec.user = Some(container.container_user.to_string());
    spec.cpu_cores = metadata.limits.cpu_cores;
    spec.memory_mib = metadata.limits.memory_mib;
    spec.disk_mib = metadata.limits.disk_mib;
    spec.pids_limit = Some(
        Protocol::Qdrant
            .engine()
            .pids_limit(&config.security.pids_limits)
            .unwrap_or(config.security.pids_limit),
    );
    spec
}
