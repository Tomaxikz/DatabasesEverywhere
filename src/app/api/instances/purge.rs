use super::{ApiError, AppState, DiskLimiter, InstancePaths, remove_path_if_exists};

pub(crate) async fn purge_instance_paths(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    let method = state
        .instances
        .get(instance_id)
        .await
        .map(|metadata| metadata.limits.disk_enforcement_method);
    purge_paths(state, instance_id, DataCleanup::Quota(method.as_deref())).await
}

pub(crate) async fn purge_shared_tenant_paths(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    purge_paths(state, instance_id, DataCleanup::Plain).await
}

pub(crate) async fn purge_runtime_paths(
    state: &AppState,
    runtime: &crate::placement::EngineRuntime,
) -> Result<(), ApiError> {
    purge_paths(
        state,
        &runtime.runtime_id,
        DataCleanup::Quota(Some(&runtime.limits.disk_enforcement_method)),
    )
    .await
}

/// Removes only a retired physical engine's private runtime state. Logical
/// instance-owned artifacts and backups deliberately survive deployment-mode
/// cutover because their ownership does not move with the container.
pub(crate) async fn purge_retired_runtime_paths(
    state: &AppState,
    runtime: &crate::placement::EngineRuntime,
) -> Result<(), ApiError> {
    purge_physical_paths(
        state,
        &runtime.runtime_id,
        &runtime.limits.disk_enforcement_method,
    )
    .await
}

pub(crate) async fn purge_provisional_runtime_paths(
    state: &AppState,
    runtime_id: &str,
    protocol: crate::shared::protocol::Protocol,
    disk_enforcement_method: Option<&str>,
) -> Result<(), ApiError> {
    let paths = InstancePaths::new(&state.config.paths, runtime_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    let limiter =
        provisional_cleanup_limiter(limiter, protocol, &paths.data, disk_enforcement_method)
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    purge_with_limiter(paths, limiter).await
}

async fn purge_physical_paths(
    state: &AppState,
    runtime_id: &str,
    disk_enforcement_method: &str,
) -> Result<(), ApiError> {
    let paths = InstancePaths::new(&state.config.paths, runtime_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    let limiter = limiter.for_persisted_method(disk_enforcement_method);
    purge_with_limiter(paths, limiter).await
}

fn provisional_cleanup_limiter(
    limiter: DiskLimiter,
    protocol: crate::shared::protocol::Protocol,
    data_path: &std::path::Path,
    disk_enforcement_method: Option<&str>,
) -> Result<DiskLimiter, crate::disk::DiskLimitError> {
    if let Some(method) = disk_enforcement_method {
        return Ok(limiter.for_persisted_method(method));
    }
    // Disk setup precedes the provisional runtime-row commit. If the daemon
    // stops in that gap, the exact target mount is the only durable evidence
    // of FuseQuota; the shared source's enforcement method is unrelated.
    let has_fuse_mount = limiter.has_legacy_fuse_mount(data_path)?;
    Ok(select_cleanup_limiter(limiter, protocol, has_fuse_mount))
}

fn select_cleanup_limiter(
    limiter: DiskLimiter,
    protocol: crate::shared::protocol::Protocol,
    has_fuse_mount: bool,
) -> DiskLimiter {
    if has_fuse_mount {
        limiter.legacy_fuse_limiter()
    } else {
        limiter.for_protocol(protocol)
    }
}

async fn purge_with_limiter(paths: InstancePaths, limiter: DiskLimiter) -> Result<(), ApiError> {
    limiter
        .release_instance_storage(&paths.instance_id, &paths.data)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    for path in [paths.data, paths.logs, paths.sockets, paths.runtime_config] {
        remove_path_if_exists(&path).await?;
    }
    Ok(())
}

enum DataCleanup<'a> {
    Plain,
    Quota(Option<&'a str>),
}

async fn purge_paths(
    state: &AppState,
    instance_id: &str,
    cleanup: DataCleanup<'_>,
) -> Result<(), ApiError> {
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let disk_limiter = match cleanup {
        DataCleanup::Plain => None,
        DataCleanup::Quota(method) => {
            let limiter = DiskLimiter::with_fuse_root(
                state.config.disk.clone(),
                state.config.paths.fuse_root(),
            );
            Some(match method {
                Some(method) => limiter.for_persisted_method(method),
                None => limiter,
            })
        }
    };
    if let Some(disk_limiter) = &disk_limiter {
        disk_limiter
            .release_instance_storage(instance_id, &paths.data)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    }
    let deleted_backups = crate::api::backups::purge_instance_backups(state, instance_id).await?;
    if deleted_backups > 0 {
        tracing::info!(
            event = "audit instance_backups_purged",
            instance_id,
            deleted_backups
        );
    }
    let mut purge_paths = vec![
        paths.data,
        paths.logs,
        paths.sockets,
        paths.artifacts,
        paths.exports,
        paths.imports,
        paths.backups,
        paths.runtime_config,
        crate::api::artifacts::instance_spool_root(state, instance_id),
    ];
    let retained_volumes = retained_instance_volume_paths(&purge_paths[0])
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to discover retained instance volumes: {error}"
            ))
        })?;
    // Retained major-upgrade/restore volumes can themselves be Btrfs
    // subvolumes or ZFS datasets. Remove their native quota object before the
    // generic filesystem cleanup; `remove_dir_all` cannot delete those roots.
    for retained_volume in &retained_volumes {
        if let Some(disk_limiter) = &disk_limiter {
            disk_limiter
                .purge_instance_data(retained_volume)
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))?;
        }
    }
    purge_paths.extend(retained_volumes);
    for path in purge_paths {
        remove_path_if_exists(&path).await?;
    }
    Ok(())
}

pub(crate) async fn retained_instance_volume_paths(
    data_path: &std::path::Path,
) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    let Some(parent) = data_path.parent() else {
        return Ok(Vec::new());
    };
    let Some(instance_name) = data_path.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    let prefixes = [
        format!(".dbe-major-upgrade-old-{instance_name}-"),
        format!(".dbe-restore-{instance_name}-"),
    ];
    let mut directory = match tokio::fs::read_dir(parent).await {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut paths = Vec::new();
    while let Some(entry) = directory.next_entry().await? {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| retained_volume_name_matches(name, &prefixes))
        {
            paths.push(entry.path());
        }
    }
    Ok(paths)
}

fn retained_volume_name_matches(name: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|suffix| uuid::Uuid::parse_str(suffix).is_ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{DiskConfig, DiskLimitMode},
        shared::protocol::Protocol,
    };

    #[test]
    fn persisted_target_method_survives_a_node_mode_change() {
        let limiter = DiskLimiter::new(DiskConfig {
            mode: DiskLimitMode::SoftScanner,
            ..DiskConfig::default()
        });

        let selected = provisional_cleanup_limiter(
            limiter,
            Protocol::Postgres,
            std::path::Path::new("unused-when-method-is-known"),
            Some("fuse_quota"),
        )
        .unwrap();

        assert_eq!(selected.mode(), DiskLimitMode::FuseQuota);
    }

    #[test]
    fn observed_provisional_fuse_mount_overrides_the_current_node_mode() {
        let limiter = DiskLimiter::new(DiskConfig {
            mode: DiskLimitMode::SoftScanner,
            ..DiskConfig::default()
        });

        let selected = select_cleanup_limiter(limiter, Protocol::Postgres, true);

        assert_eq!(selected.mode(), DiskLimitMode::FuseQuota);
    }

    #[test]
    fn provisional_mount_probe_errors_are_not_treated_as_no_mount() {
        let limiter = DiskLimiter::with_fuse_root(DiskConfig::default(), "relative-fuse-root");

        let error = provisional_cleanup_limiter(
            limiter,
            Protocol::Postgres,
            std::path::Path::new("/var/lib/dbev/volumes/instances/target"),
            None,
        )
        .unwrap_err();

        assert!(matches!(error, crate::disk::DiskLimitError::PathIo { .. }));
    }
}
