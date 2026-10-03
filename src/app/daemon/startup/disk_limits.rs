use super::*;

pub(in super::super) async fn restore_disk_limits(
    config: &Config,
    manager: &InstanceManager,
    docker: &DockerRuntime,
    disk_limiter: &DiskLimiter,
) -> anyhow::Result<()> {
    let instances = manager.store().list().await.into_iter().filter(|metadata| {
        metadata.deployment_mode == crate::server::placement::DeploymentMode::Dedicated
    });
    let outcomes = futures::stream::iter(instances)
        .map(|metadata| async move {
            let outcome =
                reconcile_instance_disk_limit(config, docker, disk_limiter, &metadata).await;
            (metadata, outcome)
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut failed = 0_usize;
    for (mut metadata, outcome) in outcomes {
        let error = match outcome {
            Ok((_effective_mode, enforcement)) => {
                let enforcement_changed = metadata.limits.disk_enforced != enforcement.enforced
                    || metadata.limits.disk_enforcement_method != enforcement.method;
                if enforcement_changed {
                    metadata.limits.disk_enforced = enforcement.enforced;
                    metadata.limits.disk_enforcement_method = enforcement.method;
                    metadata.updated_at = now_rfc3339();
                    manager.upsert(metadata).await?;
                }
                continue;
            }
            Err(error) => error,
        };
        failed += 1;
        tracing::error!(
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "instance disk-limit reconciliation failed; isolating this instance and continuing daemon boot"
        );
        let stop_failed = match docker.stop(metadata.protocol, &metadata.instance_id).await {
            Ok(_) => false,
            Err(error) if error.is_not_found() || error.is_not_running() => false,
            Err(stop_error) => {
                tracing::error!(
                    event = "audit disk_limit_recovery_stop_failed",
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    %stop_error,
                    "failed to stop an instance whose disk-limit runtime could not be reconciled; quarantining it fail-closed"
                );
                true
            }
        };
        isolate_disk_failure(&mut metadata, stop_failed);
        metadata.updated_at = now_rfc3339();
        if stop_failed {
            manager
                .quarantine(
                    metadata,
                    crate::storage::quarantine::QuarantineKind::ShutdownUnconfirmed,
                )
                .await?;
        } else {
            manager.upsert(metadata).await?;
        }
    }
    if failed > 0 {
        tracing::warn!(
            failed,
            "one or more instance disk limits could not be reconciled; affected instances were isolated while daemon startup continues"
        );
    }
    Ok(())
}

pub(super) async fn reconcile_instance_disk_limit(
    config: &Config,
    docker: &DockerRuntime,
    disk_limiter: &DiskLimiter,
    metadata: &crate::server::metadata::InstanceMetadata,
) -> anyhow::Result<(
    crate::config::DiskLimitMode,
    crate::server::disk::DiskEnforcement,
)> {
    let paths = InstancePaths::new(&config.paths, &metadata.instance_id)
        .with_context(|| format!("failed to build paths for {}", metadata.instance_id))?;
    if let Some((uid, gid)) = docker.rootless_podman_host_owner() {
        paths.create_dirs().await.with_context(|| {
            format!(
                "failed to create rootless Podman paths for {}",
                metadata.instance_id
            )
        })?;
        paths
            .apply_rootless_owner(uid, gid)
            .await
            .with_context(|| {
                format!(
                    "failed to apply rootless Podman ownership for {}",
                    metadata.instance_id
                )
            })?;
    }
    let legacy_qdrant_fuse_retained = if metadata.protocol == Protocol::Qdrant {
        !migrate_qdrant_storage(config, docker, disk_limiter, metadata, &paths).await?
    } else {
        false
    };
    let effective_limiter = if legacy_qdrant_fuse_retained {
        // Migration was deliberately deferred or rolled back. The
        // existing container is still bound to FuseQuota, even if
        // the operator has since selected soft/native enforcement.
        disk_limiter.legacy_fuse_limiter()
    } else {
        disk_limiter.for_protocol(metadata.protocol)
    };
    effective_limiter.check_method_change(&metadata.limits.disk_enforcement_method)?;
    ensure_disk_mounted(docker, metadata, &paths, &effective_limiter).await?;
    let runtime_healthy = effective_limiter
        .runtime_is_healthy(&paths.data)
        .await
        .with_context(|| {
            format!(
                "failed to inspect disk-limit runtime for {}",
                metadata.instance_id
            )
        })?;
    if !runtime_healthy {
        stop_for_disk_runtime_recovery(docker, metadata).await?;
        effective_limiter
            .teardown_instance_mount(&paths.data)
            .await?;
    }
    let enforcement = effective_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .with_context(|| format!("failed to apply disk limit for {}", metadata.instance_id))?;
    Ok((effective_limiter.mode(), enforcement))
}

pub(super) async fn stop_for_disk_runtime_recovery(
    docker: &DockerRuntime,
    metadata: &crate::server::metadata::InstanceMetadata,
) -> anyhow::Result<()> {
    match docker.stop(metadata.protocol, &metadata.instance_id).await {
        Ok(_) => tracing::warn!(
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            "stopped managed instance to recover an unavailable disk-limit runtime"
        ),
        Err(error) if error.is_not_found() || error.is_not_running() => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to stop {} before recovering its disk-limit runtime",
                    metadata.instance_id
                )
            });
        }
    }
    Ok(())
}

pub(in super::super) fn isolate_disk_failure(
    metadata: &mut crate::server::metadata::InstanceMetadata,
    stop_failed: bool,
) {
    // A Failed+desired-running instance is automatically retried later in the
    // same boot. Persist explicit stopped intent for every reconciliation or
    // bind-source failure so activation cannot immediately bypass the mode we
    // failed to establish.
    metadata.desired_state = crate::server::metadata::DesiredInstanceState::Stopped;
    metadata.status = if metadata.status == InstanceStatus::Quarantined || stop_failed {
        InstanceStatus::Quarantined
    } else {
        InstanceStatus::Failed
    };
}

pub(super) async fn ensure_disk_mounted(
    docker: &DockerRuntime,
    metadata: &crate::server::metadata::InstanceMetadata,
    paths: &InstancePaths,
    effective_limiter: &DiskLimiter,
) -> anyhow::Result<()> {
    let expected_source = effective_limiter.container_data_path(&paths.data)?;
    match docker
        .verify_data_bind(metadata.protocol, &metadata.instance_id, &expected_source)
        .await
    {
        Ok(()) => Ok(()),
        // A missing container can be recreated later with the selected mode.
        // There is no running bind source that could bypass enforcement.
        Err(error) if error.is_not_found() => Ok(()),
        Err(error) => Err(error.into()),
    }
}
