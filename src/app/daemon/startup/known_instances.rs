use anyhow::Context;
use futures::StreamExt;

use crate::{
    config::Config,
    daemon::{
        runtime_paths::prepare_instance_paths,
        startup::{
            BOOT_ACTIVATION_READY_TIMEOUT,
            boot_action::{ManagedBootAction, log_boot_container_failure, managed_boot_action},
        },
    },
    runtime::docker::{CpuBurstPolicyStatus, DockerRuntime},
    server::{
        disk::DiskLimiter, manager::InstanceManager, metadata::InstanceStatus,
        paths::InstancePaths, reconcile,
    },
    utils::{
        constants::MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY, limits::mib_to_bytes, time::now_rfc3339,
    },
};

pub(in super::super) async fn start_known_instances(
    config: &Config,
    manager: &InstanceManager,
    docker: &DockerRuntime,
    instance_locks: &crate::server::locks::InstanceLocks,
) -> anyhow::Result<()> {
    let instances = manager.store().list().await.into_iter().filter(|metadata| {
        metadata.deployment_mode == crate::server::placement::DeploymentMode::Dedicated
    });
    let outcomes = futures::stream::iter(instances)
        .map(|snapshot| async move {
            start_known_instance(config, manager, docker, instance_locks, snapshot).await
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut attempted = 0_usize;
    let mut running = 0_usize;
    let mut stopped = 0_usize;
    let mut failed = 0_usize;
    let mut errors = 0_usize;

    for outcome in outcomes {
        let status = match outcome {
            Ok(Some(status)) => status,
            Ok(None) => continue,
            Err(error) => {
                errors += 1;
                tracing::error!(
                    %error,
                    "managed instance failed background activation during daemon boot; continuing with other instances"
                );
                continue;
            }
        };
        attempted += 1;
        match status {
            InstanceStatus::Booting => {}
            InstanceStatus::Running => running += 1,
            InstanceStatus::Stopped => stopped += 1,
            InstanceStatus::Failed | InstanceStatus::Quarantined => failed += 1,
            InstanceStatus::Creating | InstanceStatus::Deleting => {}
        }
    }

    tracing::info!(
        attempted,
        running,
        stopped,
        failed,
        errors,
        concurrency = MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
        "daemon boot managed instance auto-start complete"
    );
    Ok(())
}

pub(in super::super) async fn sync_cpu_burst_limits(
    manager: &InstanceManager,
    docker: &DockerRuntime,
) {
    let instances = manager
        .store()
        .list()
        .await
        .into_iter()
        .filter(|metadata| {
            metadata.deployment_mode == crate::server::placement::DeploymentMode::Dedicated
                && metadata.status == InstanceStatus::Running
        })
        .collect::<Vec<_>>();
    let checked = instances.len();
    let outcomes = futures::stream::iter(instances)
        .map(|metadata| async move {
            let result = docker
                .apply_cpu_burst_policy(metadata.protocol, &metadata.instance_id)
                .await;
            (metadata, result)
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut applied = 0_usize;
    let mut already_configured = 0_usize;
    let mut inactive = 0_usize;
    let mut unsupported = 0_usize;
    let mut failed = 0_usize;
    for (metadata, result) in outcomes {
        match result {
            Ok(CpuBurstPolicyStatus::Applied) => applied += 1,
            Ok(CpuBurstPolicyStatus::AlreadyConfigured) => already_configured += 1,
            Ok(CpuBurstPolicyStatus::Inactive) => inactive += 1,
            Ok(CpuBurstPolicyStatus::Unsupported) => unsupported += 1,
            Err(error) => {
                failed += 1;
                tracing::warn!(
                    event = "cpu_burst_policy_reconciliation_failed",
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    %error,
                    "failed to reconcile CPU burst credit; the normal CPU quota remains active"
                );
            }
        }
    }
    if unsupported > 0 {
        tracing::warn!(
            unsupported,
            "host cgroups do not expose CFS burst control for some running instances; their normal CPU quotas remain active"
        );
    }
    tracing::info!(
        checked,
        applied,
        already_configured,
        inactive,
        unsupported,
        failed,
        "managed container CPU burst policy reconciliation complete"
    );
}

pub(in super::super) async fn start_known_instance(
    config: &Config,
    manager: &InstanceManager,
    docker: &DockerRuntime,
    instance_locks: &crate::server::locks::InstanceLocks,
    snapshot: crate::server::metadata::InstanceMetadata,
) -> anyhow::Result<Option<InstanceStatus>> {
    let Some(snapshot_action) = managed_boot_action(snapshot.status, snapshot.desired_state) else {
        return Ok(None);
    };

    let _operation = instance_locks.lock(&snapshot.instance_id).await;
    let Some(mut metadata) = manager.store().get(&snapshot.instance_id).await else {
        return Ok(None);
    };
    let Some(action) = managed_boot_action(metadata.status, metadata.desired_state) else {
        return Ok(None);
    };
    if let Err(error) = docker.check_autostart(&metadata.instance_id).await {
        tracing::warn!(event = "audit container_autostart_blocked", instance_id = %metadata.instance_id, %error);
        metadata.status = InstanceStatus::Failed;
        manager.upsert_fenced(metadata.clone()).await?;
        if let Err(error) = docker.stop(metadata.protocol, &metadata.instance_id).await
            && !error.is_not_found()
            && !error.is_not_running()
        {
            tracing::error!(instance_id = %metadata.instance_id, %error,
                "could not stop a startup-blocked container; its routes remain fenced");
        }
        return Ok(Some(InstanceStatus::Failed));
    }
    if action != snapshot_action {
        tracing::debug!(
            instance_id = %metadata.instance_id,
            snapshot_action = snapshot_action.as_str(),
            action = action.as_str(),
            "managed instance boot action changed after acquiring its operation lock"
        );
    }

    tracing::info!(
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        previous_status = ?metadata.status,
        action = action.as_str(),
        "activating managed instance on daemon boot"
    );

    let mut boot_failed = false;
    let mut disk_blocked = false;
    let mut disk_bind_blocked = false;
    if let Err(error) =
        prepare_instance_paths(config, docker, metadata.protocol, &metadata.instance_id).await
    {
        boot_failed = true;
        tracing::warn!(
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "failed to prepare managed instance runtime directories during daemon boot; skipping container start"
        );
    } else {
        let paths = InstancePaths::new(&config.paths, &metadata.instance_id)
            .with_context(|| format!("failed to build paths for {}", metadata.instance_id))?;
        let disk_limiter =
            DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
                .for_persisted_protocol(
                    metadata.protocol,
                    &metadata.limits.disk_enforcement_method,
                );
        let expected_data_source = disk_limiter.container_data_path(&paths.data)?;
        if let Err(error) = docker
            .verify_data_bind(
                metadata.protocol,
                &metadata.instance_id,
                &expected_data_source,
            )
            .await
        {
            boot_failed = true;
            disk_bind_blocked = true;
            tracing::error!(
                event = "audit disk_limit_bind_boot_blocked",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %error,
                "refused to activate an instance whose container data bind does not match the selected disk enforcement"
            );
        }
        let scanner_required = crate::server::disk::soft::SoftDiskLimiter::enforcement_required(
            config.disk.mode,
            metadata.protocol,
        ) || (metadata.protocol.engine().fuse_quota_unsupported()
            && metadata.limits.disk_enforcement_method == "fuse_quota");
        if !disk_bind_blocked && scanner_required {
            let soft_limiter =
                crate::server::disk::soft::SoftDiskLimiter::new(config.disk.soft_scanner.clone());
            match soft_limiter
                .ensure_start_allowed(&crate::server::disk::soft::SoftDiskTarget {
                    instance_id: metadata.instance_id.clone(),
                    created_at: metadata.created_at.clone(),
                    protocol: metadata.protocol,
                    data_path: paths.data.clone(),
                    limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
                    durable_blocked: metadata.disk_limit_blocked,
                })
                .await
            {
                Ok(snapshot) => {
                    if metadata.disk_limit_blocked && !snapshot.blocked {
                        metadata.disk_limit_blocked = false;
                        metadata.updated_at = now_rfc3339();
                    }
                }
                Err(error) => {
                    boot_failed = true;
                    disk_blocked = true;
                    metadata.disk_limit_blocked = true;
                    tracing::error!(
                        event = "audit soft_disk_boot_blocked",
                        instance_id = %metadata.instance_id,
                        protocol = %metadata.protocol,
                        %error,
                        "refused to activate an instance whose data is above the soft disk threshold or could not be measured safely"
                    );
                }
            }
        }
        if disk_bind_blocked || disk_blocked {
            // The preflight already emitted an actionable audit event and the
            // durable stopped state is persisted below.
        } else if let Err(error) = disk_limiter
            .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
            .await
        {
            boot_failed = true;
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %error,
                "failed to prepare managed instance disk limit during daemon boot; skipping container activation"
            );
        } else if !activate_container_on_boot(docker, &metadata, action).await {
            boot_failed = true;
        }
    }

    if boot_failed
        && let Err(error) = docker.stop(metadata.protocol, &metadata.instance_id).await
        && !error.is_not_running()
        && !error.is_not_found()
    {
        tracing::error!(
            event = "audit boot_activation_cleanup_failed",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "database activation failed during daemon boot and the container could not be stopped"
        );
    }

    let mut reconciled = reconcile::reconcile_one(metadata, docker).await;
    if disk_bind_blocked {
        reconciled.desired_state = crate::server::metadata::DesiredInstanceState::Stopped;
        reconciled.status = InstanceStatus::Failed;
        reconciled.updated_at = now_rfc3339();
    } else if disk_blocked {
        reconciled.desired_state = crate::server::metadata::DesiredInstanceState::Stopped;
        reconciled.status = InstanceStatus::Stopped;
        reconciled.updated_at = now_rfc3339();
    } else if boot_failed {
        reconciled.status = InstanceStatus::Failed;
        reconciled.updated_at = now_rfc3339();
    }
    let status = reconciled.status;
    manager.upsert(reconciled).await?;
    Ok(Some(status))
}

pub(super) async fn activate_container_on_boot(
    docker: &DockerRuntime,
    metadata: &crate::server::metadata::InstanceMetadata,
    action: ManagedBootAction,
) -> bool {
    let activation = match action {
        ManagedBootAction::Start => docker.start(metadata.protocol, &metadata.instance_id).await,
        ManagedBootAction::Restart => {
            docker
                .restart(metadata.protocol, &metadata.instance_id)
                .await
        }
    };
    let (message, error) = match activation {
        Err(error) => (
            "failed to activate managed instance during daemon boot",
            error.to_string(),
        ),
        Ok(_) => match docker
            .wait_until_ready(
                metadata.protocol,
                &metadata.instance_id,
                BOOT_ACTIVATION_READY_TIMEOUT,
            )
            .await
        {
            Ok(_) => return true,
            Err(error) => (
                "managed instance did not become ready during daemon boot",
                error.to_string(),
            ),
        },
    };
    log_boot_container_failure(
        docker,
        metadata.protocol,
        &metadata.instance_id,
        message,
        error,
    )
    .await;
    false
}
