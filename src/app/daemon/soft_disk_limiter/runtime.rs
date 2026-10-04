use crate::{
    daemon::soft_disk_limiter::GRACEFUL_STOP_TIMEOUT_PADDING,
    server::{
        disk::soft::{SoftDiskLimitExceeded, SoftDiskRuntime, SoftDiskTarget, StopOutcome},
        metadata::{DesiredInstanceState, InstanceStatus},
        placement::lifecycle::mark_shared_disk_blocked,
    },
    state::AppState,
    utils::{limits::mib_to_bytes, time::now_rfc3339},
};
use std::time::Duration;

#[derive(Clone)]
pub(super) struct AppStateSoftDiskRuntime {
    pub(super) state: AppState,
    pub(super) lifecycle_lock_held: bool,
}

impl AppStateSoftDiskRuntime {
    fn target_is_current(
        &self,
        metadata: &crate::server::metadata::InstanceMetadata,
        target: &SoftDiskTarget,
    ) -> bool {
        is_current_target(metadata, target, self.state.config.disk.mode)
    }

    async fn lock_unless_held(
        &self,
        instance_id: &str,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        if self.lifecycle_lock_held {
            None
        } else {
            Some(self.state.instance_locks.lock(instance_id).await)
        }
    }

    async fn persist_disk_block(
        &self,
        target: &SoftDiskTarget,
        exceeded: &SoftDiskLimitExceeded,
    ) -> Result<bool, String> {
        if let Some(mut metadata) = self.state.instances.get(&target.instance_id).await {
            if !self.target_is_current(&metadata, target) {
                return Ok(false);
            }
            metadata.desired_state = DesiredInstanceState::Stopped;
            metadata.disk_limit_blocked = true;
            metadata.updated_at = now_rfc3339();
            self.state
                .manager
                .upsert(metadata)
                .await
                .map_err(|error| format!("failed to persist disk-limit stop intent: {error}"))?;
        } else if !mark_shared_disk_blocked(&self.state, target).await? {
            return Ok(false);
        }
        tracing::warn!(
            event = "audit soft_disk_restart_blocked",
            instance_id = %target.instance_id,
            protocol = %target.protocol,
            physical_bytes = exceeded.snapshot.usage.physical_bytes,
            stop_threshold_bytes = exceeded.snapshot.stop_threshold_bytes,
            recovery_threshold_bytes = exceeded.snapshot.recovery_threshold_bytes,
            block_reason = exceeded.reason.as_str(),
            scan_error = exceeded.reason.scan_error(),
            "persisted an intentional stopped state until disk usage recovers"
        );
        Ok(true)
    }
}

pub(in super::super) fn is_current_target(
    metadata: &crate::server::metadata::InstanceMetadata,
    target: &SoftDiskTarget,
    global_mode: crate::config::DiskLimitMode,
) -> bool {
    metadata.deployment_mode == crate::server::placement::DeploymentMode::Dedicated
        && metadata.instance_id == target.instance_id
        && metadata.created_at == target.created_at
        && metadata.protocol == target.protocol
        && matches!(
            metadata.status,
            InstanceStatus::Running | InstanceStatus::Booting
        )
        && mib_to_bytes(metadata.limits.disk_mib) == target.limit_bytes
        && soft_monitoring_required(metadata, global_mode)
}

pub(super) fn soft_monitoring_required(
    metadata: &crate::server::metadata::InstanceMetadata,
    global_mode: crate::config::DiskLimitMode,
) -> bool {
    let legacy_qdrant_fuse = metadata.protocol.engine().fuse_quota_unsupported()
        && metadata.limits.disk_enforcement_method == "fuse_quota";
    crate::server::disk::soft::SoftDiskLimiter::enforcement_required(global_mode, metadata.protocol)
        || legacy_qdrant_fuse
}

impl SoftDiskRuntime for AppStateSoftDiskRuntime {
    fn mark_disk_blocked<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        exceeded: &'a SoftDiskLimitExceeded,
    ) -> crate::server::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            let _operation = self.lock_unless_held(&target.instance_id).await;
            self.persist_disk_block(target, exceeded).await?;
            Ok(())
        })
    }

    fn graceful_stop<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        grace: Duration,
    ) -> crate::server::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            // Leave the exact stop deadline and SIGKILL fallback to the supervisor.
            let stopped = self
                .state
                .docker
                .stop_with_timeout(
                    target.protocol,
                    &target.instance_id,
                    grace.saturating_add(GRACEFUL_STOP_TIMEOUT_PADDING),
                )
                .await;
            ignore_absent_container(stopped)
        })
    }

    fn force_kill<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
    ) -> crate::server::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            let killed = self
                .state
                .docker
                .kill(target.protocol, &target.instance_id)
                .await;
            ignore_absent_container(killed)
        })
    }

    fn clear_disk_blocked<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
    ) -> crate::server::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            let _operation = self.lock_unless_held(&target.instance_id).await;
            let Some(mut metadata) = self.state.instances.get(&target.instance_id).await else {
                return Ok(());
            };
            if !self.target_is_current(&metadata, target) || !metadata.disk_limit_blocked {
                return Ok(());
            }
            metadata.disk_limit_blocked = false;
            metadata.updated_at = now_rfc3339();
            self.state
                .manager
                .upsert(metadata)
                .await
                .map_err(|error| format!("failed to clear durable disk-limit block: {error}"))
        })
    }

    fn enforce_disk_stop<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        exceeded: &'a SoftDiskLimitExceeded,
        grace: Duration,
    ) -> crate::server::disk::soft::StopRuntimeFuture<'a> {
        Box::pin(async move {
            // Keep Start serialized through durable intent and runtime shutdown.
            let _operation = self.lock_unless_held(&target.instance_id).await;
            if !self.persist_disk_block(target, exceeded).await? {
                return Ok(StopOutcome::SkippedStale);
            }
            crate::server::disk::soft::stop_with_kill_fallback(self, target, grace).await
        })
    }
}

pub(super) fn ignore_absent_container<T>(
    result: Result<T, crate::runtime::docker::DockerError>,
) -> Result<(), String> {
    match result {
        Ok(_) => Ok(()),
        Err(error) if error.is_not_found() || error.is_not_running() => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}
