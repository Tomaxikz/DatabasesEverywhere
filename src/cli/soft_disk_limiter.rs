use std::{collections::HashSet, sync::Arc};

use super::*;
use crate::{
    disk::soft::{
        ScanOutcome, SoftDiskLimitExceeded, SoftDiskRuntime, SoftDiskTarget, StopOutcome,
    },
    instances::metadata::DesiredInstanceState,
};

pub(super) async fn monitor_soft_disk_limits(state: AppState) {
    let mut shutdown = state.daemon_shutdown.subscribe();
    let mut ticker = tokio::time::interval(state.soft_disk_limiter.scan_interval());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let runtime = AppStateSoftDiskRuntime {
        state: state.clone(),
    };
    let in_flight = Arc::new(std::sync::Mutex::new(HashSet::<String>::new()));
    let mut scans = tokio::task::JoinSet::new();
    let mut next_index = 0_usize;

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    scans.abort_all();
                    return;
                }
            }
            _ = ticker.tick() => {
                schedule_soft_limited_instances(
                    &state,
                    &runtime,
                    &in_flight,
                    &mut scans,
                    &mut next_index,
                ).await;
            }
            completed = scans.join_next(), if !scans.is_empty() => {
                if let Some(Err(error)) = completed
                    && !error.is_cancelled()
                {
                    tracing::error!(%error, "soft disk scan task failed unexpectedly");
                }
                schedule_soft_limited_instances(
                    &state,
                    &runtime,
                    &in_flight,
                    &mut scans,
                    &mut next_index,
                ).await;
            }
        }
    }
}

async fn schedule_soft_limited_instances(
    state: &AppState,
    runtime: &AppStateSoftDiskRuntime,
    in_flight: &Arc<std::sync::Mutex<HashSet<String>>>,
    scans: &mut tokio::task::JoinSet<()>,
    next_index: &mut usize,
) {
    let available = state
        .soft_disk_limiter
        .max_concurrent_scans()
        .saturating_sub(scans.len());
    if available == 0 {
        return;
    }
    let mut targets = Vec::new();
    for metadata in state.instances.list().await {
        if !matches!(
            metadata.status,
            InstanceStatus::Running | InstanceStatus::Booting
        ) || !(crate::disk::soft::SoftDiskLimiter::enforcement_required(
            state.config.disk.mode,
            metadata.protocol,
        ) || (metadata.protocol == Protocol::Qdrant
            && metadata.limits.disk_enforcement_method == "fuse_quota"))
        {
            continue;
        }
        let paths = match InstancePaths::new(&state.config.paths, &metadata.instance_id) {
            Ok(paths) => paths,
            Err(error) => {
                tracing::error!(
                    event = "audit soft_disk_scan_invalid_path",
                    instance_id = %metadata.instance_id,
                    %error,
                    "soft disk limiter could not construct the instance path"
                );
                continue;
            }
        };
        targets.push(SoftDiskTarget {
            instance_id: metadata.instance_id,
            created_at: metadata.created_at,
            protocol: metadata.protocol,
            data_path: paths.data,
            limit_bytes: metadata.limits.disk_mib.saturating_mul(1024 * 1024),
            durable_blocked: metadata.disk_limit_blocked,
        });
    }
    if targets.is_empty() {
        *next_index = 0;
        return;
    }

    let start = *next_index % targets.len();
    let mut scheduled = 0_usize;
    let mut considered = 0_usize;
    while considered < targets.len() && scheduled < available {
        let index = (start + considered) % targets.len();
        considered += 1;
        let target = targets[index].clone();
        {
            let mut active = in_flight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !active.insert(target.instance_id.clone()) {
                continue;
            }
        }
        *next_index = (index + 1) % targets.len();
        scheduled += 1;
        let state = state.clone();
        let runtime = runtime.clone();
        let in_flight = Arc::clone(in_flight);
        scans.spawn(async move {
            let _in_flight = InFlightScan::new(target.instance_id.clone(), in_flight);
            match state
                .soft_disk_limiter
                .scan_and_enforce(&runtime, &target)
                .await
            {
                Ok(ScanOutcome::Healthy(_)) | Ok(ScanOutcome::AlreadyBlocked(_)) => {}
                Ok(ScanOutcome::Warning(snapshot)) => tracing::warn!(
                    event = "audit soft_disk_limit_warning",
                    instance_id = %target.instance_id,
                    protocol = %target.protocol,
                    physical_bytes = snapshot.usage.physical_bytes,
                    logical_bytes = snapshot.usage.logical_bytes,
                    limit_bytes = snapshot.limit_bytes,
                    growth_bytes_per_second = snapshot.growth_bytes_per_second,
                    peak_growth_bytes_per_second = snapshot.peak_growth_bytes_per_second,
                    predicted_seconds_to_limit = snapshot.predicted_seconds_to_limit,
                    "instance disk usage is approaching its predictive soft-stop threshold"
                ),
                Ok(ScanOutcome::Recovered(snapshot)) => tracing::info!(
                    event = "audit soft_disk_limit_recovered",
                    instance_id = %target.instance_id,
                    protocol = %target.protocol,
                    physical_bytes = snapshot.usage.physical_bytes,
                    recovery_threshold_bytes = snapshot.recovery_threshold_bytes,
                    "instance disk usage is below hysteresis; an operator may start it again"
                ),
                Ok(ScanOutcome::Stopped {
                    snapshot,
                    outcome: StopOutcome::SkippedStale,
                }) => tracing::debug!(
                    instance_id = %target.instance_id,
                    protocol = %target.protocol,
                    physical_bytes = snapshot.usage.physical_bytes,
                    "discarded a stale soft disk enforcement decision after instance state changed"
                ),
                Ok(ScanOutcome::Stopped { snapshot, outcome }) => tracing::error!(
                    event = "audit soft_disk_limit_stopped",
                    instance_id = %target.instance_id,
                    protocol = %target.protocol,
                    physical_bytes = snapshot.usage.physical_bytes,
                    logical_bytes = snapshot.usage.logical_bytes,
                    limit_bytes = snapshot.limit_bytes,
                    stop_threshold_bytes = snapshot.stop_threshold_bytes,
                    growth_bytes_per_second = snapshot.growth_bytes_per_second,
                    peak_growth_bytes_per_second = snapshot.peak_growth_bytes_per_second,
                    predicted_seconds_to_limit = snapshot.predicted_seconds_to_limit,
                    stop_outcome = match outcome {
                        StopOutcome::Graceful => "graceful",
                        StopOutcome::Forced => "forced_after_deadline",
                        StopOutcome::SkippedStale => unreachable!("handled above"),
                    },
                    "stopped an instance before soft disk-limit overshoot could consume the host"
                ),
                Err(error) => tracing::error!(
                    event = if crate::disk::soft::SoftDiskLimiter::is_capacity_outage(&error) {
                        "audit soft_disk_scanner_capacity_outage"
                    } else {
                        "audit soft_disk_limit_scan_failed"
                    },
                    instance_id = %target.instance_id,
                    protocol = %target.protocol,
                    %error,
                    "soft disk limiter scan or enforcement failed"
                ),
            }
        });
    }
}

struct InFlightScan {
    instance_id: String,
    active: Arc<std::sync::Mutex<HashSet<String>>>,
}

impl InFlightScan {
    fn new(instance_id: String, active: Arc<std::sync::Mutex<HashSet<String>>>) -> Self {
        Self {
            instance_id,
            active,
        }
    }
}

impl Drop for InFlightScan {
    fn drop(&mut self) {
        self.active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.instance_id);
    }
}

#[derive(Clone)]
struct AppStateSoftDiskRuntime {
    state: AppState,
}

impl AppStateSoftDiskRuntime {
    fn target_is_current(
        &self,
        metadata: &crate::instances::metadata::InstanceMetadata,
        target: &SoftDiskTarget,
    ) -> bool {
        soft_disk_target_is_current(metadata, target, self.state.config.disk.mode)
    }
}

pub(super) fn soft_disk_target_is_current(
    metadata: &crate::instances::metadata::InstanceMetadata,
    target: &SoftDiskTarget,
    global_mode: crate::config::DiskLimitMode,
) -> bool {
    let monitoring_required =
        crate::disk::soft::SoftDiskLimiter::enforcement_required(global_mode, metadata.protocol)
            || (metadata.protocol == Protocol::Qdrant
                && metadata.limits.disk_enforcement_method == "fuse_quota");
    metadata.instance_id == target.instance_id
        && metadata.created_at == target.created_at
        && metadata.protocol == target.protocol
        && matches!(
            metadata.status,
            InstanceStatus::Running | InstanceStatus::Booting
        )
        && metadata.limits.disk_mib.saturating_mul(1024 * 1024) == target.limit_bytes
        && monitoring_required
}

impl SoftDiskRuntime for AppStateSoftDiskRuntime {
    fn mark_disk_blocked<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        exceeded: &'a SoftDiskLimitExceeded,
    ) -> crate::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            let _operation = self.state.instance_locks.lock(&target.instance_id).await;
            let Some(mut metadata) = self.state.instances.get(&target.instance_id).await else {
                return Ok(());
            };
            if !self.target_is_current(&metadata, target) {
                return Ok(());
            }
            metadata.desired_state = DesiredInstanceState::Stopped;
            metadata.disk_limit_blocked = true;
            metadata.updated_at = now_rfc3339();
            self.state
                .manager
                .upsert(metadata)
                .await
                .map_err(|error| format!("failed to persist disk-limit stop intent: {error}"))?;
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
            Ok(())
        })
    }

    fn graceful_stop<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        grace: Duration,
    ) -> crate::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            // The outer supervisor owns the exact deadline. Give the engine a
            // slightly longer timeout so its request can be cancelled and our
            // explicit SIGKILL fallback remains authoritative at 30 seconds.
            match self
                .state
                .docker
                .stop_with_timeout(
                    target.protocol,
                    &target.instance_id,
                    grace.saturating_add(Duration::from_secs(5)),
                )
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if error.is_not_found() || error.is_not_running() => Ok(()),
                Err(error) => Err(error.to_string()),
            }
        })
    }

    fn force_kill<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
    ) -> crate::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            match self
                .state
                .docker
                .kill(target.protocol, &target.instance_id)
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if error.is_not_found() || error.is_not_running() => Ok(()),
                Err(error) => Err(error.to_string()),
            }
        })
    }

    fn clear_disk_blocked<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
    ) -> crate::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            let _operation = self.state.instance_locks.lock(&target.instance_id).await;
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
    ) -> crate::disk::soft::StopRuntimeFuture<'a> {
        Box::pin(async move {
            // This guard spans durable intent, graceful shutdown, and SIGKILL
            // fallback. A concurrent Start therefore cannot overwrite the
            // stopped intent in the gap between persistence and enforcement.
            let _operation = self.state.instance_locks.lock(&target.instance_id).await;
            let Some(mut metadata) = self.state.instances.get(&target.instance_id).await else {
                return Ok(StopOutcome::Graceful);
            };
            if !self.target_is_current(&metadata, target) {
                return Ok(StopOutcome::SkippedStale);
            }
            metadata.desired_state = DesiredInstanceState::Stopped;
            metadata.disk_limit_blocked = true;
            metadata.updated_at = now_rfc3339();
            self.state
                .manager
                .upsert(metadata)
                .await
                .map_err(|error| format!("failed to persist disk-limit stop intent: {error}"))?;
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
            crate::disk::soft::stop_with_kill_fallback(self, target, grace).await
        })
    }
}
