use crate::{
    daemon::soft_disk_limiter::{
        root_identity::{ObservationDisposition, RootIdentityTracker, watch_fingerprint},
        runtime::soft_monitoring_required,
        watch_operations::{DesiredWatch, WatchOperationQueue},
        watching::is_watching,
    },
    server::{
        disk::soft::{
            SoftDiskTarget,
            planner::{HybridScanPlanner, TargetSpec},
            watcher::SoftDiskWatcher,
        },
        metadata::InstanceStatus,
        paths::InstancePaths,
    },
    state::AppState,
    utils::limits::mib_to_bytes,
};
use std::{collections::HashMap, sync::Arc, time::Duration};

pub(super) async fn sync_soft_disk_targets(
    state: &AppState,
    watcher: &Option<Arc<SoftDiskWatcher>>,
    planner: &mut HybridScanPlanner,
    targets: &mut HashMap<String, SoftDiskTarget>,
    root_identities: &mut RootIdentityTracker,
    watch_queue: &mut WatchOperationQueue,
    now: Duration,
) {
    let mut current = HashMap::new();
    let mut candidates = Vec::new();
    for metadata in state.instances.list().await {
        let active = matches!(
            metadata.status,
            InstanceStatus::Running | InstanceStatus::Booting
        );
        if metadata.deployment_mode != crate::server::placement::DeploymentMode::Dedicated
            || !active
            || !soft_monitoring_required(&metadata, state.config.disk.mode)
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
        candidates.push(SoftDiskTarget {
            instance_id: metadata.instance_id,
            created_at: metadata.created_at,
            protocol: metadata.protocol,
            data_path: paths.data,
            limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
            durable_blocked: metadata.disk_limit_blocked,
        });
    }
    match state.placements.list().await {
        Ok(runtimes) => {
            for runtime in runtimes.into_iter().filter(|runtime| {
                runtime.deployment_mode == crate::server::placement::DeploymentMode::Shared
                    && matches!(
                        runtime.status,
                        crate::server::placement::EngineRuntimeStatus::Running
                            | crate::server::placement::EngineRuntimeStatus::Booting
                    )
                    && crate::server::disk::soft::SoftDiskLimiter::enforcement_required(
                        state.config.disk.mode,
                        runtime.protocol,
                    )
            }) {
                let paths = match InstancePaths::new(&state.config.paths, &runtime.runtime_id) {
                    Ok(paths) => paths,
                    Err(error) => {
                        tracing::error!(
                            event = "audit shared_soft_disk_scan_invalid_path",
                            runtime_id = %runtime.runtime_id,
                            %error,
                            "soft disk limiter could not construct the shared pool path"
                        );
                        continue;
                    }
                };
                candidates.push(SoftDiskTarget {
                    instance_id: runtime.runtime_id,
                    created_at: runtime.created_at,
                    protocol: runtime.protocol,
                    data_path: paths.data,
                    limit_bytes: mib_to_bytes(runtime.limits.disk_mib),
                    durable_blocked: false,
                });
            }
        }
        Err(error) => {
            tracing::error!(
                event = "audit shared_soft_disk_target_load_failed",
                %error,
                "retained the previous soft-disk targets because shared pool metadata could not be refreshed"
            );
            candidates.extend(targets.values().cloned());
        }
    }
    for target in candidates {
        let target_id = target.instance_id.clone();
        let scanner_fingerprint = target.scanner_fingerprint();
        current.insert(target_id.clone(), scanner_fingerprint.clone());
        let root_identity = root_identities.identity_for(&target_id, &scanner_fingerprint);
        let watch_fingerprint = watch_fingerprint(&scanner_fingerprint, root_identity);
        if watcher.is_some() && !target.protocol.engine().mmap_writes_bypass_inotify() {
            watch_queue.upsert(
                target_id.clone(),
                DesiredWatch {
                    fingerprint: watch_fingerprint.clone(),
                    target_fingerprint: scanner_fingerprint.clone(),
                    root: target.data_path.clone(),
                },
            );
        } else if target.protocol.engine().mmap_writes_bypass_inotify() {
            let retired = watcher
                .as_ref()
                .and_then(|watcher| watcher.retire(&target_id));
            watch_queue.remove(&target_id, retired);
        }
        let watcher_trusted = !target.protocol.engine().mmap_writes_bypass_inotify()
            && watcher.as_ref().is_some_and(|watcher| {
                watch_queue.is_confirmed(&target_id, &watch_fingerprint)
                    && is_watching(watcher, &target_id)
            });
        planner.upsert_target(
            now,
            TargetSpec {
                id: target_id.clone(),
                fingerprint: scanner_fingerprint,
                root_identity,
                enabled: true,
                watcher_trusted,
                force_periodic_full: target.protocol.engine().mmap_writes_bypass_inotify(),
            },
        );
        targets.insert(target_id, target);
    }

    let removed = targets
        .keys()
        .filter(|target_id| !current.contains_key(*target_id))
        .cloned()
        .collect::<Vec<_>>();
    for target_id in removed {
        targets.remove(&target_id);
        planner.remove_target(&target_id);
        let retired = watcher
            .as_ref()
            .and_then(|watcher| watcher.retire(&target_id));
        watch_queue.remove(&target_id, retired);
        // Preserve stop hysteresis while releasing the large usage tree.
        state.soft_disk_limiter.evict_usage_cache(&target_id).await;
    }

    root_identities.retain_targets(&current);

    if watcher.is_some() {
        watch_queue.request_retry();
    }
}

pub(super) struct RootObservationContext<'a> {
    pub(super) watcher: &'a Option<Arc<SoftDiskWatcher>>,
    pub(super) planner: &'a mut HybridScanPlanner,
    pub(super) targets: &'a HashMap<String, SoftDiskTarget>,
    pub(super) root_identities: &'a mut RootIdentityTracker,
    pub(super) watch_queue: &'a mut WatchOperationQueue,
}

pub(super) fn observe_root_identity(
    context: &mut RootObservationContext<'_>,
    target_id: &str,
    completed_fingerprint: &str,
    identity: crate::server::disk::soft::planner::RootIdentity,
    now: Duration,
) -> ObservationDisposition {
    let Some(target) = context.targets.get(target_id) else {
        return ObservationDisposition::StaleTarget;
    };
    let current_fingerprint = target.scanner_fingerprint();
    let disposition = context.root_identities.observe(
        target_id,
        completed_fingerprint,
        &current_fingerprint,
        identity,
    );
    if !matches!(
        disposition,
        ObservationDisposition::Initialized | ObservationDisposition::Replaced
    ) {
        return disposition;
    }

    if context.watcher.is_some() && !target.protocol.engine().mmap_writes_bypass_inotify() {
        context.watch_queue.upsert(
            target_id.to_string(),
            DesiredWatch {
                fingerprint: watch_fingerprint(&current_fingerprint, Some(identity)),
                target_fingerprint: current_fingerprint.clone(),
                root: target.data_path.clone(),
            },
        );
    }
    context.planner.upsert_target(
        now,
        TargetSpec {
            id: target_id.to_string(),
            fingerprint: current_fingerprint,
            root_identity: Some(identity),
            enabled: true,
            // A replaced root stays untrusted until its watch and baseline agree.
            watcher_trusted: false,
            force_periodic_full: target.protocol.engine().mmap_writes_bypass_inotify(),
        },
    );
    tracing::info!(
        event = "soft_disk_root_identity_changed",
        instance_id = target_id,
        replacement = disposition == ObservationDisposition::Replaced,
        "soft disk root identity changed; invalidated stale scans and requested a new watch-bound full baseline"
    );
    disposition
}
