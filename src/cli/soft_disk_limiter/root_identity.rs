use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::disk::soft::planner::RootIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ObservationDisposition {
    Initialized,
    Unchanged,
    Replaced,
    StaleTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    target_fingerprint: String,
    identity: RootIdentity,
}

/// Tracks identities observed by bounded scan and watch workers.
#[derive(Debug, Default)]
pub(super) struct RootIdentityTracker {
    observations: HashMap<String, Observation>,
}

impl RootIdentityTracker {
    pub(super) fn identity_for(
        &self,
        target_id: &str,
        target_fingerprint: &str,
    ) -> Option<RootIdentity> {
        self.observations
            .get(target_id)
            .filter(|observation| observation.target_fingerprint == target_fingerprint)
            .map(|observation| observation.identity)
    }

    pub(super) fn observe(
        &mut self,
        target_id: &str,
        completed_fingerprint: &str,
        current_fingerprint: &str,
        identity: RootIdentity,
    ) -> ObservationDisposition {
        if completed_fingerprint != current_fingerprint {
            return ObservationDisposition::StaleTarget;
        }
        match self.observations.get_mut(target_id) {
            Some(observation) if observation.target_fingerprint == current_fingerprint => {
                if observation.identity == identity {
                    ObservationDisposition::Unchanged
                } else {
                    observation.identity = identity;
                    ObservationDisposition::Replaced
                }
            }
            observation => {
                let value = Observation {
                    target_fingerprint: current_fingerprint.to_string(),
                    identity,
                };
                if let Some(observation) = observation {
                    *observation = value;
                } else {
                    self.observations.insert(target_id.to_string(), value);
                }
                ObservationDisposition::Initialized
            }
        }
    }

    pub(super) fn retain_targets(&mut self, current: &HashMap<String, String>) {
        self.observations.retain(|target_id, observation| {
            current
                .get(target_id)
                .is_some_and(|fingerprint| fingerprint == &observation.target_fingerprint)
        });
    }
}

/// Binds a watch to both metadata generation and opened inode.
pub(super) fn watch_fingerprint(
    target_fingerprint: &str,
    identity: Option<RootIdentity>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(target_fingerprint.len().to_le_bytes());
    digest.update(target_fingerprint.as_bytes());
    if let Some(identity) = identity {
        digest.update(identity.device.to_le_bytes());
        digest.update(identity.inode.to_le_bytes());
    }
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::super::{
        CompletedSoftDiskScan, CompletedWatchOperation, WatchOperationResult,
        complete_soft_disk_scan, complete_watch_operation,
        watch_operations::{DesiredWatch, WatchOperationQueue},
    };
    use super::*;
    use crate::{
        disk::{
            soft::{
                HybridScanExecution, PerformedScanKind, ScanOutcome, SoftDiskSnapshot,
                SoftDiskTarget,
                planner::{HybridScanPlanner, PlannerConfig, TargetSpec},
                watcher::{RegistrationStatus, WatchRegistration},
            },
            usage::DirectoryUsage,
        },
        shared::protocol::Protocol,
    };
    use std::{
        path::PathBuf,
        time::{Duration, Instant},
    };

    fn identity(device: u64, inode: u64) -> RootIdentity {
        RootIdentity { device, inode }
    }

    fn target() -> SoftDiskTarget {
        SoftDiskTarget {
            instance_id: "one".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            protocol: Protocol::Postgres,
            data_path: PathBuf::from("/srv/one"),
            limit_bytes: 1024,
            durable_blocked: false,
        }
    }

    fn planner(root_identity: RootIdentity) -> HybridScanPlanner {
        let mut planner = HybridScanPlanner::new(PlannerConfig {
            scan_interval: Duration::from_secs(15),
            full_scan_interval: Duration::from_secs(90),
            debounce: Duration::from_millis(500),
            watcher_enabled: true,
        });
        let target = target();
        let fingerprint = target.scanner_fingerprint();
        planner.upsert_target(
            Duration::ZERO,
            TargetSpec {
                id: target.instance_id,
                fingerprint,
                root_identity: Some(root_identity),
                enabled: true,
                watcher_trusted: false,
                force_periodic_full: false,
            },
        );
        planner
    }

    #[test]
    fn first_bounded_worker_observation_initializes_identity() {
        let mut tracker = RootIdentityTracker::default();
        assert_eq!(tracker.identity_for("one", "generation"), None);
        assert_eq!(
            tracker.observe("one", "generation", "generation", identity(1, 2)),
            ObservationDisposition::Initialized
        );
        assert_eq!(
            tracker.identity_for("one", "generation"),
            Some(identity(1, 2))
        );
    }

    #[test]
    fn same_path_identity_replacement_changes_watch_fingerprint() {
        let mut tracker = RootIdentityTracker::default();
        tracker.observe("one", "generation", "generation", identity(1, 2));
        let before = watch_fingerprint("generation", tracker.identity_for("one", "generation"));
        assert_eq!(
            tracker.observe("one", "generation", "generation", identity(1, 3)),
            ObservationDisposition::Replaced
        );
        let after = watch_fingerprint("generation", tracker.identity_for("one", "generation"));
        assert_ne!(before, after);
    }

    #[test]
    fn stale_completion_cannot_overwrite_reused_target_identity() {
        let mut tracker = RootIdentityTracker::default();
        tracker.observe("one", "new", "new", identity(8, 9));
        assert_eq!(
            tracker.observe("one", "old", "new", identity(1, 2)),
            ObservationDisposition::StaleTarget
        );
        assert_eq!(tracker.identity_for("one", "new"), Some(identity(8, 9)));
    }

    #[test]
    fn metadata_generation_change_drops_old_observation_on_reconcile() {
        let mut tracker = RootIdentityTracker::default();
        tracker.observe("one", "old", "old", identity(1, 2));
        tracker.retain_targets(&HashMap::from([("one".to_string(), "new".to_string())]));
        assert_eq!(tracker.identity_for("one", "old"), None);
        assert_eq!(tracker.identity_for("one", "new"), None);
    }

    #[test]
    fn stale_watch_completion_cannot_revert_a_newer_root_identity() {
        let target = target();
        let target_fingerprint = target.scanner_fingerprint();
        let old_identity = identity(1, 2);
        let new_identity = identity(1, 3);
        let mut tracker = RootIdentityTracker::default();
        tracker.observe(
            "one",
            &target_fingerprint,
            &target_fingerprint,
            new_identity,
        );
        let mut queue = WatchOperationQueue::default();
        queue.upsert(
            "one".to_string(),
            DesiredWatch {
                fingerprint: watch_fingerprint(&target_fingerprint, Some(old_identity)),
                target_fingerprint: target_fingerprint.clone(),
                root: target.data_path.clone(),
            },
        );
        let stale = queue.next(Duration::ZERO).unwrap();
        queue.upsert(
            "one".to_string(),
            DesiredWatch {
                fingerprint: watch_fingerprint(&target_fingerprint, Some(new_identity)),
                target_fingerprint: target_fingerprint.clone(),
                root: target.data_path.clone(),
            },
        );
        let completed = CompletedWatchOperation {
            operation: stale,
            result: Ok(WatchOperationResult::Registered {
                registration: WatchRegistration {
                    status: RegistrationStatus::Watching,
                    changed: true,
                    full_reconcile_pending: true,
                },
                root_identity: old_identity,
            }),
        };
        let mut planner = planner(new_identity);
        let targets = HashMap::from([("one".to_string(), target)]);
        complete_watch_operation(
            Ok(completed),
            super::super::RootObservationContext {
                watcher: &None,
                planner: &mut planner,
                targets: &targets,
                root_identities: &mut tracker,
                watch_queue: &mut queue,
            },
            Duration::from_secs(1),
            Duration::from_secs(15),
        );
        assert_eq!(
            tracker.identity_for("one", &target_fingerprint),
            Some(new_identity)
        );
    }

    #[test]
    fn stale_scan_completion_cannot_revert_a_newer_root_identity() {
        let target = target();
        let fingerprint = target.scanner_fingerprint();
        let old_identity = identity(1, 2);
        let new_identity = identity(1, 3);
        let mut planner = planner(old_identity);
        let old_candidate = planner.next_candidate(Duration::ZERO).unwrap();
        planner.upsert_target(
            Duration::from_secs(1),
            TargetSpec {
                id: target.instance_id.clone(),
                fingerprint: fingerprint.clone(),
                root_identity: Some(new_identity),
                enabled: true,
                watcher_trusted: false,
                force_periodic_full: false,
            },
        );
        let mut tracker = RootIdentityTracker::default();
        tracker.observe("one", &fingerprint, &fingerprint, new_identity);
        let snapshot = SoftDiskSnapshot {
            usage: DirectoryUsage::default(),
            limit_bytes: target.limit_bytes,
            stop_threshold_bytes: target.limit_bytes,
            recovery_threshold_bytes: target.limit_bytes / 2,
            growth_bytes_per_second: 0.0,
            peak_growth_bytes_per_second: 0.0,
            predicted_seconds_to_limit: None,
            blocked: false,
            sampled_at: Instant::now(),
        };
        let completed = CompletedSoftDiskScan {
            candidate: old_candidate,
            batch: None,
            target: target.clone(),
            elapsed: Duration::from_millis(1),
            result: Ok(HybridScanExecution {
                outcome: ScanOutcome::Healthy(snapshot),
                performed: PerformedScanKind::Full,
                measurement_succeeded: true,
                root_identity: Some(old_identity),
            }),
        };
        complete_soft_disk_scan(
            completed,
            &None,
            &HashMap::from([("one".to_string(), target)]),
            &mut tracker,
            &mut WatchOperationQueue::default(),
            &mut planner,
            Duration::from_secs(2),
        );
        assert_eq!(
            tracker.identity_for("one", &fingerprint),
            Some(new_identity)
        );
        assert_eq!(
            planner
                .next_candidate(Duration::from_secs(2))
                .unwrap()
                .root_identity,
            Some(new_identity)
        );
    }
}
