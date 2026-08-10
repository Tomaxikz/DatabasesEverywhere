use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    path::PathBuf,
    time::Duration,
};

use crate::disk::soft::watcher::RetiredWatch;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct DesiredWatch {
    pub(super) fingerprint: String,
    pub(super) target_fingerprint: String,
    pub(super) root: PathBuf,
}

impl fmt::Debug for DesiredWatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesiredWatch")
            .field("fingerprint_present", &!self.fingerprint.is_empty())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) enum WatchOperation {
    Register {
        target_id: String,
        desired: DesiredWatch,
    },
    Unregister {
        target_id: String,
        retired: RetiredWatch,
    },
    RetryDegraded,
}

impl WatchOperation {
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::Register { .. } => "register",
            Self::Unregister { .. } => "unregister",
            Self::RetryDegraded => "retry_degraded",
        }
    }

    pub(super) fn target_id(&self) -> Option<&str> {
        match self {
            Self::Register { target_id, .. } | Self::Unregister { target_id, .. } => {
                Some(target_id)
            }
            Self::RetryDegraded => None,
        }
    }
}

impl fmt::Debug for WatchOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WatchOperation")
            .field("kind", &self.kind())
            .field("target_id", &self.target_id())
            .finish()
    }
}

#[derive(Clone)]
struct ActiveOperation {
    operation: WatchOperation,
    started_at: Duration,
    stall_reported: bool,
}

#[derive(Default)]
struct PendingRetirements {
    tokens: Vec<RetiredWatch>,
    unresolved_registration: bool,
}

impl PendingRetirements {
    fn insert(&mut self, retired: RetiredWatch) {
        if !self.tokens.contains(&retired) {
            self.tokens.push(retired);
        }
    }

    fn is_empty(&self) -> bool {
        self.tokens.is_empty() && !self.unresolved_registration
    }
}

/// Serializes blocking watcher operations without blocking the monitor.
#[derive(Default)]
pub(super) struct WatchOperationQueue {
    desired: BTreeMap<String, DesiredWatch>,
    applied: HashMap<String, String>,
    failed_until: HashMap<String, (String, Duration)>,
    pending_removals: BTreeMap<String, PendingRetirements>,
    active: Option<ActiveOperation>,
    retry_requested: bool,
}

impl WatchOperationQueue {
    pub(super) fn upsert(&mut self, target_id: String, desired: DesiredWatch) {
        let changed = self
            .desired
            .get(&target_id)
            .is_none_or(|existing| existing != &desired);
        if changed {
            self.applied.remove(&target_id);
            self.failed_until.remove(&target_id);
            self.desired.insert(target_id, desired);
        }
    }

    pub(super) fn remove(&mut self, target_id: &str, retired: Option<RetiredWatch>) {
        self.desired.remove(target_id);
        let was_applied = self.applied.remove(target_id).is_some();
        self.failed_until.remove(target_id);
        let registration_may_be_in_flight = self.active.as_ref().is_some_and(|active| {
            matches!(
                &active.operation,
                WatchOperation::Register {
                    target_id: active_target,
                    ..
                } if active_target == target_id
            )
        });
        if retired.is_some() || was_applied || registration_may_be_in_flight {
            let remove_empty = {
                let pending = self
                    .pending_removals
                    .entry(target_id.to_string())
                    .or_default();
                if let Some(retired) = retired {
                    pending.insert(retired);
                }
                pending.unresolved_registration |= registration_may_be_in_flight;
                pending.is_empty()
            };
            if remove_empty {
                self.pending_removals.remove(target_id);
            }
        }
    }

    pub(super) fn resolve_retirement(&mut self, target_id: &str, retired: Option<RetiredWatch>) {
        let pending = self
            .pending_removals
            .entry(target_id.to_string())
            .or_default();
        pending.unresolved_registration = false;
        if let Some(retired) = retired {
            // A late registration can add a second root that also needs cleanup.
            pending.insert(retired);
        }
        if pending.is_empty() {
            self.pending_removals.remove(target_id);
        }
    }

    pub(super) fn retirement_pending(&self, target_id: &str) -> bool {
        self.pending_removals.contains_key(target_id)
    }

    pub(super) fn request_retry(&mut self) {
        self.retry_requested = true;
    }

    pub(super) fn disable(&mut self) {
        self.desired.clear();
        self.applied.clear();
        self.failed_until.clear();
        self.pending_removals.clear();
        self.active = None;
        self.retry_requested = false;
    }

    pub(super) fn is_confirmed(&self, target_id: &str, fingerprint: &str) -> bool {
        self.desired
            .get(target_id)
            .is_some_and(|desired| desired.fingerprint == fingerprint)
            && self
                .applied
                .get(target_id)
                .is_some_and(|applied| applied == fingerprint)
    }

    pub(super) fn is_current_desire_confirmed(&self, target_id: &str) -> bool {
        self.desired.get(target_id).is_some_and(|desired| {
            self.applied
                .get(target_id)
                .is_some_and(|applied| applied == &desired.fingerprint)
        })
    }

    pub(super) fn is_current_registration(&self, operation: &WatchOperation) -> bool {
        let WatchOperation::Register { target_id, desired } = operation else {
            return false;
        };
        !self.pending_removals.contains_key(target_id)
            && self
                .desired
                .get(target_id)
                .is_some_and(|current| current == desired)
    }

    pub(super) fn next(&mut self, now: Duration) -> Option<WatchOperation> {
        if self.active.is_some() {
            return None;
        }

        let operation = if let Some((target_id, retired)) =
            self.pending_removals
                .iter()
                .find_map(|(target_id, pending)| {
                    pending
                        .tokens
                        .first()
                        .map(|token| (target_id, token.clone()))
                }) {
            WatchOperation::Unregister {
                target_id: target_id.clone(),
                retired,
            }
        } else if let Some((target_id, desired)) =
            self.desired.iter().find(|(target_id, desired)| {
                let already_applied = self
                    .applied
                    .get(*target_id)
                    .is_some_and(|applied| applied == &desired.fingerprint);
                let retry_delayed =
                    self.failed_until
                        .get(*target_id)
                        .is_some_and(|(fingerprint, retry_at)| {
                            fingerprint == &desired.fingerprint && *retry_at > now
                        });
                !already_applied && !retry_delayed
            })
        {
            WatchOperation::Register {
                target_id: target_id.clone(),
                desired: desired.clone(),
            }
        } else if self.retry_requested {
            WatchOperation::RetryDegraded
        } else {
            return None;
        };

        self.active = Some(ActiveOperation {
            operation: operation.clone(),
            started_at: now,
            stall_reported: false,
        });
        Some(operation)
    }

    pub(super) fn complete(
        &mut self,
        operation: &WatchOperation,
        succeeded: bool,
        now: Duration,
        retry_delay: Duration,
    ) -> bool {
        let Some(active) = self.active.take() else {
            return false;
        };
        if active.operation != *operation {
            self.active = Some(active);
            return false;
        }

        match operation {
            WatchOperation::Register { target_id, desired } => {
                let still_desired = self
                    .desired
                    .get(target_id)
                    .is_some_and(|current| current == desired);
                let retirement_pending = self.pending_removals.contains_key(target_id);
                if still_desired && succeeded && !retirement_pending {
                    self.applied
                        .insert(target_id.clone(), desired.fingerprint.clone());
                    self.failed_until.remove(target_id);
                } else if still_desired && !retirement_pending {
                    self.failed_until.insert(
                        target_id.clone(),
                        (desired.fingerprint.clone(), now.saturating_add(retry_delay)),
                    );
                }
            }
            WatchOperation::Unregister { target_id, retired } => {
                let remove_entry = if let Some(pending) = self.pending_removals.get_mut(target_id) {
                    if let Some(position) = pending.tokens.iter().position(|token| token == retired)
                    {
                        pending.tokens.remove(position);
                    }
                    pending.is_empty()
                } else {
                    false
                };
                if remove_entry {
                    self.pending_removals.remove(target_id);
                }
            }
            WatchOperation::RetryDegraded => self.retry_requested = false,
        }
        true
    }

    pub(super) fn fail_active(
        &mut self,
        now: Duration,
        retry_delay: Duration,
    ) -> Option<WatchOperation> {
        let operation = self.active.as_ref()?.operation.clone();
        self.complete(&operation, false, now, retry_delay)
            .then_some(operation)
    }

    pub(super) fn take_stalled(
        &mut self,
        now: Duration,
        deadline: Duration,
    ) -> Option<WatchOperation> {
        let active = self.active.as_mut()?;
        if active.stall_reported || now.saturating_sub(active.started_at) < deadline {
            return None;
        }
        active.stall_reported = true;
        Some(active.operation.clone())
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.desired.len() + self.pending_removals.len() + usize::from(self.retry_requested)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::soft::{
        planner::{HybridScanPlanner, PlannerConfig, ScanKind, TargetSpec},
        usage_tree::RootIdentity,
    };

    fn desired(name: &str) -> DesiredWatch {
        DesiredWatch {
            fingerprint: format!("fingerprint-{name}"),
            target_fingerprint: format!("target-{name}"),
            root: PathBuf::from(format!("/srv/{name}")),
        }
    }

    #[test]
    fn repeated_reconciliation_coalesces_to_one_registration() {
        let mut queue = WatchOperationQueue::default();
        queue.upsert("one".to_string(), desired("one"));
        queue.upsert("one".to_string(), desired("one"));
        assert_eq!(queue.pending_len(), 1);

        let operation = queue.next(Duration::ZERO).unwrap();
        assert!(queue.next(Duration::ZERO).is_none());
        assert!(queue.complete(&operation, true, Duration::ZERO, Duration::from_secs(15)));
        assert!(queue.next(Duration::ZERO).is_none());
        assert!(queue.is_confirmed("one", "fingerprint-one"));
    }

    #[test]
    fn stale_registration_completion_cannot_confirm_a_replaced_root() {
        let mut queue = WatchOperationQueue::default();
        queue.upsert("one".to_string(), desired("one"));
        let stale = queue.next(Duration::ZERO).unwrap();
        queue.upsert("one".to_string(), desired("replacement"));
        assert!(!queue.is_current_registration(&stale));
        assert!(queue.complete(&stale, true, Duration::ZERO, Duration::from_secs(15)));
        assert!(!queue.is_confirmed("one", "fingerprint-replacement"));
        assert!(matches!(
            queue.next(Duration::ZERO),
            Some(WatchOperation::Register { desired, .. })
                if desired.fingerprint == "fingerprint-replacement"
        ));
    }

    #[test]
    fn removal_during_registration_is_coalesced_into_one_unregister() {
        let mut queue = WatchOperationQueue::default();
        queue.upsert("one".to_string(), desired("one"));
        let register = queue.next(Duration::ZERO).unwrap();
        queue.remove("one", None);
        assert!(queue.complete(&register, true, Duration::ZERO, Duration::from_secs(15)));
        queue.resolve_retirement(
            "one",
            Some(RetiredWatch::for_test(PathBuf::from("/srv/one"))),
        );
        assert!(matches!(
            queue.next(Duration::ZERO),
            Some(WatchOperation::Unregister { target_id, .. }) if target_id == "one"
        ));
    }

    #[test]
    fn late_registration_completion_preserves_an_existing_retirement_token() {
        let mut queue = WatchOperationQueue::default();
        queue.upsert("one".to_string(), desired("one"));
        let register = queue.next(Duration::ZERO).unwrap();
        queue.remove(
            "one",
            Some(RetiredWatch::for_test(PathBuf::from("/srv/one"))),
        );
        assert!(queue.complete(&register, true, Duration::ZERO, Duration::from_secs(15)));

        queue.resolve_retirement("one", None);

        assert!(queue.retirement_pending("one"));
        assert!(matches!(
            queue.next(Duration::ZERO),
            Some(WatchOperation::Unregister { target_id, .. }) if target_id == "one"
        ));
    }

    #[test]
    fn rapid_same_desire_readd_does_not_confirm_a_stale_registration() {
        let mut queue = WatchOperationQueue::default();
        let desired = desired("one");
        queue.upsert("one".to_string(), desired.clone());
        let stale_register = queue.next(Duration::ZERO).unwrap();
        queue.remove(
            "one",
            Some(RetiredWatch::for_test(PathBuf::from("/srv/one"))),
        );
        queue.upsert("one".to_string(), desired);
        assert!(!queue.is_current_registration(&stale_register));

        assert!(queue.complete(
            &stale_register,
            false,
            Duration::ZERO,
            Duration::from_secs(15)
        ));
        queue.resolve_retirement("one", None);

        assert!(!queue.is_current_desire_confirmed("one"));
        let unregister = queue.next(Duration::ZERO).unwrap();
        assert!(matches!(
            &unregister,
            WatchOperation::Unregister { target_id, .. } if target_id == "one"
        ));
        assert!(queue.complete(&unregister, true, Duration::ZERO, Duration::from_secs(15)));
        assert!(matches!(
            queue.next(Duration::ZERO),
            Some(WatchOperation::Register { target_id, .. }) if target_id == "one"
        ));
    }

    fn assert_applied_remove_readd_order(replacement: DesiredWatch) {
        let mut queue = WatchOperationQueue::default();
        queue.upsert("one".to_string(), desired("one"));
        let initial = queue.next(Duration::ZERO).unwrap();
        assert!(queue.complete(&initial, true, Duration::ZERO, Duration::from_secs(15)));
        queue.remove(
            "one",
            Some(RetiredWatch::for_test(PathBuf::from("/srv/one"))),
        );
        queue.upsert("one".to_string(), replacement.clone());

        let unregister = queue.next(Duration::ZERO).unwrap();
        assert!(matches!(&unregister, WatchOperation::Unregister { .. }));
        assert!(queue.complete(&unregister, true, Duration::ZERO, Duration::from_secs(15)));
        assert!(matches!(
            queue.next(Duration::ZERO),
            Some(WatchOperation::Register { desired, .. }) if desired == replacement
        ));
    }

    #[test]
    fn applied_remove_then_same_root_readd_unregisters_before_registering() {
        assert_applied_remove_readd_order(desired("one"));
    }

    #[test]
    fn applied_remove_then_changed_root_readd_unregisters_before_registering() {
        assert_applied_remove_readd_order(desired("replacement"));
    }

    #[test]
    fn stale_unregister_completion_cannot_erase_a_newer_retirement_token() {
        let mut queue = WatchOperationQueue::default();
        queue.remove(
            "one",
            Some(RetiredWatch::for_test(PathBuf::from("/srv/old"))),
        );
        let stale = queue.next(Duration::ZERO).unwrap();
        queue.remove(
            "one",
            Some(RetiredWatch::for_test(PathBuf::from("/srv/new"))),
        );

        assert!(queue.complete(&stale, true, Duration::ZERO, Duration::from_secs(15)));

        assert!(queue.retirement_pending("one"));
        assert!(matches!(
            queue.next(Duration::ZERO),
            Some(WatchOperation::Unregister { retired, .. })
                if retired == RetiredWatch::for_test(PathBuf::from("/srv/new"))
        ));
    }

    #[test]
    fn late_changed_root_registration_preserves_both_retirement_tokens() {
        let mut queue = WatchOperationQueue::default();
        queue.upsert("one".to_string(), desired("old"));
        let initial = queue.next(Duration::ZERO).unwrap();
        assert!(queue.complete(&initial, true, Duration::ZERO, Duration::from_secs(15)));
        queue.upsert("one".to_string(), desired("new"));
        let changed_register = queue.next(Duration::ZERO).unwrap();

        let old = RetiredWatch::for_test(PathBuf::from("/srv/old"));
        let new = RetiredWatch::for_test(PathBuf::from("/srv/new"));
        queue.remove("one", Some(old.clone()));
        assert!(queue.complete(
            &changed_register,
            false,
            Duration::ZERO,
            Duration::from_secs(15)
        ));
        queue.resolve_retirement("one", Some(new.clone()));

        let unregister_old = queue.next(Duration::ZERO).unwrap();
        assert!(matches!(
            &unregister_old,
            WatchOperation::Unregister { retired, .. } if retired == &old
        ));
        assert!(queue.complete(
            &unregister_old,
            true,
            Duration::ZERO,
            Duration::from_secs(15)
        ));
        let unregister_new = queue.next(Duration::ZERO).unwrap();
        assert!(matches!(
            &unregister_new,
            WatchOperation::Unregister { retired, .. } if retired == &new
        ));
        assert!(queue.complete(
            &unregister_new,
            true,
            Duration::ZERO,
            Duration::from_secs(15)
        ));
        assert!(!queue.retirement_pending("one"));
        assert!(queue.next(Duration::ZERO).is_none());
    }

    #[test]
    fn missing_retirement_token_clears_only_an_unresolved_placeholder() {
        let mut queue = WatchOperationQueue::default();
        queue.upsert("one".to_string(), desired("one"));
        let register = queue.next(Duration::ZERO).unwrap();
        queue.remove("one", None);
        assert!(queue.retirement_pending("one"));
        assert!(queue.complete(&register, false, Duration::ZERO, Duration::from_secs(15)));

        queue.resolve_retirement("one", None);

        assert!(!queue.retirement_pending("one"));
        assert!(queue.next(Duration::ZERO).is_none());
    }

    #[test]
    fn failed_registration_uses_bounded_retry_delay() {
        let mut queue = WatchOperationQueue::default();
        queue.upsert("one".to_string(), desired("one"));
        let operation = queue.next(Duration::ZERO).unwrap();
        queue.complete(&operation, false, Duration::ZERO, Duration::from_secs(15));
        assert!(queue.next(Duration::from_secs(14)).is_none());
        assert!(matches!(
            queue.next(Duration::from_secs(15)),
            Some(WatchOperation::Register { .. })
        ));
    }

    #[test]
    fn a_stalled_operation_is_reported_once_without_spawning_another() {
        let mut queue = WatchOperationQueue::default();
        queue.upsert("one".to_string(), desired("one"));
        let operation = queue.next(Duration::from_secs(1)).unwrap();
        assert!(queue.next(Duration::from_secs(2)).is_none());
        assert!(
            queue
                .take_stalled(Duration::from_secs(30), Duration::from_secs(30))
                .is_none()
        );
        assert_eq!(
            queue.take_stalled(Duration::from_secs(31), Duration::from_secs(30)),
            Some(operation)
        );
        assert!(
            queue
                .take_stalled(Duration::from_secs(60), Duration::from_secs(30))
                .is_none()
        );
    }

    #[test]
    fn retries_wait_behind_registration_and_are_coalesced() {
        let mut queue = WatchOperationQueue::default();
        queue.request_retry();
        queue.request_retry();
        queue.upsert("one".to_string(), desired("one"));
        let registration = queue.next(Duration::ZERO).unwrap();
        assert!(matches!(registration, WatchOperation::Register { .. }));
        queue.complete(&registration, true, Duration::ZERO, Duration::from_secs(15));
        assert_eq!(
            queue.next(Duration::ZERO),
            Some(WatchOperation::RetryDegraded)
        );
    }

    #[test]
    fn blocked_kernel_registration_does_not_delay_initial_full_baseline() {
        let mut queue = WatchOperationQueue::default();
        queue.upsert("one".to_string(), desired("one"));
        assert!(matches!(
            queue.next(Duration::ZERO),
            Some(WatchOperation::Register { .. })
        ));

        let mut planner = HybridScanPlanner::new(PlannerConfig {
            scan_interval: Duration::from_secs(15),
            full_scan_interval: Duration::from_secs(90),
            debounce: Duration::from_millis(500),
            watcher_enabled: true,
        });
        planner.upsert_target(
            Duration::ZERO,
            TargetSpec {
                id: "one".to_string(),
                fingerprint: "scanner-one".to_string(),
                root_identity: Some(RootIdentity {
                    device: 1,
                    inode: 2,
                }),
                enabled: true,
                watcher_trusted: false,
                force_periodic_full: false,
            },
        );

        let baseline = planner.next_candidate(Duration::ZERO).unwrap();
        assert_eq!(baseline.kind, ScanKind::Full);
        assert!(queue.next(Duration::ZERO).is_none());
    }

    #[test]
    fn disabling_acceleration_discards_active_and_queued_kernel_work() {
        let mut queue = WatchOperationQueue::default();
        queue.upsert("one".to_string(), desired("one"));
        queue.upsert("two".to_string(), desired("two"));
        assert!(queue.next(Duration::ZERO).is_some());
        queue.request_retry();

        queue.disable();

        assert_eq!(queue.pending_len(), 0);
        assert!(queue.next(Duration::from_secs(60)).is_none());
        assert!(!queue.is_current_desire_confirmed("one"));
    }
}
