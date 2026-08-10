use std::{collections::BTreeMap, time::Duration};

pub(crate) use super::usage_tree::RootIdentity;

/// Monotonic time supplied by the caller for deterministic scheduling.
pub(crate) type PlannerTick = Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlannerConfig {
    pub scan_interval: Duration,
    pub full_scan_interval: Duration,
    pub debounce: Duration,
    pub watcher_enabled: bool,
}

impl PlannerConfig {
    fn normalized(mut self) -> Self {
        if self.scan_interval.is_zero() {
            self.scan_interval = Duration::from_nanos(1);
        }
        self.full_scan_interval = self.full_scan_interval.max(self.scan_interval);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetSpec {
    pub id: String,
    /// Hash of target properties that affect scan meaning.
    pub fingerprint: String,
    pub root_identity: Option<RootIdentity>,
    pub enabled: bool,
    pub watcher_trusted: bool,
    /// Require an authoritative full scan at every base interval.
    pub force_periodic_full: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanKind {
    Full,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanReason {
    Initial,
    TargetChanged,
    #[cfg(test)]
    ConfigurationChanged,
    Dirty,
    Overflow,
    WatcherFallback,
    PeriodicFull,
    FullDeadline,
    PartialFallback,
    RetryAfterFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanCandidate {
    pub target_id: String,
    pub kind: ScanKind,
    pub reason: ScanReason,
    pub fingerprint: String,
    pub root_identity: Option<RootIdentity>,
    /// Highest watcher generation this scan is expected to cover.
    pub captured_generation: u64,
    pub revision: u64,
    pub token: u64,
    pub due_at: PlannerTick,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanCompletion {
    Succeeded {
        performed: ScanKind,
    },
    /// Incremental accounting was ambiguous; retry with a full scan.
    #[cfg(test)]
    NeedsFull,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompletionDisposition {
    Applied,
    Stale,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpsertDisposition {
    Inserted,
    Reset,
    Unchanged,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlannerTargetStatus {
    pub baseline_available: bool,
    pub dirty_generation: u64,
    pub acknowledged_generation: u64,
    pub in_flight: bool,
    pub last_scan_at: Option<PlannerTick>,
    pub last_full_at: Option<PlannerTick>,
    pub next_periodic_due: PlannerTick,
    pub full_deadline: PlannerTick,
}

#[derive(Debug, Clone, Copy)]
struct FullRequirement {
    due_at: PlannerTick,
    generation: u64,
    reason: ScanReason,
}

#[derive(Debug, Clone, Copy)]
struct InFlight {
    token: u64,
    revision: u64,
}

#[derive(Debug, Clone)]
struct TargetState {
    spec: TargetSpec,
    revision: u64,
    dirty_generation: u64,
    acknowledged_generation: u64,
    dirty_due: Option<PlannerTick>,
    baseline_available: bool,
    full_requirement: Option<FullRequirement>,
    last_dispatch_at: Option<PlannerTick>,
    last_scan_at: Option<PlannerTick>,
    last_full_at: Option<PlannerTick>,
    next_periodic_due: PlannerTick,
    full_deadline: PlannerTick,
    in_flight: Option<InFlight>,
    last_dispatch_order: u64,
}

impl TargetState {
    fn new(spec: TargetSpec, now: PlannerTick) -> Self {
        let full_requirement = spec.enabled.then_some(FullRequirement {
            due_at: now,
            generation: 0,
            reason: ScanReason::Initial,
        });
        Self {
            spec,
            revision: 1,
            dirty_generation: 0,
            acknowledged_generation: 0,
            dirty_due: None,
            baseline_available: false,
            full_requirement,
            last_dispatch_at: None,
            last_scan_at: None,
            last_full_at: None,
            next_periodic_due: now,
            full_deadline: now,
            in_flight: None,
            last_dispatch_order: 0,
        }
    }

    fn reset(&mut self, now: PlannerTick, reason: ScanReason) {
        // Preserve the in-flight lease until its stale worker completes.
        let in_flight = self.in_flight;
        let last_dispatch_at = in_flight.and(self.last_dispatch_at);
        self.revision = self.revision.saturating_add(1);
        self.dirty_generation = 0;
        self.acknowledged_generation = 0;
        self.dirty_due = None;
        self.baseline_available = false;
        self.full_requirement = self.spec.enabled.then_some(FullRequirement {
            due_at: now,
            generation: 0,
            reason,
        });
        self.last_dispatch_at = last_dispatch_at;
        self.last_scan_at = None;
        self.last_full_at = None;
        self.next_periodic_due = now;
        self.full_deadline = now;
        self.in_flight = in_flight;
    }

    #[cfg(test)]
    fn status(&self) -> PlannerTargetStatus {
        PlannerTargetStatus {
            baseline_available: self.baseline_available,
            dirty_generation: self.dirty_generation,
            acknowledged_generation: self.acknowledged_generation,
            in_flight: self.in_flight.is_some(),
            last_scan_at: self.last_scan_at,
            last_full_at: self.last_full_at,
            next_periodic_due: self.next_periodic_due,
            full_deadline: self.full_deadline,
        }
    }
}

#[derive(Debug)]
pub(crate) struct HybridScanPlanner {
    config: PlannerConfig,
    targets: BTreeMap<String, TargetState>,
    next_token: u64,
    dispatch_order: u64,
    shutdown: bool,
}

impl HybridScanPlanner {
    pub fn new(config: PlannerConfig) -> Self {
        Self {
            config: config.normalized(),
            targets: BTreeMap::new(),
            next_token: 0,
            dispatch_order: 0,
            shutdown: false,
        }
    }

    #[cfg(test)]
    pub fn config(&self) -> PlannerConfig {
        self.config
    }

    #[cfg(test)]
    pub fn reconfigure(&mut self, now: PlannerTick, config: PlannerConfig) -> bool {
        let config = config.normalized();
        if self.config == config {
            return false;
        }
        self.config = config;
        for target in self.targets.values_mut() {
            target.reset(now, ScanReason::ConfigurationChanged);
        }
        true
    }

    pub fn upsert_target(&mut self, now: PlannerTick, spec: TargetSpec) -> UpsertDisposition {
        let id = spec.id.clone();
        let Some(target) = self.targets.get_mut(&id) else {
            self.targets.insert(id, TargetState::new(spec, now));
            return UpsertDisposition::Inserted;
        };
        if target.spec == spec {
            return UpsertDisposition::Unchanged;
        }
        target.spec = spec;
        target.reset(now, ScanReason::TargetChanged);
        UpsertDisposition::Reset
    }

    pub fn remove_target(&mut self, target_id: &str) -> bool {
        self.targets.remove(target_id).is_some()
    }

    pub fn set_watcher_trusted(
        &mut self,
        target_id: &str,
        trusted: bool,
        now: PlannerTick,
    ) -> bool {
        let Some(target) = self.targets.get_mut(target_id) else {
            return false;
        };
        if target.spec.watcher_trusted == trusted {
            return false;
        }
        target.spec.watcher_trusted = trusted;
        target.reset(now, ScanReason::TargetChanged);
        true
    }

    /// Record a monotonically increasing watcher generation.
    pub fn mark_dirty(
        &mut self,
        target_id: &str,
        now: PlannerTick,
        watcher_generation: u64,
    ) -> bool {
        let Some(target) = self.targets.get_mut(target_id) else {
            return false;
        };
        if !target.spec.enabled
            || watcher_generation == 0
            || watcher_generation <= target.dirty_generation
        {
            return false;
        }
        target.dirty_generation = watcher_generation;
        // Leading-edge debounce bounds latency during continuous activity.
        let due_at = next_dirty_due(target, now, self.config);
        target.dirty_due.get_or_insert(due_at);
        true
    }

    pub fn mark_overflow(
        &mut self,
        target_id: &str,
        now: PlannerTick,
        watcher_generation: u64,
    ) -> bool {
        let Some(target) = self.targets.get_mut(target_id) else {
            return false;
        };
        if !target.spec.enabled {
            return false;
        }
        let generation_advanced = watcher_generation > target.dirty_generation;
        if generation_advanced {
            target.dirty_generation = watcher_generation;
            let due_at = next_dirty_due(target, now, self.config);
            target.dirty_due.get_or_insert(due_at);
        }
        // New generations may expand, but never erase, a failed scan's backoff.
        if let Some(required) = &mut target.full_requirement {
            if required.reason == ScanReason::RetryAfterFailure {
                required.generation = required.generation.max(target.dirty_generation);
                return generation_advanced;
            }
            if !generation_advanced {
                return false;
            }
            // Preserve an existing cadence deadline while merging overflow work.
            required.generation = required.generation.max(target.dirty_generation);
            if required.due_at <= now {
                required.reason = ScanReason::Overflow;
            }
            return true;
        }
        target.full_requirement = Some(FullRequirement {
            due_at: now,
            generation: target.dirty_generation,
            reason: ScanReason::Overflow,
        });
        true
    }

    /// Invalidates every enabled registration after a global watcher error.
    #[cfg(test)]
    pub fn mark_all_overflow(&mut self, now: PlannerTick) -> Vec<(String, u64)> {
        let mut affected = Vec::new();
        for (id, target) in &mut self.targets {
            if !target.spec.enabled {
                continue;
            }
            target.dirty_generation = target.dirty_generation.saturating_add(1).max(1);
            target.full_requirement = Some(FullRequirement {
                due_at: now,
                generation: target.dirty_generation,
                reason: ScanReason::Overflow,
            });
            affected.push((id.clone(), target.dirty_generation));
        }
        affected
    }

    pub fn next_candidate(&mut self, now: PlannerTick) -> Option<ScanCandidate> {
        if self.shutdown {
            return None;
        }

        let selected = self
            .targets
            .iter()
            .filter_map(|(id, target)| {
                let (due_at, kind, reason) = self.due_work(target)?;
                (due_at <= now).then_some((
                    due_at,
                    target.last_dispatch_order,
                    id.clone(),
                    kind,
                    reason,
                ))
            })
            .min_by(|left, right| (left.0, left.1, &left.2).cmp(&(right.0, right.1, &right.2)))?;

        let (due_at, _, id, kind, reason) = selected;
        self.next_token = self.next_token.saturating_add(1).max(1);
        self.dispatch_order = self.dispatch_order.saturating_add(1).max(1);
        let token = self.next_token;
        let dispatch_order = self.dispatch_order;
        let target = self
            .targets
            .get_mut(&id)
            .expect("selected planner target must still exist");
        target.last_dispatch_order = dispatch_order;
        target.last_dispatch_at = Some(now);
        target.in_flight = Some(InFlight {
            token,
            revision: target.revision,
        });
        Some(ScanCandidate {
            target_id: id,
            kind,
            reason,
            fingerprint: target.spec.fingerprint.clone(),
            root_identity: target.spec.root_identity,
            captured_generation: target.dirty_generation,
            revision: target.revision,
            token,
            due_at,
        })
    }

    /// Returns the delay until non-running work is next eligible.
    pub fn next_wakeup(&self, now: PlannerTick) -> Option<Duration> {
        if self.shutdown {
            return None;
        }
        self.targets
            .values()
            .filter_map(|target| self.due_work(target).map(|work| work.0))
            .min()
            .map(|due_at| due_at.saturating_sub(now))
    }

    pub fn complete(
        &mut self,
        candidate: &ScanCandidate,
        now: PlannerTick,
        completion: ScanCompletion,
    ) -> CompletionDisposition {
        let Some(target) = self.targets.get_mut(&candidate.target_id) else {
            return CompletionDisposition::Missing;
        };
        let Some(in_flight) = target.in_flight else {
            return CompletionDisposition::Stale;
        };
        if in_flight.token != candidate.token || in_flight.revision != candidate.revision {
            return CompletionDisposition::Stale;
        }
        if target.revision != candidate.revision
            || target.spec.fingerprint != candidate.fingerprint
            || target.spec.root_identity != candidate.root_identity
        {
            // A retained pre-reset worker only releases occupancy.
            target.in_flight = None;
            return CompletionDisposition::Stale;
        }

        target.in_flight = None;
        target.last_scan_at = Some(now);
        target.next_periodic_due = add_tick(now, self.config.scan_interval);

        match completion {
            ScanCompletion::Succeeded { performed } => {
                if candidate.kind == ScanKind::Full && performed != ScanKind::Full {
                    Self::require_full_after(
                        target,
                        now,
                        candidate,
                        ScanReason::PartialFallback,
                        self.config.debounce,
                        self.config.scan_interval,
                    );
                } else {
                    Self::acknowledge_generation(
                        target,
                        candidate.captured_generation,
                        now,
                        self.config.debounce,
                        self.config.scan_interval,
                    );
                    if performed == ScanKind::Full {
                        target.baseline_available = true;
                        target.last_full_at = Some(now);
                        target.full_deadline = add_tick(now, self.config.full_scan_interval);
                        let requirement_was_covered =
                            target.full_requirement.is_some_and(|required| {
                                required.generation <= candidate.captured_generation
                            });
                        if requirement_was_covered {
                            target.full_requirement = None;
                        } else if let Some(required) = &mut target.full_requirement {
                            // Uncovered overflow remains pending at the base cadence.
                            if required.reason == ScanReason::RetryAfterFailure {
                                required.reason = ScanReason::Overflow;
                            }
                            let cadence_due = add_tick(now, self.config.scan_interval);
                            required.due_at =
                                required.due_at.max(cadence_due).min(target.full_deadline);
                        }
                    }
                }
            }
            #[cfg(test)]
            ScanCompletion::NeedsFull => {
                Self::require_full_after(
                    target,
                    now,
                    candidate,
                    ScanReason::PartialFallback,
                    self.config.debounce,
                    self.config.scan_interval,
                );
            }
            ScanCompletion::Failed => {
                let retry_at = add_tick(now, self.config.scan_interval);
                target.full_requirement = Some(FullRequirement {
                    due_at: retry_at,
                    generation: target.dirty_generation.max(candidate.captured_generation),
                    reason: ScanReason::RetryAfterFailure,
                });
            }
        }
        CompletionDisposition::Applied
    }

    #[cfg(test)]
    pub fn target_status(&self, target_id: &str) -> Option<PlannerTargetStatus> {
        self.targets.get(target_id).map(TargetState::status)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub fn shutdown(&mut self) {
        self.shutdown = true;
    }

    #[cfg(test)]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    fn require_full_after(
        target: &mut TargetState,
        now: PlannerTick,
        candidate: &ScanCandidate,
        reason: ScanReason,
        debounce: Duration,
        scan_interval: Duration,
    ) {
        target.full_requirement = Some(FullRequirement {
            due_at: add_tick(now, debounce).max(add_tick(now, scan_interval)),
            generation: target.dirty_generation.max(candidate.captured_generation),
            reason,
        });
    }

    fn acknowledge_generation(
        target: &mut TargetState,
        captured_generation: u64,
        now: PlannerTick,
        debounce: Duration,
        scan_interval: Duration,
    ) {
        target.acknowledged_generation = target.acknowledged_generation.max(captured_generation);
        if target.dirty_generation <= captured_generation {
            target.dirty_due = None;
        } else {
            // Events arriving in flight remain bounded by the base cadence.
            target.dirty_due = Some(add_tick(now, debounce).max(add_tick(now, scan_interval)));
        }
    }

    fn due_work(&self, target: &TargetState) -> Option<(PlannerTick, ScanKind, ScanReason)> {
        if !target.spec.enabled || target.in_flight.is_some() {
            return None;
        }
        if let Some(required) = target.full_requirement {
            return Some((required.due_at, ScanKind::Full, required.reason));
        }
        if !target.baseline_available {
            return Some((
                target.next_periodic_due,
                ScanKind::Full,
                ScanReason::Initial,
            ));
        }
        if !self.config.watcher_enabled || !target.spec.watcher_trusted {
            return Some((
                target.next_periodic_due,
                ScanKind::Full,
                ScanReason::WatcherFallback,
            ));
        }
        if target.spec.force_periodic_full {
            return Some((
                target.next_periodic_due,
                ScanKind::Full,
                ScanReason::PeriodicFull,
            ));
        }

        let full = (
            target.full_deadline,
            ScanKind::Full,
            ScanReason::FullDeadline,
        );
        let Some(dirty_due) = target.dirty_due else {
            return Some(full);
        };
        let partial = (dirty_due, ScanKind::Partial, ScanReason::Dirty);
        Some(if partial.0 < full.0 { partial } else { full })
    }
}

fn next_dirty_due(target: &TargetState, now: PlannerTick, config: PlannerConfig) -> PlannerTick {
    let debounce_due = add_tick(now, config.debounce);
    let last_activity = target.last_scan_at.max(target.last_dispatch_at);
    let cadence_due = last_activity
        .map(|activity| add_tick(activity, config.scan_interval))
        .unwrap_or(Duration::ZERO);
    debounce_due.max(cadence_due)
}

fn add_tick(left: PlannerTick, right: Duration) -> PlannerTick {
    left.checked_add(right).unwrap_or(Duration::MAX)
}

#[cfg(test)]
#[path = "planner_tests.rs"]
mod tests;
