use super::*;

fn seconds(value: u64) -> Duration {
    Duration::from_secs(value)
}

fn millis(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn config() -> PlannerConfig {
    PlannerConfig {
        scan_interval: seconds(15),
        full_scan_interval: seconds(90),
        debounce: millis(500),
        watcher_enabled: true,
    }
}

fn target(id: &str) -> TargetSpec {
    TargetSpec {
        id: id.to_string(),
        fingerprint: format!("fingerprint:{id}"),
        root_identity: Some(RootIdentity {
            device: 7,
            inode: id.len() as u64,
        }),
        enabled: true,
        watcher_trusted: true,
        force_periodic_full: false,
    }
}

fn complete_full(planner: &mut HybridScanPlanner, candidate: &ScanCandidate, now: PlannerTick) {
    assert_eq!(candidate.kind, ScanKind::Full);
    assert_eq!(
        planner.complete(
            candidate,
            now,
            ScanCompletion::Succeeded {
                performed: ScanKind::Full,
            },
        ),
        CompletionDisposition::Applied
    );
}

fn planner_with_baseline(id: &str, completed_at: PlannerTick) -> HybridScanPlanner {
    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, target(id));
    let candidate = planner
        .next_candidate(Duration::ZERO)
        .expect("expected a value from next_candidate");
    complete_full(&mut planner, &candidate, completed_at);
    planner
}

#[test]
fn zero_base_interval_is_normalized_and_full_interval_never_precedes_it() {
    let planner = HybridScanPlanner::new(PlannerConfig {
        scan_interval: Duration::ZERO,
        full_scan_interval: Duration::ZERO,
        debounce: Duration::ZERO,
        watcher_enabled: true,
    });
    assert_eq!(planner.config().scan_interval, Duration::from_nanos(1));
    assert_eq!(planner.config().full_scan_interval, Duration::from_nanos(1));

    let planner = HybridScanPlanner::new(PlannerConfig {
        scan_interval: seconds(120),
        full_scan_interval: seconds(90),
        ..config()
    });
    assert_eq!(planner.config().full_scan_interval, seconds(120));
}

#[test]
fn a_new_enabled_target_requires_an_immediate_full_scan() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    assert_eq!(
        planner.upsert_target(seconds(4), target("a")),
        UpsertDisposition::Inserted
    );
    let candidate = planner
        .next_candidate(seconds(4))
        .context("expected a value from next_candidate")?;
    assert_eq!(candidate.kind, ScanKind::Full);
    assert_eq!(candidate.reason, ScanReason::Initial);
    assert_eq!(candidate.due_at, seconds(4));

    Ok(())
}

#[test]
fn disabled_targets_do_not_schedule_until_enabled() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    let mut spec = target("a");
    spec.enabled = false;
    planner.upsert_target(Duration::ZERO, spec.clone());
    assert!(planner.next_candidate(seconds(100)).is_none());
    assert!(planner.next_wakeup(seconds(100)).is_none());

    spec.enabled = true;
    assert_eq!(
        planner.upsert_target(seconds(101), spec),
        UpsertDisposition::Reset
    );
    assert_eq!(
        planner
            .next_candidate(seconds(101))
            .context("seconds should provide a value")?
            .kind,
        ScanKind::Full
    );

    Ok(())
}

#[test]
fn an_identical_upsert_preserves_a_valid_baseline() {
    let mut planner = planner_with_baseline("a", seconds(1));
    assert_eq!(
        planner.upsert_target(seconds(2), target("a")),
        UpsertDisposition::Unchanged
    );
    assert_eq!(planner.next_wakeup(seconds(2)), Some(seconds(89)));
}

#[test]
fn fingerprint_changes_invalidate_the_baseline_and_in_flight_scan() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", seconds(1));
    planner.mark_dirty("a", seconds(20), 1);
    let partial = planner
        .next_candidate(millis(20_500))
        .context("expected a value from next_candidate")?;
    let mut changed = target("a");
    changed.fingerprint.push_str(":replacement");
    planner.upsert_target(seconds(21), changed);

    assert_eq!(
        planner.complete(
            &partial,
            seconds(22),
            ScanCompletion::Succeeded {
                performed: ScanKind::Partial,
            },
        ),
        CompletionDisposition::Stale
    );
    assert_eq!(
        planner
            .next_candidate(seconds(22))
            .context("seconds should provide a value")?
            .reason,
        ScanReason::TargetChanged
    );

    Ok(())
}

#[test]
fn old_revision_releases_occupancy_before_replacement_full_scan_starts() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, target("a"));
    let old_revision = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;

    let mut replacement = target("a");
    replacement.fingerprint.push_str(":new-root");
    assert_eq!(
        planner.upsert_target(seconds(1), replacement.clone()),
        UpsertDisposition::Reset
    );

    // The stale worker retains the instance's single scan slot.
    assert!(
        planner
            .target_status("a")
            .context("target status should provide a value")?
            .in_flight
    );
    assert!(planner.next_candidate(seconds(100)).is_none());
    assert_eq!(
        planner.complete(
            &old_revision,
            seconds(101),
            ScanCompletion::Succeeded {
                performed: ScanKind::Full,
            },
        ),
        CompletionDisposition::Stale
    );

    let current_revision = planner
        .next_candidate(seconds(101))
        .context("expected a value from next_candidate")?;
    assert_eq!(current_revision.kind, ScanKind::Full);
    assert_eq!(current_revision.reason, ScanReason::TargetChanged);
    assert_eq!(current_revision.fingerprint, replacement.fingerprint);
    complete_full(&mut planner, &current_revision, seconds(102));

    assert_eq!(
        planner.complete(
            &old_revision,
            seconds(103),
            ScanCompletion::Succeeded {
                performed: ScanKind::Full,
            },
        ),
        CompletionDisposition::Stale
    );
    let status = planner
        .target_status("a")
        .context("expected a value from target_status")?;
    assert!(status.baseline_available);
    assert_eq!(status.last_full_at, Some(seconds(102)));

    Ok(())
}

#[test]
fn root_identity_changes_require_a_new_full_baseline() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", seconds(1));
    let mut replacement = target("a");
    replacement.root_identity = Some(RootIdentity {
        device: 9,
        inode: 99,
    });
    planner.upsert_target(seconds(5), replacement);
    let candidate = planner
        .next_candidate(seconds(5))
        .context("expected a value from next_candidate")?;
    assert_eq!(candidate.kind, ScanKind::Full);
    assert_eq!(candidate.reason, ScanReason::TargetChanged);

    Ok(())
}

#[test]
fn removing_a_target_cleans_pending_and_in_flight_state() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, target("a"));
    let candidate = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    assert!(planner.remove_target("a"));
    assert!(!planner.remove_target("a"));
    assert!(planner.is_empty());
    assert_eq!(
        planner.complete(&candidate, seconds(1), ScanCompletion::Failed),
        CompletionDisposition::Missing
    );

    Ok(())
}

#[test]
fn dirty_before_the_initial_baseline_does_not_downgrade_the_full_scan() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, target("a"));
    planner.mark_dirty("a", Duration::ZERO, 3);
    let candidate = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    assert_eq!(candidate.kind, ScanKind::Full);
    assert_eq!(candidate.captured_generation, 3);

    Ok(())
}

#[test]
fn successful_full_scan_sets_baseline_periodic_due_and_fixed_deadline() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let planner = planner_with_baseline("a", seconds(2));
    let status = planner
        .target_status("a")
        .context("expected a value from target_status")?;
    assert!(status.baseline_available);
    assert_eq!(status.last_scan_at, Some(seconds(2)));
    assert_eq!(status.last_full_at, Some(seconds(2)));
    assert_eq!(status.next_periodic_due, seconds(17));
    assert_eq!(status.full_deadline, seconds(92));

    Ok(())
}

#[test]
fn clean_trusted_target_sleeps_until_the_mandatory_full_deadline() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", seconds(1));
    assert!(planner.next_candidate(seconds(90)).is_none());
    assert_eq!(planner.next_wakeup(seconds(90)), Some(seconds(1)));
    let candidate = planner
        .next_candidate(seconds(91))
        .context("expected a value from next_candidate")?;
    assert_eq!(candidate.kind, ScanKind::Full);
    assert_eq!(candidate.reason, ScanReason::FullDeadline);

    Ok(())
}

#[test]
fn dirty_change_is_not_due_before_debounce() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    assert!(planner.mark_dirty("a", seconds(20), 1));
    assert!(planner.next_candidate(millis(20_499)).is_none());
    assert_eq!(planner.next_wakeup(millis(20_499)), Some(millis(1)));
    let candidate = planner
        .next_candidate(millis(20_500))
        .context("expected a value from next_candidate")?;
    assert_eq!(candidate.kind, ScanKind::Partial);
    assert_eq!(candidate.reason, ScanReason::Dirty);

    Ok(())
}

#[test]
fn event_storm_coalesces_without_postponing_the_leading_deadline() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    planner.mark_dirty("a", seconds(20), 1);
    planner.mark_dirty("a", millis(20_100), 2);
    planner.mark_dirty("a", millis(20_499), 50);
    let candidate = planner
        .next_candidate(millis(20_500))
        .context("expected a value from next_candidate")?;
    assert_eq!(candidate.due_at, millis(20_500));
    assert_eq!(candidate.captured_generation, 50);

    Ok(())
}

#[test]
fn continuous_dirty_events_are_bounded_to_one_scan_per_base_interval() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    for generation in 1..=100 {
        let event_at = millis(generation * 100);
        assert!(planner.mark_dirty("a", event_at, generation));
    }

    // Base cadence delays dirty work until t=15.
    assert!(planner.next_candidate(millis(14_999)).is_none());
    let first = planner
        .next_candidate(seconds(15))
        .context("expected a value from next_candidate")?;
    assert_eq!(first.kind, ScanKind::Partial);
    assert_eq!(first.captured_generation, 100);

    // Writes during the scan begin a fresh base interval.
    for generation in 101..=150 {
        let event_at = millis(15_000 + (generation - 100) * 2);
        assert!(planner.mark_dirty("a", event_at, generation));
    }
    planner.complete(
        &first,
        millis(15_200),
        ScanCompletion::Succeeded {
            performed: ScanKind::Partial,
        },
    );
    assert!(planner.next_candidate(millis(30_199)).is_none());
    let second = planner
        .next_candidate(millis(30_200))
        .context("expected a value from next_candidate")?;
    assert_eq!(second.kind, ScanKind::Partial);
    assert_eq!(second.captured_generation, 150);

    Ok(())
}

#[test]
fn duplicate_or_out_of_order_generations_are_ignored() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    assert!(planner.mark_dirty("a", seconds(1), 5));
    assert!(!planner.mark_dirty("a", seconds(2), 5));
    assert!(!planner.mark_dirty("a", seconds(2), 4));
    assert!(!planner.mark_dirty("a", seconds(2), 0));
    assert_eq!(
        planner
            .target_status("a")
            .context("target status should provide a value")?
            .dirty_generation,
        5
    );

    Ok(())
}

#[test]
fn successful_partial_acknowledges_exactly_the_captured_generation() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    planner.mark_dirty("a", seconds(20), 7);
    let candidate = planner
        .next_candidate(millis(20_500))
        .context("expected a value from next_candidate")?;
    planner.complete(
        &candidate,
        seconds(21),
        ScanCompletion::Succeeded {
            performed: ScanKind::Partial,
        },
    );
    let status = planner
        .target_status("a")
        .context("expected a value from target_status")?;
    assert_eq!(status.acknowledged_generation, 7);
    assert_eq!(status.dirty_generation, 7);
    assert_eq!(planner.next_wakeup(seconds(21)), Some(seconds(69)));

    Ok(())
}

#[test]
fn event_arriving_during_scan_remains_dirty_and_is_redebounced() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    planner.mark_dirty("a", seconds(20), 1);
    let candidate = planner
        .next_candidate(millis(20_500))
        .context("expected a value from next_candidate")?;
    planner.mark_dirty("a", millis(20_600), 2);
    planner.complete(
        &candidate,
        seconds(21),
        ScanCompletion::Succeeded {
            performed: ScanKind::Partial,
        },
    );
    assert!(planner.next_candidate(millis(35_999)).is_none());
    let next = planner
        .next_candidate(seconds(36))
        .context("expected a value from next_candidate")?;
    assert_eq!(next.kind, ScanKind::Partial);
    assert_eq!(next.captured_generation, 2);

    Ok(())
}

#[test]
fn partial_scans_never_postpone_the_mandatory_full_deadline() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", seconds(1));
    planner.mark_dirty("a", seconds(40), 1);
    let partial = planner
        .next_candidate(millis(40_500))
        .context("expected a value from next_candidate")?;
    planner.complete(
        &partial,
        seconds(41),
        ScanCompletion::Succeeded {
            performed: ScanKind::Partial,
        },
    );
    assert_eq!(
        planner
            .target_status("a")
            .context("target status should provide a value")?
            .full_deadline,
        seconds(91)
    );
    assert_eq!(
        planner
            .next_candidate(seconds(91))
            .context("seconds should provide a value")?
            .reason,
        ScanReason::FullDeadline
    );

    Ok(())
}

#[test]
fn actual_full_fallback_from_partial_refreshes_the_full_deadline() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    planner.mark_dirty("a", seconds(20), 1);
    let candidate = planner
        .next_candidate(millis(20_500))
        .context("expected a value from next_candidate")?;
    assert_eq!(candidate.kind, ScanKind::Partial);
    planner.complete(
        &candidate,
        seconds(22),
        ScanCompletion::Succeeded {
            performed: ScanKind::Full,
        },
    );
    let status = planner
        .target_status("a")
        .context("expected a value from target_status")?;
    assert_eq!(status.last_full_at, Some(seconds(22)));
    assert_eq!(status.full_deadline, seconds(112));

    Ok(())
}

#[test]
fn a_full_candidate_reported_as_partial_remains_full_required() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, target("a"));
    let candidate = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    planner.complete(
        &candidate,
        seconds(1),
        ScanCompletion::Succeeded {
            performed: ScanKind::Partial,
        },
    );
    assert!(planner.next_candidate(seconds(15)).is_none());
    let retry = planner
        .next_candidate(seconds(16))
        .context("expected a value from next_candidate")?;
    assert_eq!(retry.kind, ScanKind::Full);
    assert_eq!(retry.reason, ScanReason::PartialFallback);

    Ok(())
}

#[test]
fn failed_partial_escalates_to_a_full_retry_at_the_base_interval() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    planner.mark_dirty("a", seconds(20), 1);
    let partial = planner
        .next_candidate(millis(20_500))
        .context("expected a value from next_candidate")?;
    planner.complete(&partial, seconds(21), ScanCompletion::Failed);
    assert!(planner.next_candidate(seconds(35)).is_none());
    let retry = planner
        .next_candidate(seconds(36))
        .context("expected a value from next_candidate")?;
    assert_eq!(retry.kind, ScanKind::Full);
    assert_eq!(retry.reason, ScanReason::RetryAfterFailure);

    Ok(())
}

#[test]
fn overflow_during_full_scan_is_not_cleared_by_older_completion() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, target("a"));
    let first = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    planner.mark_overflow("a", millis(100), 1);
    complete_full(&mut planner, &first, seconds(1));
    assert!(planner.next_candidate(millis(15_999)).is_none());
    let second = planner
        .next_candidate(seconds(16))
        .context("expected a value from next_candidate")?;
    assert_eq!(second.kind, ScanKind::Full);
    assert_eq!(second.captured_generation, 1);

    Ok(())
}

#[test]
fn continuous_successful_overflow_is_limited_to_one_full_scan_per_base_interval()
-> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    let mut generation = 1;
    let mut dispatch_at = seconds(4);

    assert!(planner.mark_overflow("a", dispatch_at, generation));
    for _ in 0..4 {
        let candidate = planner
            .next_candidate(dispatch_at)
            .context("expected a value from next_candidate")?;
        assert_eq!(candidate.kind, ScanKind::Full);
        assert_eq!(candidate.reason, ScanReason::Overflow);
        assert_eq!(candidate.captured_generation, generation);

        generation += 1;
        assert!(planner.mark_overflow("a", dispatch_at + millis(100), generation));
        let completed_at = dispatch_at + seconds(1);
        complete_full(&mut planner, &candidate, completed_at);

        let next_due = completed_at + config().scan_interval;
        assert!(
            planner
                .next_candidate(next_due - Duration::from_nanos(1))
                .is_none()
        );
        assert_eq!(
            planner.next_wakeup(completed_at),
            Some(config().scan_interval)
        );
        dispatch_at = next_due;
    }

    Ok(())
}

#[test]
fn newer_overflow_after_success_preserves_the_pending_cadence_deadline() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    assert!(planner.mark_overflow("a", seconds(4), 1));
    let first = planner
        .next_candidate(seconds(4))
        .context("expected a value from next_candidate")?;

    assert!(planner.mark_overflow("a", millis(4_100), 2));
    complete_full(&mut planner, &first, seconds(5));
    assert_eq!(planner.next_wakeup(seconds(5)), Some(seconds(15)));

    // New overflow joins the cadence-limited follow-up.
    assert!(planner.mark_overflow("a", seconds(10), 3));
    assert_eq!(planner.next_wakeup(seconds(10)), Some(seconds(10)));
    assert!(planner.next_candidate(millis(19_999)).is_none());

    let follow_up = planner
        .next_candidate(seconds(20))
        .context("expected a value from next_candidate")?;
    assert_eq!(follow_up.kind, ScanKind::Full);
    assert_eq!(follow_up.reason, ScanReason::Overflow);
    assert_eq!(follow_up.captured_generation, 3);

    Ok(())
}

#[test]
fn recaptured_overflow_generation_preserves_failed_full_scan_backoff() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    assert!(planner.mark_overflow("a", seconds(4), 8));
    let failed = planner
        .next_candidate(seconds(4))
        .context("expected a value from next_candidate")?;
    planner.complete(&failed, seconds(5), ScanCompletion::Failed);

    // Retained generation 8 must not erase the retry deadline.
    assert!(!planner.mark_overflow("a", seconds(6), 8));
    assert!(!planner.mark_overflow("a", seconds(10), 8));
    assert!(!planner.mark_overflow("a", seconds(12), 7));
    assert!(planner.next_candidate(seconds(19)).is_none());
    assert_eq!(planner.next_wakeup(seconds(19)), Some(seconds(1)));

    let retry = planner
        .next_candidate(seconds(20))
        .context("expected a value from next_candidate")?;
    assert_eq!(retry.kind, ScanKind::Full);
    assert_eq!(retry.reason, ScanReason::RetryAfterFailure);
    assert_eq!(retry.captured_generation, 8);

    Ok(())
}

#[test]
fn continuously_advancing_overflow_generations_preserve_retry_backoff() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    planner.mark_overflow("a", seconds(4), 8);
    let failed = planner
        .next_candidate(seconds(4))
        .context("expected a value from next_candidate")?;
    planner.complete(&failed, seconds(5), ScanCompletion::Failed);

    for generation in 9..=100 {
        assert!(planner.mark_overflow("a", millis(6_000 + generation), generation));
    }
    assert!(planner.next_candidate(seconds(19)).is_none());
    let retry = planner
        .next_candidate(seconds(20))
        .context("expected a value from next_candidate")?;
    assert_eq!(retry.kind, ScanKind::Full);
    assert_eq!(retry.reason, ScanReason::RetryAfterFailure);
    assert_eq!(retry.captured_generation, 100);

    Ok(())
}

#[test]
fn generation_arriving_during_successful_retry_is_cadence_limited() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    planner.mark_overflow("a", seconds(4), 8);
    let failed = planner
        .next_candidate(seconds(4))
        .context("expected a value from next_candidate")?;
    planner.complete(&failed, seconds(5), ScanCompletion::Failed);

    let retry = planner
        .next_candidate(seconds(20))
        .context("expected a value from next_candidate")?;
    assert!(planner.mark_overflow("a", millis(20_100), 9));
    planner.complete(
        &retry,
        seconds(21),
        ScanCompletion::Succeeded {
            performed: ScanKind::Full,
        },
    );

    assert!(planner.next_candidate(seconds(35)).is_none());
    let remaining = planner
        .next_candidate(seconds(36))
        .context("expected a value from next_candidate")?;
    assert_eq!(remaining.kind, ScanKind::Full);
    assert_eq!(remaining.reason, ScanReason::Overflow);
    assert_eq!(remaining.captured_generation, 9);

    Ok(())
}

#[test]
fn qdrant_style_target_runs_full_at_every_base_interval() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut spec = target("qdrant");
    spec.force_periodic_full = true;
    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, spec);
    let initial = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    complete_full(&mut planner, &initial, seconds(1));
    assert!(planner.next_candidate(seconds(15)).is_none());
    let periodic = planner
        .next_candidate(seconds(16))
        .context("expected a value from next_candidate")?;
    assert_eq!(periodic.kind, ScanKind::Full);
    assert_eq!(periodic.reason, ScanReason::PeriodicFull);

    Ok(())
}

#[test]
fn globally_disabled_watcher_uses_exact_periodic_full_scans() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut disabled = config();
    disabled.watcher_enabled = false;
    let mut planner = HybridScanPlanner::new(disabled);
    planner.upsert_target(Duration::ZERO, target("a"));
    let initial = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    complete_full(&mut planner, &initial, seconds(1));
    assert_eq!(planner.next_wakeup(seconds(1)), Some(seconds(15)));
    let periodic = planner
        .next_candidate(seconds(16))
        .context("expected a value from next_candidate")?;
    assert_eq!(periodic.kind, ScanKind::Full);
    assert_eq!(periodic.reason, ScanReason::WatcherFallback);

    Ok(())
}

#[test]
fn untrusted_target_uses_periodic_full_while_others_remain_hybrid() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut untrusted = target("a");
    untrusted.watcher_trusted = false;
    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, untrusted);
    let initial = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    complete_full(&mut planner, &initial, seconds(1));
    let periodic = planner
        .next_candidate(seconds(16))
        .context("expected a value from next_candidate")?;
    assert_eq!(periodic.reason, ScanReason::WatcherFallback);

    Ok(())
}

#[test]
fn losing_watcher_trust_invalidates_an_in_flight_partial() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = planner_with_baseline("a", Duration::ZERO);
    planner.mark_dirty("a", seconds(20), 1);
    let partial = planner
        .next_candidate(millis(20_500))
        .context("expected a value from next_candidate")?;
    assert!(planner.set_watcher_trusted("a", false, seconds(21)));
    assert_eq!(
        planner.complete(
            &partial,
            seconds(22),
            ScanCompletion::Succeeded {
                performed: ScanKind::Partial,
            },
        ),
        CompletionDisposition::Stale
    );
    assert_eq!(
        planner
            .next_candidate(seconds(22))
            .context("seconds should provide a value")?
            .kind,
        ScanKind::Full
    );

    Ok(())
}

#[test]
fn equal_due_targets_are_dispatched_round_robin_in_id_order_initially() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    for id in ["c", "a", "b"] {
        planner.upsert_target(Duration::ZERO, target(id));
    }
    assert_eq!(
        planner
            .next_candidate(Duration::ZERO)
            .context("next candidate should provide a value")?
            .target_id,
        "a"
    );
    assert_eq!(
        planner
            .next_candidate(Duration::ZERO)
            .context("next candidate should provide a value")?
            .target_id,
        "b"
    );
    assert_eq!(
        planner
            .next_candidate(Duration::ZERO)
            .context("next candidate should provide a value")?
            .target_id,
        "c"
    );

    Ok(())
}

#[test]
fn older_due_work_wins_over_a_noisy_newer_target() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, target("idle"));
    planner.upsert_target(Duration::ZERO, target("noisy"));
    let idle = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    let noisy = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    complete_full(&mut planner, &idle, Duration::ZERO);
    complete_full(&mut planner, &noisy, seconds(10));

    planner.mark_dirty("noisy", millis(90_100), 1);
    assert_eq!(
        planner
            .next_candidate(millis(90_600))
            .context("millis should provide a value")?
            .target_id,
        "idle"
    );

    Ok(())
}

#[test]
fn completion_redebounce_prevents_noisy_target_from_starving_overdue_idle() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, target("a-noisy"));
    planner.upsert_target(Duration::ZERO, target("b-idle"));
    let noisy_initial = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    let idle_initial = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    complete_full(&mut planner, &noisy_initial, Duration::ZERO);
    complete_full(&mut planner, &idle_initial, Duration::ZERO);

    planner.mark_dirty("a-noisy", seconds(89), 1);
    let noisy = planner
        .next_candidate(millis(89_500))
        .context("expected a value from next_candidate")?;
    planner.mark_dirty("a-noisy", millis(89_600), 2);
    planner.complete(
        &noisy,
        seconds(90),
        ScanCompletion::Succeeded {
            performed: ScanKind::Partial,
        },
    );
    assert_eq!(
        planner
            .next_candidate(seconds(90))
            .context("seconds should provide a value")?
            .target_id,
        "b-idle"
    );

    Ok(())
}

#[test]
fn stale_token_cannot_complete_a_different_scan() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, target("a"));
    let candidate = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    let mut forged = candidate.clone();
    forged.token = forged.token.saturating_add(100);
    assert_eq!(
        planner.complete(&forged, seconds(1), ScanCompletion::Failed),
        CompletionDisposition::Stale
    );
    assert!(
        planner
            .target_status("a")
            .context("target status should provide a value")?
            .in_flight
    );

    Ok(())
}

#[test]
fn shutdown_stops_new_work_and_wakeups() {
    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::ZERO, target("a"));
    planner.shutdown();
    assert!(planner.is_shutdown());
    assert!(planner.next_candidate(seconds(100)).is_none());
    assert!(planner.next_wakeup(seconds(100)).is_none());
}

#[test]
fn monotonic_deadlines_saturate_instead_of_wrapping() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut planner = HybridScanPlanner::new(config());
    planner.upsert_target(Duration::MAX, target("a"));
    let candidate = planner
        .next_candidate(Duration::MAX)
        .context("expected a value from next_candidate")?;
    complete_full(&mut planner, &candidate, Duration::MAX);
    let status = planner
        .target_status("a")
        .context("expected a value from target_status")?;
    assert_eq!(status.next_periodic_due, Duration::MAX);
    assert_eq!(status.full_deadline, Duration::MAX);

    Ok(())
}

#[test]
fn unknown_events_are_ignored_without_creating_targets() {
    let mut planner = HybridScanPlanner::new(config());
    assert!(!planner.mark_dirty("missing", Duration::ZERO, 1));
    assert!(!planner.mark_overflow("missing", Duration::ZERO, 1));
    assert!(!planner.set_watcher_trusted("missing", false, Duration::ZERO));
    assert_eq!(planner.len(), 0);
}
