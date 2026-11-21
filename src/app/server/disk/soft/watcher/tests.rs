use notify::Watcher;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use notify::{
    Event, EventKind,
    event::{AccessKind, CreateKind, DataChange, Flag, ModifyKind, RemoveKind, RenameMode},
};
use tempfile::TempDir;

use super::*;
use crate::server::disk::soft::planner::{
    HybridScanPlanner, PlannerConfig, ScanCompletion, ScanKind, ScanReason, TargetSpec,
};

const TARGET: &str = "instance-one";
const FINGERPRINT: &str = "fingerprint-one";

#[derive(Clone, Copy)]
enum InjectedWatchFailure {
    None,
    Generic,
    PathNotFound,
    MaxFiles,
}

#[derive(Clone, Copy)]
enum InjectedUnwatchFailure {
    None,
    Generic,
    WatchNotFound,
}

struct RecordingWatcher {
    watch_failure: InjectedWatchFailure,
    unwatch_failure: InjectedUnwatchFailure,
    operations: Vec<&'static str>,
}

impl RecordingWatcher {
    fn with_failures(
        watch_failure: InjectedWatchFailure,
        unwatch_failure: InjectedUnwatchFailure,
    ) -> Self {
        Self {
            watch_failure,
            unwatch_failure,
            operations: Vec::new(),
        }
    }
}

impl Watcher for RecordingWatcher {
    fn new<F: notify::EventHandler>(_event_handler: F, _config: Config) -> notify::Result<Self> {
        Ok(Self {
            watch_failure: InjectedWatchFailure::None,
            unwatch_failure: InjectedUnwatchFailure::None,
            operations: Vec::new(),
        })
    }

    fn watch(&mut self, _path: &Path, _recursive_mode: RecursiveMode) -> notify::Result<()> {
        self.operations.push("watch");
        match self.watch_failure {
            InjectedWatchFailure::None => Ok(()),
            InjectedWatchFailure::Generic => {
                Err(notify::Error::generic("injected recursive watch failure"))
            }
            InjectedWatchFailure::PathNotFound => Err(notify::Error::path_not_found()),
            InjectedWatchFailure::MaxFiles => {
                Err(notify::Error::new(notify::ErrorKind::MaxFilesWatch))
            }
        }
    }

    fn unwatch(&mut self, _path: &Path) -> notify::Result<()> {
        self.operations.push("unwatch");
        match self.unwatch_failure {
            InjectedUnwatchFailure::None => Ok(()),
            InjectedUnwatchFailure::Generic => {
                Err(notify::Error::generic("injected cleanup failure"))
            }
            InjectedUnwatchFailure::WatchNotFound => Err(notify::Error::watch_not_found()),
        }
    }

    fn kind() -> notify::WatcherKind {
        notify::WatcherKind::NullWatcher
    }
}

fn watcher_and_root(maximum_dirty_paths: usize) -> (SoftDiskWatcher, TempDir, PathBuf) {
    let temporary = tempfile::tempdir().expect("tempdir should succeed");
    let root = temporary.path().join("data");
    std::fs::create_dir(&root).expect("create dir should succeed");
    let watcher =
        SoftDiskWatcher::new_with_retry_policy(maximum_dirty_paths, Duration::ZERO, Duration::ZERO);
    let registration = watcher
        .register(TARGET, FINGERPRINT, &root)
        .expect("register should succeed");
    assert_eq!(registration.status, RegistrationStatus::Watching);
    acknowledge_initial(&watcher, TARGET);
    (watcher, temporary, root)
}

fn acknowledge_initial(watcher: &SoftDiskWatcher, target_id: &str) {
    let initial = watcher
        .capture(target_id)
        .expect("expected a value from capture");
    assert!(initial.requires_full_reconcile());
    assert!(watcher.acknowledge(&initial));
    assert!(watcher.capture(target_id).is_none());
}

#[test]
fn recursive_watch_install_unwinds_failures_and_reports_contamination() {
    let unwound: &[&str] = &["watch", "unwatch"];
    let installed: &[&str] = &["watch"];
    for (name, watch_failure, unwatch_failure, expected, operations) in [
        (
            "failed watch unwinds cleanly",
            InjectedWatchFailure::Generic,
            InjectedUnwatchFailure::None,
            RecursiveWatchInstall::FailedCleanly,
            unwound,
        ),
        (
            "cleanup failure contaminates the backend",
            InjectedWatchFailure::Generic,
            InjectedUnwatchFailure::Generic,
            RecursiveWatchInstall::BackendContaminated,
            unwound,
        ),
        (
            "deleted root without an installed watch fails cleanly",
            InjectedWatchFailure::PathNotFound,
            InjectedUnwatchFailure::WatchNotFound,
            RecursiveWatchInstall::FailedCleanly,
            unwound,
        ),
        (
            "watch limit without proven rollback contaminates the backend",
            InjectedWatchFailure::MaxFiles,
            InjectedUnwatchFailure::WatchNotFound,
            RecursiveWatchInstall::BackendContaminated,
            unwound,
        ),
        (
            "successful watch is not unwound",
            InjectedWatchFailure::None,
            InjectedUnwatchFailure::None,
            RecursiveWatchInstall::Installed,
            installed,
        ),
    ] {
        let mut watcher = RecordingWatcher::with_failures(watch_failure, unwatch_failure);

        assert_eq!(
            install_recursive_watch(&mut watcher, Path::new("/target")),
            expected,
            "{name}"
        );
        assert_eq!(watcher.operations, operations, "{name}");
    }
}

fn data_event(path: impl Into<PathBuf>) -> Event {
    Event::new(EventKind::Modify(ModifyKind::Data(DataChange::Content))).add_path(path.into())
}

fn create_event(path: impl Into<PathBuf>) -> Event {
    Event::new(EventKind::Create(CreateKind::Any)).add_path(path.into())
}

fn remove_event(path: impl Into<PathBuf>) -> Event {
    Event::new(EventKind::Remove(RemoveKind::Any)).add_path(path.into())
}

fn inject(watcher: &SoftDiskWatcher, event: Event) {
    watcher.handle_callback_for_test(Ok(event));
}

fn insert_logical_target(watcher: &SoftDiskWatcher, target_id: &str, root: PathBuf) {
    let mut state = watcher.shared.state.lock();
    state.next_registration_generation = next_nonzero(state.next_registration_generation);
    let target = TargetState {
        fingerprint: format!("fingerprint-{target_id}"),
        root: root.clone(),
        registration_generation: state.next_registration_generation,
        target_generation: 0,
        full_generation: None,
        dirty_paths: BTreeMap::new(),
        acknowledged_global_generation: watcher.shared.global_generation.load(Ordering::Acquire),
        health: WatchHealth::Watching,
        health_generation: 0,
        retry_attempts: 0,
        retry_at: Instant::now(),
    };
    state.roots.insert(root, target_id.to_string());
    state.targets.insert(target_id.to_string(), target);
}

#[test]
fn registration_starts_with_an_authoritative_reconcile() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    std::fs::create_dir(&root)?;
    let watcher = SoftDiskWatcher::new(32);

    let result = watcher.register(TARGET, FINGERPRINT, &root)?;
    let batch = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;

    assert!(result.changed);
    assert!(result.full_reconcile_pending);
    assert!(batch.requires_full_reconcile());
    assert!(batch.relative_paths().is_empty());
    assert_eq!(batch.target_id(), TARGET);
    assert_eq!(batch.fingerprint(), FINGERPRINT);
    assert!(batch.generation() > 0);
    assert!(batch.watcher_active());

    Ok(())
}

#[test]
fn registration_is_reported_once_by_the_coalescing_drain() {
    let (watcher, _temporary, _root) = watcher_and_root(32);

    let changes = watcher.drain_changes();

    assert!(!changes.global_reconcile);
    assert_eq!(changes.target_ids, [TARGET.to_string()]);
    assert!(!changes.is_empty());
    assert!(watcher.drain_changes().is_empty());
}

#[test]
fn retained_full_batch_does_not_cancel_planner_retry_backoff() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    std::fs::create_dir(&root)?;
    let watcher = SoftDiskWatcher::new(32);
    watcher.register(TARGET, FINGERPRINT, &root)?;
    let initial_batch = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;

    let mut planner = HybridScanPlanner::new(PlannerConfig {
        scan_interval: Duration::from_secs(15),
        full_scan_interval: Duration::from_secs(90),
        debounce: Duration::from_millis(500),
        watcher_enabled: true,
    });
    planner.upsert_target(
        Duration::ZERO,
        TargetSpec {
            id: TARGET.to_string(),
            fingerprint: FINGERPRINT.to_string(),
            root_identity: None,
            enabled: true,
            watcher_trusted: true,
            force_periodic_full: false,
        },
    );
    assert!(planner.mark_overflow(TARGET, Duration::ZERO, initial_batch.generation()));
    let first = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    planner.complete(&first, Duration::from_secs(1), ScanCompletion::Failed);

    // Re-capturing a failed batch must preserve its retry deadline.
    let retained_batch = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;
    assert_eq!(retained_batch.generation(), initial_batch.generation());
    assert!(!planner.mark_overflow(TARGET, Duration::from_secs(2), retained_batch.generation()));
    assert!(planner.next_candidate(Duration::from_secs(15)).is_none());
    let retry = planner
        .next_candidate(Duration::from_secs(16))
        .context("expected a value from next_candidate")?;
    assert_eq!(retry.reason, ScanReason::RetryAfterFailure);
    planner.complete(
        &retry,
        Duration::from_secs(17),
        ScanCompletion::Succeeded {
            performed: ScanKind::Full,
        },
    );
    assert!(watcher.acknowledge(&retained_batch));
    assert!(watcher.capture(TARGET).is_none());

    Ok(())
}

#[test]
fn hot_top_level_file_events_are_cadence_limited_by_the_planner() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    let mut planner = HybridScanPlanner::new(PlannerConfig {
        scan_interval: Duration::from_secs(15),
        full_scan_interval: Duration::from_secs(90),
        debounce: Duration::from_millis(500),
        watcher_enabled: true,
    });
    planner.upsert_target(
        Duration::ZERO,
        TargetSpec {
            id: TARGET.to_string(),
            fingerprint: FINGERPRINT.to_string(),
            root_identity: None,
            enabled: true,
            watcher_trusted: true,
            force_periodic_full: false,
        },
    );
    let baseline = planner
        .next_candidate(Duration::ZERO)
        .context("expected a value from next_candidate")?;
    planner.complete(
        &baseline,
        Duration::ZERO,
        ScanCompletion::Succeeded {
            performed: ScanKind::Full,
        },
    );

    // Top-level writes map to the root and still obey base cadence.
    for generation in 1..=50_u64 {
        inject(
            &watcher,
            data_event(root.join(format!("database-{generation}.data"))),
        );
        let batch = watcher
            .capture(TARGET)
            .context("expected a value from capture")?;
        assert!(!batch.requires_full_reconcile());
        assert_eq!(batch.relative_paths(), [PathBuf::new()]);
        planner.mark_dirty(
            TARGET,
            Duration::from_millis(generation * 100),
            batch.generation(),
        );
    }

    assert!(
        planner
            .next_candidate(Duration::from_millis(14_999))
            .is_none()
    );
    let due = planner
        .next_candidate(Duration::from_secs(15))
        .context("expected a value from next_candidate")?;
    assert_eq!(due.kind, ScanKind::Partial);

    Ok(())
}

#[test]
fn idempotent_registration_does_not_create_new_work() -> anyhow::Result<()> {
    let (watcher, _temporary, root) = watcher_and_root(32);

    let result = watcher.register(TARGET, FINGERPRINT, &root)?;

    assert!(!result.changed);
    assert!(!result.full_reconcile_pending);
    assert!(watcher.capture(TARGET).is_none());

    Ok(())
}

#[test]
fn registration_rejects_empty_identity_without_disclosing_it() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let error = SoftDiskWatcher::new(32)
        .register("", "fingerprint", temporary.path())
        .expect_err("path should return an error");

    assert_eq!(error, WatchRegistrationError::InvalidIdentity);
    assert!(!error.to_string().contains("fingerprint"));

    Ok(())
}

#[test]
fn registration_rejects_relative_and_parent_traversal_roots() -> anyhow::Result<()> {
    let watcher = SoftDiskWatcher::new(32);
    assert_eq!(
        watcher
            .register(TARGET, FINGERPRINT, Path::new("relative/data"))
            .expect_err("register should return an error"),
        WatchRegistrationError::InvalidRoot
    );

    let temporary = tempfile::tempdir()?;
    let unsafe_root = temporary.path().join("safe/../outside");
    assert_eq!(
        watcher
            .register(TARGET, FINGERPRINT, &unsafe_root)
            .expect_err("register should return an error"),
        WatchRegistrationError::InvalidRoot
    );

    Ok(())
}

#[test]
fn one_root_cannot_be_owned_by_two_targets() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    let error = watcher
        .register("instance-two", "fingerprint-two", &root)
        .expect_err("register should return an error");

    assert_eq!(error, WatchRegistrationError::RootCollision);
    assert!(watcher.status(TARGET).is_some());
    assert!(watcher.status("instance-two").is_none());
}

#[test]
fn file_changes_are_reduced_to_minimal_root_relative_parent_directories() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let cases: [(&str, &[&str], &[&str]); 4] = [
        (
            "file maps to its parent",
            &["database/table/part.bin"],
            &["database/table"],
        ),
        (
            "ancestor subsumes descendants",
            &["a/b/c/file-one", "a/b/file-two"],
            &["a/b"],
        ),
        (
            "later ancestor replaces descendants",
            &["a/b/file-one", "a/c/file-two", "a/file-three"],
            &["a"],
        ),
        (
            "siblings remain independent",
            &["alpha/file", "beta/file"],
            &["alpha", "beta"],
        ),
    ];
    for (name, changed, expected) in cases {
        let (watcher, _temporary, root) = watcher_and_root(32);

        for path in changed {
            inject(&watcher, data_event(root.join(path)));
        }
        let batch = watcher
            .capture(TARGET)
            .context("expected a value from capture")?;

        assert!(!batch.requires_full_reconcile(), "{name}");
        assert_eq!(
            batch.relative_paths(),
            expected.iter().map(PathBuf::from).collect::<Vec<_>>(),
            "{name}"
        );
    }

    Ok(())
}

#[test]
fn dirty_path_bound_collapses_to_a_full_reconcile() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(2);

    for directory in ["alpha", "beta", "gamma"] {
        inject(&watcher, data_event(root.join(directory).join("file")));
    }
    let batch = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;

    assert!(batch.requires_full_reconcile());
    assert!(batch.relative_paths().is_empty());
    assert!(
        watcher
            .status(TARGET)
            .context("status should provide a value")?
            .full_reconcile_pending
    );

    Ok(())
}

#[test]
fn zero_dirty_path_bound_is_safely_clamped() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(0);

    inject(&watcher, data_event(root.join("alpha/file")));
    assert!(
        !watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );
    inject(&watcher, data_event(root.join("beta/file")));

    assert!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );

    Ok(())
}

#[test]
fn event_on_an_existing_dirty_path_advances_its_generation() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("a/file")));
    let captured_before_second_write = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;

    inject(&watcher, data_event(root.join("a/file")));
    assert!(watcher.acknowledge(&captured_before_second_write));

    let remaining = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;
    assert_eq!(remaining.relative_paths(), [PathBuf::from("a")]);
    assert!(remaining.generation() > captured_before_second_write.generation());

    Ok(())
}

#[test]
fn event_on_descendant_advances_the_recorded_ancestor_generation() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("a/file")));
    let captured = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;

    inject(&watcher, data_event(root.join("a/b/other-file")));
    assert!(watcher.acknowledge(&captured));

    assert_eq!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .relative_paths(),
        [PathBuf::from("a")]
    );

    Ok(())
}

#[test]
fn unrelated_event_during_scan_is_preserved_after_acknowledgement() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("before/file")));
    let captured = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;

    inject(&watcher, data_event(root.join("during/file")));
    assert!(watcher.acknowledge(&captured));

    assert_eq!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .relative_paths(),
        [PathBuf::from("during")]
    );

    Ok(())
}

#[test]
fn global_reconcile_during_scan_survives_an_old_acknowledgement() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("before/file")));
    let captured = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;

    watcher.force_full_all();
    assert!(watcher.acknowledge(&captured));

    assert!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );

    Ok(())
}

#[test]
fn global_reconcile_advances_each_targets_planner_generation() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    let _ = watcher.drain_changes();
    inject(&watcher, data_event(root.join("before/file")));
    let before = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;

    watcher.force_full_all();
    let after = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;
    let changes = watcher.drain_changes();

    assert!(after.requires_full_reconcile());
    assert!(after.generation() > before.generation());
    assert!(changes.global_reconcile);
    assert!(changes.target_ids.is_empty());

    Ok(())
}

#[test]
fn target_full_reconcile_during_scan_survives_an_old_acknowledgement() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("before/file")));
    let captured = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;

    assert!(watcher.force_full(TARGET));
    assert!(watcher.acknowledge(&captured));

    assert!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );

    Ok(())
}

#[test]
fn stale_acknowledgement_cannot_clear_a_replaced_registration() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("before/file")));
    let stale = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;

    let replacement = watcher.register(TARGET, "fingerprint-two", &root)?;

    assert!(replacement.changed);
    assert!(!watcher.acknowledge(&stale));
    assert!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );

    Ok(())
}

#[test]
fn same_fingerprint_with_a_new_root_still_rejects_stale_ack() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, temporary, old_root) = watcher_and_root(32);
    inject(&watcher, data_event(old_root.join("before/file")));
    let stale = watcher
        .capture(TARGET)
        .context("expected a value from capture")?;
    let new_root = temporary.path().join("new-data");
    std::fs::create_dir(&new_root)?;

    watcher.register(TARGET, FINGERPRINT, &new_root)?;

    assert!(!watcher.acknowledge(&stale));
    assert!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );

    Ok(())
}

#[test]
fn sibling_prefixes_route_to_the_exact_root() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let temporary = tempfile::tempdir()?;
    let root_one = temporary.path().join("db");
    let root_two = temporary.path().join("db2");
    std::fs::create_dir(&root_one)?;
    std::fs::create_dir(&root_two)?;
    let watcher = SoftDiskWatcher::new(32);
    watcher.register("one", "fp-one", &root_one)?;
    watcher.register("two", "fp-two", &root_two)?;
    acknowledge_initial(&watcher, "one");
    acknowledge_initial(&watcher, "two");

    inject(&watcher, data_event(root_two.join("nested/file")));

    assert!(watcher.capture("one").is_none());
    assert_eq!(
        watcher
            .capture("two")
            .context("capture should provide a value")?
            .relative_paths(),
        [PathBuf::from("nested")]
    );

    Ok(())
}

#[test]
fn nested_roots_route_to_the_nearest_registered_root() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let temporary = tempfile::tempdir()?;
    let outer = temporary.path().join("outer");
    let inner = outer.join("inner");
    std::fs::create_dir_all(&inner)?;
    let watcher = SoftDiskWatcher::new(32);
    watcher.register("outer", "fp-outer", &outer)?;
    watcher.register("inner", "fp-inner", &inner)?;
    acknowledge_initial(&watcher, "outer");
    acknowledge_initial(&watcher, "inner");

    inject(&watcher, data_event(inner.join("table/file")));

    assert!(watcher.capture("outer").is_none());
    assert_eq!(
        watcher
            .capture("inner")
            .context("capture should provide a value")?
            .relative_paths(),
        [PathBuf::from("table")]
    );

    Ok(())
}

#[test]
fn large_target_set_reports_only_the_one_changed_target() {
    let watcher = SoftDiskWatcher::new(32);
    let base = PathBuf::from("/var/lib/dbev-large-target-test");
    const TARGET_COUNT: usize = 20_000;
    const CHANGED_INDEX: usize = 17_321;
    for index in 0..TARGET_COUNT {
        insert_logical_target(
            &watcher,
            &format!("target-{index}"),
            base.join(index.to_string()),
        );
    }

    inject(
        &watcher,
        data_event(
            base.join(CHANGED_INDEX.to_string())
                .join("schema/table.data"),
        ),
    );
    let changes = watcher.drain_changes();

    assert!(!changes.global_reconcile);
    assert_eq!(changes.target_ids, [format!("target-{CHANGED_INDEX}")]);
    assert!(
        watcher
            .capture(&format!("target-{CHANGED_INDEX}"))
            .is_some()
    );
    assert!(watcher.capture("target-0").is_none());
}

#[test]
fn event_storm_coalesces_to_one_pending_target() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    let _ = watcher.drain_changes();
    let event = data_event(root.join("schema/table.data"));

    for _ in 0..10_000 {
        inject(&watcher, event.clone());
    }
    let changes = watcher.drain_changes();

    assert!(!changes.global_reconcile);
    assert_eq!(changes.target_ids, [TARGET.to_string()]);
    assert!(watcher.drain_changes().is_empty());
    assert_eq!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .relative_paths(),
        [PathBuf::from("schema")]
    );

    Ok(())
}

#[test]
fn pending_target_bound_escalates_to_one_global_reconcile() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let temporary = tempfile::tempdir()?;
    let watcher = SoftDiskWatcher::new_with_limits(32, 2, Duration::ZERO, Duration::ZERO);
    for index in 0..3 {
        let root = temporary.path().join(index.to_string());
        std::fs::create_dir(&root)?;
        watcher.register(
            &format!("target-{index}"),
            &format!("fingerprint-{index}"),
            &root,
        )?;
    }

    let changes = watcher.drain_changes();

    assert!(changes.global_reconcile);
    assert!(changes.target_ids.is_empty());
    assert!(watcher.drain_changes().is_empty());
    for index in 0..3 {
        assert!(
            watcher
                .capture(&format!("target-{index}"))
                .context("capture should provide a value")?
                .requires_full_reconcile()
        );
    }

    Ok(())
}

#[test]
fn logical_retirement_immediately_removes_event_routing() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    let _ = watcher.drain_changes();

    let retired = watcher
        .retire(TARGET)
        .context("expected a value from retire")?;
    inject(&watcher, data_event(root.join("late/table.data")));
    let changes = watcher.drain_changes();

    assert_eq!(changes.target_ids, [TARGET.to_string()]);
    assert!(watcher.status(TARGET).is_none());
    assert!(watcher.capture(TARGET).is_none());
    assert!(!format!("{retired:?}").contains(root.to_string_lossy().as_ref()));
    watcher.unwatch_retired(&retired);

    Ok(())
}

#[test]
fn retirement_during_kernel_registration_rolls_back_the_late_watch() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    std::fs::create_dir(&root)?;
    let watcher = Arc::new(SoftDiskWatcher::new_with_retry_policy(
        32,
        Duration::ZERO,
        Duration::ZERO,
    ));
    let pause = watcher.pause_next_registration_after_install();
    let worker = {
        let watcher = Arc::clone(&watcher);
        let root = root.clone();
        std::thread::spawn(move || {
            watcher
                .register(TARGET, FINGERPRINT, &root)
                .expect("register should succeed")
        })
    };
    pause.installed.wait();

    let retired = watcher
        .retire(TARGET)
        .expect("the logical registration must be visible before kernel completion");
    pause.resume.wait();
    let stale = worker
        .join()
        .map_err(|_| anyhow::anyhow!("test thread panicked"))?;

    assert_eq!(stale.status, RegistrationStatus::Degraded);
    assert!(!stale.changed);
    assert!(watcher.status(TARGET).is_none());
    assert_eq!(watcher.stale_cleanup_attempts.load(Ordering::Relaxed), 1);
    drop(retired);

    // A stale operation cannot confirm an immediate same-root re-add.
    let replacement = watcher.register(TARGET, FINGERPRINT, &root)?;
    assert_eq!(replacement.status, RegistrationStatus::Watching);
    assert!(watcher.is_watching(TARGET, FINGERPRINT));

    Ok(())
}

#[test]
fn retired_kernel_cleanup_never_unwatches_a_reused_root() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    let retired = watcher
        .retire(TARGET)
        .context("expected a value from retire")?;
    watcher.register("replacement", "replacement-fingerprint", &root)?;

    watcher.unwatch_retired(&retired);
    acknowledge_initial(&watcher, "replacement");
    inject(&watcher, data_event(root.join("schema/table.data")));

    assert!(watcher.capture("replacement").is_some());

    Ok(())
}

#[test]
fn a_two_root_rename_dirties_both_targets() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let temporary = tempfile::tempdir()?;
    let source_root = temporary.path().join("source");
    let destination_root = temporary.path().join("destination");
    std::fs::create_dir(&source_root)?;
    std::fs::create_dir(&destination_root)?;
    let watcher = SoftDiskWatcher::new(32);
    watcher.register("source", "source-fp", &source_root)?;
    watcher.register("destination", "destination-fp", &destination_root)?;
    acknowledge_initial(&watcher, "source");
    acknowledge_initial(&watcher, "destination");
    let event = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
        .add_path(source_root.join("old/table.db"))
        .add_path(destination_root.join("new/table.db"));

    inject(&watcher, event);

    assert_eq!(
        watcher
            .capture("source")
            .context("capture should provide a value")?
            .relative_paths(),
        [PathBuf::from("old")]
    );
    assert_eq!(
        watcher
            .capture("destination")
            .context("capture should provide a value")?
            .relative_paths(),
        [PathBuf::from("new")]
    );

    Ok(())
}

#[test]
fn access_only_and_ordinary_other_events_are_ignored() {
    for kind in [EventKind::Access(AccessKind::Read), EventKind::Other] {
        let (watcher, _temporary, root) = watcher_and_root(32);

        inject(&watcher, Event::new(kind).add_path(root.join("file")));

        assert!(watcher.capture(TARGET).is_none(), "{kind:?}");
    }
}

#[test]
fn rescan_flag_is_honored_before_other_kind_filtering() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    let event = Event::new(EventKind::Other)
        .add_path(root.join("file"))
        .set_flag(Flag::Rescan);

    inject(&watcher, event);

    assert!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );

    Ok(())
}

#[test]
fn callback_errors_force_global_reconciliation_without_leaking_paths() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    let error = notify::Error::generic("backend failed").add_path(root.join("secret-name"));

    watcher.handle_callback_for_test(Err(error));

    assert!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );
    assert_eq!(
        watcher
            .status(TARGET)
            .context("status should provide a value")?
            .status,
        RegistrationStatus::Degraded
    );

    Ok(())
}

#[test]
fn callback_error_retry_rebuilds_backend_and_all_watches() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    watcher.handle_callback_for_test(Err(notify::Error::generic("backend failed")));

    let retry = watcher.retry_degraded();

    assert_eq!(retry.attempted, 1);
    assert_eq!(retry.restored, 1);
    assert!(retry.backend_available);
    assert_eq!(
        watcher
            .status(TARGET)
            .context("status should provide a value")?
            .status,
        RegistrationStatus::Watching
    );
    inject(&watcher, data_event(root.join("still-observed/file")));
    assert!(watcher.capture(TARGET).is_some());

    Ok(())
}

#[test]
fn registration_waits_for_pending_atomic_backend_rebuild() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, temporary, _root) = watcher_and_root(32);
    watcher.handle_callback_for_test(Err(notify::Error::generic("backend failed")));
    let second_root = temporary.path().join("second");
    std::fs::create_dir(&second_root)?;

    let registration = watcher.register("instance-two", "fingerprint-two", &second_root)?;

    assert_eq!(registration.status, RegistrationStatus::Degraded);
    let retry = watcher.retry_degraded();
    assert_eq!(retry.attempted, 2);
    assert_eq!(retry.restored, 2);
    assert_eq!(retry.still_degraded, 0);
    assert_eq!(
        watcher
            .status(TARGET)
            .context("status should provide a value")?
            .status,
        RegistrationStatus::Watching
    );
    assert_eq!(
        watcher
            .status("instance-two")
            .context("status should provide a value")?
            .status,
        RegistrationStatus::Watching
    );

    Ok(())
}

#[test]
fn pathless_mutation_forces_global_reconciliation() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, _root) = watcher_and_root(32);

    inject(&watcher, Event::new(EventKind::Create(CreateKind::File)));

    assert!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );

    Ok(())
}

#[test]
fn relative_callback_paths_are_never_forwarded() {
    let (watcher, _temporary, _root) = watcher_and_root(32);

    inject(&watcher, data_event("relative/attacker-controlled.db"));

    assert!(watcher.capture(TARGET).is_none());
}

#[test]
fn traversal_like_callback_path_forces_target_full_reconcile() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);

    inject(
        &watcher,
        data_event(root.join("database/../outside/file.db")),
    );

    assert!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );

    Ok(())
}

#[test]
fn create_and_remove_events_both_dirty_the_parent() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);

    inject(&watcher, create_event(root.join("a/new-file")));
    inject(&watcher, remove_event(root.join("b/old-file")));

    assert_eq!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .relative_paths(),
        [PathBuf::from("a"), PathBuf::from("b")]
    );

    Ok(())
}

#[test]
fn root_removal_or_rename_requires_full_reconcile_and_watch_retry() -> anyhow::Result<()> {
    use anyhow::Context as _;

    for kind in [
        EventKind::Remove(RemoveKind::Any),
        EventKind::Modify(ModifyKind::Name(RenameMode::From)),
    ] {
        let (watcher, _temporary, root) = watcher_and_root(32);

        inject(&watcher, Event::new(kind).add_path(root));
        let status = watcher
            .status(TARGET)
            .context("expected a value from status")?;

        assert_eq!(status.status, RegistrationStatus::Degraded, "{kind:?}");
        assert!(status.full_reconcile_pending, "{kind:?}");
        assert!(
            watcher
                .capture(TARGET)
                .context("capture should provide a value")?
                .requires_full_reconcile(),
            "{kind:?}"
        );
    }

    Ok(())
}

#[test]
fn root_metadata_change_is_full_but_does_not_claim_watch_loss() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    let event = Event::new(EventKind::Modify(ModifyKind::Metadata(
        notify::event::MetadataKind::Permissions,
    )))
    .add_path(root);

    inject(&watcher, event);

    assert_eq!(
        watcher
            .status(TARGET)
            .context("status should provide a value")?
            .status,
        RegistrationStatus::Watching
    );
    assert!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );

    Ok(())
}

#[test]
fn dirty_batch_debug_output_redacts_identity_and_paths() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(
        &watcher,
        data_event(root.join("secret-schema/secret-table")),
    );

    let debug = format!(
        "{:?}",
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
    );

    assert!(!debug.contains(TARGET));
    assert!(!debug.contains(FINGERPRINT));
    assert!(!debug.contains("secret"));
    assert!(debug.contains("dirty_directory_count"));

    Ok(())
}

#[tokio::test]
async fn change_wait_is_race_free_when_signal_precedes_wait() -> anyhow::Result<()> {
    let (watcher, _temporary, _root) = watcher_and_root(32);
    let observed = watcher.current_change_sequence();
    watcher.force_full(TARGET);

    let changed =
        tokio::time::timeout(Duration::from_secs(1), watcher.changed_after(observed)).await?;

    assert_ne!(changed, observed);

    Ok(())
}

#[tokio::test]
async fn one_signal_wakes_all_registered_change_waiters() -> anyhow::Result<()> {
    let (watcher, _temporary, _root) = watcher_and_root(32);
    let watcher = std::sync::Arc::new(watcher);
    let observed = watcher.current_change_sequence();
    let first = {
        let watcher = std::sync::Arc::clone(&watcher);
        tokio::spawn(async move { watcher.changed_after(observed).await })
    };
    let second = {
        let watcher = std::sync::Arc::clone(&watcher);
        tokio::spawn(async move { watcher.changed_after(observed).await })
    };
    tokio::task::yield_now().await;

    watcher.force_full(TARGET);

    let (first, second) = tokio::time::timeout(Duration::from_secs(1), async {
        (
            first
                .await
                .expect("one signal wakes all registered change waiters should succeed"),
            second
                .await
                .expect("one signal wakes all registered change waiters should succeed"),
        )
    })
    .await?;
    assert_ne!(first, observed);
    assert_eq!(first, second);

    Ok(())
}

#[test]
fn registration_failure_degrades_and_retry_recovers_after_root_appears() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("not-created-yet");
    let watcher = SoftDiskWatcher::new_with_retry_policy(32, Duration::ZERO, Duration::ZERO);
    let registration = watcher.register(TARGET, FINGERPRINT, &root)?;
    assert_eq!(registration.status, RegistrationStatus::Degraded);
    acknowledge_initial(&watcher, TARGET);
    let _ = watcher.drain_changes();

    std::fs::create_dir(&root)?;
    let retry = watcher.retry_degraded();

    assert_eq!(retry.attempted, 1);
    assert_eq!(retry.restored, 1);
    assert_eq!(retry.still_degraded, 0);
    assert!(retry.backend_available);
    assert_eq!(
        watcher
            .status(TARGET)
            .context("status should provide a value")?
            .status,
        RegistrationStatus::Watching
    );
    assert!(
        watcher
            .capture(TARGET)
            .context("capture should provide a value")?
            .requires_full_reconcile()
    );
    assert_eq!(watcher.drain_changes().target_ids, [TARGET.to_string()]);

    Ok(())
}

async fn wait_for_dirty(watcher: &SoftDiskWatcher, target_id: &str) -> DirtyBatch {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut sequence = watcher.current_change_sequence();
    loop {
        if let Some(batch) = watcher.capture(target_id) {
            return batch;
        }
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .expect("inotify event was not observed before deadline");
        sequence = tokio::time::timeout(remaining, watcher.changed_after(sequence))
            .await
            .expect("inotify event was not observed before deadline");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_inotify_observes_recursive_create_write_and_delete() -> anyhow::Result<()> {
    let (watcher, _temporary, root) = watcher_and_root(64);
    let nested = root.join("new/schema");
    std::fs::create_dir_all(&nested)?;
    let file = nested.join("table.data");
    std::fs::write(&file, b"first")?;
    std::fs::write(&file, b"second")?;
    std::fs::remove_file(&file)?;

    let batch = wait_for_dirty(&watcher, TARGET).await;

    // Backends may coalesce the same filesystem activity differently.
    assert!(batch.requires_full_reconcile() || !batch.relative_paths().is_empty());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_inotify_observes_cross_root_rename_on_both_targets() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let source_root = temporary.path().join("source");
    let destination_root = temporary.path().join("destination");
    std::fs::create_dir(&source_root)?;
    std::fs::create_dir(&destination_root)?;
    let source = source_root.join("moving.data");
    std::fs::write(&source, b"data")?;
    let watcher = SoftDiskWatcher::new(64);
    watcher.register("source", "source-fp", &source_root)?;
    watcher.register("destination", "destination-fp", &destination_root)?;
    acknowledge_initial(&watcher, "source");
    acknowledge_initial(&watcher, "destination");

    std::fs::rename(source, destination_root.join("moved.data"))?;

    let source_batch = wait_for_dirty(&watcher, "source").await;
    let destination_batch = wait_for_dirty(&watcher, "destination").await;
    assert!(source_batch.requires_full_reconcile() || !source_batch.relative_paths().is_empty());
    assert!(
        destination_batch.requires_full_reconcile()
            || !destination_batch.relative_paths().is_empty()
    );

    Ok(())
}
