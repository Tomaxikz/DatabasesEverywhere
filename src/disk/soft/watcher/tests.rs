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
use crate::disk::soft::planner::{
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
    fn failing(fail_unwatch: bool) -> Self {
        Self {
            watch_failure: InjectedWatchFailure::Generic,
            unwatch_failure: if fail_unwatch {
                InjectedUnwatchFailure::Generic
            } else {
                InjectedUnwatchFailure::None
            },
            operations: Vec::new(),
        }
    }

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
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir(&root).unwrap();
    let watcher =
        SoftDiskWatcher::new_with_retry_policy(maximum_dirty_paths, Duration::ZERO, Duration::ZERO);
    let registration = watcher.register(TARGET, FINGERPRINT, &root).unwrap();
    assert_eq!(registration.status, RegistrationStatus::Watching);
    acknowledge_initial(&watcher, TARGET);
    (watcher, temporary, root)
}

fn acknowledge_initial(watcher: &SoftDiskWatcher, target_id: &str) {
    let initial = watcher.capture(target_id).unwrap();
    assert!(initial.requires_full_reconcile());
    assert!(watcher.acknowledge(&initial));
    assert!(watcher.capture(target_id).is_none());
}

#[test]
fn failed_recursive_watch_immediately_unwinds_partial_registration() {
    let mut watcher = RecordingWatcher::failing(false);

    assert_eq!(
        install_recursive_watch(&mut watcher, Path::new("/target")),
        RecursiveWatchInstall::FailedCleanly
    );
    assert_eq!(watcher.operations, ["watch", "unwatch"]);
}

#[test]
fn recursive_watch_cleanup_failure_marks_backend_contaminated() {
    let mut watcher = RecordingWatcher::failing(true);

    assert_eq!(
        install_recursive_watch(&mut watcher, Path::new("/target")),
        RecursiveWatchInstall::BackendContaminated
    );
    assert_eq!(watcher.operations, ["watch", "unwatch"]);
}

#[test]
fn deleted_root_without_an_installed_watch_is_a_clean_target_failure() {
    let mut watcher = RecordingWatcher::with_failures(
        InjectedWatchFailure::PathNotFound,
        InjectedUnwatchFailure::WatchNotFound,
    );

    assert_eq!(
        install_recursive_watch(&mut watcher, Path::new("/target")),
        RecursiveWatchInstall::FailedCleanly
    );
    assert_eq!(watcher.operations, ["watch", "unwatch"]);
}

#[test]
fn watch_limit_failure_without_proven_rollback_contaminates_the_backend() {
    let mut watcher = RecordingWatcher::with_failures(
        InjectedWatchFailure::MaxFiles,
        InjectedUnwatchFailure::WatchNotFound,
    );

    assert_eq!(
        install_recursive_watch(&mut watcher, Path::new("/target")),
        RecursiveWatchInstall::BackendContaminated
    );
    assert_eq!(watcher.operations, ["watch", "unwatch"]);
}

#[test]
fn successful_recursive_watch_is_not_unwound() {
    let mut watcher = RecordingWatcher {
        watch_failure: InjectedWatchFailure::None,
        unwatch_failure: InjectedUnwatchFailure::None,
        operations: Vec::new(),
    };

    assert_eq!(
        install_recursive_watch(&mut watcher, Path::new("/target")),
        RecursiveWatchInstall::Installed
    );
    assert_eq!(watcher.operations, ["watch"]);
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
    let mut state = lock_recover(&watcher.shared.state);
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
fn registration_starts_with_an_authoritative_reconcile() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir(&root).unwrap();
    let watcher = SoftDiskWatcher::new(32);

    let result = watcher.register(TARGET, FINGERPRINT, &root).unwrap();
    let batch = watcher.capture(TARGET).unwrap();

    assert!(result.changed);
    assert!(result.full_reconcile_pending);
    assert!(batch.requires_full_reconcile());
    assert!(batch.relative_paths().is_empty());
    assert_eq!(batch.target_id(), TARGET);
    assert_eq!(batch.fingerprint(), FINGERPRINT);
    assert!(batch.generation() > 0);
    assert!(batch.watcher_active());
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
fn retained_full_batch_does_not_cancel_planner_retry_backoff() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir(&root).unwrap();
    let watcher = SoftDiskWatcher::new(32);
    watcher.register(TARGET, FINGERPRINT, &root).unwrap();
    let initial_batch = watcher.capture(TARGET).unwrap();

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
    let first = planner.next_candidate(Duration::ZERO).unwrap();
    planner.complete(&first, Duration::from_secs(1), ScanCompletion::Failed);

    // Re-capturing a failed batch must preserve its retry deadline.
    let retained_batch = watcher.capture(TARGET).unwrap();
    assert_eq!(retained_batch.generation(), initial_batch.generation());
    assert!(!planner.mark_overflow(TARGET, Duration::from_secs(2), retained_batch.generation()));
    assert!(planner.next_candidate(Duration::from_secs(15)).is_none());
    let retry = planner.next_candidate(Duration::from_secs(16)).unwrap();
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
}

#[test]
fn hot_top_level_file_events_are_cadence_limited_by_the_planner() {
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
    let baseline = planner.next_candidate(Duration::ZERO).unwrap();
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
        let batch = watcher.capture(TARGET).unwrap();
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
    let due = planner.next_candidate(Duration::from_secs(15)).unwrap();
    assert_eq!(due.kind, ScanKind::Partial);
}

#[test]
fn idempotent_registration_does_not_create_new_work() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    let result = watcher.register(TARGET, FINGERPRINT, &root).unwrap();

    assert!(!result.changed);
    assert!(!result.full_reconcile_pending);
    assert!(watcher.capture(TARGET).is_none());
}

#[test]
fn registration_rejects_empty_identity_without_disclosing_it() {
    let temporary = tempfile::tempdir().unwrap();
    let error = SoftDiskWatcher::new(32)
        .register("", "fingerprint", temporary.path())
        .unwrap_err();

    assert_eq!(error, WatchRegistrationError::InvalidIdentity);
    assert!(!error.to_string().contains("fingerprint"));
}

#[test]
fn registration_rejects_relative_and_parent_traversal_roots() {
    let watcher = SoftDiskWatcher::new(32);
    assert_eq!(
        watcher
            .register(TARGET, FINGERPRINT, Path::new("relative/data"))
            .unwrap_err(),
        WatchRegistrationError::InvalidRoot
    );

    let temporary = tempfile::tempdir().unwrap();
    let unsafe_root = temporary.path().join("safe/../outside");
    assert_eq!(
        watcher
            .register(TARGET, FINGERPRINT, &unsafe_root)
            .unwrap_err(),
        WatchRegistrationError::InvalidRoot
    );
}

#[test]
fn one_root_cannot_be_owned_by_two_targets() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    let error = watcher
        .register("instance-two", "fingerprint-two", &root)
        .unwrap_err();

    assert_eq!(error, WatchRegistrationError::RootCollision);
    assert!(watcher.status(TARGET).is_some());
    assert!(watcher.status("instance-two").is_none());
}

#[test]
fn unregister_is_idempotent_and_drops_late_events() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    assert!(watcher.unregister(TARGET));
    assert!(!watcher.unregister(TARGET));
    inject(&watcher, data_event(root.join("late.db")));

    assert!(watcher.capture(TARGET).is_none());
    assert!(watcher.status(TARGET).is_none());
}

#[test]
fn file_changes_are_reduced_to_root_relative_parent_directories() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    inject(&watcher, data_event(root.join("database/table/part.bin")));
    let batch = watcher.capture(TARGET).unwrap();

    assert!(!batch.requires_full_reconcile());
    assert_eq!(batch.relative_paths(), [PathBuf::from("database/table")]);
    assert!(batch.relative_paths()[0].is_relative());
}

#[test]
fn a_direct_child_maps_to_the_relative_root() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    inject(&watcher, data_event(root.join("root-file.db")));
    let batch = watcher.capture(TARGET).unwrap();

    assert_eq!(batch.relative_paths(), [PathBuf::new()]);
}

#[test]
fn an_ancestor_dirty_directory_subsumes_descendants() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    inject(&watcher, data_event(root.join("a/b/c/file-one")));
    inject(&watcher, data_event(root.join("a/b/file-two")));
    let batch = watcher.capture(TARGET).unwrap();

    assert_eq!(batch.relative_paths(), [PathBuf::from("a/b")]);
}

#[test]
fn a_later_ancestor_replaces_existing_descendants() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    inject(&watcher, data_event(root.join("a/b/file-one")));
    inject(&watcher, data_event(root.join("a/c/file-two")));
    inject(&watcher, data_event(root.join("a/file-three")));
    let batch = watcher.capture(TARGET).unwrap();

    assert_eq!(batch.relative_paths(), [PathBuf::from("a")]);
}

#[test]
fn sibling_dirty_directories_remain_independent() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    inject(&watcher, data_event(root.join("alpha/file")));
    inject(&watcher, data_event(root.join("beta/file")));
    let batch = watcher.capture(TARGET).unwrap();

    assert_eq!(
        batch.relative_paths(),
        [PathBuf::from("alpha"), PathBuf::from("beta")]
    );
}

#[test]
fn dirty_path_bound_collapses_to_a_full_reconcile() {
    let (watcher, _temporary, root) = watcher_and_root(2);

    for directory in ["alpha", "beta", "gamma"] {
        inject(&watcher, data_event(root.join(directory).join("file")));
    }
    let batch = watcher.capture(TARGET).unwrap();

    assert!(batch.requires_full_reconcile());
    assert!(batch.relative_paths().is_empty());
    assert!(watcher.status(TARGET).unwrap().full_reconcile_pending);
}

#[test]
fn zero_dirty_path_bound_is_safely_clamped() {
    let (watcher, _temporary, root) = watcher_and_root(0);

    inject(&watcher, data_event(root.join("alpha/file")));
    assert!(!watcher.capture(TARGET).unwrap().requires_full_reconcile());
    inject(&watcher, data_event(root.join("beta/file")));

    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
}

#[test]
fn event_on_an_existing_dirty_path_advances_its_generation() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("a/file")));
    let captured_before_second_write = watcher.capture(TARGET).unwrap();

    inject(&watcher, data_event(root.join("a/file")));
    assert!(watcher.acknowledge(&captured_before_second_write));

    let remaining = watcher.capture(TARGET).unwrap();
    assert_eq!(remaining.relative_paths(), [PathBuf::from("a")]);
    assert!(remaining.generation() > captured_before_second_write.generation());
}

#[test]
fn event_on_descendant_advances_the_recorded_ancestor_generation() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("a/file")));
    let captured = watcher.capture(TARGET).unwrap();

    inject(&watcher, data_event(root.join("a/b/other-file")));
    assert!(watcher.acknowledge(&captured));

    assert_eq!(
        watcher.capture(TARGET).unwrap().relative_paths(),
        [PathBuf::from("a")]
    );
}

#[test]
fn unrelated_event_during_scan_is_preserved_after_acknowledgement() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("before/file")));
    let captured = watcher.capture(TARGET).unwrap();

    inject(&watcher, data_event(root.join("during/file")));
    assert!(watcher.acknowledge(&captured));

    assert_eq!(
        watcher.capture(TARGET).unwrap().relative_paths(),
        [PathBuf::from("during")]
    );
}

#[test]
fn global_reconcile_during_scan_survives_an_old_acknowledgement() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("before/file")));
    let captured = watcher.capture(TARGET).unwrap();

    watcher.force_full_all();
    assert!(watcher.acknowledge(&captured));

    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
}

#[test]
fn global_reconcile_advances_each_targets_planner_generation() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    let _ = watcher.drain_changes();
    inject(&watcher, data_event(root.join("before/file")));
    let before = watcher.capture(TARGET).unwrap();

    watcher.force_full_all();
    let after = watcher.capture(TARGET).unwrap();
    let changes = watcher.drain_changes();

    assert!(after.requires_full_reconcile());
    assert!(after.generation() > before.generation());
    assert!(changes.global_reconcile);
    assert!(changes.target_ids.is_empty());
}

#[test]
fn target_full_reconcile_during_scan_survives_an_old_acknowledgement() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("before/file")));
    let captured = watcher.capture(TARGET).unwrap();

    assert!(watcher.force_full(TARGET));
    assert!(watcher.acknowledge(&captured));

    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
}

#[test]
fn stale_acknowledgement_cannot_clear_a_replaced_registration() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(&watcher, data_event(root.join("before/file")));
    let stale = watcher.capture(TARGET).unwrap();

    let replacement = watcher.register(TARGET, "fingerprint-two", &root).unwrap();

    assert!(replacement.changed);
    assert!(!watcher.acknowledge(&stale));
    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
}

#[test]
fn same_fingerprint_with_a_new_root_still_rejects_stale_ack() {
    let (watcher, temporary, old_root) = watcher_and_root(32);
    inject(&watcher, data_event(old_root.join("before/file")));
    let stale = watcher.capture(TARGET).unwrap();
    let new_root = temporary.path().join("new-data");
    std::fs::create_dir(&new_root).unwrap();

    watcher.register(TARGET, FINGERPRINT, &new_root).unwrap();

    assert!(!watcher.acknowledge(&stale));
    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
}

#[test]
fn sibling_prefixes_route_to_the_exact_root() {
    let temporary = tempfile::tempdir().unwrap();
    let root_one = temporary.path().join("db");
    let root_two = temporary.path().join("db2");
    std::fs::create_dir(&root_one).unwrap();
    std::fs::create_dir(&root_two).unwrap();
    let watcher = SoftDiskWatcher::new(32);
    watcher.register("one", "fp-one", &root_one).unwrap();
    watcher.register("two", "fp-two", &root_two).unwrap();
    acknowledge_initial(&watcher, "one");
    acknowledge_initial(&watcher, "two");

    inject(&watcher, data_event(root_two.join("nested/file")));

    assert!(watcher.capture("one").is_none());
    assert_eq!(
        watcher.capture("two").unwrap().relative_paths(),
        [PathBuf::from("nested")]
    );
}

#[test]
fn nested_roots_route_to_the_nearest_registered_root() {
    let temporary = tempfile::tempdir().unwrap();
    let outer = temporary.path().join("outer");
    let inner = outer.join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    let watcher = SoftDiskWatcher::new(32);
    watcher.register("outer", "fp-outer", &outer).unwrap();
    watcher.register("inner", "fp-inner", &inner).unwrap();
    acknowledge_initial(&watcher, "outer");
    acknowledge_initial(&watcher, "inner");

    inject(&watcher, data_event(inner.join("table/file")));

    assert!(watcher.capture("outer").is_none());
    assert_eq!(
        watcher.capture("inner").unwrap().relative_paths(),
        [PathBuf::from("table")]
    );
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
fn event_storm_coalesces_to_one_pending_target() {
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
        watcher.capture(TARGET).unwrap().relative_paths(),
        [PathBuf::from("schema")]
    );
}

#[test]
fn pending_target_bound_escalates_to_one_global_reconcile() {
    let temporary = tempfile::tempdir().unwrap();
    let watcher = SoftDiskWatcher::new_with_limits(32, 2, Duration::ZERO, Duration::ZERO);
    for index in 0..3 {
        let root = temporary.path().join(index.to_string());
        std::fs::create_dir(&root).unwrap();
        watcher
            .register(
                &format!("target-{index}"),
                &format!("fingerprint-{index}"),
                &root,
            )
            .unwrap();
    }

    let changes = watcher.drain_changes();

    assert!(changes.global_reconcile);
    assert!(changes.target_ids.is_empty());
    assert!(watcher.drain_changes().is_empty());
    for index in 0..3 {
        assert!(
            watcher
                .capture(&format!("target-{index}"))
                .unwrap()
                .requires_full_reconcile()
        );
    }
}

#[test]
fn logical_retirement_immediately_removes_event_routing() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    let _ = watcher.drain_changes();

    let retired = watcher.retire(TARGET).unwrap();
    inject(&watcher, data_event(root.join("late/table.data")));
    let changes = watcher.drain_changes();

    assert_eq!(changes.target_ids, [TARGET.to_string()]);
    assert!(watcher.status(TARGET).is_none());
    assert!(watcher.capture(TARGET).is_none());
    assert!(!format!("{retired:?}").contains(root.to_string_lossy().as_ref()));
    watcher.unwatch_retired(&retired);
}

#[test]
fn retirement_during_kernel_registration_rolls_back_the_late_watch() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir(&root).unwrap();
    let watcher = Arc::new(SoftDiskWatcher::new_with_retry_policy(
        32,
        Duration::ZERO,
        Duration::ZERO,
    ));
    let pause = watcher.pause_next_registration_after_install();
    let worker = {
        let watcher = Arc::clone(&watcher);
        let root = root.clone();
        std::thread::spawn(move || watcher.register(TARGET, FINGERPRINT, &root).unwrap())
    };
    pause.installed.wait();

    let retired = watcher
        .retire(TARGET)
        .expect("the logical registration must be visible before kernel completion");
    pause.resume.wait();
    let stale = worker.join().unwrap();

    assert_eq!(stale.status, RegistrationStatus::Degraded);
    assert!(!stale.changed);
    assert!(watcher.status(TARGET).is_none());
    assert_eq!(watcher.stale_cleanup_attempts.load(Ordering::Relaxed), 1);
    drop(retired);

    // A stale operation cannot confirm an immediate same-root re-add.
    let replacement = watcher.register(TARGET, FINGERPRINT, &root).unwrap();
    assert_eq!(replacement.status, RegistrationStatus::Watching);
    assert!(watcher.is_watching(TARGET, FINGERPRINT));
}

#[test]
fn retired_kernel_cleanup_never_unwatches_a_reused_root() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    let retired = watcher.retire(TARGET).unwrap();
    watcher
        .register("replacement", "replacement-fingerprint", &root)
        .unwrap();

    watcher.unwatch_retired(&retired);
    acknowledge_initial(&watcher, "replacement");
    inject(&watcher, data_event(root.join("schema/table.data")));

    assert!(watcher.capture("replacement").is_some());
}

#[test]
fn a_two_root_rename_dirties_both_targets() {
    let temporary = tempfile::tempdir().unwrap();
    let source_root = temporary.path().join("source");
    let destination_root = temporary.path().join("destination");
    std::fs::create_dir(&source_root).unwrap();
    std::fs::create_dir(&destination_root).unwrap();
    let watcher = SoftDiskWatcher::new(32);
    watcher
        .register("source", "source-fp", &source_root)
        .unwrap();
    watcher
        .register("destination", "destination-fp", &destination_root)
        .unwrap();
    acknowledge_initial(&watcher, "source");
    acknowledge_initial(&watcher, "destination");
    let event = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
        .add_path(source_root.join("old/table.db"))
        .add_path(destination_root.join("new/table.db"));

    inject(&watcher, event);

    assert_eq!(
        watcher.capture("source").unwrap().relative_paths(),
        [PathBuf::from("old")]
    );
    assert_eq!(
        watcher.capture("destination").unwrap().relative_paths(),
        [PathBuf::from("new")]
    );
}

#[test]
fn access_only_events_are_ignored() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    let event = Event::new(EventKind::Access(AccessKind::Read)).add_path(root.join("file"));

    inject(&watcher, event);

    assert!(watcher.capture(TARGET).is_none());
}

#[test]
fn ordinary_other_events_are_ignored() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(
        &watcher,
        Event::new(EventKind::Other).add_path(root.join("file")),
    );

    assert!(watcher.capture(TARGET).is_none());
}

#[test]
fn rescan_flag_is_honored_before_other_kind_filtering() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    let event = Event::new(EventKind::Other)
        .add_path(root.join("file"))
        .set_flag(Flag::Rescan);

    inject(&watcher, event);

    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
}

#[test]
fn callback_errors_force_global_reconciliation_without_leaking_paths() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    let error = notify::Error::generic("backend failed").add_path(root.join("secret-name"));

    watcher.handle_callback_for_test(Err(error));

    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
    assert_eq!(
        watcher.status(TARGET).unwrap().status,
        RegistrationStatus::Degraded
    );
}

#[test]
fn callback_error_retry_rebuilds_backend_and_all_watches() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    watcher.handle_callback_for_test(Err(notify::Error::generic("backend failed")));

    let retry = watcher.retry_degraded();

    assert_eq!(retry.attempted, 1);
    assert_eq!(retry.restored, 1);
    assert!(retry.backend_available);
    assert_eq!(
        watcher.status(TARGET).unwrap().status,
        RegistrationStatus::Watching
    );
    inject(&watcher, data_event(root.join("still-observed/file")));
    assert!(watcher.capture(TARGET).is_some());
}

#[test]
fn registration_waits_for_pending_atomic_backend_rebuild() {
    let (watcher, temporary, _root) = watcher_and_root(32);
    watcher.handle_callback_for_test(Err(notify::Error::generic("backend failed")));
    let second_root = temporary.path().join("second");
    std::fs::create_dir(&second_root).unwrap();

    let registration = watcher
        .register("instance-two", "fingerprint-two", &second_root)
        .unwrap();

    assert_eq!(registration.status, RegistrationStatus::Degraded);
    let retry = watcher.retry_degraded();
    assert_eq!(retry.attempted, 2);
    assert_eq!(retry.restored, 2);
    assert_eq!(retry.still_degraded, 0);
    assert_eq!(
        watcher.status(TARGET).unwrap().status,
        RegistrationStatus::Watching
    );
    assert_eq!(
        watcher.status("instance-two").unwrap().status,
        RegistrationStatus::Watching
    );
}

#[test]
fn pathless_mutation_forces_global_reconciliation() {
    let (watcher, _temporary, _root) = watcher_and_root(32);

    inject(&watcher, Event::new(EventKind::Create(CreateKind::File)));

    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
}

#[test]
fn relative_callback_paths_are_never_forwarded() {
    let (watcher, _temporary, _root) = watcher_and_root(32);

    inject(&watcher, data_event("relative/attacker-controlled.db"));

    assert!(watcher.capture(TARGET).is_none());
}

#[test]
fn traversal_like_callback_path_forces_target_full_reconcile() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    inject(
        &watcher,
        data_event(root.join("database/../outside/file.db")),
    );

    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
}

#[test]
fn create_and_remove_events_both_dirty_the_parent() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    inject(&watcher, create_event(root.join("a/new-file")));
    inject(&watcher, remove_event(root.join("b/old-file")));

    assert_eq!(
        watcher.capture(TARGET).unwrap().relative_paths(),
        [PathBuf::from("a"), PathBuf::from("b")]
    );
}

#[test]
fn root_removal_requires_full_reconcile_and_watch_retry() {
    let (watcher, _temporary, root) = watcher_and_root(32);

    inject(&watcher, remove_event(root));
    let status = watcher.status(TARGET).unwrap();

    assert_eq!(status.status, RegistrationStatus::Degraded);
    assert!(status.full_reconcile_pending);
    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
}

#[test]
fn root_rename_requires_full_reconcile_and_watch_retry() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    let event = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::From))).add_path(root);

    inject(&watcher, event);

    assert_eq!(
        watcher.status(TARGET).unwrap().status,
        RegistrationStatus::Degraded
    );
    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
}

#[test]
fn root_metadata_change_is_full_but_does_not_claim_watch_loss() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    let event = Event::new(EventKind::Modify(ModifyKind::Metadata(
        notify::event::MetadataKind::Permissions,
    )))
    .add_path(root);

    inject(&watcher, event);

    assert_eq!(
        watcher.status(TARGET).unwrap().status,
        RegistrationStatus::Watching
    );
    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
}

#[test]
fn dirty_batch_debug_output_redacts_identity_and_paths() {
    let (watcher, _temporary, root) = watcher_and_root(32);
    inject(
        &watcher,
        data_event(root.join("secret-schema/secret-table")),
    );

    let debug = format!("{:?}", watcher.capture(TARGET).unwrap());

    assert!(!debug.contains(TARGET));
    assert!(!debug.contains(FINGERPRINT));
    assert!(!debug.contains("secret"));
    assert!(debug.contains("dirty_directory_count"));
}

#[tokio::test]
async fn change_wait_is_race_free_when_signal_precedes_wait() {
    let (watcher, _temporary, _root) = watcher_and_root(32);
    let observed = watcher.current_change_sequence();
    watcher.force_full(TARGET);

    let changed = tokio::time::timeout(Duration::from_secs(1), watcher.changed_after(observed))
        .await
        .unwrap();

    assert_ne!(changed, observed);
}

#[tokio::test]
async fn one_signal_wakes_all_registered_change_waiters() {
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
        (first.await.unwrap(), second.await.unwrap())
    })
    .await
    .unwrap();
    assert_ne!(first, observed);
    assert_eq!(first, second);
}

#[test]
fn registration_failure_degrades_and_retry_recovers_after_root_appears() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("not-created-yet");
    let watcher = SoftDiskWatcher::new_with_retry_policy(32, Duration::ZERO, Duration::ZERO);
    let registration = watcher.register(TARGET, FINGERPRINT, &root).unwrap();
    assert_eq!(registration.status, RegistrationStatus::Degraded);
    acknowledge_initial(&watcher, TARGET);
    let _ = watcher.drain_changes();

    std::fs::create_dir(&root).unwrap();
    let retry = watcher.retry_degraded();

    assert_eq!(retry.attempted, 1);
    assert_eq!(retry.restored, 1);
    assert_eq!(retry.still_degraded, 0);
    assert!(retry.backend_available);
    assert_eq!(
        watcher.status(TARGET).unwrap().status,
        RegistrationStatus::Watching
    );
    assert!(watcher.capture(TARGET).unwrap().requires_full_reconcile());
    assert_eq!(watcher.drain_changes().target_ids, [TARGET.to_string()]);
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_inotify_observes_recursive_create_write_and_delete() {
    let (watcher, _temporary, root) = watcher_and_root(64);
    let nested = root.join("new/schema");
    std::fs::create_dir_all(&nested).unwrap();
    let file = nested.join("table.data");
    std::fs::write(&file, b"first").unwrap();
    std::fs::write(&file, b"second").unwrap();
    std::fs::remove_file(&file).unwrap();

    let batch = wait_for_dirty(&watcher, TARGET).await;

    // Backends may coalesce the same filesystem activity differently.
    assert!(batch.requires_full_reconcile() || !batch.relative_paths().is_empty());
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_inotify_observes_cross_root_rename_on_both_targets() {
    let temporary = tempfile::tempdir().unwrap();
    let source_root = temporary.path().join("source");
    let destination_root = temporary.path().join("destination");
    std::fs::create_dir(&source_root).unwrap();
    std::fs::create_dir(&destination_root).unwrap();
    let source = source_root.join("moving.data");
    std::fs::write(&source, b"data").unwrap();
    let watcher = SoftDiskWatcher::new(64);
    watcher
        .register("source", "source-fp", &source_root)
        .unwrap();
    watcher
        .register("destination", "destination-fp", &destination_root)
        .unwrap();
    acknowledge_initial(&watcher, "source");
    acknowledge_initial(&watcher, "destination");

    std::fs::rename(source, destination_root.join("moved.data")).unwrap();

    let source_batch = wait_for_dirty(&watcher, "source").await;
    let destination_batch = wait_for_dirty(&watcher, "destination").await;
    assert!(source_batch.requires_full_reconcile() || !source_batch.relative_paths().is_empty());
    assert!(
        destination_batch.requires_full_reconcile()
            || !destination_batch.relative_paths().is_empty()
    );
}
