use std::{
    fs::{self, File, hard_link},
    os::unix::fs::{MetadataExt, symlink},
    path::{Path, PathBuf},
    time::Duration,
};

use crate::disk::usage::scan_directory_blocking;

use super::*;

fn limits() -> ScanLimits {
    ScanLimits {
        timeout: Duration::from_secs(5),
        max_entries: 10_000,
        max_depth: 128,
    }
}

fn baseline(root: &Path) -> UsageTreeCache {
    UsageTreeCache::scan_full(root, "generation-one".to_string(), limits()).unwrap()
}

fn reconcile(
    cache: &mut UsageTreeCache,
    root: &Path,
    dirty_directories: &[&str],
) -> Result<DirectoryUsage, ReconcileError> {
    cache.reconcile(
        root,
        "generation-one",
        &dirty_directories
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>(),
        limits(),
    )
}

fn assert_matches_full(cache: &UsageTreeCache, root: &Path) {
    assert_eq!(
        cache.usage(),
        scan_directory_blocking(root, limits()).unwrap()
    );
}

#[test]
fn full_baseline_exactly_matches_the_authoritative_scanner() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(root.join("a/b")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(root.join("root.bin"), b"root").unwrap();
    fs::write(root.join("a/one.bin"), vec![1_u8; 71]).unwrap();
    fs::write(root.join("a/b/two.bin"), vec![2_u8; 113]).unwrap();
    fs::write(outside.join("not-counted"), vec![3_u8; 1_000]).unwrap();
    symlink(&outside, root.join("outside-link")).unwrap();

    let cache = baseline(&root);

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 188);
    assert_eq!(cache.nodes.len(), 3);
}

#[test]
fn bounded_full_scan_reports_directory_limit_instead_of_retaining_a_large_tree() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("one")).unwrap();
    fs::create_dir_all(root.join("two")).unwrap();

    let result =
        UsageTreeCache::scan_full_bounded(&root, "generation".to_string(), limits(), 2).unwrap();

    assert!(matches!(result, BoundedFullScan::DirectoryLimitExceeded));
}

#[test]
fn reconcile_rejects_per_target_growth_transactionally_before_commit() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("nested")).unwrap();
    fs::write(root.join("nested/old.bin"), b"old").unwrap();
    let mut cache =
        match UsageTreeCache::scan_full_bounded(&root, "generation-one".to_string(), limits(), 2)
            .unwrap()
        {
            BoundedFullScan::Cached(cache) => cache,
            BoundedFullScan::DirectoryLimitExceeded => panic!("the baseline must fit"),
        };
    let original_usage = cache.usage();

    fs::create_dir(root.join("nested/new")).unwrap();
    fs::write(root.join("nested/new/value.bin"), b"new").unwrap();
    let error = cache
        .reconcile(
            &root,
            "generation-one",
            &[PathBuf::from("nested")],
            limits(),
        )
        .unwrap_err();

    assert!(error.requires_full_scan());
    assert_eq!(cache.directory_count(), 2);
    assert_eq!(cache.usage(), original_usage);
}

#[test]
fn partial_batch_enforces_one_cumulative_directory_bound_across_subtrees() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::create_dir_all(root.join("b")).unwrap();
    let mut cache =
        match UsageTreeCache::scan_full_bounded(&root, "generation-one".to_string(), limits(), 5)
            .unwrap()
        {
            BoundedFullScan::Cached(cache) => cache,
            BoundedFullScan::DirectoryLimitExceeded => panic!("the baseline must fit"),
        };
    let original_usage = cache.usage();

    // Both replacements share one five-node staging budget.
    fs::create_dir_all(root.join("a/one/two/three")).unwrap();
    fs::create_dir(root.join("b/new")).unwrap();
    let error = cache
        .reconcile(
            &root,
            "generation-one",
            &[PathBuf::from("a"), PathBuf::from("b")],
            limits(),
        )
        .unwrap_err();

    assert!(error.requires_full_scan());
    assert!(
        error
            .to_string()
            .contains("cumulative incremental cache directory bound")
    );
    assert_eq!(cache.directory_count(), 3);
    assert_eq!(cache.usage(), original_usage);
}

#[test]
fn partial_batch_accepts_multiple_subtrees_when_the_final_cache_fits_exactly() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::create_dir_all(root.join("b")).unwrap();
    let mut cache =
        match UsageTreeCache::scan_full_bounded(&root, "generation-one".to_string(), limits(), 5)
            .unwrap()
        {
            BoundedFullScan::Cached(cache) => cache,
            BoundedFullScan::DirectoryLimitExceeded => panic!("the baseline must fit"),
        };

    fs::create_dir(root.join("a/new")).unwrap();
    fs::create_dir(root.join("b/new")).unwrap();
    cache
        .reconcile(
            &root,
            "generation-one",
            &[PathBuf::from("a"), PathBuf::from("b")],
            limits(),
        )
        .unwrap();

    assert_eq!(cache.directory_count(), 5);
    assert_matches_full(&cache, &root);
}

#[test]
fn full_baseline_preserves_sparse_logical_and_physical_accounting() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("nested")).unwrap();
    let sparse = File::create(root.join("nested/sparse.bin")).unwrap();
    sparse.set_len(32 * 1024 * 1024).unwrap();

    let cache = baseline(&root);

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 32 * 1024 * 1024);
    assert!(cache.usage().physical_bytes < cache.usage().logical_bytes);
}

#[test]
fn full_baseline_counts_hard_links_like_the_authoritative_scanner() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::create_dir_all(root.join("b")).unwrap();
    fs::write(root.join("a/original"), vec![7_u8; 211]).unwrap();
    hard_link(root.join("a/original"), root.join("b/link")).unwrap();

    let cache = baseline(&root);

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 422);
}

#[test]
fn exposes_the_open_root_device_and_inode_without_following_a_symlink() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    let link = temporary.path().join("data-link");
    fs::create_dir(&root).unwrap();
    symlink(&root, &link).unwrap();
    let metadata = fs::symlink_metadata(&root).unwrap();

    let identity = root_identity(&root).unwrap();

    assert_eq!(identity.device, metadata.dev());
    assert_eq!(identity.inode, metadata.ino());
    assert!(root_identity(&link).is_err());
}

#[test]
fn cache_retains_the_caller_target_generation_and_root_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let cache = UsageTreeCache::scan_full(
        temporary.path(),
        "opaque-instance-fingerprint".to_string(),
        limits(),
    )
    .unwrap();

    assert_eq!(cache.target_generation, "opaque-instance-fingerprint");
    assert_eq!(
        cache.root_identity,
        root_identity(temporary.path()).unwrap()
    );
}

#[test]
fn modifying_a_nested_file_reconciles_only_its_dirty_directory() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/b")).unwrap();
    fs::write(root.join("a/b/value"), b"old").unwrap();
    let mut cache = baseline(&root);
    fs::write(root.join("a/b/value"), vec![4_u8; 8_193]).unwrap();

    reconcile(&mut cache, &root, &["a/b"]).unwrap();

    assert_matches_full(&cache, &root);
}

#[test]
fn truncating_a_file_updates_logical_and_allocated_totals() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::write(root.join("a/value"), vec![5_u8; 64 * 1024]).unwrap();
    let mut cache = baseline(&root);
    File::options()
        .write(true)
        .open(root.join("a/value"))
        .unwrap()
        .set_len(9)
        .unwrap();

    reconcile(&mut cache, &root, &["a"]).unwrap();

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 9);
}

#[test]
fn creating_and_deleting_files_updates_entries_and_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::write(root.join("a/old"), vec![1_u8; 31]).unwrap();
    let mut cache = baseline(&root);
    fs::remove_file(root.join("a/old")).unwrap();
    fs::write(root.join("a/new"), vec![2_u8; 47]).unwrap();
    fs::write(root.join("a/second"), vec![3_u8; 53]).unwrap();

    reconcile(&mut cache, &root, &["a"]).unwrap();

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 100);
}

#[test]
fn a_new_uncached_directory_climbs_to_its_cached_parent() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    let mut cache = baseline(&root);
    fs::create_dir_all(root.join("a/new/nested")).unwrap();
    fs::write(root.join("a/new/nested/value"), vec![9_u8; 97]).unwrap();

    reconcile(&mut cache, &root, &["a/new"]).unwrap();

    assert_matches_full(&cache, &root);
    assert!(cache.nodes.contains_key(Path::new("a/new/nested")));
}

#[test]
fn a_deleted_directory_climbs_to_the_nearest_existing_cached_parent() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/deleted/nested")).unwrap();
    fs::write(root.join("a/deleted/nested/value"), b"gone").unwrap();
    let mut cache = baseline(&root);
    fs::remove_dir_all(root.join("a/deleted")).unwrap();

    reconcile(&mut cache, &root, &["a/deleted"]).unwrap();

    assert_matches_full(&cache, &root);
    assert!(!cache.nodes.contains_key(Path::new("a/deleted")));
}

#[test]
fn a_directory_replaced_by_a_regular_file_reconciles_its_parent() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/replaced")).unwrap();
    fs::write(root.join("a/replaced/old"), b"old").unwrap();
    let mut cache = baseline(&root);
    fs::remove_dir_all(root.join("a/replaced")).unwrap();
    fs::write(root.join("a/replaced"), vec![8_u8; 123]).unwrap();

    reconcile(&mut cache, &root, &["a/replaced"]).unwrap();

    assert_matches_full(&cache, &root);
    assert!(!cache.nodes.contains_key(Path::new("a/replaced")));
}

#[test]
fn a_directory_replaced_by_a_symlink_never_follows_the_link() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(root.join("a/replaced")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(root.join("a/replaced/old"), b"old").unwrap();
    fs::write(outside.join("large-secret"), vec![0_u8; 128 * 1024]).unwrap();
    let mut cache = baseline(&root);
    fs::remove_dir_all(root.join("a/replaced")).unwrap();
    symlink(&outside, root.join("a/replaced")).unwrap();

    reconcile(&mut cache, &root, &["a/replaced"]).unwrap();

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 0);
}

#[test]
fn rename_within_one_directory_is_reconciled_atomically() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/old/nested")).unwrap();
    fs::write(root.join("a/old/nested/value"), b"value").unwrap();
    let mut cache = baseline(&root);
    fs::rename(root.join("a/old"), root.join("a/new")).unwrap();

    reconcile(&mut cache, &root, &["a"]).unwrap();

    assert_matches_full(&cache, &root);
    assert!(cache.nodes.contains_key(Path::new("a/new/nested")));
    assert!(!cache.nodes.contains_key(Path::new("a/old")));
}

#[test]
fn rename_between_directories_updates_both_subtrees_as_one_batch() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/moved/nested")).unwrap();
    fs::create_dir_all(root.join("b")).unwrap();
    fs::write(root.join("a/moved/nested/value"), vec![1_u8; 700]).unwrap();
    let mut cache = baseline(&root);
    fs::rename(root.join("a/moved"), root.join("b/moved")).unwrap();

    reconcile(&mut cache, &root, &["a", "b"]).unwrap();

    assert_matches_full(&cache, &root);
    assert!(!cache.nodes.contains_key(Path::new("a/moved")));
    assert!(cache.nodes.contains_key(Path::new("b/moved/nested")));
}

#[test]
fn ancestor_hints_subsume_descendant_hints() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/b/c")).unwrap();
    for index in 0..8 {
        fs::write(root.join(format!("a/b/c/{index}")), [index as u8]).unwrap();
    }
    let mut cache = baseline(&root);
    fs::write(root.join("a/b/c/new"), b"new").unwrap();

    reconcile(&mut cache, &root, &["a", "a/b", "a/b/c"]).unwrap();

    assert_matches_full(&cache, &root);
}

#[test]
fn duplicate_hints_are_deduplicated() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::write(root.join("a/value"), b"before").unwrap();
    let mut cache = baseline(&root);
    fs::write(root.join("a/value"), b"after-after").unwrap();

    reconcile(&mut cache, &root, &["a", "a", "a"]).unwrap();

    assert_matches_full(&cache, &root);
}

#[test]
fn an_empty_hint_batch_preserves_the_current_snapshot() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("value"), b"before").unwrap();
    let mut cache = baseline(&root);
    let before = cache.usage();
    fs::write(root.join("value"), b"changed but not hinted").unwrap();

    let result = reconcile(&mut cache, &root, &[]).unwrap();

    assert_eq!(result, before);
    assert_eq!(cache.usage(), before);
}

#[test]
fn root_hint_requires_a_full_reconciliation() {
    let temporary = tempfile::tempdir().unwrap();
    let mut cache = baseline(temporary.path());

    let error = reconcile(&mut cache, temporary.path(), &[""]).unwrap_err();

    assert!(error.requires_full_scan());
}

#[test]
fn absolute_and_parent_traversal_hints_require_a_full_reconciliation() {
    let temporary = tempfile::tempdir().unwrap();
    fs::create_dir(temporary.path().join("a")).unwrap();
    let mut cache = baseline(temporary.path());

    for unsafe_path in ["/tmp/outside", "../outside", "a/../outside", "."] {
        let error = cache
            .reconcile(
                temporary.path(),
                "generation-one",
                &[PathBuf::from(unsafe_path)],
                limits(),
            )
            .unwrap_err();
        assert!(error.requires_full_scan(), "{unsafe_path}");
    }
}

#[test]
fn errors_never_expose_tenant_controlled_dirty_path_names() {
    let temporary = tempfile::tempdir().unwrap();
    let mut cache = baseline(temporary.path());
    let secret = "tenant-secret-password-do-not-log";

    let error = cache
        .reconcile(
            temporary.path(),
            "generation-one",
            &[PathBuf::from(format!("../{secret}"))],
            limits(),
        )
        .unwrap_err();

    assert!(!error.to_string().contains(secret));
}

#[test]
fn a_target_generation_change_invalidates_without_mutating_the_cache() {
    let temporary = tempfile::tempdir().unwrap();
    fs::create_dir(temporary.path().join("a")).unwrap();
    let mut cache = baseline(temporary.path());
    let before = cache.usage();

    let error = cache
        .reconcile(
            temporary.path(),
            "different-generation",
            &[PathBuf::from("a")],
            limits(),
        )
        .unwrap_err();

    assert!(error.requires_full_scan());
    assert_eq!(cache.usage(), before);
}

#[test]
fn replacing_the_root_at_the_same_path_invalidates_the_cache() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    let old = temporary.path().join("old-data");
    fs::create_dir_all(root.join("a")).unwrap();
    let mut cache = baseline(&root);
    fs::rename(&root, &old).unwrap();
    fs::create_dir_all(root.join("a")).unwrap();

    let error = reconcile(&mut cache, &root, &["a"]).unwrap_err();

    assert!(error.requires_full_scan());
}

#[test]
fn failed_second_subtree_scan_does_not_commit_the_first_subtree() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::create_dir_all(root.join("b")).unwrap();
    fs::write(root.join("a/value"), b"old-a").unwrap();
    fs::write(root.join("b/value"), b"old-b").unwrap();
    let mut cache = baseline(&root);
    let before = cache.usage();
    fs::write(root.join("a/value"), vec![1_u8; 16_000]).unwrap();
    fs::create_dir(root.join("b/deep")).unwrap();
    fs::write(root.join("b/deep/value"), b"too deep").unwrap();
    let strict_depth = ScanLimits {
        max_depth: 1,
        ..limits()
    };

    let error = cache
        .reconcile(
            &root,
            "generation-one",
            &[PathBuf::from("a"), PathBuf::from("b")],
            strict_depth,
        )
        .unwrap_err();

    assert!(matches!(error, ReconcileError::Io(_)));
    assert_eq!(cache.usage(), before);
}

#[test]
fn partial_batch_shares_one_entry_budget_and_remains_transactional() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::create_dir_all(root.join("b")).unwrap();
    let mut cache = baseline(&root);
    let before = cache.usage();
    for index in 0..6 {
        fs::write(root.join(format!("a/{index}")), [0]).unwrap();
        fs::write(root.join(format!("b/{index}")), [0]).unwrap();
    }
    let small_budget = ScanLimits {
        max_entries: 8,
        ..limits()
    };

    let error = cache
        .reconcile(
            &root,
            "generation-one",
            &[PathBuf::from("a"), PathBuf::from("b")],
            small_budget,
        )
        .unwrap_err();

    assert!(matches!(error, ReconcileError::Io(_)));
    assert_eq!(cache.usage(), before);
}

#[test]
fn partial_batch_shares_one_timeout_budget() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    let mut cache = baseline(&root);
    let before = cache.usage();
    let no_time = ScanLimits {
        timeout: Duration::ZERO,
        ..limits()
    };

    let error = cache
        .reconcile(&root, "generation-one", &[PathBuf::from("a")], no_time)
        .unwrap_err();

    assert!(
        matches!(error, ReconcileError::Io(ref source) if source.kind() == ErrorKind::TimedOut)
    );
    assert_eq!(cache.usage(), before);
}

#[test]
fn partial_scans_enforce_depth_from_the_real_root_not_the_subtree() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    let mut cache = baseline(&root);
    fs::create_dir_all(root.join("a/deep/deeper")).unwrap();
    let shallow = ScanLimits {
        max_depth: 1,
        ..limits()
    };

    let error = cache
        .reconcile(&root, "generation-one", &[PathBuf::from("a")], shallow)
        .unwrap_err();

    assert!(matches!(error, ReconcileError::Io(_)));
}

#[test]
fn full_and_partial_scans_enforce_entry_bounds() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    for index in 0..5 {
        fs::write(root.join(format!("a/{index}")), [0]).unwrap();
    }
    let too_small = ScanLimits {
        max_entries: 3,
        ..limits()
    };

    assert!(UsageTreeCache::scan_full(&root, "generation".to_string(), too_small).is_err());

    let mut cache = baseline(&root);
    let before = cache.usage();
    fs::write(root.join("a/new"), [0]).unwrap();
    let error = cache
        .reconcile(&root, "generation-one", &[PathBuf::from("a")], too_small)
        .unwrap_err();
    assert!(matches!(error, ReconcileError::Io(_)));
    assert_eq!(cache.usage(), before);
}

#[test]
fn sparse_file_growth_is_reconciled_without_using_logical_size_as_physical() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    let sparse_path = root.join("a/sparse");
    File::create(&sparse_path)
        .unwrap()
        .set_len(1_024 * 1_024)
        .unwrap();
    let mut cache = baseline(&root);
    File::options()
        .write(true)
        .open(&sparse_path)
        .unwrap()
        .set_len(64 * 1_024 * 1_024)
        .unwrap();

    reconcile(&mut cache, &root, &["a"]).unwrap();

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 64 * 1_024 * 1_024);
}

#[test]
fn hard_link_changes_do_not_silently_switch_to_inode_deduplication() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::create_dir_all(root.join("b")).unwrap();
    let original = root.join("a/original");
    fs::write(&original, vec![0_u8; 32]).unwrap();
    hard_link(&original, root.join("b/link")).unwrap();
    let mut cache = baseline(&root);
    File::options()
        .write(true)
        .open(&original)
        .unwrap()
        .set_len(512)
        .unwrap();

    reconcile(&mut cache, &root, &["a", "b"]).unwrap();

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 1_024);
}

#[test]
fn cached_directory_count_tracks_subtree_creation_and_deletion() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    let mut cache = baseline(&root);
    assert_eq!(cache.nodes.len(), 2);
    fs::create_dir_all(root.join("a/one/two/three")).unwrap();
    reconcile(&mut cache, &root, &["a"]).unwrap();
    assert_eq!(cache.nodes.len(), 5);
    fs::remove_dir_all(root.join("a/one")).unwrap();
    reconcile(&mut cache, &root, &["a"]).unwrap();
    assert_eq!(cache.nodes.len(), 2);
}

#[test]
fn a_missing_cached_child_requires_full_reconciliation_without_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/b")).unwrap();
    let mut cache = baseline(&root);
    cache.nodes.remove(Path::new("a/b"));
    let before = cache.usage();

    let error = reconcile(&mut cache, &root, &["a"]).unwrap_err();

    assert!(error.requires_full_scan());
    assert_eq!(cache.usage(), before);
}

#[test]
fn an_inconsistent_cached_aggregate_requires_full_reconciliation() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    let mut cache = baseline(&root);
    cache
        .nodes
        .get_mut(Path::new(""))
        .unwrap()
        .total
        .logical_bytes += 1;
    let before = cache.usage();

    let error = reconcile(&mut cache, &root, &["a"]).unwrap_err();

    assert!(error.requires_full_scan());
    assert_eq!(cache.usage(), before);
}

#[test]
fn a_missing_root_cache_node_requires_full_reconciliation() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    let mut cache = baseline(&root);
    cache.nodes.remove(Path::new(""));

    let error = reconcile(&mut cache, &root, &["a"]).unwrap_err();

    assert!(error.requires_full_scan());
}

#[test]
fn an_unsafe_cached_child_component_requires_full_reconciliation() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a")).unwrap();
    let mut cache = baseline(&root);
    cache
        .nodes
        .get_mut(Path::new(""))
        .unwrap()
        .children
        .insert(OsString::from("../escape"));

    let error = reconcile(&mut cache, &root, &["a"]).unwrap_err();

    assert!(error.requires_full_scan());
}

#[test]
fn full_scan_with_no_time_budget_fails_without_publishing_a_cache() {
    let temporary = tempfile::tempdir().unwrap();
    let no_time = ScanLimits {
        timeout: Duration::ZERO,
        ..limits()
    };

    let error =
        UsageTreeCache::scan_full(temporary.path(), "generation".to_string(), no_time).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::TimedOut);
}
