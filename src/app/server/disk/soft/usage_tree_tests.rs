use std::{
    fs::{self, File, hard_link},
    os::unix::fs::{MetadataExt, symlink},
    path::{Path, PathBuf},
    time::Duration,
};

use crate::server::disk::usage::scan_directory_sync;

use super::*;

fn limits() -> ScanLimits {
    ScanLimits {
        timeout: Duration::from_secs(5),
        max_entries: 10_000,
        max_depth: 128,
    }
}

fn baseline(root: &Path) -> UsageTreeCache {
    UsageTreeCache::scan_full(root, "generation-one".to_string(), limits())
        .expect("limits should succeed")
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
        scan_directory_sync(root, limits()).expect("limits should succeed")
    );
}

#[test]
fn full_baseline_exactly_matches_the_authoritative_scanner() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(root.join("a/b"))?;
    fs::create_dir_all(&outside)?;
    fs::write(root.join("root.bin"), b"root")?;
    fs::write(root.join("a/one.bin"), vec![1_u8; 71])?;
    fs::write(root.join("a/b/two.bin"), vec![2_u8; 113])?;
    fs::write(outside.join("not-counted"), vec![3_u8; 1_000])?;
    symlink(&outside, root.join("outside-link"))?;

    let cache = baseline(&root);

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 188);
    assert_eq!(cache.nodes.len(), 3);

    Ok(())
}

#[test]
fn bounded_full_scan_reports_directory_limit_instead_of_retaining_a_large_tree()
-> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("one"))?;
    fs::create_dir_all(root.join("two"))?;

    let result = UsageTreeCache::scan_full_bounded(&root, "generation".to_string(), limits(), 2)?;

    assert!(matches!(result, BoundedFullScan::DirectoryLimitExceeded));

    Ok(())
}

#[test]
fn reconcile_rejects_per_target_growth_transactionally_before_commit() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("nested"))?;
    fs::write(root.join("nested/old.bin"), b"old")?;
    let mut cache = match UsageTreeCache::scan_full_bounded(
        &root,
        "generation-one".to_string(),
        limits(),
        2,
    )? {
        BoundedFullScan::Cached(cache) => cache,
        BoundedFullScan::DirectoryLimitExceeded => panic!("the baseline must fit"),
    };
    let original_usage = cache.usage();

    fs::create_dir(root.join("nested/new"))?;
    fs::write(root.join("nested/new/value.bin"), b"new")?;
    let error = cache
        .reconcile(
            &root,
            "generation-one",
            &[PathBuf::from("nested")],
            limits(),
        )
        .expect_err("limits should return an error");

    assert!(error.requires_full_scan());
    assert_eq!(cache.directory_count(), 2);
    assert_eq!(cache.usage(), original_usage);

    Ok(())
}

#[test]
fn partial_batch_enforces_one_cumulative_directory_bound_across_subtrees() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    fs::create_dir_all(root.join("b"))?;
    let mut cache = match UsageTreeCache::scan_full_bounded(
        &root,
        "generation-one".to_string(),
        limits(),
        5,
    )? {
        BoundedFullScan::Cached(cache) => cache,
        BoundedFullScan::DirectoryLimitExceeded => panic!("the baseline must fit"),
    };
    let original_usage = cache.usage();

    // Both replacements share one five-node staging budget.
    fs::create_dir_all(root.join("a/one/two/three"))?;
    fs::create_dir(root.join("b/new"))?;
    let error = cache
        .reconcile(
            &root,
            "generation-one",
            &[PathBuf::from("a"), PathBuf::from("b")],
            limits(),
        )
        .expect_err("limits should return an error");

    assert!(error.requires_full_scan());
    assert!(
        error
            .to_string()
            .contains("cumulative incremental cache directory bound")
    );
    assert_eq!(cache.directory_count(), 3);
    assert_eq!(cache.usage(), original_usage);

    Ok(())
}

#[test]
fn partial_batch_accepts_multiple_subtrees_when_the_final_cache_fits_exactly() -> anyhow::Result<()>
{
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    fs::create_dir_all(root.join("b"))?;
    let mut cache = match UsageTreeCache::scan_full_bounded(
        &root,
        "generation-one".to_string(),
        limits(),
        5,
    )? {
        BoundedFullScan::Cached(cache) => cache,
        BoundedFullScan::DirectoryLimitExceeded => panic!("the baseline must fit"),
    };

    fs::create_dir(root.join("a/new"))?;
    fs::create_dir(root.join("b/new"))?;
    cache.reconcile(
        &root,
        "generation-one",
        &[PathBuf::from("a"), PathBuf::from("b")],
        limits(),
    )?;

    assert_eq!(cache.directory_count(), 5);
    assert_matches_full(&cache, &root);

    Ok(())
}

#[test]
fn full_baseline_preserves_sparse_logical_and_physical_accounting() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("nested"))?;
    let sparse = File::create(root.join("nested/sparse.bin"))?;
    sparse.set_len(32 * 1024 * 1024)?;

    let cache = baseline(&root);

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 32 * 1024 * 1024);
    assert!(cache.usage().physical_bytes < cache.usage().logical_bytes);

    Ok(())
}

#[test]
fn full_baseline_counts_hard_links_like_the_authoritative_scanner() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    fs::create_dir_all(root.join("b"))?;
    fs::write(root.join("a/original"), vec![7_u8; 211])?;
    hard_link(root.join("a/original"), root.join("b/link"))?;

    let cache = baseline(&root);

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 422);

    Ok(())
}

#[test]
fn exposes_the_open_root_device_and_inode_without_following_a_symlink() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    let link = temporary.path().join("data-link");
    fs::create_dir(&root)?;
    symlink(&root, &link)?;
    let metadata = fs::symlink_metadata(&root)?;

    let identity = root_identity(&root)?;

    assert_eq!(identity.device, metadata.dev());
    assert_eq!(identity.inode, metadata.ino());
    assert!(root_identity(&link).is_err());

    Ok(())
}

#[test]
fn modifying_a_nested_file_reconciles_only_its_dirty_directory() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/b"))?;
    fs::write(root.join("a/b/value"), b"old")?;
    let mut cache = baseline(&root);
    fs::write(root.join("a/b/value"), vec![4_u8; 8_193])?;

    reconcile(&mut cache, &root, &["a/b"])?;

    assert_matches_full(&cache, &root);

    Ok(())
}

#[test]
fn truncating_a_file_updates_logical_and_allocated_totals() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    fs::write(root.join("a/value"), vec![5_u8; 64 * 1024])?;
    let mut cache = baseline(&root);
    File::options()
        .write(true)
        .open(root.join("a/value"))?
        .set_len(9)?;

    reconcile(&mut cache, &root, &["a"])?;

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 9);

    Ok(())
}

#[test]
fn creating_and_deleting_files_updates_entries_and_bytes() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    fs::write(root.join("a/old"), vec![1_u8; 31])?;
    let mut cache = baseline(&root);
    fs::remove_file(root.join("a/old"))?;
    fs::write(root.join("a/new"), vec![2_u8; 47])?;
    fs::write(root.join("a/second"), vec![3_u8; 53])?;

    reconcile(&mut cache, &root, &["a"])?;

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 100);

    Ok(())
}

#[test]
fn a_new_uncached_directory_climbs_to_its_cached_parent() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    let mut cache = baseline(&root);
    fs::create_dir_all(root.join("a/new/nested"))?;
    fs::write(root.join("a/new/nested/value"), vec![9_u8; 97])?;

    reconcile(&mut cache, &root, &["a/new"])?;

    assert_matches_full(&cache, &root);
    assert!(cache.nodes.contains_key(Path::new("a/new/nested")));

    Ok(())
}

#[test]
fn a_deleted_directory_climbs_to_the_nearest_existing_cached_parent() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/deleted/nested"))?;
    fs::write(root.join("a/deleted/nested/value"), b"gone")?;
    let mut cache = baseline(&root);
    fs::remove_dir_all(root.join("a/deleted"))?;

    reconcile(&mut cache, &root, &["a/deleted"])?;

    assert_matches_full(&cache, &root);
    assert!(!cache.nodes.contains_key(Path::new("a/deleted")));

    Ok(())
}

#[test]
fn a_directory_replaced_by_a_regular_file_reconciles_its_parent() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/replaced"))?;
    fs::write(root.join("a/replaced/old"), b"old")?;
    let mut cache = baseline(&root);
    fs::remove_dir_all(root.join("a/replaced"))?;
    fs::write(root.join("a/replaced"), vec![8_u8; 123])?;

    reconcile(&mut cache, &root, &["a/replaced"])?;

    assert_matches_full(&cache, &root);
    assert!(!cache.nodes.contains_key(Path::new("a/replaced")));

    Ok(())
}

#[test]
fn a_directory_replaced_by_a_symlink_never_follows_the_link() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(root.join("a/replaced"))?;
    fs::create_dir_all(&outside)?;
    fs::write(root.join("a/replaced/old"), b"old")?;
    fs::write(outside.join("large-secret"), vec![0_u8; 128 * 1024])?;
    let mut cache = baseline(&root);
    fs::remove_dir_all(root.join("a/replaced"))?;
    symlink(&outside, root.join("a/replaced"))?;

    reconcile(&mut cache, &root, &["a/replaced"])?;

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 0);

    Ok(())
}

#[test]
fn rename_within_one_directory_is_reconciled_atomically() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/old/nested"))?;
    fs::write(root.join("a/old/nested/value"), b"value")?;
    let mut cache = baseline(&root);
    fs::rename(root.join("a/old"), root.join("a/new"))?;

    reconcile(&mut cache, &root, &["a"])?;

    assert_matches_full(&cache, &root);
    assert!(cache.nodes.contains_key(Path::new("a/new/nested")));
    assert!(!cache.nodes.contains_key(Path::new("a/old")));

    Ok(())
}

#[test]
fn rename_between_directories_updates_both_subtrees_as_one_batch() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/moved/nested"))?;
    fs::create_dir_all(root.join("b"))?;
    fs::write(root.join("a/moved/nested/value"), vec![1_u8; 700])?;
    let mut cache = baseline(&root);
    fs::rename(root.join("a/moved"), root.join("b/moved"))?;

    reconcile(&mut cache, &root, &["a", "b"])?;

    assert_matches_full(&cache, &root);
    assert!(!cache.nodes.contains_key(Path::new("a/moved")));
    assert!(cache.nodes.contains_key(Path::new("b/moved/nested")));

    Ok(())
}

#[test]
fn ancestor_hints_subsume_descendant_hints() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a/b/c"))?;
    for index in 0..8 {
        fs::write(root.join(format!("a/b/c/{index}")), [index as u8])?;
    }
    let mut cache = baseline(&root);
    fs::write(root.join("a/b/c/new"), b"new")?;

    reconcile(&mut cache, &root, &["a", "a/b", "a/b/c"])?;

    assert_matches_full(&cache, &root);

    Ok(())
}

#[test]
fn duplicate_hints_are_deduplicated() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    fs::write(root.join("a/value"), b"before")?;
    let mut cache = baseline(&root);
    fs::write(root.join("a/value"), b"after-after")?;

    reconcile(&mut cache, &root, &["a", "a", "a"])?;

    assert_matches_full(&cache, &root);

    Ok(())
}

#[test]
fn an_empty_hint_batch_preserves_the_current_snapshot() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir(&root)?;
    fs::write(root.join("value"), b"before")?;
    let mut cache = baseline(&root);
    let before = cache.usage();
    fs::write(root.join("value"), b"changed but not hinted")?;

    let result = reconcile(&mut cache, &root, &[])?;

    assert_eq!(result, before);
    assert_eq!(cache.usage(), before);

    Ok(())
}

#[test]
fn root_hint_requires_a_full_reconciliation() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let mut cache = baseline(temporary.path());

    let error =
        reconcile(&mut cache, temporary.path(), &[""]).expect_err("path should return an error");

    assert!(error.requires_full_scan());

    Ok(())
}

#[test]
fn absolute_and_parent_traversal_hints_require_a_full_reconciliation() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    fs::create_dir(temporary.path().join("a"))?;
    let mut cache = baseline(temporary.path());

    for unsafe_path in ["/tmp/outside", "../outside", "a/../outside", "."] {
        let error = cache
            .reconcile(
                temporary.path(),
                "generation-one",
                &[PathBuf::from(unsafe_path)],
                limits(),
            )
            .expect_err("limits should return an error");
        assert!(error.requires_full_scan(), "{unsafe_path}");
    }

    Ok(())
}

#[test]
fn errors_never_expose_tenant_controlled_dirty_path_names() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let mut cache = baseline(temporary.path());
    let secret = "tenant-secret-password-do-not-log";

    let error = cache
        .reconcile(
            temporary.path(),
            "generation-one",
            &[PathBuf::from(format!("../{secret}"))],
            limits(),
        )
        .expect_err("limits should return an error");

    assert!(!error.to_string().contains(secret));

    Ok(())
}

#[test]
fn a_target_generation_change_invalidates_without_mutating_the_cache() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    fs::create_dir(temporary.path().join("a"))?;
    let mut cache = baseline(temporary.path());
    let before = cache.usage();

    let error = cache
        .reconcile(
            temporary.path(),
            "different-generation",
            &[PathBuf::from("a")],
            limits(),
        )
        .expect_err("limits should return an error");

    assert!(error.requires_full_scan());
    assert_eq!(cache.usage(), before);

    Ok(())
}

#[test]
fn replacing_the_root_at_the_same_path_invalidates_the_cache() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    let old = temporary.path().join("old-data");
    fs::create_dir_all(root.join("a"))?;
    let mut cache = baseline(&root);
    fs::rename(&root, &old)?;
    fs::create_dir_all(root.join("a"))?;

    let error = reconcile(&mut cache, &root, &["a"]).expect_err("reconcile should return an error");

    assert!(error.requires_full_scan());

    Ok(())
}

#[test]
fn failed_second_subtree_scan_does_not_commit_the_first_subtree() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    fs::create_dir_all(root.join("b"))?;
    fs::write(root.join("a/value"), b"old-a")?;
    fs::write(root.join("b/value"), b"old-b")?;
    let mut cache = baseline(&root);
    let before = cache.usage();
    fs::write(root.join("a/value"), vec![1_u8; 16_000])?;
    fs::create_dir(root.join("b/deep"))?;
    fs::write(root.join("b/deep/value"), b"too deep")?;
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
        .expect_err("reconcile should return an error");

    assert!(matches!(error, ReconcileError::Io(_)));
    assert_eq!(cache.usage(), before);

    Ok(())
}

#[test]
fn partial_batch_shares_one_entry_budget_and_remains_transactional() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    fs::create_dir_all(root.join("b"))?;
    let mut cache = baseline(&root);
    let before = cache.usage();
    for index in 0..6 {
        fs::write(root.join(format!("a/{index}")), [0])?;
        fs::write(root.join(format!("b/{index}")), [0])?;
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
        .expect_err("reconcile should return an error");

    assert!(matches!(error, ReconcileError::Io(_)));
    assert_eq!(cache.usage(), before);

    Ok(())
}

#[test]
fn partial_batch_shares_one_timeout_budget() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    let mut cache = baseline(&root);
    let before = cache.usage();
    let no_time = ScanLimits {
        timeout: Duration::ZERO,
        ..limits()
    };

    let error = cache
        .reconcile(&root, "generation-one", &[PathBuf::from("a")], no_time)
        .expect_err("reconcile should return an error");

    assert!(
        matches!(error, ReconcileError::Io(ref source) if source.kind() == ErrorKind::TimedOut)
    );
    assert_eq!(cache.usage(), before);

    Ok(())
}

#[test]
fn partial_scans_enforce_depth_from_the_real_root_not_the_subtree() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    let mut cache = baseline(&root);
    fs::create_dir_all(root.join("a/deep/deeper"))?;
    let shallow = ScanLimits {
        max_depth: 1,
        ..limits()
    };

    let error = cache
        .reconcile(&root, "generation-one", &[PathBuf::from("a")], shallow)
        .expect_err("reconcile should return an error");

    assert!(matches!(error, ReconcileError::Io(_)));

    Ok(())
}

#[test]
fn full_and_partial_scans_enforce_entry_bounds() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    for index in 0..5 {
        fs::write(root.join(format!("a/{index}")), [0])?;
    }
    let too_small = ScanLimits {
        max_entries: 3,
        ..limits()
    };

    assert!(UsageTreeCache::scan_full(&root, "generation".to_string(), too_small).is_err());

    let mut cache = baseline(&root);
    let before = cache.usage();
    fs::write(root.join("a/new"), [0])?;
    let error = cache
        .reconcile(&root, "generation-one", &[PathBuf::from("a")], too_small)
        .expect_err("reconcile should return an error");
    assert!(matches!(error, ReconcileError::Io(_)));
    assert_eq!(cache.usage(), before);

    Ok(())
}

#[test]
fn sparse_file_growth_is_reconciled_without_using_logical_size_as_physical() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    let sparse_path = root.join("a/sparse");
    File::create(&sparse_path)?.set_len(1_024 * 1_024)?;
    let mut cache = baseline(&root);
    File::options()
        .write(true)
        .open(&sparse_path)?
        .set_len(64 * 1_024 * 1_024)?;

    reconcile(&mut cache, &root, &["a"])?;

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 64 * 1_024 * 1_024);

    Ok(())
}

#[test]
fn hard_link_changes_do_not_silently_switch_to_inode_deduplication() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    fs::create_dir_all(root.join("b"))?;
    let original = root.join("a/original");
    fs::write(&original, vec![0_u8; 32])?;
    hard_link(&original, root.join("b/link"))?;
    let mut cache = baseline(&root);
    File::options().write(true).open(&original)?.set_len(512)?;

    reconcile(&mut cache, &root, &["a", "b"])?;

    assert_matches_full(&cache, &root);
    assert_eq!(cache.usage().logical_bytes, 1_024);

    Ok(())
}

#[test]
fn cached_directory_count_tracks_subtree_creation_and_deletion() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("data");
    fs::create_dir_all(root.join("a"))?;
    let mut cache = baseline(&root);
    assert_eq!(cache.nodes.len(), 2);
    fs::create_dir_all(root.join("a/one/two/three"))?;
    reconcile(&mut cache, &root, &["a"])?;
    assert_eq!(cache.nodes.len(), 5);
    fs::remove_dir_all(root.join("a/one"))?;
    reconcile(&mut cache, &root, &["a"])?;
    assert_eq!(cache.nodes.len(), 2);

    Ok(())
}

#[test]
fn a_corrupted_cache_requires_full_reconciliation_without_mutation() -> anyhow::Result<()> {
    type Corrupt = fn(&mut UsageTreeCache);
    let corruptions: [(&str, &str, Corrupt); 4] = [
        ("missing child", "a/b", |cache| {
            cache.nodes.remove(Path::new("a/b"));
        }),
        ("inconsistent aggregate", "a", |cache| {
            cache
                .nodes
                .get_mut(Path::new(""))
                .expect("expected a value from get_mut")
                .total
                .logical_bytes += 1;
        }),
        ("missing root", "a", |cache| {
            cache.nodes.remove(Path::new(""));
        }),
        ("unsafe child component", "a", |cache| {
            cache
                .nodes
                .get_mut(Path::new(""))
                .expect("expected a value from get_mut")
                .children
                .insert(OsString::from("../escape"));
        }),
    ];
    for (name, tree, corrupt) in corruptions {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("data");
        fs::create_dir_all(root.join(tree))?;
        let mut cache = baseline(&root);
        corrupt(&mut cache);
        let before = cache.usage();

        let error =
            reconcile(&mut cache, &root, &["a"]).expect_err("reconcile should return an error");

        assert!(error.requires_full_scan(), "{name}");
        assert_eq!(cache.usage(), before, "{name}");
    }

    Ok(())
}

#[test]
fn full_scan_with_no_time_budget_fails_without_publishing_a_cache() -> anyhow::Result<()> {
    let temporary = tempfile::tempdir()?;
    let no_time = ScanLimits {
        timeout: Duration::ZERO,
        ..limits()
    };

    let error = UsageTreeCache::scan_full(temporary.path(), "generation".to_string(), no_time)
        .expect_err("to string should return an error");

    assert_eq!(error.kind(), ErrorKind::TimedOut);

    Ok(())
}
