#![cfg(unix)]

use std::{fs, os::unix::fs::symlink};

use super::*;

const RECOVERY_ID: &str = "00000000-0000-4000-8000-000000000001";
const ORPHAN_ID: &str = "00000000-0000-4000-8000-000000000002";
const WRITE_ID: &str = "00000000-0000-4000-8000-000000000003";

fn staging_root(temp: &tempfile::TempDir) -> PathBuf {
    let root = temp.path().join("import-export");
    fs::create_dir_all(&root).unwrap();
    root
}

fn write_manifest(root: &Path, id: &str, protocol: &str, rollback_file: &str) -> PathBuf {
    let path = root.join(format!(".dbe-import-recovery-{id}.json"));
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "recovery_kind": "logical_remote_import",
            "instance_id": "inst_recovery",
            "protocol": protocol,
            "import_mode": "wipe",
            "rollback_file": rollback_file,
            "created_at": "2026-08-10T00:00:00Z"
        }))
        .unwrap(),
    )
    .unwrap();
    path
}

#[test]
fn missing_and_empty_roots_are_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing");

    assert_eq!(
        cleanup_root_with_limits(&missing, 8, 8).unwrap(),
        ImportTempCleanupSummary::default()
    );
    fs::create_dir(&missing).unwrap();
    assert_eq!(
        cleanup_root_with_limits(&missing, 8, 8).unwrap(),
        ImportTempCleanupSummary::default()
    );
    assert_eq!(
        cleanup_root_with_limits(&missing, 8, 8).unwrap(),
        ImportTempCleanupSummary::default()
    );
}

#[test]
fn root_must_be_a_real_directory() {
    let temp = tempfile::tempdir().unwrap();
    let real = temp.path().join("real");
    let linked = temp.path().join("linked");
    let regular = temp.path().join("regular");
    fs::create_dir(&real).unwrap();
    fs::write(&regular, b"not a directory").unwrap();
    symlink(&real, &linked).unwrap();

    assert!(
        cleanup_root_with_limits(&linked, 8, 8)
            .unwrap_err()
            .to_string()
            .contains("real directory")
    );
    assert!(
        cleanup_root_with_limits(&regular, 8, 8)
            .unwrap_err()
            .to_string()
            .contains("real directory")
    );
}

#[test]
fn cleanup_removes_only_exact_v4_allowlisted_names() {
    let temp = tempfile::tempdir().unwrap();
    let root = staging_root(&temp);
    let exact_import = root.join(format!(".dbe-import-{RECOVERY_ID}.postgres.sql"));
    let exact_export = root.join(format!(".dbe-export-{ORPHAN_ID}.mysql.sql"));
    let exact_atomic = root.join(format!(
        "..dbe-import-recovery-{RECOVERY_ID}.json.{WRITE_ID}.tmp"
    ));
    let exact_directory = root.join(format!(".dbe-unarchive-{RECOVERY_ID}"));
    for path in [&exact_import, &exact_export, &exact_atomic] {
        fs::write(path, b"temporary").unwrap();
    }
    fs::create_dir(&exact_directory).unwrap();
    fs::write(exact_directory.join("dump.sql"), b"temporary").unwrap();

    let lookalikes = [
        format!(".dbe-import-{RECOVERY_ID}.postgres.sql.extra"),
        ".dbe-import-AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA.postgres.sql".to_string(),
        ".dbe-import-00000000-0000-1000-8000-000000000001.postgres.sql".to_string(),
        format!(".dbe-import-{RECOVERY_ID}.postgres.exe"),
        format!(".dbe-unarchive-{RECOVERY_ID}-extra"),
        format!("..dbe-import-recovery-{RECOVERY_ID}.json.{WRITE_ID}.tmp.extra"),
    ];
    for name in &lookalikes {
        fs::write(root.join(name), b"preserve").unwrap();
    }
    let unknown_directory = root.join(".dbe-unarchive-manual");
    fs::create_dir(&unknown_directory).unwrap();

    let summary = cleanup_root_with_limits(&root, 32, 32).unwrap();

    assert_eq!(summary.removed_files, 3);
    assert_eq!(summary.removed_directories, 1);
    assert!(!exact_import.exists());
    assert!(!exact_export.exists());
    assert!(!exact_atomic.exists());
    assert!(!exact_directory.exists());
    for name in &lookalikes {
        assert!(root.join(name).exists(), "lookalike {name} was removed");
    }
    assert!(unknown_directory.exists());
}

#[test]
fn matching_symlinks_are_preserved_and_recursive_cleanup_never_follows_links() {
    let temp = tempfile::tempdir().unwrap();
    let root = staging_root(&temp);
    let victim = temp.path().join("victim");
    fs::write(&victim, b"untouched").unwrap();

    let matching_link = root.join(format!(".dbe-import-{RECOVERY_ID}.postgres.sql"));
    symlink(&victim, &matching_link).unwrap();
    let unarchive = root.join(format!(".dbe-unarchive-{RECOVERY_ID}"));
    fs::create_dir(&unarchive).unwrap();
    symlink(&victim, unarchive.join("outside-link")).unwrap();

    let summary = cleanup_root_with_limits(&root, 8, 8).unwrap();

    assert_eq!(summary.removed_directories, 1);
    assert_eq!(summary.removed_files, 0);
    assert!(
        fs::symlink_metadata(&matching_link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    assert!(!unarchive.exists());
}

#[test]
fn valid_manifest_protects_only_its_exact_rollback() {
    let temp = tempfile::tempdir().unwrap();
    let root = staging_root(&temp);
    let protected_name = format!(".dbe-import-rollback-{RECOVERY_ID}.postgres.sql");
    let orphan_name = format!(".dbe-import-rollback-{ORPHAN_ID}.postgres.sql");
    let protected = root.join(&protected_name);
    let orphan = root.join(&orphan_name);
    let manifest = write_manifest(&root, RECOVERY_ID, "postgres", &protected_name);
    fs::write(&protected, b"rollback").unwrap();
    fs::write(&orphan, b"orphan").unwrap();

    let summary = cleanup_root_with_limits(&root, 8, 8).unwrap();

    assert_eq!(summary.protected_rollbacks, 1);
    assert_eq!(summary.removed_files, 1);
    assert!(manifest.exists());
    assert!(protected.exists());
    assert!(!orphan.exists());
}

#[test]
fn malformed_or_mismatched_manifest_aborts_before_deletion() {
    for mismatch in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = staging_root(&temp);
        let orphan = root.join(format!(".dbe-import-{ORPHAN_ID}.postgres.sql"));
        fs::write(&orphan, b"must survive").unwrap();
        let manifest = root.join(format!(".dbe-import-recovery-{RECOVERY_ID}.json"));
        if mismatch {
            write_manifest(
                &root,
                RECOVERY_ID,
                "postgres",
                &format!(".dbe-import-rollback-{ORPHAN_ID}.postgres.sql"),
            );
        } else {
            fs::write(&manifest, b"not-json").unwrap();
        }

        assert!(cleanup_root_with_limits(&root, 8, 8).is_err());
        assert_eq!(fs::read(&orphan).unwrap(), b"must survive");
        assert!(manifest.exists());
    }
}

#[test]
fn root_scan_limit_accepts_boundary_and_overflow_deletes_nothing() {
    let boundary = tempfile::tempdir().unwrap();
    let boundary_root = staging_root(&boundary);
    for id in [RECOVERY_ID, ORPHAN_ID] {
        fs::write(
            boundary_root.join(format!(".dbe-import-{id}.postgres.sql")),
            b"orphan",
        )
        .unwrap();
    }
    assert_eq!(
        cleanup_root_with_limits(&boundary_root, 2, 8)
            .unwrap()
            .removed_files,
        2
    );

    let overflow = tempfile::tempdir().unwrap();
    let overflow_root = staging_root(&overflow);
    let candidate = overflow_root.join(format!(".dbe-import-{RECOVERY_ID}.postgres.sql"));
    fs::write(&candidate, b"must survive").unwrap();
    fs::write(overflow_root.join("unknown-1"), b"unknown").unwrap();
    fs::write(overflow_root.join("unknown-2"), b"unknown").unwrap();

    assert!(cleanup_root_with_limits(&overflow_root, 2, 8).is_err());
    assert_eq!(fs::read(&candidate).unwrap(), b"must survive");
}

#[test]
fn recursive_scan_limit_is_preflighted_before_any_deletion() {
    let temp = tempfile::tempdir().unwrap();
    let root = staging_root(&temp);
    let candidate = root.join(format!(".dbe-import-{RECOVERY_ID}.postgres.sql"));
    fs::write(&candidate, b"must survive").unwrap();
    let unarchive = root.join(format!(".dbe-unarchive-{ORPHAN_ID}"));
    fs::create_dir(&unarchive).unwrap();
    for index in 0..3 {
        fs::write(unarchive.join(format!("entry-{index}")), b"data").unwrap();
    }

    assert!(cleanup_root_with_limits(&root, 8, 2).is_err());
    assert_eq!(fs::read(&candidate).unwrap(), b"must survive");
    assert!(unarchive.exists());
}

#[test]
fn exact_manifest_symlink_aborts_without_touching_other_entries() {
    let temp = tempfile::tempdir().unwrap();
    let root = staging_root(&temp);
    let candidate = root.join(format!(".dbe-export-{ORPHAN_ID}.mysql.sql"));
    let victim = temp.path().join("manifest-victim");
    fs::write(&candidate, b"must survive").unwrap();
    fs::write(&victim, b"{}").unwrap();
    symlink(
        &victim,
        root.join(format!(".dbe-import-recovery-{RECOVERY_ID}.json")),
    )
    .unwrap();

    assert!(cleanup_root_with_limits(&root, 8, 8).is_err());
    assert!(candidate.exists());
    assert_eq!(fs::read(&victim).unwrap(), b"{}");
}
