use std::{fs, os::unix::fs::symlink};

use super::*;

const RECOVERY_ID: &str = "00000000-0000-4000-8000-000000000001";
const ORPHAN_ID: &str = "00000000-0000-4000-8000-000000000002";
const WRITE_ID: &str = "00000000-0000-4000-8000-000000000003";
const SIMPLE_RESTORE_ID: &str = "00000000000040008000000000000004";

fn staging_root(temp: &tempfile::TempDir) -> PathBuf {
    let root = temp.path().join("import-export");
    fs::create_dir_all(&root).expect("create dir all should succeed");
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
        .expect("to vec should succeed"),
    )
    .expect("to vec should succeed");
    path
}

#[test]
fn missing_and_empty_roots_are_idempotent() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let missing = temp.path().join("missing");

    assert_eq!(
        cleanup_root(&missing, 8, 8)?,
        ImportTempCleanupSummary::default()
    );
    fs::create_dir(&missing)?;
    assert_eq!(
        cleanup_root(&missing, 8, 8)?,
        ImportTempCleanupSummary::default()
    );
    assert_eq!(
        cleanup_root(&missing, 8, 8)?,
        ImportTempCleanupSummary::default()
    );

    Ok(())
}

#[test]
fn root_must_be_a_real_directory() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let real = temp.path().join("real");
    let linked = temp.path().join("linked");
    let regular = temp.path().join("regular");
    fs::create_dir(&real)?;
    fs::write(&regular, b"not a directory")?;
    symlink(&real, &linked)?;

    assert!(
        cleanup_root(&linked, 8, 8)
            .expect_err("cleanup root should return an error")
            .to_string()
            .contains("real directory")
    );
    assert!(
        cleanup_root(&regular, 8, 8)
            .expect_err("cleanup root should return an error")
            .to_string()
            .contains("real directory")
    );

    Ok(())
}

#[test]
fn cleanup_removes_only_exact_v4_allowlisted_names() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = staging_root(&temp);
    let exact_import = root.join(format!(".dbe-import-{RECOVERY_ID}.postgres.sql"));
    let exact_export = root.join(format!(".dbe-export-{ORPHAN_ID}.mysql.sql"));
    let exact_atomic = root.join(format!(
        "..dbe-import-recovery-{RECOVERY_ID}.json.{WRITE_ID}.tmp"
    ));
    let exact_directory = root.join(format!(".dbe-unarchive-{RECOVERY_ID}"));
    for path in [&exact_import, &exact_export, &exact_atomic] {
        fs::write(path, b"temporary")?;
    }
    fs::create_dir(&exact_directory)?;
    fs::write(exact_directory.join("dump.sql"), b"temporary")?;

    let lookalikes = [
        format!(".dbe-import-{RECOVERY_ID}.postgres.sql.extra"),
        ".dbe-import-AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA.postgres.sql".to_string(),
        ".dbe-import-00000000-0000-1000-8000-000000000001.postgres.sql".to_string(),
        format!(".dbe-import-{RECOVERY_ID}.postgres.exe"),
        format!(".dbe-unarchive-{RECOVERY_ID}-extra"),
        format!("..dbe-import-recovery-{RECOVERY_ID}.json.{WRITE_ID}.tmp.extra"),
    ];
    for name in &lookalikes {
        fs::write(root.join(name), b"preserve")?;
    }
    let unknown_directory = root.join(".dbe-unarchive-manual");
    fs::create_dir(&unknown_directory)?;

    let summary = cleanup_root(&root, 32, 32)?;

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

    Ok(())
}

#[test]
fn matching_symlinks_are_preserved_and_recursive_cleanup_never_follows_links() -> anyhow::Result<()>
{
    let temp = tempfile::tempdir()?;
    let root = staging_root(&temp);
    let victim = temp.path().join("victim");
    fs::write(&victim, b"untouched")?;

    let matching_link = root.join(format!(".dbe-import-{RECOVERY_ID}.postgres.sql"));
    symlink(&victim, &matching_link)?;
    let unarchive = root.join(format!(".dbe-unarchive-{RECOVERY_ID}"));
    fs::create_dir(&unarchive)?;
    symlink(&victim, unarchive.join("outside-link"))?;

    let summary = cleanup_root(&root, 8, 8)?;

    assert_eq!(summary.removed_directories, 1);
    assert_eq!(summary.removed_files, 0);
    assert!(
        fs::symlink_metadata(&matching_link)?
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&victim)?, b"untouched");
    assert!(!unarchive.exists());

    Ok(())
}

#[test]
fn valid_manifest_protects_only_its_exact_rollback() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = staging_root(&temp);
    let protected_name = format!(".dbe-import-rollback-{RECOVERY_ID}.postgres.sql");
    let orphan_name = format!(".dbe-import-rollback-{ORPHAN_ID}.postgres.sql");
    let protected = root.join(&protected_name);
    let orphan = root.join(&orphan_name);
    let manifest = write_manifest(&root, RECOVERY_ID, "postgres", &protected_name);
    fs::write(&protected, b"rollback")?;
    fs::write(&orphan, b"orphan")?;

    let summary = cleanup_root(&root, 8, 8)?;

    assert_eq!(summary.protected_rollbacks, 1);
    assert_eq!(summary.removed_files, 1);
    assert!(manifest.exists());
    assert!(protected.exists());
    assert!(!orphan.exists());

    Ok(())
}

#[test]
fn malformed_or_mismatched_manifest_aborts_before_deletion() -> anyhow::Result<()> {
    for mismatch in [false, true] {
        let temp = tempfile::tempdir()?;
        let root = staging_root(&temp);
        let orphan = root.join(format!(".dbe-import-{ORPHAN_ID}.postgres.sql"));
        fs::write(&orphan, b"must survive")?;
        let manifest = root.join(format!(".dbe-import-recovery-{RECOVERY_ID}.json"));
        if mismatch {
            write_manifest(
                &root,
                RECOVERY_ID,
                "postgres",
                &format!(".dbe-import-rollback-{ORPHAN_ID}.postgres.sql"),
            );
        } else {
            fs::write(&manifest, b"not-json")?;
        }

        assert!(cleanup_root(&root, 8, 8).is_err());
        assert_eq!(fs::read(&orphan)?, b"must survive");
        assert!(manifest.exists());
    }

    Ok(())
}

#[test]
fn root_scan_limit_accepts_boundary_and_overflow_deletes_nothing() -> anyhow::Result<()> {
    let boundary = tempfile::tempdir()?;
    let boundary_root = staging_root(&boundary);
    for id in [RECOVERY_ID, ORPHAN_ID] {
        fs::write(
            boundary_root.join(format!(".dbe-import-{id}.postgres.sql")),
            b"orphan",
        )?;
    }
    assert_eq!(cleanup_root(&boundary_root, 2, 8)?.removed_files, 2);

    let overflow = tempfile::tempdir()?;
    let overflow_root = staging_root(&overflow);
    let candidate = overflow_root.join(format!(".dbe-import-{RECOVERY_ID}.postgres.sql"));
    fs::write(&candidate, b"must survive")?;
    fs::write(overflow_root.join("unknown-1"), b"unknown")?;
    fs::write(overflow_root.join("unknown-2"), b"unknown")?;

    assert!(cleanup_root(&overflow_root, 2, 8).is_err());
    assert_eq!(fs::read(&candidate)?, b"must survive");

    Ok(())
}

#[test]
fn recursive_scan_limit_is_preflighted_before_any_deletion() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = staging_root(&temp);
    let candidate = root.join(format!(".dbe-import-{RECOVERY_ID}.postgres.sql"));
    fs::write(&candidate, b"must survive")?;
    let unarchive = root.join(format!(".dbe-unarchive-{ORPHAN_ID}"));
    fs::create_dir(&unarchive)?;
    for index in 0..3 {
        fs::write(unarchive.join(format!("entry-{index}")), b"data")?;
    }

    assert!(cleanup_root(&root, 8, 2).is_err());
    assert_eq!(fs::read(&candidate)?, b"must survive");
    assert!(unarchive.exists());

    Ok(())
}

#[test]
fn exact_manifest_symlink_aborts_without_touching_other_entries() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = staging_root(&temp);
    let candidate = root.join(format!(".dbe-export-{ORPHAN_ID}.mysql.sql"));
    let victim = temp.path().join("manifest-victim");
    fs::write(&candidate, b"must survive")?;
    fs::write(&victim, b"{}")?;
    symlink(
        &victim,
        root.join(format!(".dbe-import-recovery-{RECOVERY_ID}.json")),
    )?;

    assert!(cleanup_root(&root, 8, 8).is_err());
    assert!(candidate.exists());
    assert_eq!(fs::read(&victim)?, b"{}");

    Ok(())
}

#[test]
fn shared_restore_cleanup_removes_only_exact_private_sandboxes() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = staging_root(&temp);
    let sandbox = root.join(format!(".dbe-shared-restore-{SIMPLE_RESTORE_ID}"));
    fs::create_dir(&sandbox)?;
    fs::write(sandbox.join("input"), b"snapshot")?;

    let lookalike = root.join(format!(".dbe-shared-restore-{SIMPLE_RESTORE_ID}-extra"));
    fs::create_dir(&lookalike)?;
    fs::write(lookalike.join("input"), b"preserve")?;
    let victim = temp.path().join("victim");
    fs::create_dir(&victim)?;
    fs::write(victim.join("input"), b"untouched")?;
    let linked = root.join(".dbe-shared-restore-00000000000040008000000000000005");
    symlink(&victim, &linked)?;

    let summary = cleanup_shared_restore_root(&root)?;

    assert_eq!(summary.removed_directories, 1);
    assert!(!sandbox.exists());
    assert!(lookalike.exists());
    assert!(fs::symlink_metadata(&linked)?.file_type().is_symlink());
    assert_eq!(fs::read(victim.join("input"))?, b"untouched");

    Ok(())
}

#[test]
fn malformed_shared_restore_sandbox_is_retained() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = staging_root(&temp);
    let sandbox = root.join(format!(".dbe-shared-restore-{SIMPLE_RESTORE_ID}"));
    fs::create_dir(&sandbox)?;
    fs::write(sandbox.join("input"), b"snapshot")?;
    fs::write(sandbox.join("unexpected"), b"preserve")?;

    assert!(cleanup_shared_restore_root(&root).is_err());
    assert!(sandbox.exists());

    Ok(())
}
