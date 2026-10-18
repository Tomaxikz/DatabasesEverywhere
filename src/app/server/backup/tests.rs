use super::*;

async fn commit_test_backup(
    storage: &BackupStorage,
    root: &Path,
    backup_id: &str,
    created_at_unix: i64,
) -> StoredBackup {
    let bundle = BackupBundle::create(root, "inst_one", backup_id)
        .await
        .unwrap();
    tokio::fs::write(&bundle.archive, b"archive").await.unwrap();
    let mut manifest = build_manifest(
        backup_id.to_string(),
        "inst_one".to_string(),
        Protocol::Postgres,
        BackupLayout::Physical,
        &bundle.archive,
        false,
        test_details(BackupLayout::Physical),
    )
    .await
    .unwrap();
    manifest.created_at_unix = created_at_unix;
    manifest.created_at = OffsetDateTime::from_unix_timestamp(created_at_unix)
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
    bundle.write_metadata(&manifest).await.unwrap();
    storage
        .commit(&bundle, &manifest, &drivers::DiscardJournal)
        .await
        .unwrap();
    bundle.cleanup().await;
    manifest
}

#[tokio::test]
async fn storage_facade_round_trips_backups_and_lists_newest_first() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("backups");
    let storage = BackupStorage::Local(drivers::local::LocalBackupDriver::new(root.clone()));
    storage.preflight().await.unwrap();
    assert!(storage.list("inst_one").await.unwrap().is_empty());

    for (backup_id, timestamp) in [
        ("a-old.physical.tar.gz", 100),
        ("b-new.physical.tar.gz", 300),
        ("c-middle.physical.tar.gz", 200),
    ] {
        let manifest = commit_test_backup(&storage, &root, backup_id, timestamp).await;
        let found = storage.find("inst_one", backup_id).await.unwrap();
        assert_eq!(found.backup_id, manifest.backup_id);
        assert_eq!(found.sha256, manifest.sha256);
        assert_eq!(found.created_at_unix, timestamp);
    }

    let listed = storage.list("inst_one").await.unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|backup| backup.backup_id.as_str())
            .collect::<Vec<_>>(),
        [
            "b-new.physical.tar.gz",
            "c-middle.physical.tar.gz",
            "a-old.physical.tar.gz"
        ]
    );
    assert!(storage.list("inst_other").await.unwrap().is_empty());
    for backup in listed {
        storage.delete("inst_one", &backup.backup_id).await.unwrap();
    }
    assert!(storage.list("inst_one").await.unwrap().is_empty());
}

#[tokio::test]
async fn storage_facade_preserves_validation_and_missing_backup_errors() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("backups");
    let storage = BackupStorage::Local(drivers::local::LocalBackupDriver::new(root.clone()));
    storage.preflight().await.unwrap();
    let manifest = commit_test_backup(&storage, &root, "valid.physical.tar.gz", 100).await;

    for backup_id in ["../outside", "valid.physical.tar.gz.metadata.json"] {
        assert!(matches!(
            storage.find("inst_one", backup_id).await,
            Err(BackupStoreError::InvalidBackupId)
        ));
        assert!(matches!(
            storage.delete("inst_one", backup_id).await,
            Err(BackupStoreError::InvalidBackupId)
        ));
    }
    assert!(matches!(
        storage.list("../outside").await,
        Err(BackupStoreError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        storage.find("inst_one", "missing.physical.tar.gz").await,
        Err(BackupStoreError::NotFound)
    ));
    assert!(matches!(
        storage.delete("inst_one", "missing.physical.tar.gz").await,
        Err(BackupStoreError::NotFound)
    ));
    assert_eq!(storage.list("inst_one").await.unwrap().len(), 1);
    assert_eq!(
        storage
            .find("inst_one", &manifest.backup_id)
            .await
            .unwrap()
            .sha256,
        manifest.sha256
    );
}

#[tokio::test]
async fn storage_facade_preserves_corrupt_manifest_errors() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("backups");
    let storage = BackupStorage::Local(drivers::local::LocalBackupDriver::new(root.clone()));
    storage.preflight().await.unwrap();
    let manifest = commit_test_backup(&storage, &root, "valid.physical.tar.gz", 100).await;
    tokio::fs::write(
        root.join("inst_one")
            .join(metadata_file_name(&manifest.backup_id)),
        b"invalid metadata",
    )
    .await
    .unwrap();

    assert!(matches!(
        storage.find("inst_one", &manifest.backup_id).await,
        Err(BackupStoreError::Corrupt(_))
    ));
    assert!(matches!(
        storage.list("inst_one").await,
        Err(BackupStoreError::Corrupt(_))
    ));
}

#[tokio::test]
async fn materialized_guard_cleans_only_temporary_files() {
    let temp = tempfile::tempdir().unwrap();
    for temporary in [true, false] {
        let path = temp.path().join(if temporary {
            "remote.dump"
        } else {
            "local.dump"
        });
        tokio::fs::write(&path, b"backup").await.unwrap();
        drop(MaterializedBackup {
            path: path.clone(),
            temporary,
            capacity: None,
        });
        assert_eq!(path.exists(), !temporary);
    }
}

#[tokio::test]
async fn cancelled_download_waiter_leaves_cleanup_with_the_worker() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("spool.dump");
    tokio::fs::write(&path, b"partial").await.unwrap();
    let guard = MaterializedBackup {
        path: path.clone(),
        temporary: true,
        capacity: None,
    };
    let (release, resume) = tokio::sync::oneshot::channel();
    let (started, waiting) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        started.send(()).unwrap();
        resume.await.unwrap();
        tokio::fs::write(&guard.path, b"complete").await.unwrap();
        guard
    });
    let completed = worker.abort_handle();
    let waiter = tokio::spawn(worker);
    waiting.await.unwrap();
    waiter.abort();
    let _ = waiter.await;
    assert!(path.exists(), "spool belongs to the still-running worker");
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !completed.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !path.exists(),
        "unobserved worker result must clean its spool"
    );
}

#[test]
fn backup_ids_cannot_address_internal_sidecars() {
    assert!(validate_backup_id("id.physical.tar.gz").is_ok());
    assert!(validate_backup_id("id.logical.dump").is_ok());
    assert!(validate_backup_id("id.physical.tar.gz.catalog.json").is_err());
    assert!(validate_backup_id("id.physical.tar.gz.metadata.json").is_err());
    assert!(validate_backup_id("../id.physical.tar.gz").is_err());
}

#[test]
fn old_manifests_default_to_physical_while_new_ids_mark_logical_backups() {
    let old: StoredBackup = serde_json::from_value(serde_json::json!({
        "schema_version": manifest::LEGACY_MANIFEST_SCHEMA_VERSION,
        "backup_id": "old.physical.tar.gz",
        "instance_id": "inst_old",
        "protocol": "postgres",
        "size_bytes": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "created_at_unix": 1767225600,
        "sha256": "0".repeat(64),
        "catalog_available": false
    }))
    .unwrap();
    assert_eq!(old.layout, BackupLayout::Physical);
    assert!(new_backup_id(BackupLayout::Logical).ends_with(".logical.dump"));
}

fn legacy_manifest_json(layout: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "backup_id": "old.physical.tar.gz",
        "instance_id": "inst_old",
        "protocol": "postgres",
        "layout": layout,
        "size_bytes": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "created_at_unix": 1767225600,
        "sha256": "0".repeat(64),
        "catalog_available": false
    })
}

#[test]
fn legacy_manifests_restore_by_layout_without_invented_guarantees() {
    for (layout, expected) in [
        (
            "physical",
            manifest::RestoreFormat::DataDirectoryArchive { legacy: true },
        ),
        (
            "logical",
            manifest::RestoreFormat::LogicalDump { legacy: true },
        ),
    ] {
        let bytes = serde_json::to_vec(&legacy_manifest_json(layout)).unwrap();
        let legacy = StoredBackup::from_json(&bytes, "inst_old", "metadata").unwrap();
        assert_eq!(legacy.restore_format(), expected);
        assert_eq!(legacy.consistency(), None);
        // Re-serializing a legacy record must not upgrade it.
        let round_trip = serde_json::to_value(&legacy).unwrap();
        assert_eq!(round_trip["schema_version"], 1);
        assert!(round_trip.get("details").is_none());
    }
}

#[test]
fn schema_versions_and_details_must_agree() {
    let mut legacy_with_details = legacy_manifest_json("physical");
    legacy_with_details["details"] =
        serde_json::to_value(test_details(BackupLayout::Physical)).unwrap();
    let bytes = serde_json::to_vec(&legacy_with_details).unwrap();
    assert!(matches!(
        StoredBackup::from_json(&bytes, "inst_old", "metadata"),
        Err(BackupStoreError::Corrupt(_))
    ));

    let mut v2_without_details = legacy_manifest_json("physical");
    v2_without_details["schema_version"] = serde_json::json!(2);
    let bytes = serde_json::to_vec(&v2_without_details).unwrap();
    assert!(matches!(
        StoredBackup::from_json(&bytes, "inst_old", "metadata"),
        Err(BackupStoreError::Corrupt(_))
    ));
}

#[test]
fn future_schema_versions_are_rejected_as_unsupported() {
    let mut future = legacy_manifest_json("physical");
    future["schema_version"] = serde_json::json!(3);
    future["something_new"] = serde_json::json!({"recipe": "x"});
    let bytes = serde_json::to_vec(&future).unwrap();
    assert!(matches!(
        StoredBackup::from_json(&bytes, "inst_old", "metadata"),
        Err(BackupStoreError::UnsupportedFormat(message)) if message.contains("schema 3")
    ));
}

#[tokio::test]
async fn current_manifests_round_trip_their_restore_contract() {
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("archive");
    tokio::fs::write(&archive, b"archive").await.unwrap();
    let manifest = build_manifest(
        "new.logical.dump".to_string(),
        "inst_one".to_string(),
        Protocol::Postgres,
        BackupLayout::Logical,
        &archive,
        false,
        test_details(BackupLayout::Logical),
    )
    .await
    .unwrap();
    assert_eq!(manifest.schema_version, BACKUP_MANIFEST_SCHEMA_VERSION);
    let parsed =
        StoredBackup::from_json(&manifest.to_json().unwrap(), "inst_one", "metadata").unwrap();
    assert_eq!(parsed.details, manifest.details);
    assert_eq!(
        parsed.restore_format(),
        manifest::RestoreFormat::LogicalDump { legacy: false }
    );
    assert_eq!(
        parsed.consistency(),
        Some(manifest::ConsistencyLevel::PerObject)
    );
    // A contract that disagrees with the layout is never written.
    assert!(
        build_manifest(
            "bad.physical.tar.gz".to_string(),
            "inst_one".to_string(),
            Protocol::Postgres,
            BackupLayout::Physical,
            &archive,
            false,
            test_details(BackupLayout::Logical),
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn startup_cleanup_removes_only_incomplete_staging() {
    let temp = tempfile::tempdir().unwrap();
    let staging = temp.path().join(".staging").join("inst_one");
    tokio::fs::create_dir_all(&staging).await.unwrap();
    tokio::fs::write(staging.join("partial"), b"data")
        .await
        .unwrap();
    tokio::fs::write(temp.path().join("published.physical.tar.gz"), b"backup")
        .await
        .unwrap();

    assert!(cleanup_staging(temp.path()).await.unwrap());
    assert!(!staging.exists());
    assert!(temp.path().join("published.physical.tar.gz").exists());
}

#[tokio::test]
async fn startup_cleanup_leaves_online_capture_staging_to_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let staging = temp.path().join(".staging").join("inst_one");
    let capture = staging.join(".0123456789abcdef0123456789abcdef.capture");
    tokio::fs::create_dir_all(capture.join("pgdata"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(staging.join(".bundle-id.bundle"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(temp.path().join(".staging/.kopia-manifests"))
        .await
        .unwrap();

    assert!(cleanup_staging(temp.path()).await.unwrap());
    assert!(capture.join("pgdata").exists());
    assert!(!staging.join(".bundle-id.bundle").exists());
    assert!(!temp.path().join(".staging/.kopia-manifests").exists());
    assert!(is_capture_dir_name(std::ffi::OsStr::new(
        ".0123456789abcdef0123456789abcdef.capture"
    )));
    assert!(!is_capture_dir_name(std::ffi::OsStr::new(".x.capture")));
}

#[tokio::test]
async fn startup_cleanup_removes_backup_materializations_only() {
    let temp = tempfile::tempdir().unwrap();
    tokio::fs::create_dir_all(temp.path().join("backup-materialized"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(temp.path().join("backup-catalogs"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(temp.path().join("remote-import"))
        .await
        .unwrap();

    assert_eq!(cleanup_materializations(temp.path()).await.unwrap(), 2);
    assert!(temp.path().join("remote-import").exists());
}
