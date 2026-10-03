use super::*;

#[test]
fn only_an_intentional_observed_stop_is_an_expected_backup_skip() {
    let mut metadata = crate::server::test_support::metadata("tenant", Protocol::Postgres);
    for status in [
        InstanceStatus::Creating,
        InstanceStatus::Booting,
        InstanceStatus::Running,
        InstanceStatus::Stopped,
        InstanceStatus::Failed,
        InstanceStatus::Quarantined,
        InstanceStatus::Deleting,
    ] {
        for desired in [DesiredInstanceState::Running, DesiredInstanceState::Stopped] {
            metadata.status = status;
            metadata.desired_state = desired;
            assert_eq!(
                intentionally_stopped_backup(&metadata).is_some(),
                status == InstanceStatus::Stopped && desired == DesiredInstanceState::Stopped,
                "{status:?} / {desired:?}"
            );
        }
    }
}

#[test]
fn backup_pass_separates_expected_skips_from_errors_and_reports_partial_failure() {
    let mut metadata = crate::server::test_support::metadata("tenant", Protocol::Postgres);
    metadata.status = InstanceStatus::Stopped;
    metadata.desired_state = DesiredInstanceState::Stopped;
    let mut response = RunBackupResponse::default();
    assert_eq!(response.status(), "completed");
    response.record(
        &metadata,
        Ok(BackupAttempt::Skipped(
            intentionally_stopped_backup(&metadata).unwrap(),
        )),
    );
    assert_eq!(response.status(), "completed_with_skips");
    // Even a stopped snapshot must not disguise errors encountered while
    // checking ownership, reconciling, scheduling, or storing a backup.
    for error in [
        ApiError::Conflict("tenant placement does not match its shared runtime".into()),
        ApiError::BadRequest("instance is not running (status=Failed)".into()),
        ApiError::RateLimited,
        ApiError::ServiceUnavailable("scheduler closed".into()),
        ApiError::Runtime("private-storage-detail".into()),
    ] {
        response.record(&metadata, Err(error));
    }
    assert_eq!(response.status(), "failed");
    response.record(
        &metadata,
        Ok(BackupAttempt::Completed(BackupInfo {
            id: "backup.physical.tar.gz".into(),
            instance_id: "healthy-tenant".into(),
            protocol: Protocol::Postgres,
            layout: BackupLayout::Physical,
            size_bytes: 1,
            modified_at: "2026-09-11T10:00:00Z".into(),
            sha256: "ab".repeat(32),
        })),
    );
    assert_eq!(response.status(), "partial_failure");
    assert_eq!(response.backups.len(), 1);
    assert_eq!(response.skipped.len(), 1);
    assert_eq!(response.failed.len(), 5);
    let value = serde_json::to_value(&response).unwrap();
    assert_eq!(
        value["skipped"][0]["reason"]["code"],
        "intentionally_stopped"
    );
    assert_eq!(value["failed"][0]["reason"]["code"], "conflict");
    assert_eq!(value["failed"][4]["reason"]["code"], "internal_error");
    assert!(value["failed"][4]["reason"]["error_id"].is_string());
    assert!(!value.to_string().contains("private-storage-detail"));
}

#[tokio::test]
async fn an_empty_backup_pass_has_no_spurious_failures() {
    let (state, _directory) = crate::subsystems::test_support::database(Default::default()).await;
    let response = backup_all_instances(&state).await;
    assert_eq!(response.status(), "completed");
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        serde_json::json!({
            "backups": [], "skipped": [], "failed": [],
        })
    );
}

#[test]
fn catalog_selection_is_bounded_and_object_scoped() {
    let catalog = BackupCatalog {
        schema_version: crate::server::backup::catalog::BACKUP_CATALOG_SCHEMA_VERSION,
        backup_id: "one.physical.tar.gz".to_string(),
        instance_id: "inst_one".to_string(),
        protocol: Protocol::Postgres,
        database_name: "app".to_string(),
        captured_at: "2024-01-01T00:00:00Z".to_string(),
        consistency: "test".to_string(),
        truncated: false,
        warnings: Vec::new(),
        objects: vec![crate::server::backup::catalog::BackupCatalogObject {
            id: "public.users".to_string(),
            namespace: "public".to_string(),
            name: "users".to_string(),
            kind: "table".to_string(),
            estimated_rows: Some(3),
            columns: vec![BackupCatalogColumn {
                name: "id".into(),
                data_type: "integer".into(),
                nullable: false,
                ordinal: 1,
            }],
            preview_rows: vec![serde_json::json!({"id": 1}), serde_json::json!({"id": 2})],
            preview_truncated: true,
        }],
    };

    let selection = select_catalog_object(&catalog, Some("public.users"), 1, 1)
        .unwrap()
        .unwrap();
    assert_eq!(selection.returned, 1);
    assert_eq!(selection.rows[0]["id"], 2);
    assert!(selection.truncated);
    assert_eq!(selection.columns[0].name, "id");
    let objects = backup_objects(&catalog, true).unwrap();
    let json = serde_json::to_value(&objects).unwrap();
    assert_eq!(json[0]["column_count"], 1);
    assert!(json[0].get("columns").is_none());
    assert!(backup_objects(&catalog, false).is_none());
    assert!(select_catalog_object(&catalog, Some("foreign.table"), 0, 1).is_err());
}

#[test]
fn backup_protocol_identity_blocks_cross_engine_restore() {
    assert!(check_backup_protocol("one.logical.dump", Protocol::Mysql, Protocol::Mysql,).is_ok());
    assert!(
        check_backup_protocol("one.logical.dump", Protocol::Mysql, Protocol::Postgres,).is_err()
    );
}

#[test]
fn logical_restore_cost_does_not_expand_to_the_tenant_disk_limit() {
    assert_eq!(
        restore_input_bytes(BackupLayout::Logical, 7 * 1024 * 1024, 100 * 1024),
        7 * 1024 * 1024
    );
    assert_eq!(
        restore_input_bytes(BackupLayout::Physical, 7 * 1024 * 1024, 100),
        100 * 1024 * 1024
    );
}

#[test]
fn logical_restore_reserves_the_source_pin_and_both_rollback_copies() {
    assert_eq!(
        crate::subsystems::import_export::logical::shared_restore_staging_bytes(7, 11).unwrap(),
        29
    );
    assert!(
        crate::subsystems::import_export::logical::shared_restore_staging_bytes(1, u64::MAX)
            .is_err()
    );
}

#[test]
fn backup_layout_is_bound_to_the_current_deployment_mode() {
    for (mode, compatible, stale) in [
        (
            DeploymentMode::Dedicated,
            BackupLayout::Physical,
            BackupLayout::Logical,
        ),
        (
            DeploymentMode::Shared,
            BackupLayout::Logical,
            BackupLayout::Physical,
        ),
    ] {
        assert!(check_backup_layout("current", compatible, mode).is_ok());
        let error = check_backup_layout("stale", stale, mode).unwrap_err();
        assert_eq!(error.status(), http::StatusCode::CONFLICT);
    }
}

#[test]
fn backup_info_keeps_restore_compatibility_fields() {
    let info = backup_info(StoredBackup {
        schema_version: 2,
        backup_id: "one.logical.dump".to_string(),
        instance_id: "inst_one".to_string(),
        protocol: Protocol::Postgres,
        layout: BackupLayout::Logical,
        size_bytes: 42,
        created_at: "2024-01-01T00:00:00Z".to_string(),
        created_at_unix: 1_704_067_200,
        sha256: "ab".repeat(32),
        catalog_available: true,
    });

    let value = serde_json::to_value(info).unwrap();
    assert_eq!(value["protocol"], "postgres");
    assert_eq!(value["layout"], "logical");
}
