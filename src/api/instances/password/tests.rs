use super::*;

#[test]
fn password_validation_rejects_empty_multiline_and_oversized_secrets() {
    assert!(validate_password(Protocol::Postgres, &SecretString::from("")).is_err());
    assert!(validate_password(Protocol::Postgres, &SecretString::from("line1\nline2")).is_err());
    assert!(
        validate_password(
            Protocol::Postgres,
            &SecretString::from("x".repeat(MAX_PASSWORD_CHARACTERS + 1)),
        )
        .is_err()
    );
}

#[test]
fn mariadb_rollback_uses_the_persisted_native_verifier_not_stale_environment() {
    assert!(credential_environment_keys(Protocol::Mariadb).is_empty());
}

#[test]
fn resp_acl_path_follows_persisted_fuse_enforcement() {
    let temporary = tempfile::tempdir().unwrap();
    let raw_data = temporary.path().join("volumes").join("inst_resp");
    let fuse_root = temporary.path().join("fuse");
    let limiter = DiskLimiter::with_fuse_root(
        crate::config::DiskConfig {
            mode: crate::config::DiskLimitMode::SoftScanner,
            ..crate::config::DiskConfig::default()
        },
        &fuse_root,
    )
    .for_persisted_method("fuse_quota");

    let credential_data_path = limiter.container_data_path(&raw_data).unwrap();

    assert_ne!(credential_data_path, raw_data);
    assert!(credential_data_path.starts_with(fuse_root.join("instances")));
}

#[test]
fn qdrant_password_must_be_a_valid_header_value() {
    assert!(validate_password(Protocol::Qdrant, &SecretString::from("valid-api-key")).is_ok());
    assert!(validate_password(Protocol::Qdrant, &SecretString::from("invalid\u{7f}")).is_err());
}

#[test]
fn clickhouse_rotation_uses_recreated_startup_configuration() {
    let current = PreviousCredential {
        environment: Some(SecretString::from("current-password")),
        ..PreviousCredential::default()
    };
    let replacement = SecretString::from("replacement-password");

    assert!(requires_container_recreation(
        Protocol::Clickhouse,
        &current
    ));
    assert_eq!(
        credential_environment_keys(Protocol::Clickhouse),
        &["CLICKHOUSE_PASSWORD"]
    );
    assert_eq!(
        spec_password(Protocol::Clickhouse, &replacement, &current, false)
            .unwrap()
            .unwrap()
            .expose_secret(),
        "replacement-password"
    );
    assert_eq!(
        spec_password(Protocol::Clickhouse, &replacement, &current, true)
            .unwrap()
            .unwrap()
            .expose_secret(),
        "current-password"
    );
}

#[test]
fn mysql_rotation_bypasses_binlogging_without_reprovisioning_the_tenant() {
    let script = mysql_rotation_script("app_user").unwrap();

    assert!(script.contains("SET SESSION sql_log_bin = 0;"));
    assert!(script.contains("DBE_ROTATED_PASSWORD_B64"));
    assert!(script.contains("DBE_ROTATION_ADMIN_PASSWORD"));
    assert!(script.contains("caching_sha2_password"));
    assert!(script.contains("ALTER USER `app_user`"));
    assert!(!script.contains("CREATE DATABASE"));
    assert!(!script.contains("CREATE USER"));
    assert!(!script.contains("GRANT ALL PRIVILEGES"));
    assert!(!script.contains("$MYSQL_ROOT_PASSWORD"));
}

#[test]
fn mysql_rollback_restores_the_captured_authentication_string() {
    let script = mysql_auth_restore_script("app_user", "caching_sha2_password").unwrap();

    assert!(script.contains("DBE_PREVIOUS_MYSQL_AUTH_B64"));
    assert!(script.contains("DBE_ROTATION_ADMIN_PASSWORD"));
    assert!(script.contains("IDENTIFIED WITH `caching_sha2_password` AS"));
    assert!(!script.contains("DBE_ROTATED_PASSWORD_B64"));
}

#[test]
fn maintenance_negative_probe_accepts_only_protocol_auth_rejections() {
    let postgres = exec_failure("FATAL: password authentication failed for user dbe_admin");
    let mariadb = exec_failure(
        "ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)",
    );
    let mongodb = exec_failure("MongoServerError: Authentication failed. code: 18");
    let transport = exec_failure("cannot connect to local socket");
    let timeout = crate::runtime::docker::DockerError::ExecTimedOut {
        container: "dbe-test".to_string(),
        operation: "sh [arguments redacted]".to_string(),
        timeout_seconds: 5,
    };

    assert!(definite_password_rejection(Protocol::Postgres, &postgres));
    assert!(definite_password_rejection(Protocol::Mariadb, &mariadb));
    assert!(definite_password_rejection(Protocol::Mongodb, &mongodb));
    assert!(!definite_password_rejection(Protocol::Postgres, &transport));
    assert!(!definite_password_rejection(Protocol::Postgres, &timeout));
}

#[test]
fn captured_auth_comparison_rejects_any_changed_verifier() {
    assert!(protected_value_matches(
        "SCRAM-SHA-256$expected",
        "SCRAM-SHA-256$expected"
    ));
    assert!(!protected_value_matches(
        "SCRAM-SHA-256$expected",
        "SCRAM-SHA-256$changed"
    ));
    assert!(!protected_value_matches(
        "same-prefix",
        "same-prefix-longer"
    ));
}

fn exec_failure(output: &str) -> crate::runtime::docker::DockerError {
    crate::runtime::docker::DockerError::ExecFailed {
        container: "dbe-test".to_string(),
        operation: "sh [arguments redacted]".to_string(),
        exit_code: 1,
        failure_output: output.to_string(),
    }
}

#[test]
fn postgres_rotation_authenticates_with_the_protected_internal_admin() {
    let script = postgres_rotation_script("app_user", "app_db");

    assert!(script.contains("PGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\""));
    assert!(script.contains("DBE_ROTATED_PASSWORD"));
    assert!(!script.contains("PGPASSWORD=\"$POSTGRES_PASSWORD\""));
    assert!(!script.contains("$POSTGRES_USER"));
    assert!(!script.contains("$POSTGRES_DB"));
    assert!(!script.contains(" peer "));
}

#[test]
fn postgres_rotation_hardens_password_enforcement_after_setting_the_secret() {
    assert!(requires_postgres_auth_hardening(
        Protocol::Postgres,
        Some(&SecretString::from("replacement-password"))
    ));
    assert!(!requires_postgres_auth_hardening(Protocol::Postgres, None));
    assert!(!requires_postgres_auth_hardening(
        Protocol::Mysql,
        Some(&SecretString::from("replacement-password"))
    ));
}

#[test]
fn route_auth_updates_only_protocol_specific_hidden_material() {
    let mut metadata = test_metadata(Protocol::Qdrant);
    apply_new_route_auth(
        &mut metadata,
        &SecretString::from("new-key"),
        &PreviousCredential::default(),
        b"test-qdrant-route-key",
    );

    assert_eq!(
        metadata.route_key_sha256.as_deref(),
        Some(
            crate::protocols::qdrant::route_key_fingerprint(b"test-qdrant-route-key", "new-key")
                .as_str()
        )
    );
    assert!(metadata.mariadb_native_password_sha1_stage2.is_none());
    assert_eq!(metadata.tenant_password.as_deref(), Some("new-key"));
}

#[test]
fn mysql_route_auth_adopts_the_verified_maintenance_credential() {
    let mut metadata = test_metadata(Protocol::Mysql);
    let previous = PreviousCredential {
        maintenance: Some(SecretString::from("verified-root")),
        ..PreviousCredential::default()
    };

    apply_new_route_auth(
        &mut metadata,
        &SecretString::from("replacement-password"),
        &previous,
        b"test-qdrant-route-key",
    );

    assert_eq!(
        metadata.mysql_root_password.as_deref(),
        Some("verified-root")
    );
    let expected =
        crate::protocols::mariadb::native_password_sha1_stage2_hex("replacement-password");
    assert_eq!(
        metadata.mysql_native_password_sha1_stage2.as_deref(),
        Some(expected.as_str())
    );
}

#[test]
fn password_commit_resolution_accepts_only_exact_previous_or_intended_metadata() {
    let previous = test_metadata(Protocol::Postgres);
    let mut intended = previous.clone();
    intended.tenant_password = Some("replacement-password".to_string());
    intended.updated_at = "2026-01-02T00:00:00Z".to_string();

    assert!(matches!(
        classify_password_metadata_commit(intended.clone(), &previous, &intended),
        PasswordMetadataCommitResolution::Committed
    ));
    assert!(matches!(
        classify_password_metadata_commit(previous.clone(), &previous, &intended),
        PasswordMetadataCommitResolution::Previous
    ));

    let mut divergent = intended.clone();
    divergent.status = InstanceStatus::Failed;
    match classify_password_metadata_commit(divergent.clone(), &previous, &intended) {
        PasswordMetadataCommitResolution::Uncertain {
            persisted: Some(persisted),
            ..
        } => assert_eq!(persisted.status, divergent.status),
        _ => panic!("divergent metadata must remain uncertain"),
    }
}

#[test]
fn only_immutable_or_legacy_protocol_credentials_require_recreation() {
    let current_resp = PreviousCredential {
        environment: Some(SecretString::from("current-password")),
        acl: Some(b"user dbe_health on nopass -@all +ping\n".to_vec()),
        ..PreviousCredential::default()
    };
    let legacy_resp = PreviousCredential {
        acl: Some(b"user dbe_health on nopass -@all +ping\n".to_vec()),
        ..PreviousCredential::default()
    };

    assert!(!requires_container_recreation(
        Protocol::Postgres,
        &current_resp
    ));
    assert!(!requires_container_recreation(
        Protocol::Mongodb,
        &current_resp
    ));
    assert!(!requires_container_recreation(
        Protocol::Redis,
        &current_resp
    ));
    assert!(requires_container_recreation(Protocol::Redis, &legacy_resp));
    assert!(requires_container_recreation(
        Protocol::Clickhouse,
        &current_resp
    ));
    assert!(requires_container_recreation(
        Protocol::Qdrant,
        &current_resp
    ));
}

#[test]
fn uncertain_rotation_is_quarantined_and_stopped_for_boot() {
    let metadata = test_metadata(Protocol::Mongodb);

    let quarantined = quarantined_metadata(&metadata);

    assert_eq!(quarantined.status, InstanceStatus::Quarantined);
    assert_eq!(
        quarantined.desired_state,
        crate::instances::metadata::DesiredInstanceState::Stopped
    );
}

#[tokio::test]
async fn panic_recovery_keeps_the_instance_lock_until_recovery_finishes() {
    let locks = crate::instances::locks::InstanceLocks::default();
    let (recovery_started_tx, recovery_started_rx) = tokio::sync::oneshot::channel();
    let (release_recovery_tx, release_recovery_rx) = tokio::sync::oneshot::channel();
    let supervisor = tokio::spawn({
        let locks = locks.clone();
        async move {
            run_password_worker_with_panic_recovery(
                &locks,
                "inst_password_panic",
                async { panic!("injected password worker panic") },
                move |_| async move {
                    recovery_started_tx.send(()).unwrap();
                    release_recovery_rx.await.unwrap();
                    7_u8
                },
            )
            .await
        }
    });

    recovery_started_rx.await.unwrap();
    let contender = tokio::spawn({
        let locks = locks.clone();
        async move { locks.lock("inst_password_panic").await }
    });
    tokio::task::yield_now().await;
    assert!(!contender.is_finished());

    release_recovery_tx.send(()).unwrap();
    assert_eq!(supervisor.await.unwrap(), 7);
    tokio::time::timeout(Duration::from_secs(1), contender)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn panic_recovery_prefers_newly_committed_durable_auth_over_stale_store_auth() {
    let mut stale = test_metadata(Protocol::Mysql);
    stale.tenant_password = Some("old-password".to_string());
    stale.mysql_root_password = Some("old-root".to_string());
    let mut durable = stale.clone();
    durable.tenant_password = Some("new-password".to_string());
    durable.mysql_root_password = Some("new-root".to_string());

    match classify_password_worker_panic_recovery(Ok(Some(durable)), Some(&stale)) {
        PasswordWorkerPanicRecoveryPlan::QuarantineDurable(metadata) => {
            assert_eq!(metadata.tenant_password.as_deref(), Some("new-password"));
            assert_eq!(metadata.mysql_root_password.as_deref(), Some("new-root"));
        }
        PasswordWorkerPanicRecoveryPlan::StopWithoutPersistence { .. } => {
            panic!("a readable durable commit must be the quarantine source")
        }
    }
}

#[test]
fn unreadable_durable_state_never_carries_stale_credentials_into_recovery() {
    let mut stale = test_metadata(Protocol::Postgres);
    stale.tenant_password = Some("stale-password".to_string());

    match classify_password_worker_panic_recovery(
        Err("injected durable read failure".to_string()),
        Some(&stale),
    ) {
        PasswordWorkerPanicRecoveryPlan::StopWithoutPersistence { protocol, reason } => {
            assert_eq!(protocol, Some(Protocol::Postgres));
            assert!(reason.contains("injected durable read failure"));
            assert!(!reason.contains("stale-password"));
        }
        PasswordWorkerPanicRecoveryPlan::QuarantineDurable(_) => {
            panic!("unreadable durable state must not persist a stale store snapshot")
        }
    }
}

fn test_metadata(protocol: Protocol) -> InstanceMetadata {
    InstanceMetadata {
        schema_version: crate::instances::metadata::SCHEMA_VERSION,
        instance_id: "inst_password_test".to_string(),
        protocol,
        status: InstanceStatus::Running,
        desired_state: crate::instances::metadata::DesiredInstanceState::Running,
        disk_limit_blocked: false,
        public: crate::instances::metadata::PublicEndpoint {
            host: "db.example.test".to_string(),
            port: 1234,
        },
        backend: crate::shared::backend::BackendEndpoint::UnixSocket {
            socket_path: "/run/dbev/test.sock".to_string(),
        },
        runtime: crate::instances::metadata::RuntimeMetadata {
            kind: crate::instances::metadata::RuntimeKind::Docker,
            container_name: "dbe-test".to_string(),
            network_mode: "none".to_string(),
        },
        database: crate::instances::metadata::DatabaseIdentity {
            name: "app_db".to_string(),
            username: "app_user".to_string(),
        },
        route_key_sha256: None,
        mariadb_native_password_sha1_stage2: None,
        mariadb_root_password: None,
        mysql_native_password_sha1_stage2: None,
        mysql_root_password: None,
        mongodb_root_password: None,
        postgres_admin_password: None,
        tenant_password: None,
        limits: crate::shared::limits::InstanceLimits::default(),
        image: None,
        database_version: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}
