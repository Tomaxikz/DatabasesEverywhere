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
    let script = mysql_family_rotation_script(
        Protocol::Mysql,
        "app_db",
        "app_user",
        "0123456789abcdef0123456789abcdef01234567",
    )
    .unwrap();

    assert!(script.contains("SET SESSION sql_log_bin = 0;"));
    assert!(script.contains("ALTER USER `app_user`"));
    assert!(!script.contains("CREATE DATABASE"));
    assert!(!script.contains("CREATE USER"));
    assert!(!script.contains("GRANT ALL PRIVILEGES"));
}

#[test]
fn route_auth_updates_only_protocol_specific_hidden_material() {
    let mut metadata = test_metadata(Protocol::Qdrant);
    apply_new_route_auth(&mut metadata, &SecretString::from("new-key"));

    assert_eq!(
        metadata.route_key_sha256.as_deref(),
        Some(crate::protocols::qdrant::route_key_sha256("new-key").as_str())
    );
    assert!(metadata.mariadb_native_password_sha1_stage2.is_none());
    assert_eq!(metadata.tenant_password.as_deref(), Some("new-key"));
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
        tenant_password: None,
        limits: crate::shared::limits::InstanceLimits::default(),
        image: None,
        database_version: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}
