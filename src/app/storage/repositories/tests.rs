use super::*;
use crate::{
    instances::{metadata::InstanceDatabaseVersion, test_support},
    shared::protocol::Protocol,
    storage::{secrets::is_encrypted, sqlite},
};

#[tokio::test]
async fn shared_upsert_waits_for_writer_before_reading_recovery_state() {
    use crate::placement::{PlacementRepository, ReserveTenant};
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let runtime =
        crate::placement::test_support::runtime("pool", Protocol::Postgres, "postgres:18");
    placements.save(&runtime).await.unwrap();
    let mut metadata = sample_metadata();
    metadata.deployment_mode = DeploymentMode::Shared;
    metadata.runtime_id = runtime.runtime_id.clone();
    metadata.owner = runtime.owner.clone();
    metadata.limits.disk_mib = 64;
    metadata.tenant_password = Some("preserved-secret".into());
    placements
        .reserve(ReserveTenant {
            owner: runtime.owner.unwrap(),
            instance_id: &metadata.instance_id,
            runtime_id: &runtime.runtime_id,
            database: &metadata.database.name,
            username: &metadata.database.username,
            limits: &metadata.limits,
        })
        .await
        .unwrap();
    placements
        .mark_provisioned(&metadata.instance_id)
        .await
        .unwrap();
    repository.upsert(&metadata).await.unwrap();

    // A second connection updates the recovery fence while startup saves a
    // shared tenant. A deferred read/write upgrade fails immediately here,
    // despite SQLite's busy timeout; admission must precede the read.
    let mut writer = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    sqlx::query("UPDATE instance_metadata SET protected_secret_recovery_required = 1 WHERE instance_id = ?1")
        .bind(&metadata.instance_id).execute(&mut *writer).await.unwrap();
    metadata.tenant_password = Some("must-not-replace-fenced-secret".into());
    let save = repository.upsert(&metadata);
    tokio::pin!(save);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut save)
            .await
            .is_err()
    );
    writer.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), save)
        .await
        .unwrap()
        .unwrap();

    let (fenced, encrypted): (bool, String) = sqlx::query_as(
        "SELECT protected_secret_recovery_required, tenant_password FROM instance_metadata JOIN instance_route_auth USING (instance_id) WHERE instance_id = ?1",
    ).bind(&metadata.instance_id).fetch_one(&pool).await.unwrap();
    assert!(fenced);
    assert!(is_encrypted(&encrypted));
    assert_eq!(
        repository
            .unprotect_route_secret("tenant_password", &metadata.instance_id, Some(encrypted))
            .unwrap(),
        Some("preserved-secret".into())
    );
}

#[tokio::test]
async fn upserts_and_lists_instance_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::new(pool.clone());
    let mut metadata = sample_metadata();
    metadata.database_version = Some(InstanceDatabaseVersion {
        current: Some("18.4".to_string()),
        error: None,
    });

    repository.upsert(&metadata).await.unwrap();
    let instances = repository.list().await.unwrap();

    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].instance_id, "inst_abc");
    assert_eq!(instances[0].database.username, "app");
    let runtime_version: Option<String> = sqlx::query_scalar(
        "SELECT database_version FROM engine_runtimes WHERE runtime_id = 'inst_abc'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(runtime_version.as_deref(), Some("18.4"));
}

#[tokio::test]
async fn get_returns_none_for_missing_instance() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::new(pool);

    let metadata = repository.get("missing").await.unwrap();

    assert!(metadata.is_none());
}

#[tokio::test]
async fn persists_desired_state_outside_public_metadata_json() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::new(pool.clone());
    let mut metadata = sample_metadata();
    metadata.desired_state = DesiredInstanceState::Stopped;
    metadata.disk_limit_blocked = true;

    repository.upsert(&metadata).await.unwrap();

    let (desired_state, disk_limit_blocked, metadata_json): (String, bool, String) =
        sqlx::query_as(
        "SELECT desired_state, disk_limit_blocked, metadata_json FROM instance_metadata WHERE instance_id = ?1",
    )
    .bind("inst_abc")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(desired_state, "stopped");
    assert!(disk_limit_blocked);
    assert!(!metadata_json.contains("desired_state"));
    assert!(!metadata_json.contains("disk_limit_blocked"));
    let loaded = repository.get("inst_abc").await.unwrap().unwrap();
    assert_eq!(loaded.desired_state, DesiredInstanceState::Stopped);
    assert!(loaded.disk_limit_blocked);
    assert!(
        !serde_json::to_string(&loaded)
            .unwrap()
            .contains("desired_state")
    );
    assert!(
        !serde_json::to_string(&loaded)
            .unwrap()
            .contains("disk_limit_blocked")
    );
}

#[tokio::test]
async fn delete_removes_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::new(pool.clone());
    let metadata = sample_metadata();
    repository.upsert(&metadata).await.unwrap();

    assert!(repository.delete("inst_abc").await.unwrap());
    assert!(repository.get("inst_abc").await.unwrap().is_none());
    let runtimes: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM engine_runtimes WHERE runtime_id = 'inst_abc'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(runtimes, 0);
}

#[tokio::test]
async fn durable_metadata_rejects_every_duplicate_route_identity() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::new(pool);
    for (index, protocol) in [
        Protocol::Postgres,
        Protocol::Redis,
        Protocol::Valkey,
        Protocol::Qdrant,
    ]
    .into_iter()
    .enumerate()
    {
        let mut first = sample_metadata();
        first.instance_id = format!("inst_first_{index}");
        first.protocol = protocol;
        first.database.name = format!("database_{index}");
        first.database.username = format!("user_{index}");
        first.runtime.container_name = format!("dbe-{protocol}-first-{index}");
        if protocol == Protocol::Qdrant {
            first.route_key_sha256 = Some(format!("route-key-{index}"));
        }

        let mut duplicate = first.clone();
        duplicate.instance_id = format!("inst_duplicate_{index}");
        duplicate.runtime.container_name = format!("dbe-{protocol}-duplicate-{index}");
        if matches!(
            protocol,
            Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
        ) {
            duplicate.database.name = format!("other_database_{index}");
        }

        repository.upsert(&first).await.unwrap();
        assert!(
            matches!(
                repository.upsert(&duplicate).await,
                Err(RepositoryError::Sqlx(sqlx::Error::Database(_)))
            ),
            "accepted duplicate {protocol} route"
        );
    }
}

#[tokio::test]
async fn durable_metadata_allows_same_database_for_a_distinct_user() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::new(pool);
    let first = sample_metadata();
    let mut distinct_route = sample_metadata();
    distinct_route.instance_id = "inst_other".to_string();
    distinct_route.database.username = "other_user".to_string();
    distinct_route.runtime.container_name = "dbe-postgres-inst_other".to_string();

    repository.upsert(&first).await.unwrap();
    repository.upsert(&distinct_route).await.unwrap();
}

#[tokio::test]
async fn persists_hidden_mariadb_auth_verifier() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::new(pool);
    let mut metadata = sample_metadata();
    metadata.protocol = Protocol::Mariadb;
    metadata.mariadb_native_password_sha1_stage2 =
        Some("0123456789abcdef0123456789abcdef01234567".to_string());
    metadata.mariadb_root_password = Some("internal-root-password".to_string());

    repository.upsert(&metadata).await.unwrap();

    let loaded = repository.get("inst_abc").await.unwrap().unwrap();
    assert_eq!(
        loaded.mariadb_native_password_sha1_stage2.as_deref(),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
    assert_eq!(
        loaded.mariadb_root_password.as_deref(),
        Some("internal-root-password")
    );
    let public_json = serde_json::to_string(&loaded).unwrap();
    assert!(!public_json.contains("mariadb_native_password_sha1_stage2"));
    assert!(!public_json.contains("mariadb_root_password"));
}

#[tokio::test]
async fn encrypted_repository_stores_hidden_mysql_auth_material_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut metadata = sample_metadata();
    metadata.protocol = Protocol::Mysql;
    metadata.mysql_native_password_sha1_stage2 =
        Some("0123456789abcdef0123456789abcdef01234567".to_string());
    metadata.mysql_root_password = Some("internal-mysql-root-password".to_string());

    repository.upsert(&metadata).await.unwrap();

    let (raw_verifier, raw_root): (String, String) = sqlx::query_as(
        "SELECT mysql_native_password_sha1_stage2, mysql_root_password FROM instance_route_auth WHERE instance_id = ?1",
    )
    .bind("inst_abc")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(is_encrypted(&raw_verifier));
    assert!(is_encrypted(&raw_root));
    assert!(!raw_root.contains("internal-mysql-root-password"));

    let loaded = repository.get("inst_abc").await.unwrap().unwrap();
    assert_eq!(
        loaded.mysql_native_password_sha1_stage2.as_deref(),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
    assert_eq!(
        loaded.mysql_root_password.as_deref(),
        Some("internal-mysql-root-password")
    );
    let public_json = serde_json::to_string(&loaded).unwrap();
    assert!(!public_json.contains("mysql_native_password_sha1_stage2"));
    assert!(!public_json.contains("mysql_root_password"));
}

#[tokio::test]
async fn persists_hidden_mongodb_root_password() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::new(pool);
    let mut metadata = sample_metadata();
    metadata.protocol = Protocol::Mongodb;
    metadata.mongodb_root_password = Some("internal-mongo-root-password".to_string());

    repository.upsert(&metadata).await.unwrap();

    let loaded = repository.get("inst_abc").await.unwrap().unwrap();
    assert_eq!(
        loaded.mongodb_root_password.as_deref(),
        Some("internal-mongo-root-password")
    );
    let public_json = serde_json::to_string(&loaded).unwrap();
    assert!(!public_json.contains("mongodb_root_password"));
}

#[tokio::test]
async fn encrypted_repository_stores_hidden_route_auth_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut metadata = sample_metadata();
    metadata.protocol = Protocol::Mongodb;
    metadata.mongodb_root_password = Some("internal-mongo-root-password".to_string());

    repository.upsert(&metadata).await.unwrap();

    let raw: String = sqlx::query_scalar(
        "SELECT mongodb_root_password FROM instance_route_auth WHERE instance_id = ?1",
    )
    .bind("inst_abc")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(is_encrypted(&raw));
    assert!(!raw.contains("internal-mongo-root-password"));

    let loaded = repository.get("inst_abc").await.unwrap().unwrap();
    assert_eq!(
        loaded.mongodb_root_password.as_deref(),
        Some("internal-mongo-root-password")
    );
}

#[tokio::test]
async fn encrypted_repository_stores_tenant_password_outside_public_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut metadata = sample_metadata();
    // A caller-controlled secret may legitimately begin with the storage
    // envelope marker. It must still be encrypted rather than mistaken
    // for an already protected repository value.
    metadata.tenant_password = Some("dbev1:current-tenant-password".to_string());

    repository.upsert(&metadata).await.unwrap();

    let raw: String = sqlx::query_scalar(
        "SELECT tenant_password FROM instance_route_auth WHERE instance_id = ?1",
    )
    .bind("inst_abc")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(is_encrypted(&raw));
    assert_ne!(raw, "dbev1:current-tenant-password");
    assert!(!raw.contains("current-tenant-password"));

    let loaded = repository.get("inst_abc").await.unwrap().unwrap();
    assert_eq!(
        loaded.tenant_password.as_deref(),
        Some("dbev1:current-tenant-password")
    );
    let public_json = serde_json::to_string(&loaded).unwrap();
    assert!(!public_json.contains("tenant_password"));
    assert!(!public_json.contains("dbev1:current-tenant-password"));
}

#[tokio::test]
async fn encrypted_repository_stores_postgres_admin_password_outside_public_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut metadata = sample_metadata();
    metadata.protocol = Protocol::Postgres;
    metadata.postgres_admin_password = Some("internal-postgres-admin-secret".to_string());

    repository.upsert(&metadata).await.unwrap();

    let raw: String = sqlx::query_scalar(
        "SELECT postgres_admin_password FROM instance_route_auth WHERE instance_id = ?1",
    )
    .bind("inst_abc")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(is_encrypted(&raw));
    assert!(!raw.contains("internal-postgres-admin-secret"));

    let loaded = repository.get("inst_abc").await.unwrap().unwrap();
    assert_eq!(
        loaded.postgres_admin_password.as_deref(),
        Some("internal-postgres-admin-secret")
    );
    let public_json = serde_json::to_string(&loaded).unwrap();
    assert!(!public_json.contains("postgres_admin_password"));
    assert!(!public_json.contains("internal-postgres-admin-secret"));
}

#[tokio::test]
async fn encrypted_repository_rejects_ambiguous_prefixed_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let plain_repository = InstanceRepository::new(pool.clone());
    let mut metadata = sample_metadata();
    let ambiguous = "dbev1:chosen-by-the-user";
    metadata.tenant_password = Some(ambiguous.to_string());
    plain_repository.upsert(&metadata).await.unwrap();

    let encrypted_repository = InstanceRepository::encrypted(pool, dir.path()).unwrap();
    let error = encrypted_repository.get("inst_abc").await.unwrap_err();

    assert_invalid_protected_secret(error, "tenant_password", ambiguous);
}

#[tokio::test]
async fn encrypted_repository_rejects_corrupted_ciphertext_without_plaintext_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut metadata = sample_metadata();
    metadata.tenant_password = Some("secret-before-corruption".to_string());
    repository.upsert(&metadata).await.unwrap();

    let raw: String = sqlx::query_scalar(
        "SELECT tenant_password FROM instance_route_auth WHERE instance_id = ?1",
    )
    .bind("inst_abc")
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut corrupted = raw.into_bytes();
    let ciphertext_offset = corrupted.iter().rposition(|byte| *byte == b':').unwrap() + 1;
    corrupted[ciphertext_offset] = if corrupted[ciphertext_offset] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let corrupted = String::from_utf8(corrupted).unwrap();
    sqlx::query("UPDATE instance_route_auth SET tenant_password = ?1 WHERE instance_id = ?2")
        .bind(&corrupted)
        .bind("inst_abc")
        .execute(&pool)
        .await
        .unwrap();

    let error = repository.get("inst_abc").await.unwrap_err();
    assert_invalid_protected_secret(error, "tenant_password", &corrupted);
}

#[tokio::test]
async fn encrypted_repository_rejects_ciphertext_bound_to_the_wrong_field() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut metadata = sample_metadata();
    metadata.tenant_password = Some("field-bound-secret".to_string());
    repository.upsert(&metadata).await.unwrap();

    let raw: String = sqlx::query_scalar(
        "SELECT tenant_password FROM instance_route_auth WHERE instance_id = ?1",
    )
    .bind("inst_abc")
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE instance_route_auth SET mongodb_root_password = ?1, tenant_password = NULL WHERE instance_id = ?2",
    )
    .bind(&raw)
    .bind("inst_abc")
    .execute(&pool)
    .await
    .unwrap();

    let error = repository.get("inst_abc").await.unwrap_err();
    assert_invalid_protected_secret(error, "mongodb_root_password", &raw);
}

#[tokio::test]
async fn encrypted_repository_rewrites_legacy_plaintext_route_auth() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let plain_repository = InstanceRepository::new(pool.clone());
    let mut metadata = sample_metadata();
    metadata.protocol = Protocol::Mongodb;
    metadata.mongodb_root_password = Some("legacy-plain-root".to_string());
    plain_repository.upsert(&metadata).await.unwrap();

    let encrypted_repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let loaded = encrypted_repository.list().await.unwrap();
    let rewritten = encrypted_repository
        .rewrite_route_auth(&loaded)
        .await
        .unwrap();

    assert_eq!(rewritten, 1);
    let raw: String = sqlx::query_scalar(
        "SELECT mongodb_root_password FROM instance_route_auth WHERE instance_id = ?1",
    )
    .bind("inst_abc")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(is_encrypted(&raw));
    assert!(!raw.contains("legacy-plain-root"));
}

#[tokio::test]
async fn hardening_attestation_is_bound_to_container_generation_and_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut metadata = sample_metadata();
    metadata.tenant_password = Some("tenant-secret".to_string());
    metadata.postgres_admin_password = Some("admin-secret".to_string());
    repository.upsert(&metadata).await.unwrap();

    repository
        .record_hardening_attestation(
            &metadata,
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "2026-08-13T12:00:00Z",
            1,
        )
        .await
        .unwrap();

    assert!(
        repository
            .hardening_is_current(
                &metadata,
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "2026-08-13T12:00:00Z",
                1,
            )
            .await
            .unwrap()
    );
    assert!(
        !repository
            .hardening_is_current(
                &metadata,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "2026-08-13T12:00:00Z",
                1,
            )
            .await
            .unwrap()
    );
    assert!(
        !repository
            .hardening_is_current(
                &metadata,
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "2026-08-13T12:01:00Z",
                1,
            )
            .await
            .unwrap()
    );
    assert!(
        !repository
            .hardening_is_current(
                &metadata,
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "2026-08-13T12:00:00Z",
                2,
            )
            .await
            .unwrap()
    );
    metadata.tenant_password = Some("rotated-tenant-secret".to_string());
    assert!(
        !repository
            .hardening_is_current(
                &metadata,
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "2026-08-13T12:00:00Z",
                1,
            )
            .await
            .unwrap()
    );
    metadata.tenant_password = Some("tenant-secret".to_string());
    sqlx::query(
        "UPDATE instance_auth_hardening_attestations SET container_id = ?1, container_started_at = ?2, hardening_revision = 2 WHERE instance_id = ?3",
    )
    .bind("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    .bind("2026-08-13T12:01:00Z")
    .bind("inst_abc")
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        !repository
            .hardening_is_current(
                &metadata,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "2026-08-13T12:01:00Z",
                2,
            )
            .await
            .unwrap()
    );

    let binding: String = sqlx::query_scalar(
        "SELECT credential_binding FROM instance_auth_hardening_attestations WHERE instance_id = ?1",
    )
    .bind("inst_abc")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(binding.starts_with("dbevh1:"));
    assert!(!binding.contains("tenant-secret"));
    assert!(!binding.contains("admin-secret"));
}

#[tokio::test]
async fn hardening_attestation_cascades_when_instance_is_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut metadata = sample_metadata();
    metadata.tenant_password = Some("tenant-secret".to_string());
    metadata.postgres_admin_password = Some("admin-secret".to_string());
    repository.upsert(&metadata).await.unwrap();
    repository
        .record_hardening_attestation(
            &metadata,
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "2026-08-13T12:00:00Z",
            1,
        )
        .await
        .unwrap();

    assert!(repository.delete("inst_abc").await.unwrap());
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM instance_auth_hardening_attestations WHERE instance_id = ?1",
    )
    .bind("inst_abc")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remaining, 0);
}

fn assert_invalid_protected_secret(
    error: RepositoryError,
    expected_field: &str,
    protected_value: &str,
) {
    let message = error.to_string();
    assert!(message.contains("inst_abc"));
    assert!(message.contains(expected_field));
    assert!(!message.contains(protected_value));
    match error {
        RepositoryError::InvalidProtectedSecret {
            instance_id,
            field,
            source: SecretStoreError::InvalidCiphertext,
        } => {
            assert_eq!(instance_id, "inst_abc");
            assert_eq!(field, expected_field);
        }
        error => panic!("unexpected repository error: {error}"),
    }
}

fn sample_metadata() -> InstanceMetadata {
    let mut metadata = test_support::metadata("inst_abc", Protocol::Postgres);
    metadata.public.port = 5433;
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: "/run/dbev/sockets/inst_abc/.s.PGSQL.5432".to_string(),
    };
    metadata.database.name = "app_db".to_string();
    metadata.database.username = "app".to_string();
    metadata.created_at = "2026-01-01T12:00:00Z".to_string();
    metadata.updated_at = metadata.created_at.clone();
    metadata
}
