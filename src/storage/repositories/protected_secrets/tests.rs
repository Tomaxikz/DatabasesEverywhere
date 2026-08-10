use secrecy::SecretString;

use super::*;
use crate::{
    instances::{
        manager::InstanceManager,
        metadata::{
            DatabaseIdentity, PublicEndpoint, RuntimeKind, RuntimeMetadata, SCHEMA_VERSION,
        },
        state::InstanceStore,
    },
    shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
    storage::{secrets::is_encrypted, sqlite},
};

#[tokio::test]
async fn daemon_load_quarantines_only_the_ambiguous_instance_and_preserves_raw_data() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let plain = InstanceRepository::new(pool.clone());
    let ambiguous = "dbev1:user-selected-password";
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some(ambiguous.to_string());
    plain.upsert(&affected).await.unwrap();

    let encrypted = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut healthy = metadata("inst_healthy", "healthy_user");
    healthy.tenant_password = Some("healthy-password".to_string());
    encrypted.upsert(&healthy).await.unwrap();
    let manager = InstanceManager::new(InstanceStore::default(), encrypted.clone());

    manager.load_from_storage().await.unwrap();

    let affected = manager.store().get("inst_affected").await.unwrap();
    assert_eq!(affected.status, InstanceStatus::Quarantined);
    assert_eq!(affected.desired_state, DesiredInstanceState::Stopped);
    assert!(affected.tenant_password.is_none());
    assert_eq!(
        manager
            .store()
            .get("inst_healthy")
            .await
            .unwrap()
            .tenant_password
            .as_deref(),
        Some("healthy-password")
    );
    assert_eq!(
        raw_field(&pool, "inst_affected", "tenant_password").await,
        ambiguous
    );
    assert!(recovery_required(&pool, "inst_affected").await);

    manager.upsert(affected).await.unwrap();
    assert_eq!(
        raw_field(&pool, "inst_affected", "tenant_password").await,
        ambiguous
    );
}

#[tokio::test]
async fn exact_offline_repair_encrypts_the_legacy_plaintext_and_leaves_instance_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let plain = InstanceRepository::new(pool.clone());
    let ambiguous = "dbev1:user-selected-password";
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some(ambiguous.to_string());
    plain.upsert(&affected).await.unwrap();
    let encrypted = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    encrypted.load_for_daemon().await.unwrap();

    let repair = encrypted
        .repair_ambiguous_protected_secret(
            "inst_affected",
            ProtectedSecretField::TenantPassword,
            &SecretString::from(ambiguous),
        )
        .await
        .unwrap();

    assert!(repair.remaining_fields.is_empty());
    let raw = raw_field(&pool, "inst_affected", "tenant_password").await;
    assert!(is_encrypted(&raw));
    assert_ne!(raw, ambiguous);
    assert!(!recovery_required(&pool, "inst_affected").await);
    let loaded = encrypted.get("inst_affected").await.unwrap().unwrap();
    assert_eq!(loaded.tenant_password.as_deref(), Some(ambiguous));
    assert_eq!(loaded.status, InstanceStatus::Stopped);
    assert_eq!(loaded.desired_state, DesiredInstanceState::Stopped);
    assert!(
        encrypted
            .load_for_daemon()
            .await
            .unwrap()
            .protected_secret_incidents
            .is_empty()
    );
}

#[tokio::test]
async fn repair_mismatch_is_atomic_and_does_not_reinterpret_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let encrypted = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some("actual-password".to_string());
    encrypted.upsert(&affected).await.unwrap();
    let mut raw = raw_field(&pool, "inst_affected", "tenant_password")
        .await
        .into_bytes();
    let last = raw.len() - 1;
    raw[last] = if raw[last] == b'A' { b'B' } else { b'A' };
    let corrupted = String::from_utf8(raw).unwrap();
    set_raw_field(&pool, "inst_affected", "tenant_password", &corrupted).await;
    encrypted.load_for_daemon().await.unwrap();

    let error = encrypted
        .repair_ambiguous_protected_secret(
            "inst_affected",
            ProtectedSecretField::TenantPassword,
            &SecretString::from("actual-password"),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        RepositoryError::ProtectedSecretPlaintextMismatch { .. }
    ));
    assert_eq!(
        raw_field(&pool, "inst_affected", "tenant_password").await,
        corrupted
    );
    assert!(recovery_required(&pool, "inst_affected").await);
    let (status, desired): (String, String) = sqlx::query_as(
        "SELECT status, desired_state FROM instance_metadata WHERE instance_id = ?1",
    )
    .bind("inst_affected")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (status.as_str(), desired.as_str()),
        ("quarantined", "stopped")
    );
}

#[tokio::test]
async fn multiple_ambiguous_fields_remain_quarantined_until_each_is_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let plain = InstanceRepository::new(pool.clone());
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some("dbev1:tenant".to_string());
    affected.postgres_admin_password = Some("dbev1:admin".to_string());
    plain.upsert(&affected).await.unwrap();
    let encrypted = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let loaded = encrypted.load_for_daemon().await.unwrap();
    assert_eq!(
        loaded.protected_secret_incidents[0].fields,
        vec![
            ProtectedSecretField::PostgresAdminPassword,
            ProtectedSecretField::TenantPassword
        ]
    );

    let first = encrypted
        .repair_ambiguous_protected_secret(
            "inst_affected",
            ProtectedSecretField::TenantPassword,
            &SecretString::from("dbev1:tenant"),
        )
        .await
        .unwrap();
    assert_eq!(
        first.remaining_fields,
        vec![ProtectedSecretField::PostgresAdminPassword]
    );
    assert!(recovery_required(&pool, "inst_affected").await);

    let second = encrypted
        .repair_ambiguous_protected_secret(
            "inst_affected",
            ProtectedSecretField::PostgresAdminPassword,
            &SecretString::from("dbev1:admin"),
        )
        .await
        .unwrap();
    assert!(second.remaining_fields.is_empty());
    let loaded = encrypted.get("inst_affected").await.unwrap().unwrap();
    assert_eq!(loaded.status, InstanceStatus::Stopped);
    assert_eq!(loaded.tenant_password.as_deref(), Some("dbev1:tenant"));
    assert_eq!(
        loaded.postgres_admin_password.as_deref(),
        Some("dbev1:admin")
    );
}

#[tokio::test]
async fn malformed_public_metadata_still_fails_the_daemon_load() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    repository
        .upsert(&metadata("inst_affected", "affected_user"))
        .await
        .unwrap();
    sqlx::query("UPDATE instance_metadata SET metadata_json = '{' WHERE instance_id = ?1")
        .bind("inst_affected")
        .execute(&pool)
        .await
        .unwrap();

    assert!(matches!(
        repository.load_for_daemon().await,
        Err(RepositoryError::Json(_))
    ));
}

#[tokio::test]
async fn restored_key_clears_recovery_quarantine_but_never_auto_starts() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some("valid-password".to_string());
    repository.upsert(&affected).await.unwrap();
    let key_path = dir.path().join("metadata.key");
    let original_key = std::fs::read_to_string(&key_path).unwrap();
    std::fs::write(&key_path, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap();
    let wrong_key_repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let quarantined = wrong_key_repository.load_for_daemon().await.unwrap();
    assert_eq!(quarantined.protected_secret_incidents.len(), 1);
    assert_eq!(quarantined.metadata[0].status, InstanceStatus::Quarantined);
    std::fs::write(&key_path, original_key).unwrap();
    let restored_repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();

    let loaded = restored_repository.load_for_daemon().await.unwrap();

    assert!(loaded.protected_secret_incidents.is_empty());
    assert_eq!(loaded.metadata[0].status, InstanceStatus::Stopped);
    assert_eq!(
        loaded.metadata[0].desired_state,
        DesiredInstanceState::Stopped
    );
    assert!(!recovery_required(&pool, "inst_affected").await);
}

#[tokio::test]
async fn repair_rejects_already_valid_ciphertext_without_changing_state() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some("valid-password".to_string());
    repository.upsert(&affected).await.unwrap();
    let before = raw_field(&pool, "inst_affected", "tenant_password").await;

    let error = repository
        .repair_ambiguous_protected_secret(
            "inst_affected",
            ProtectedSecretField::TenantPassword,
            &SecretString::from("valid-password"),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        RepositoryError::ProtectedSecretAlreadyValid { .. }
    ));
    assert_eq!(
        raw_field(&pool, "inst_affected", "tenant_password").await,
        before
    );
}

#[test]
fn protected_secret_field_parser_accepts_cli_spelling_only() {
    assert_eq!(
        "tenant-password".parse(),
        Ok(ProtectedSecretField::TenantPassword)
    );
    assert_eq!(
        "postgres_admin_password".parse(),
        Ok(ProtectedSecretField::PostgresAdminPassword)
    );
    assert!("metadata_json".parse::<ProtectedSecretField>().is_err());
}

async fn raw_field(pool: &sqlx::SqlitePool, instance_id: &str, field: &str) -> String {
    let query = format!("SELECT {field} FROM instance_route_auth WHERE instance_id = ?1");
    sqlx::query_scalar(&query)
        .bind(instance_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn set_raw_field(pool: &sqlx::SqlitePool, instance_id: &str, field: &str, value: &str) {
    let query = format!("UPDATE instance_route_auth SET {field} = ?1 WHERE instance_id = ?2");
    sqlx::query(&query)
        .bind(value)
        .bind(instance_id)
        .execute(pool)
        .await
        .unwrap();
}

async fn recovery_required(pool: &sqlx::SqlitePool, instance_id: &str) -> bool {
    sqlx::query_scalar(
        "SELECT protected_secret_recovery_required FROM instance_metadata WHERE instance_id = ?1",
    )
    .bind(instance_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn metadata(instance_id: &str, username: &str) -> InstanceMetadata {
    InstanceMetadata {
        schema_version: SCHEMA_VERSION,
        instance_id: instance_id.to_string(),
        protocol: Protocol::Postgres,
        status: InstanceStatus::Running,
        desired_state: DesiredInstanceState::Running,
        disk_limit_blocked: false,
        public: PublicEndpoint {
            host: "db.example.com".to_string(),
            port: 5433,
        },
        backend: BackendEndpoint::UnixSocket {
            socket_path: format!("/run/dbev/sockets/{instance_id}/.s.PGSQL.5432"),
        },
        runtime: RuntimeMetadata {
            kind: RuntimeKind::Docker,
            container_name: format!("dbe-postgres-{instance_id}"),
            network_mode: "none".to_string(),
        },
        database: DatabaseIdentity {
            name: format!("db_{instance_id}"),
            username: username.to_string(),
        },
        route_key_sha256: None,
        mariadb_native_password_sha1_stage2: None,
        mariadb_root_password: None,
        mysql_native_password_sha1_stage2: None,
        mysql_root_password: None,
        mongodb_root_password: None,
        postgres_admin_password: None,
        tenant_password: None,
        limits: InstanceLimits::default(),
        image: None,
        database_version: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}
