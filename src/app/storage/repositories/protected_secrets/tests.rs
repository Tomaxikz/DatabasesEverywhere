use secrecy::SecretString;

use super::*;
use crate::{
    databases::protocol::Protocol,
    server::{manager::InstanceManager, state::InstanceStore, test_support},
    storage::{secrets::is_encrypted, sqlite},
    utils::backend::BackendEndpoint,
};

#[tokio::test]
async fn daemon_load_quarantines_only_the_ambiguous_instance_and_preserves_raw_data()
-> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let plain = InstanceRepository::new(pool.clone());
    let ambiguous = "dbev1:user-selected-password'; --";
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some(ambiguous.to_string());
    plain.upsert(&affected).await?;

    let encrypted = InstanceRepository::encrypted(pool.clone(), dir.path())?;
    let mut healthy = metadata("inst_healthy", "healthy_user");
    healthy.tenant_password = Some("healthy-password".to_string());
    encrypted.upsert(&healthy).await?;
    let manager = InstanceManager::new(InstanceStore::default(), encrypted.clone());

    manager.load_from_storage().await?;

    let affected = manager
        .store()
        .get("inst_affected")
        .await
        .context("missing inst_affected entry")?;
    assert_eq!(affected.status, InstanceStatus::Quarantined);
    assert_eq!(affected.desired_state, DesiredInstanceState::Stopped);
    assert!(affected.tenant_password.is_none());
    assert_eq!(
        manager
            .store()
            .get("inst_healthy")
            .await
            .context("get should provide a value")?
            .tenant_password
            .as_deref(),
        Some("healthy-password")
    );
    assert_eq!(raw_tenant_password(&pool, "inst_affected").await, ambiguous);
    assert!(recovery_required(&pool, "inst_affected").await);

    manager.upsert(affected).await?;
    assert_eq!(raw_tenant_password(&pool, "inst_affected").await, ambiguous);

    Ok(())
}

#[tokio::test]
async fn live_verified_replacement_atomically_clears_the_recovery_marker() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let plain = InstanceRepository::new(pool.clone());
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some("dbev1:ambiguous".to_string());
    plain.upsert(&affected).await?;
    let encrypted = InstanceRepository::encrypted(pool.clone(), dir.path())?;
    let loaded = encrypted.load_for_daemon().await?;
    let mut recovered = loaded
        .metadata
        .into_iter()
        .next()
        .context("expected a value from next")?;
    recovered.status = InstanceStatus::Running;
    recovered.desired_state = DesiredInstanceState::Running;
    recovered.tenant_password = Some("verified-replacement".to_string());

    let error = encrypted
        .upsert_recovered_secrets(&recovered)
        .await
        .expect_err("upsert recovered secrets should return an error");
    assert!(matches!(
        error,
        RepositoryError::IncompleteProtectedSecretRecovery { .. }
    ));
    assert!(recovery_required(&pool, "inst_affected").await);
    assert_eq!(
        raw_tenant_password(&pool, "inst_affected").await,
        "dbev1:ambiguous"
    );

    recovered.postgres_admin_password = Some("verified-admin".to_string());
    encrypted.upsert_recovered_secrets(&recovered).await?;

    assert!(!recovery_required(&pool, "inst_affected").await);
    assert!(is_encrypted(
        &raw_tenant_password(&pool, "inst_affected").await
    ));
    let loaded = encrypted
        .get("inst_affected")
        .await?
        .context("get should provide a value")?;
    assert_eq!(
        loaded.tenant_password.as_deref(),
        Some("verified-replacement")
    );
    assert_eq!(loaded.status, InstanceStatus::Running);

    Ok(())
}

#[tokio::test]
async fn exact_offline_repair_encrypts_the_legacy_plaintext_and_leaves_instance_stopped()
-> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let plain = InstanceRepository::new(pool.clone());
    let ambiguous = "dbev1:user-selected-password";
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some(ambiguous.to_string());
    plain.upsert(&affected).await?;
    let encrypted = InstanceRepository::encrypted(pool.clone(), dir.path())?;
    encrypted.load_for_daemon().await?;

    let repair = encrypted
        .repair_ambiguous_secret(
            "inst_affected",
            ProtectedSecretField::TenantPassword,
            &SecretString::from(ambiguous),
        )
        .await?;

    assert!(repair.remaining_fields.is_empty());
    let raw = raw_tenant_password(&pool, "inst_affected").await;
    assert!(is_encrypted(&raw));
    assert_ne!(raw, ambiguous);
    assert!(!recovery_required(&pool, "inst_affected").await);
    let loaded = encrypted
        .get("inst_affected")
        .await?
        .context("get should provide a value")?;
    assert_eq!(loaded.tenant_password.as_deref(), Some(ambiguous));
    assert_eq!(loaded.status, InstanceStatus::Stopped);
    assert_eq!(loaded.desired_state, DesiredInstanceState::Stopped);
    assert!(
        encrypted
            .load_for_daemon()
            .await?
            .protected_secret_incidents
            .is_empty()
    );

    Ok(())
}

#[tokio::test]
async fn repair_mismatch_is_atomic_and_does_not_reinterpret_corruption() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let encrypted = InstanceRepository::encrypted(pool.clone(), dir.path())?;
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some("actual-password".to_string());
    encrypted.upsert(&affected).await?;
    let mut raw = raw_tenant_password(&pool, "inst_affected")
        .await
        .into_bytes();
    let last = raw.len() - 1;
    raw[last] = if raw[last] == b'A' { b'B' } else { b'A' };
    let corrupted = String::from_utf8(raw)?;
    set_raw_tenant_password(&pool, "inst_affected", &corrupted).await;
    encrypted.load_for_daemon().await?;

    let error = encrypted
        .repair_ambiguous_secret(
            "inst_affected",
            ProtectedSecretField::TenantPassword,
            &SecretString::from("actual-password"),
        )
        .await
        .expect_err("repair ambiguous secret should return an error");

    assert!(matches!(
        error,
        RepositoryError::ProtectedSecretPlaintextMismatch { .. }
    ));
    assert_eq!(raw_tenant_password(&pool, "inst_affected").await, corrupted);
    assert!(recovery_required(&pool, "inst_affected").await);
    let (status, desired): (String, String) = sqlx::query_as(
        "SELECT status, desired_state FROM instance_metadata WHERE instance_id = ?1",
    )
    .bind("inst_affected")
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        (status.as_str(), desired.as_str()),
        ("quarantined", "stopped")
    );

    Ok(())
}

#[tokio::test]
async fn multiple_ambiguous_fields_remain_quarantined_until_each_is_repaired() -> anyhow::Result<()>
{
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let plain = InstanceRepository::new(pool.clone());
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some("dbev1:tenant".to_string());
    affected.postgres_admin_password = Some("dbev1:admin".to_string());
    plain.upsert(&affected).await?;
    let encrypted = InstanceRepository::encrypted(pool.clone(), dir.path())?;
    let loaded = encrypted.load_for_daemon().await?;
    assert_eq!(
        loaded.protected_secret_incidents[0].fields,
        vec![
            ProtectedSecretField::PostgresAdminPassword,
            ProtectedSecretField::TenantPassword
        ]
    );

    let first = encrypted
        .repair_ambiguous_secret(
            "inst_affected",
            ProtectedSecretField::TenantPassword,
            &SecretString::from("dbev1:tenant"),
        )
        .await?;
    assert_eq!(
        first.remaining_fields,
        vec![ProtectedSecretField::PostgresAdminPassword]
    );
    assert!(recovery_required(&pool, "inst_affected").await);

    let second = encrypted
        .repair_ambiguous_secret(
            "inst_affected",
            ProtectedSecretField::PostgresAdminPassword,
            &SecretString::from("dbev1:admin"),
        )
        .await?;
    assert!(second.remaining_fields.is_empty());
    let loaded = encrypted
        .get("inst_affected")
        .await?
        .context("get should provide a value")?;
    assert_eq!(loaded.status, InstanceStatus::Stopped);
    assert_eq!(loaded.tenant_password.as_deref(), Some("dbev1:tenant"));
    assert_eq!(
        loaded.postgres_admin_password.as_deref(),
        Some("dbev1:admin")
    );

    Ok(())
}

#[tokio::test]
async fn malformed_public_metadata_still_fails_the_daemon_load() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path())?;
    repository
        .upsert(&metadata("inst_affected", "affected_user"))
        .await?;
    sqlx::query("UPDATE instance_metadata SET metadata_json = '{' WHERE instance_id = ?1")
        .bind("inst_affected")
        .execute(&pool)
        .await?;

    assert!(matches!(
        repository.load_for_daemon().await,
        Err(RepositoryError::Json(_))
    ));

    Ok(())
}

#[tokio::test]
async fn restored_key_clears_recovery_quarantine_but_never_auto_starts() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path())?;
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some("valid-password".to_string());
    repository.upsert(&affected).await?;
    let key_path = dir.path().join("metadata.key");
    let original_key = std::fs::read_to_string(&key_path)?;
    std::fs::write(&key_path, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")?;
    let wrong_key_repository = InstanceRepository::encrypted(pool.clone(), dir.path())?;
    let quarantined = wrong_key_repository.load_for_daemon().await?;
    assert_eq!(quarantined.protected_secret_incidents.len(), 1);
    assert_eq!(quarantined.metadata[0].status, InstanceStatus::Quarantined);
    std::fs::write(&key_path, original_key)?;
    let restored_repository = InstanceRepository::encrypted(pool.clone(), dir.path())?;

    let loaded = restored_repository.load_for_daemon().await?;

    assert!(loaded.protected_secret_incidents.is_empty());
    assert_eq!(loaded.metadata[0].status, InstanceStatus::Stopped);
    assert_eq!(
        loaded.metadata[0].desired_state,
        DesiredInstanceState::Stopped
    );
    assert!(!recovery_required(&pool, "inst_affected").await);

    Ok(())
}

#[tokio::test]
async fn repair_rejects_already_valid_ciphertext_without_changing_state() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let repository = InstanceRepository::encrypted(pool.clone(), dir.path())?;
    let mut affected = metadata("inst_affected", "affected_user");
    affected.tenant_password = Some("valid-password".to_string());
    repository.upsert(&affected).await?;
    let before = raw_tenant_password(&pool, "inst_affected").await;

    let error = repository
        .repair_ambiguous_secret(
            "inst_affected",
            ProtectedSecretField::TenantPassword,
            &SecretString::from("valid-password"),
        )
        .await
        .expect_err("repair ambiguous secret should return an error");

    assert!(matches!(
        error,
        RepositoryError::ProtectedSecretAlreadyValid { .. }
    ));
    assert_eq!(raw_tenant_password(&pool, "inst_affected").await, before);

    Ok(())
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
    assert!(
        "tenant_password = NULL --"
            .parse::<ProtectedSecretField>()
            .is_err()
    );
}

async fn raw_tenant_password(pool: &sqlx::SqlitePool, instance_id: &str) -> String {
    sqlx::query_scalar("SELECT tenant_password FROM instance_route_auth WHERE instance_id = ?1")
        .bind(instance_id)
        .fetch_one(pool)
        .await
        .expect("fetch one should succeed")
}

async fn set_raw_tenant_password(pool: &sqlx::SqlitePool, instance_id: &str, value: &str) {
    sqlx::query("UPDATE instance_route_auth SET tenant_password = ?1 WHERE instance_id = ?2")
        .bind(value)
        .bind(instance_id)
        .execute(pool)
        .await
        .expect("execute should succeed");
}

async fn recovery_required(pool: &sqlx::SqlitePool, instance_id: &str) -> bool {
    sqlx::query_scalar(
        "SELECT protected_secret_recovery_required FROM instance_metadata WHERE instance_id = ?1",
    )
    .bind(instance_id)
    .fetch_one(pool)
    .await
    .expect("fetch one should succeed")
}

fn metadata(instance_id: &str, username: &str) -> InstanceMetadata {
    let mut metadata = test_support::metadata(instance_id, Protocol::Postgres);
    metadata.public.port = 5433;
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: format!("/run/dbev/sockets/{instance_id}/.s.PGSQL.5432"),
    };
    metadata.database.name = format!("db_{instance_id}");
    metadata.database.username = username.to_string();
    metadata
}
