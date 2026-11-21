use super::*;
use crate::{
    databases::protocol::Protocol,
    server::placement::{EngineRuntimeStatus, PlacementRepository},
    server::{metadata::InstanceStatus, test_support::metadata},
    storage::{repositories::InstanceRepository, sqlite},
};

#[tokio::test]
async fn typed_instance_cause_is_atomic_persistent_and_secret_free() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db = sqlite::connect(dir.path()).await?;
    let repository = InstanceRepository::new(db.clone());
    let mut instance = metadata("instance_history", Protocol::Postgres);
    instance.tenant_password = Some("must-not-appear-in-history".into());
    repository.upsert(&instance).await?;
    instance.status = InstanceStatus::Quarantined;
    repository
        .upsert_quarantined(&instance, QuarantineKind::CredentialIntegrity)
        .await?;
    let events = list(&db, Some(&instance.instance_id), false, None, 100).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].code, "credential_integrity");
    assert_eq!(events[0].recovery_class, "repair_required");
    assert!(!serde_json::to_string(&events)?.contains("must-not-appear"));
    let first_seen = events[0].first_seen.clone();
    // Ordinary reconciliation must not replace or append to the original cause.
    repository.upsert(&instance).await?;
    repository.upsert(&instance).await?;
    db.close().await;
    let reopened = sqlite::connect(dir.path()).await?;
    let events = list(&reopened, None, false, None, 100).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].first_seen, first_seen);
    assert_eq!(events[0].occurrences, 1);

    Ok(())
}

#[tokio::test]
async fn raw_sql_and_unclassified_writers_cannot_omit_the_journal() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db = sqlite::connect(dir.path()).await?;
    let repository = InstanceRepository::new(db.clone());
    let instance = metadata("raw_transition", Protocol::Postgres);
    repository.upsert(&instance).await?;
    sqlx::query("UPDATE instance_metadata SET status='quarantined' WHERE instance_id=?1")
        .bind(&instance.instance_id)
        .execute(&db)
        .await?;
    let events = list(&db, None, false, None, 100).await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].code, "unknown");
    assert_eq!(events[0].recovery_class, "manual_review");
    sqlx::query(
        "UPDATE instance_metadata SET protected_secret_recovery_required=1 WHERE instance_id=?1",
    )
    .bind(&instance.instance_id)
    .execute(&db)
    .await?;
    let events = list(&db, None, false, None, 100).await?;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .any(|event| event.code == "credential_integrity")
    );
    assert!(events.iter().any(|event| event.code == "unknown"));
    // An outer UPSERT can override INSERT OR IGNORE inside a SQLite trigger.
    // Repeated writes with a credential fence must remain idempotent regardless.
    let mut quarantined = instance.clone();
    quarantined.status = InstanceStatus::Quarantined;
    repository.upsert(&quarantined).await?;
    repository.upsert(&quarantined).await?;
    assert_eq!(list(&db, None, false, None, 100).await?.len(), 2);

    Ok(())
}

#[tokio::test]
async fn causes_accumulate_without_erasing_history_and_close_on_recovery_or_delete()
-> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let db = sqlite::connect(dir.path()).await?;
    let repository = PlacementRepository::new(db.clone());
    let mut runtime = crate::server::placement::test_support::runtime(
        "pool_history",
        Protocol::Postgres,
        "postgres:18.4",
    );
    runtime.status = EngineRuntimeStatus::Quarantined;
    repository
        .save_quarantined(&runtime, QuarantineKind::ShutdownUnconfirmed)
        .await?;
    repository
        .save_quarantined(&runtime, QuarantineKind::ShutdownUnconfirmed)
        .await?;
    repository
        .save_quarantined(&runtime, QuarantineKind::StorageBoundary)
        .await?;
    repository.save(&runtime).await?;
    let events = list(&db, None, false, None, 100).await?;
    assert_eq!(events.len(), 2);
    let shutdown = events
        .iter()
        .find(|event| event.code == "shutdown_unconfirmed")
        .context("expected a value from find")?;
    assert_eq!(shutdown.recovery_class, "validated_retry");
    assert_eq!(shutdown.occurrences, 2);
    runtime.status = EngineRuntimeStatus::Stopped;
    repository.save(&runtime).await?;
    assert!(list(&db, None, false, None, 100).await?.is_empty());
    let history = list(&db, None, true, None, 100).await?;
    assert_eq!(history.len(), 2);
    assert!(
        history
            .iter()
            .all(|event| event.final_status.as_deref() == Some("stopped"))
    );
    runtime.status = EngineRuntimeStatus::Quarantined;
    repository
        .save_quarantined(&runtime, QuarantineKind::ShutdownUnconfirmed)
        .await?;
    assert_eq!(list(&db, None, true, None, 100).await?.len(), 3);
    repository.delete(&runtime.runtime_id).await?;
    assert!(list(&db, None, false, None, 100).await?.is_empty());
    let page = list(&db, Some("pool_history"), true, None, 1).await?;
    assert_eq!(page[0].final_status.as_deref(), Some("deleted"));
    assert_eq!(
        list(&db, None, true, Some(page[0].event_id), 100)
            .await?
            .len(),
        2
    );

    Ok(())
}

#[tokio::test]
async fn failed_metadata_or_journal_write_rolls_back_both() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let db = sqlite::connect(dir.path()).await?;
    let repository = InstanceRepository::new(db.clone());
    let mut instance = metadata("rollback_history", Protocol::Postgres);
    repository.upsert(&instance).await?;
    sqlx::query(
        "CREATE TRIGGER reject_quarantine BEFORE UPDATE ON instance_metadata
        WHEN NEW.status='quarantined' BEGIN SELECT RAISE(ABORT, 'simulated metadata failure'); END",
    )
    .execute(&db)
    .await?;
    instance.status = InstanceStatus::Quarantined;
    assert!(
        repository
            .upsert_quarantined(&instance, QuarantineKind::MetadataUncertain)
            .await
            .is_err()
    );
    assert!(list(&db, None, true, None, 100).await?.is_empty());
    assert_eq!(
        repository
            .get(&instance.instance_id)
            .await?
            .context("get should provide a value")?
            .status,
        InstanceStatus::Running
    );
    sqlx::query("DROP TRIGGER reject_quarantine")
        .execute(&db)
        .await?;
    sqlx::query(
        "CREATE TRIGGER reject_journal BEFORE INSERT ON quarantine_events
        BEGIN SELECT RAISE(ABORT, 'simulated journal failure'); END",
    )
    .execute(&db)
    .await?;
    assert!(
        repository
            .upsert_quarantined(&instance, QuarantineKind::MetadataUncertain)
            .await
            .is_err()
    );
    assert_eq!(
        repository
            .get(&instance.instance_id)
            .await?
            .context("get should provide a value")?
            .status,
        InstanceStatus::Running
    );
    let store = crate::server::state::InstanceStore::default();
    store
        .upsert(
            repository
                .get(&instance.instance_id)
                .await?
                .context("get should provide a value")?,
        )
        .await;
    let manager = crate::server::manager::InstanceManager::new(store.clone(), repository);
    assert!(
        manager
            .quarantine(instance.clone(), QuarantineKind::MetadataUncertain)
            .await
            .is_err()
    );
    assert!(store.routes_fenced(&instance.instance_id).await);
    assert!(list(&db, None, true, None, 100).await?.is_empty());

    Ok(())
}

#[tokio::test]
async fn migration_backfills_legacy_unknown_without_claiming_an_original_cause()
-> anyhow::Result<()> {
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    sqlx::raw_sql("CREATE TABLE instance_metadata(instance_id TEXT, created_at TEXT, status TEXT, protected_secret_recovery_required INTEGER);
        CREATE TABLE engine_runtimes(runtime_id TEXT, created_at TEXT, status TEXT, deployment_mode TEXT, owner_panel TEXT, owner_server TEXT);
        INSERT INTO instance_metadata VALUES ('old_instance','old-generation','quarantined',0);
        INSERT INTO engine_runtimes VALUES ('old_pool','old-generation','quarantined','shared',NULL,NULL);")
        .execute(&db).await?;
    sqlx::raw_sql(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/20260919120000_quarantine_history.sql"
    )))
    .execute(&db)
    .await?;
    let events = list(&db, None, false, None, 100).await?;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event.code == "legacy_unknown" && event.recovery_class == "manual_review")
    );
    sqlx::query("UPDATE instance_metadata SET status='stopped' WHERE instance_id='old_instance'")
        .execute(&db)
        .await?;
    assert_eq!(list(&db, None, false, None, 100).await?.len(), 1);
    assert_eq!(list(&db, None, true, None, 100).await?.len(), 2);

    Ok(())
}

#[tokio::test]
async fn reused_entity_id_does_not_inherit_active_causes_from_its_old_generation()
-> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db = sqlite::connect(dir.path()).await?;
    let repository = InstanceRepository::new(db.clone());
    let mut instance = metadata("reused_id", Protocol::Postgres);
    instance.status = InstanceStatus::Quarantined;
    repository
        .upsert_quarantined(&instance, QuarantineKind::CredentialIntegrity)
        .await?;
    instance.created_at = "2026-09-19T12:00:00Z".into();
    repository
        .upsert_quarantined(&instance, QuarantineKind::IsolationMismatch)
        .await?;
    let active = list(&db, None, false, None, 100).await?;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].code, "isolation_mismatch");
    let history = list(&db, None, true, None, 100).await?;
    assert_eq!(history.len(), 2);
    assert!(
        history
            .iter()
            .any(|event| event.final_status.as_deref() == Some("replaced"))
    );

    Ok(())
}
