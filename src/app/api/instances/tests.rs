use super::*;

#[tokio::test]
async fn cancelled_resize_waiter_does_not_leave_queued_work() {
    use crate::{
        auth::api_token::ApiToken,
        instances::{manager::InstanceManager, state::InstanceStore},
        storage::repositories::InstanceRepository,
    };
    use axum::extract::FromRequestParts;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_lazy("sqlite::memory:")
        .unwrap();
    let store = InstanceStore::default();
    let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool.clone()));
    let state = crate::api::test_support::state(
        Default::default(),
        Default::default(),
        ApiToken::new("test-token"),
        store,
        manager,
        pool,
    );
    let (mut parts, _) = http::Request::builder()
        .header("authorization", "Bearer test-token")
        .body(())
        .unwrap()
        .into_parts();
    let auth = ApiRequestContext::from_request_parts(&mut parts, &state)
        .await
        .unwrap();
    let creation = state.instance_locks.lock_creation().await;
    let worker_state = state.clone();
    let waiter = tokio::spawn(update_instance_limits(
        State(worker_state),
        auth,
        ApiPath("missing-tenant".to_string()),
        ApiJson(LimitsRequest {
            cpu_cores: 1.0,
            memory_mib: 256,
            disk_mib: 1024,
        }),
    ));
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while state.daemon_shutdown.active_mutation_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    waiter.abort();
    let _ = waiter.await;
    assert_eq!(state.daemon_shutdown.active_mutation_count(), 0);
    drop(creation);
    assert!(
        state
            .daemon_shutdown
            .wait_for_mutation_drain(std::time::Duration::from_secs(1))
            .await
    );
    assert_eq!(state.daemon_shutdown.active_mutation_count(), 0);
}

async fn assert_owned_task_survives_waiter<F>(label: &str, spawn: F)
where
    F: FnOnce(
        std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    ) -> tokio::task::JoinHandle<()>,
{
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let owned = spawn(Box::pin(async move {
        let _ = started_tx.send(());
        let _ = release_rx.await;
        let _ = finished_tx.send(());
    }));
    let waiter = tokio::spawn(async move {
        let _ = owned.await;
    });
    started_rx.await.unwrap();
    waiter.abort();
    let _ = waiter.await;
    release_tx.send(()).unwrap();

    let finished = tokio::time::timeout(std::time::Duration::from_secs(1), finished_rx).await;
    assert!(
        matches!(finished, Ok(Ok(()))),
        "owned {label} operation should outlive its request waiter"
    );
}

#[tokio::test]
async fn owned_background_tasks_outlive_their_request_waiters() {
    assert_owned_task_survives_waiter("major upgrade", spawn_upgrade_task).await;
    assert_owned_task_survives_waiter("lifecycle", spawn_owned_mutation_task).await;
}

#[tokio::test]
async fn runtime_cache_invalidation_rejects_a_late_stale_publication() {
    let cache = InstanceRuntimeInfoCache::default();
    let stale_epoch = cache.epoch().await;
    cache.remove("inst_cache_race").await;
    let image = crate::instances::metadata::InstanceImageStatus {
        current: Some("postgres:16".to_string()),
        configured: "postgres:17".to_string(),
        update_available: true,
    };

    assert!(
        !cache
            .store_if_epoch("inst_cache_race".to_string(), image.clone(), stale_epoch)
            .await
    );
    assert!(
        cache
            .fresh("inst_cache_race", "postgres:17")
            .await
            .is_none()
    );

    let current_epoch = cache.epoch().await;
    assert!(
        cache
            .store_if_epoch("inst_cache_race".to_string(), image, current_epoch)
            .await
    );
    assert!(
        cache
            .fresh("inst_cache_race", "postgres:17")
            .await
            .is_some()
    );
}

#[test]
fn live_runtime_cannot_publish_a_durable_pre_ready_or_failed_state() {
    let running_inspection = Ok(DockerInstanceInspection {
        status: DockerContainerStatus::Running,
        network_mode: Some("none".to_string()),
        health: Some("healthy".to_string()),
        image: Some("sha256:image".to_string()),
    });
    for status in [
        InstanceStatus::Creating,
        InstanceStatus::Booting,
        InstanceStatus::Stopped,
        InstanceStatus::Failed,
        InstanceStatus::Quarantined,
        InstanceStatus::Deleting,
    ] {
        let mut metadata = sample_lifecycle_metadata();
        metadata.status = status;
        assert_eq!(
            runtime_info::classify_live_status(&metadata, Some(&running_inspection)),
            status
        );
    }

    let mut stopping = sample_lifecycle_metadata();
    stopping.desired_state = DesiredInstanceState::Stopped;
    assert_eq!(
        runtime_info::classify_live_status(&stopping, Some(&running_inspection)),
        InstanceStatus::Stopped
    );
}

fn sample_lifecycle_metadata() -> InstanceMetadata {
    let mut metadata =
        crate::instances::test_support::metadata("inst_lifecycle", Protocol::Postgres);
    metadata.backend = crate::shared::backend::BackendEndpoint::UnixSocket {
        socket_path: "/run/dbev/inst_lifecycle/.s.PGSQL.5432".to_string(),
    };
    metadata.database.name = "app".to_string();
    metadata.database.username = "tenant".to_string();
    metadata.tenant_password = Some("old-password".to_string());
    metadata
}

#[test]
fn shared_pool_logs_are_never_available_through_any_api_transport() {
    let mut metadata = sample_lifecycle_metadata();
    assert!(check_logs_available(&metadata).is_ok());

    metadata.deployment_mode = crate::placement::DeploymentMode::Shared;
    metadata.runtime_id = "pool_postgres_test".to_string();
    let error = check_logs_available(&metadata).unwrap_err().to_string();

    assert!(error.contains("pool-wide"));
    assert!(error.contains("other databases"));
}

#[test]
fn major_upgrade_commit_resolution_accepts_only_the_exact_intended_row() {
    let previous = sample_lifecycle_metadata();
    let mut intended = previous.clone();
    intended.updated_at = "2026-01-02T00:00:00Z".to_string();
    intended.tenant_password = Some("replacement-password".to_string());

    assert_eq!(
        classify_upgrade_commit(&intended, &previous, &intended),
        MajorUpgradeCommitResolution::Committed
    );

    let mut mismatched_secret = intended.clone();
    mismatched_secret.tenant_password = Some("unexpected-password".to_string());
    assert!(matches!(
        classify_upgrade_commit(&mismatched_secret, &previous, &intended),
        MajorUpgradeCommitResolution::Uncertain(_)
    ));
}

#[test]
fn major_upgrade_commit_resolution_rolls_back_only_the_exact_previous_row() {
    let previous = sample_lifecycle_metadata();
    let mut intended = previous.clone();
    intended.updated_at = "2026-01-02T00:00:00Z".to_string();

    assert_eq!(
        classify_upgrade_commit(&previous, &previous, &intended),
        MajorUpgradeCommitResolution::NotCommitted
    );

    let mut divergent = previous.clone();
    divergent.status = InstanceStatus::Failed;
    assert!(matches!(
        classify_upgrade_commit(&divergent, &previous, &intended),
        MajorUpgradeCommitResolution::Uncertain(_)
    ));
}

#[test]
fn failed_image_update_quarantine_is_fail_closed() {
    let metadata = sample_lifecycle_metadata();
    let quarantined = quarantine_image_metadata(&metadata);

    assert_eq!(quarantined.status, InstanceStatus::Quarantined);
    assert_eq!(quarantined.desired_state, DesiredInstanceState::Stopped);
    assert_eq!(quarantined.instance_id, metadata.instance_id);
    assert_eq!(quarantined.tenant_password, metadata.tenant_password);
}

#[tokio::test]
async fn retained_instance_volume_paths_are_scoped_to_the_exact_instance() {
    let root = tempfile::tempdir().unwrap();
    let data_path = root.path().join("inst_customer_db");
    let old_upgrade = root
        .path()
        .join(".dbe-major-upgrade-old-inst_customer_db-550e8400-e29b-41d4-a716-446655440000");
    let failed_restore = root
        .path()
        .join(".dbe-restore-inst_customer_db-550e8400-e29b-41d4-a716-446655440001");
    let unrelated = root
        .path()
        .join(".dbe-major-upgrade-old-inst_customer_db-other-550e8400-e29b-41d4-a716-446655440002");
    tokio::fs::create_dir(&old_upgrade).await.unwrap();
    tokio::fs::create_dir(&failed_restore).await.unwrap();
    tokio::fs::create_dir(&unrelated).await.unwrap();

    let mut paths = retained_instance_volume_paths(&data_path).await.unwrap();
    paths.sort();
    let mut expected = vec![old_upgrade, failed_restore];
    expected.sort();

    assert_eq!(paths, expected);
}

#[tokio::test]
async fn major_upgrade_rollback_location_never_guesses_which_volume_is_authoritative() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let backup = root.path().join("backup");

    tokio::fs::create_dir(&data).await.unwrap();
    assert_eq!(
        classify_upgrade_rollback(&data, &backup).await.unwrap(),
        MajorUpgradeRollbackLocation::OriginalDataInPlace
    );

    tokio::fs::rename(&data, &backup).await.unwrap();
    assert_eq!(
        classify_upgrade_rollback(&data, &backup).await.unwrap(),
        MajorUpgradeRollbackLocation::OldVolumeBackup
    );

    tokio::fs::create_dir(&data).await.unwrap();
    assert!(classify_upgrade_rollback(&data, &backup).await.is_err());

    tokio::fs::remove_dir(&data).await.unwrap();
    tokio::fs::remove_dir(&backup).await.unwrap();
    assert!(classify_upgrade_rollback(&data, &backup).await.is_err());
}

#[test]
fn deletion_preserves_quarantine_to_avoid_claiming_a_duplicate_route() {
    assert_eq!(
        deletion_status(InstanceStatus::Quarantined),
        InstanceStatus::Quarantined
    );
    assert_eq!(
        deletion_status(InstanceStatus::Running),
        InstanceStatus::Deleting
    );
    assert_eq!(
        deletion_status(InstanceStatus::Deleting),
        InstanceStatus::Deleting
    );
}

#[test]
fn parses_major_version_from_common_image_tags() {
    assert_eq!(image_major_version("mongo:7.0.37"), Some(7));
    assert_eq!(
        image_major_version("docker.io/library/postgres:18.4"),
        Some(18)
    );
    assert_eq!(
        image_major_version("registry.example.com:5000/db/mariadb:12.3.2"),
        Some(12)
    );
    assert_eq!(image_major_version("mysql:8.4"), Some(8));
}

#[test]
fn rejects_unpinned_images_for_existing_instance_updates() {
    assert!(image_major_version("mongo:latest").is_none());
    assert!(image_major_version("mongo@sha256:abc").is_none());
    assert!(image_major_version("mongo").is_none());
}

#[test]
fn parses_major_version_values() {
    assert_eq!(parse_major_version("8.3"), Some(8));
    assert_eq!(parse_major_version("v7.0"), None);
    assert_eq!(parse_major_version("latest"), None);
}

#[test]
fn classifies_major_version_changes() {
    let change = classify_image_update(Protocol::Mongodb, "mongo:7.0.37", "mongo:8.3.4").unwrap();
    assert_eq!(change, ImageVersionChange::Major);

    let change =
        classify_image_update(Protocol::Postgres, "postgres:18.3", "postgres:18.4").unwrap();
    assert_eq!(change, ImageVersionChange::SameMajorOrUnknown);
}

#[test]
fn requires_parseable_tags_for_different_existing_images() {
    let error =
        classify_image_update(Protocol::Mongodb, "mongo:7.0.37", "mongo:latest").unwrap_err();
    assert!(error.to_string().contains("cannot compare requested image"));
}

#[test]
fn major_upgrade_path_blocks_downgrades() {
    let error = validate_upgrade_path(Protocol::Postgres, 18, 17).unwrap_err();
    assert!(error.to_string().contains("downgrade is blocked"));
}

#[test]
fn mongodb_major_upgrade_path_blocks_skipped_versions() {
    let error = validate_upgrade_path(Protocol::Mongodb, 6, 8).unwrap_err();
    assert!(error.to_string().contains("cannot skip versions"));

    assert!(validate_upgrade_path(Protocol::Mongodb, 7, 8).is_ok());
}

#[test]
fn non_mongodb_dump_upgrade_path_allows_skipped_versions() {
    assert!(validate_upgrade_path(Protocol::Postgres, 14, 18).is_ok());
}

#[test]
fn major_migration_support_is_limited_to_logical_dump_protocols() {
    assert!(check_major_upgrade(Protocol::Postgres).is_ok());
    assert!(check_major_upgrade(Protocol::Mysql).is_ok());
    assert!(check_major_upgrade(Protocol::Mongodb).is_ok());
    assert!(check_major_upgrade(Protocol::Redis).is_err());
    assert!(check_major_upgrade(Protocol::Valkey).is_err());
    assert!(check_major_upgrade(Protocol::Qdrant).is_err());
}

#[test]
fn replacement_validation_uses_managed_database_unix_sockets() {
    let postgres = replacement_check_command(Protocol::Postgres, "app_user", "app_db").unwrap();
    assert!(postgres.contains("-h /var/run/postgresql"));
    assert!(!postgres.contains("-h 127.0.0.1"));

    let mariadb = replacement_check_command(Protocol::Mariadb, "app_user", "app_db").unwrap();
    assert!(mariadb.contains("--protocol=socket"));
    assert!(mariadb.contains("--socket=/run/mysqld/mysqld.sock"));
    assert!(!mariadb.contains("-h 127.0.0.1"));

    let mysql = replacement_check_command(Protocol::Mysql, "app_user", "app_db").unwrap();
    assert!(mysql.contains("--protocol=socket"));
    assert!(mysql.contains("--socket=/var/run/mysqld/mysqld.sock"));
}

#[test]
fn normalizes_database_version_outputs() {
    assert_eq!(
        normalize_database_version(Protocol::Postgres, "postgres (PostgreSQL) 18.4\n"),
        Some("18.4".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Mariadb,
            "mariadb  Ver 15.1 Distrib 12.3.2-MariaDB, for Linux (x86_64)\n"
        ),
        Some("12.3.2-MariaDB".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Mysql,
            "mysqld  Ver 8.4.6 for Linux on x86_64 (MySQL Community Server - GPL)\n"
        ),
        Some("8.4.6".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Redis,
            "Redis server v=8.8.0 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64\n"
        ),
        Some("8.8.0".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Valkey,
            "Valkey server v=9.1.1 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64\n"
        ),
        Some("9.1.1".to_string())
    );
    assert_eq!(
        normalize_database_version(Protocol::Mongodb, "v8.3.4\n"),
        Some("8.3.4".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Clickhouse,
            "ClickHouse server version 25.8.25.37 (official build).\n"
        ),
        Some("25.8.25.37".to_string())
    );
    assert_eq!(
        normalize_database_version(Protocol::Qdrant, "qdrant 1.18.2\n"),
        Some("1.18.2".to_string())
    );
}
