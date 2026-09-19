use super::*;
use crate::{config::Config, placement::ReserveTenant, shared::protocol::Protocol};

fn runtime() -> EngineRuntime {
    let mut runtime = crate::placement::test_support::runtime(
        "pool_recover",
        Protocol::Clickhouse,
        "clickhouse:25.3",
    );
    runtime.status = EngineRuntimeStatus::Quarantined;
    runtime.admin_secret = Some("test-admin".into());
    runtime.limits.disk_mib = 64 * 1024;
    runtime.backend = BackendEndpoint::UnixSocket {
        socket_path: "/run/dbev/sockets/pool_recover/clickhouse-native.sock".into(),
    };
    runtime
}

#[test]
fn recovery_accepts_an_attested_pinned_image_without_accepting_drift() {
    let mut pool = runtime();
    pool.database_version = Some("25.3.1.2".into());
    pool.compatibility = Some(crate::placement::RuntimeCompatibility {
        container_id: "container-one".into(),
        image_id: "sha256:installed".into(),
        probe_revision: crate::compatibility::COMPATIBILITY_PROBE_REVISION,
    });
    assert!(recovery_image_matches(
        &pool,
        Some("sha256:installed"),
        "container-one",
        "sha256:installed"
    ));
    assert!(!recovery_image_matches(
        &pool,
        Some("sha256:changed"),
        "container-one",
        "sha256:changed"
    ));
    assert!(!recovery_image_matches(
        &pool,
        Some("sha256:installed"),
        "different-container",
        "sha256:installed"
    ));
    assert!(!recovery_image_matches(
        &pool,
        Some("another:tag"),
        "container-one",
        "sha256:installed"
    ));
    pool.compatibility = None;
    assert!(!recovery_image_matches(
        &pool,
        Some("sha256:installed"),
        "container-one",
        "sha256:installed"
    ));
}

#[test]
fn recovery_pool_gates_preserve_unrelated_quarantines_and_stopped_intent() {
    let base = runtime();
    assert!(check_pool(&base, "test-panel").is_ok());
    assert!(check_pool(&base, "other-panel").is_err());
    let mut pool = base.clone();
    pool.owner = None;
    assert!(check_pool(&pool, "test-panel").is_err());
    pool = base.clone();
    pool.pending_image = Some("replacement".into());
    assert!(check_pool(&pool, "test-panel").is_err());
    pool = base.clone();
    pool.desired_state = DesiredInstanceState::Stopped;
    assert!(check_pool(&pool, "test-panel").is_err());
    pool = base.clone();
    pool.admin_secret = None;
    assert!(check_pool(&pool, "test-panel").is_err());
    for status in [
        EngineRuntimeStatus::Deleting,
        EngineRuntimeStatus::Creating,
        EngineRuntimeStatus::Running,
        EngineRuntimeStatus::Stopped,
    ] {
        pool = base.clone();
        pool.status = status;
        assert!(check_pool(&pool, "test-panel").is_err());
    }
}

fn tenant(pool: &EngineRuntime) -> InstanceMetadata {
    let mut metadata = crate::instances::test_support::metadata("tenant_recover", pool.protocol);
    metadata.owner = pool.owner.clone();
    metadata.deployment_mode = DeploymentMode::Shared;
    metadata.runtime_id = pool.runtime_id.clone();
    metadata.backend = pool.backend.clone();
    metadata.runtime = pool.runtime.clone();
    metadata.status = InstanceStatus::Quarantined;
    metadata.desired_state = DesiredInstanceState::Stopped;
    metadata.tenant_password = Some("test-tenant-password".into());
    metadata
}

#[test]
fn tenant_recovery_requires_exact_reserved_identity_and_stopped_intent() {
    let pool = runtime();
    let base = tenant(&pool);
    let reservation = TenantReservation {
        instance_id: base.instance_id.clone(),
        runtime_id: pool.runtime_id.clone(),
        database: base.database.name.clone(),
        username: base.database.username.clone(),
        state: TenantReservationState::Provisioned,
        limits: base.limits.clone(),
    };
    assert!(check_tenant(&pool, &base, &reservation).is_ok());
    let mut value = base.clone();
    value.owner = None;
    assert!(check_tenant(&pool, &value, &reservation).is_err());
    value = base.clone();
    value.desired_state = DesiredInstanceState::Running;
    assert!(check_tenant(&pool, &value, &reservation).is_err());
    value = base.clone();
    value.tenant_password = None;
    assert!(check_tenant(&pool, &value, &reservation).is_err());
    value = base.clone();
    value.database.name = "other".into();
    assert!(check_tenant(&pool, &value, &reservation).is_err());
    let mut changed = reservation;
    changed.state = TenantReservationState::Reserved;
    assert!(check_tenant(&pool, &base, &changed).is_err());
}

async fn fixture() -> (AppState, tempfile::TempDir, sqlx::SqlitePool, EngineRuntime) {
    let (state, dir) = crate::api::test_support::database(Config::default()).await;
    let db = crate::storage::sqlite::connect(dir.path()).await.unwrap();
    let mut pool = runtime();
    let metadata = tenant(&pool);
    pool.status = EngineRuntimeStatus::Running;
    state.placements.save(&pool).await.unwrap();
    state
        .placements
        .reserve(ReserveTenant {
            owner: pool.owner.clone().unwrap(),
            instance_id: &metadata.instance_id,
            runtime_id: &pool.runtime_id,
            database: &metadata.database.name,
            username: &metadata.database.username,
            limits: &metadata.limits,
        })
        .await
        .unwrap();
    state
        .placements
        .mark_provisioned(&metadata.instance_id)
        .await
        .unwrap();
    state.manager.upsert_fenced(metadata).await.unwrap();
    pool = state
        .placements
        .get(&pool.runtime_id)
        .await
        .unwrap()
        .unwrap();
    pool.status = EngineRuntimeStatus::Quarantined;
    state.placements.save(&pool).await.unwrap();
    (state, dir, db, pool)
}

#[tokio::test]
async fn deliberately_stopped_pool_is_not_a_recovery_candidate() {
    let (state, _dir, _db, mut pool) = fixture().await;
    pool.status = EngineRuntimeStatus::Stopped;
    pool.desired_state = DesiredInstanceState::Stopped;
    state.placements.save(&pool).await.unwrap();
    let summary = recover_dead_pools(&state).await.unwrap();
    assert_eq!(summary.candidates, 0);
    assert_eq!(summary.attempted, 0);
    assert_eq!(
        state
            .placements
            .get(&pool.runtime_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        EngineRuntimeStatus::Stopped
    );
    assert_eq!(
        state
            .manager
            .get_persisted("tenant_recover")
            .await
            .unwrap()
            .unwrap()
            .status,
        InstanceStatus::Quarantined
    );
}

#[tokio::test]
async fn successful_publication_keeps_tenants_stopped_and_preserves_credentials() {
    let (state, _dir, _db, mut pool) = fixture().await;
    pool.status = EngineRuntimeStatus::Running;
    publish_recovery(&state, pool.clone(), &["tenant_recover".into()])
        .await
        .unwrap();
    assert_eq!(
        state
            .placements
            .get(&pool.runtime_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        EngineRuntimeStatus::Running
    );
    let metadata = state
        .manager
        .get_persisted("tenant_recover")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(metadata.status, InstanceStatus::Stopped);
    assert_eq!(metadata.desired_state, DesiredInstanceState::Stopped);
    assert_eq!(
        metadata.tenant_password.as_deref(),
        Some("test-tenant-password")
    );
    assert_eq!(
        state.instances.get("tenant_recover").await.unwrap().status,
        InstanceStatus::Stopped
    );
}

#[tokio::test]
async fn failed_tenant_publication_does_not_release_pool_quarantine() {
    let (state, _dir, db, mut pool) = fixture().await;
    sqlx::query(
        "CREATE TRIGGER reject_recovery BEFORE UPDATE ON instance_metadata
        WHEN NEW.status = 'stopped' BEGIN SELECT RAISE(ABORT, 'test write failure'); END",
    )
    .execute(&db)
    .await
    .unwrap();
    pool.status = EngineRuntimeStatus::Running;
    assert!(
        publish_recovery(&state, pool.clone(), &["tenant_recover".into()])
            .await
            .is_err()
    );
    assert_eq!(
        state
            .placements
            .get(&pool.runtime_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        EngineRuntimeStatus::Quarantined
    );
    assert_eq!(
        state
            .manager
            .get_persisted("tenant_recover")
            .await
            .unwrap()
            .unwrap()
            .status,
        InstanceStatus::Quarantined
    );
}

#[tokio::test]
async fn retained_restore_manifests_and_workspaces_block_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.paths.data = dir.path().to_string_lossy().into_owned();
    let tmp = std::path::PathBuf::from(config.paths.tmp_root());
    let volumes = std::path::PathBuf::from(config.paths.volumes_root());
    tokio::fs::create_dir_all(tmp.join("import-export"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(&volumes).await.unwrap();
    let uuid = uuid::Uuid::new_v4();
    let path = tmp
        .join("import-export")
        .join(format!(".dbe-import-recovery-{uuid}.json"));
    crate::shared::files::atomic_write_private(&path, br#"{"instance_id":"tenant_recover"}"#)
        .unwrap();
    tokio::fs::create_dir(volumes.join(format!(".dbe-restore-pool_recover-{uuid}")))
        .await
        .unwrap();
    let blocked = retained_recovery_targets(&config).await.unwrap();
    assert!(blocked.contains("tenant_recover"));
    assert!(blocked.contains("pool_recover"));
}

#[tokio::test]
async fn separate_secret_and_import_incidents_remain_blocked() {
    let (state, _dir, db, _pool) = fixture().await;
    let id = "tenant_recover";
    assert!(!state.placements.tenant_recovery_blocked(id).await.unwrap());
    assert!(
        state
            .placements
            .tenant_recovery_blocked("missing")
            .await
            .unwrap()
    );
    sqlx::query("UPDATE instance_metadata SET protected_secret_recovery_required = 1 WHERE instance_id = ?1")
        .bind(id).execute(&db).await.unwrap();
    assert!(state.placements.tenant_recovery_blocked(id).await.unwrap());
    sqlx::query("UPDATE instance_metadata SET protected_secret_recovery_required = 0 WHERE instance_id = ?1")
        .bind(id).execute(&db).await.unwrap();
    sqlx::query("INSERT INTO import_export_jobs(job_id, instance_id, action, status, created_at, updated_at)
        VALUES ('failed', ?1, 'import', 'failed', 'now', 'now')").bind(id).execute(&db).await.unwrap();
    assert!(state.placements.tenant_recovery_blocked(id).await.unwrap());
}

#[tokio::test]
async fn automatic_scan_finds_all_dead_pools_without_bypassing_ownership() {
    let (state, dir, _db, pool) = fixture().await;
    let mut other = runtime();
    other.runtime_id = "pool_failed".into();
    other.owner = Some(crate::placement::test_support::owner("other-server"));
    other.status = EngineRuntimeStatus::Failed;
    other.desired_state = DesiredInstanceState::Running;
    state.placements.save(&other).await.unwrap();
    let mut data = (*state).clone();
    let mut config = (**state.config).clone();
    config.paths.data = dir.path().to_string_lossy().into_owned();
    config.token_id = "wrong-panel".into();
    config.daemon.recover_shared_pools = vec![pool.runtime_id.clone()];
    tokio::fs::create_dir_all(config.paths.volumes_root())
        .await
        .unwrap();
    data.config = std::sync::Arc::new(crate::config::RuntimeConfig::new(config).unwrap());
    let state = AppState::new(data);
    let summary = recover_dead_pools(&state).await.unwrap();
    // Even a legacy selector naming just one pool no longer limits discovery.
    assert_eq!(summary.candidates, 2);
    assert_eq!(summary.refused, 2);
    assert_eq!(summary.attempted, 0);
    for expected in [&pool, &other] {
        assert_eq!(
            state
                .placements
                .get(&expected.runtime_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            expected.status
        );
    }
    assert_eq!(
        state
            .placements
            .get(&other.runtime_id)
            .await
            .unwrap()
            .unwrap()
            .desired_state,
        DesiredInstanceState::Stopped
    );
    assert_eq!(
        state
            .manager
            .get_persisted("tenant_recover")
            .await
            .unwrap()
            .unwrap()
            .status,
        InstanceStatus::Quarantined
    );
}

#[test]
fn recovery_discovers_only_failed_and_quarantined_shared_pools() {
    let mut pool = runtime();
    for status in [
        EngineRuntimeStatus::Failed,
        EngineRuntimeStatus::Quarantined,
    ] {
        pool.status = status;
        assert!(is_candidate(&pool));
    }
    for status in [
        EngineRuntimeStatus::Running,
        EngineRuntimeStatus::Stopped,
        EngineRuntimeStatus::Creating,
        EngineRuntimeStatus::Booting,
        EngineRuntimeStatus::Deleting,
    ] {
        pool.status = status;
        assert!(!is_candidate(&pool));
    }
    pool.status = EngineRuntimeStatus::Failed;
    pool.deployment_mode = DeploymentMode::Dedicated;
    assert!(!is_candidate(&pool));
}

#[test]
fn failed_pool_retry_preserves_known_tenant_intent() {
    let mut pool = runtime();
    pool.status = EngineRuntimeStatus::Failed;
    pool.desired_state = DesiredInstanceState::Stopped;
    assert!(check_pool(&pool, "test-panel").is_ok());
    let mut child = tenant(&pool);
    let reservation = TenantReservation {
        instance_id: child.instance_id.clone(),
        runtime_id: pool.runtime_id.clone(),
        database: child.database.name.clone(),
        username: child.database.username.clone(),
        state: TenantReservationState::Provisioned,
        limits: child.limits.clone(),
    };
    child.status = InstanceStatus::Failed;
    child.desired_state = DesiredInstanceState::Running;
    assert!(check_tenant(&pool, &child, &reservation).is_ok());
    child.status = InstanceStatus::Stopped;
    child.desired_state = DesiredInstanceState::Stopped;
    assert!(check_tenant(&pool, &child, &reservation).is_ok());
    child.status = InstanceStatus::Quarantined;
    child.desired_state = DesiredInstanceState::Running;
    assert!(check_tenant(&pool, &child, &reservation).is_err());
    child.status = InstanceStatus::Deleting;
    assert!(check_tenant(&pool, &child, &reservation).is_err());
}

#[tokio::test]
async fn failed_pool_publication_keeps_tenants_fenced_and_durable_pool_quarantined() {
    let (state, _dir, db, mut pool) = fixture().await;
    sqlx::query(
        "CREATE TRIGGER reject_pool_recovery BEFORE UPDATE ON engine_runtimes
        WHEN NEW.status = 'running' BEGIN SELECT RAISE(ABORT, 'test pool write failure'); END",
    )
    .execute(&db)
    .await
    .unwrap();
    pool.status = EngineRuntimeStatus::Running;
    assert!(
        publish_recovery(&state, pool.clone(), &["tenant_recover".into()])
            .await
            .is_err()
    );
    assert_eq!(
        state
            .placements
            .get(&pool.runtime_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        EngineRuntimeStatus::Quarantined
    );
    let metadata = state
        .manager
        .get_persisted("tenant_recover")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(metadata.status, InstanceStatus::Stopped);
    assert_eq!(metadata.desired_state, DesiredInstanceState::Stopped);
    assert!(state.instances.routes_fenced("tenant_recover").await);
}
