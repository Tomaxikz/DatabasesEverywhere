use std::sync::Arc;

use super::*;
use crate::{
    auth::api_token::ApiToken,
    config::{Config, ImageAllowlistConfig, ImageConfig},
    instances::{manager::InstanceManager, state::InstanceStore},
    jobs::import_export::ImportExportJobs,
    runtime::docker::DockerRuntime,
    storage::{repositories::InstanceRepository, sqlite},
};

#[tokio::test]
async fn create_request_enforces_configured_and_allowlisted_images() {
    let state = test_state(Config {
        images: ImageConfig {
            postgres: "postgres:18.4".to_string(),
            allowed: ImageAllowlistConfig {
                postgres: vec!["postgres:18.5".to_string()],
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    for image in ["postgres:18.4", "postgres:18.5"] {
        let mut request = create_request(Protocol::Postgres);
        request.image = Some(image.to_string());
        assert_eq!(
            requested_or_configured_image(&state, &request).unwrap(),
            image
        );
    }
    let mut request = create_request(Protocol::Postgres);
    request.image = Some("postgres:18.6".to_string());
    assert!(
        requested_or_configured_image(&state, &request)
            .unwrap_err()
            .to_string()
            .contains("is not allowed")
    );
}

#[test]
fn qdrant_creation_resolves_fuse_fallback_to_soft_scanner() {
    let limiter = crate::disk::DiskLimiter::new(crate::config::DiskConfig::default())
        .for_protocol(Protocol::Qdrant);

    assert_eq!(limiter.mode(), crate::config::DiskLimitMode::SoftScanner);
}

#[tokio::test]
async fn create_request_allows_same_database_name_for_a_distinct_route_user() {
    let state = test_state(Config::default()).await;
    state
        .instances
        .upsert(sample_metadata(
            "inst_existing_pg",
            Protocol::Postgres,
            "shared_db",
            "first_user",
        ))
        .await;
    let mut request = create_request(Protocol::Postgres);
    request.instance_id = "inst_new_pg".to_string();
    request.database = "shared_db".to_string();
    request.username = "second_user".to_string();

    reject_duplicate_instance(&state, &request).await.unwrap();
}

#[tokio::test]
async fn create_request_rejects_existing_cache_route_for_username() {
    for protocol in [Protocol::Redis, Protocol::Valkey] {
        let state = test_state(Config::default()).await;
        state
            .instances
            .upsert(sample_metadata(
                "inst_existing_cache",
                protocol,
                "first_cache",
                "shared_user",
            ))
            .await;
        let mut request = create_request(protocol);
        request.instance_id = "inst_new_cache".to_string();
        request.database = "second_cache".to_string();
        request.username = "shared_user".to_string();

        let error = reject_duplicate_instance(&state, &request)
            .await
            .unwrap_err();
        assert!(matches!(error, ApiError::Conflict(_)));
        assert!(
            error.to_string().contains(&format!(
                "{protocol} route already exists for username shared_user"
            )),
            "wrong conflict for {protocol}: {error}"
        );
    }
}

#[tokio::test]
async fn redis_and_valkey_use_separate_route_namespaces() {
    let state = test_state(Config::default()).await;
    state
        .instances
        .upsert(sample_metadata(
            "inst_existing_redis",
            Protocol::Redis,
            "cache",
            "shared_user",
        ))
        .await;
    let mut request = create_request(Protocol::Valkey);
    request.instance_id = "inst_new_valkey".to_string();
    request.database = "cache".to_string();
    request.username = "shared_user".to_string();

    reject_duplicate_instance(&state, &request).await.unwrap();
}

#[tokio::test]
async fn failed_legacy_mysql_is_removed_without_affecting_healthy_mysql_routes() {
    let store = InstanceStore::default();
    let legacy = sample_metadata(
        "inst_legacy_mysql",
        Protocol::Mysql,
        "legacy_db",
        "legacy_user",
    );
    let healthy = sample_metadata(
        "inst_healthy_mysql",
        Protocol::Mysql,
        "healthy_db",
        "healthy_user",
    );
    store.upsert(legacy.clone()).await;
    store.upsert(healthy).await;

    let failed = mysql_auth_failed_metadata(&legacy);
    store.upsert(failed.clone()).await;

    assert_eq!(failed.status, InstanceStatus::Failed);
    assert_eq!(
        failed.desired_state,
        crate::instances::metadata::DesiredInstanceState::Running
    );
    assert!(matches!(
        store.resolve_mysql("legacy_user", Some("legacy_db")).await,
        crate::instances::state::DatabaseRouteResolution::NotFound
    ));
    assert!(matches!(
        store
            .resolve_mysql("healthy_user", Some("healthy_db"))
            .await,
        crate::instances::state::DatabaseRouteResolution::Found { .. }
    ));
}

#[test]
fn allocation_guard_rejects_pool_and_free_reserve_overcommit() {
    for (resource, allocated, requested, pool, free, reserve, diagnostic) in [
        (
            "memory",
            7_000,
            2_000,
            8_000,
            16_000,
            512,
            "projected allocation 9000 MiB",
        ),
        (
            "disk",
            10_000,
            1_500,
            20_000,
            3_000,
            2_048,
            "safety reserve would be breached",
        ),
    ] {
        let error = enforce_resource_allocation(
            resource,
            mib_to_bytes(allocated),
            0,
            mib_to_bytes(requested),
            mib_to_bytes(pool),
            mib_to_bytes(free),
            mib_to_bytes(reserve),
        )
        .unwrap_err();

        assert!(matches!(error, ApiError::ServiceUnavailable(_)));
        assert!(error.to_string().contains(diagnostic));
    }
}

#[test]
fn allocation_guard_allows_decreases_while_node_is_over_capacity() {
    enforce_resource_allocation(
        "memory",
        mib_to_bytes(10_000),
        mib_to_bytes(2_000),
        mib_to_bytes(1_000),
        mib_to_bytes(8_000),
        0,
        mib_to_bytes(512),
    )
    .unwrap();
}

#[test]
fn cpu_allocation_guard_rejects_projected_overcommit() {
    let error = enforce_cpu_allocation(7.5, 0.0, 1.0, 8).unwrap_err();

    assert!(matches!(error, ApiError::ServiceUnavailable(_)));
    assert!(
        error
            .to_string()
            .contains("projected allocation 8.50 cores")
    );
    assert!(error.to_string().contains("detected 8-core capacity"));
}

#[test]
fn cpu_allocation_guard_allows_decreases_while_overcommitted() {
    enforce_cpu_allocation(12.0, 4.0, 2.0, 8).unwrap();
}

fn create_request(protocol: Protocol) -> CreateInstanceRequest {
    CreateInstanceRequest {
        instance_id: "inst_test_pg".to_string(),
        protocol,
        database: "test_db".to_string(),
        username: "test_user".to_string(),
        password: "test-password".to_string(),
        public_host: "127.0.0.1".to_string(),
        public_port: None,
        project_id: None,
        image: None,
        limits: None,
        purge_stale_resources: false,
        purge_stale_resources_confirmation: None,
    }
}

fn sample_metadata(
    instance_id: &str,
    protocol: Protocol,
    database: &str,
    username: &str,
) -> InstanceMetadata {
    InstanceMetadata {
        schema_version: SCHEMA_VERSION,
        instance_id: instance_id.to_string(),
        protocol,
        status: InstanceStatus::Running,
        desired_state: crate::instances::metadata::DesiredInstanceState::Running,
        disk_limit_blocked: false,
        public: PublicEndpoint {
            host: "127.0.0.1".to_string(),
            port: 5432,
        },
        backend: BackendEndpoint::UnixSocket {
            socket_path: format!("/run/dbev/sockets/{instance_id}/.s.PGSQL.5432"),
        },
        runtime: RuntimeMetadata {
            kind: RuntimeKind::Docker,
            container_name: format!("dbe-{}-{instance_id}", protocol.as_str()),
            network_mode: "none".to_string(),
        },
        database: DatabaseIdentity {
            name: database.to_string(),
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
        limits: crate::shared::limits::InstanceLimits::default(),
        image: None,
        database_version: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

async fn test_state(config: Config) -> AppState {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let store = InstanceStore::default();
    let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool.clone()));
    AppState::new(crate::api::routes::AppStateData {
        config: Arc::new(config),
        config_path: dir.path().join("config.yml"),
        config_patches: crate::api::config_admin::ConfigPatchCoordinator::default(),
        api_token: ApiToken::new("secret"),
        instances: store,
        manager,
        docker: DockerRuntime::offline_for_tests(&Default::default(), false),
        import_export_jobs: ImportExportJobs::default(),
        import_uploads: crate::api::import_export::ImportUploadService::new(
            crate::storage::import_uploads::ImportUploadRepository::new(pool),
            2,
        ),
        api_rate_limiter: crate::api::security::ApiRateLimiter::default(),
        install_progress: crate::api::progress::InstallProgressStore::default(),
        artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
        resource_cache: crate::api::resources::ResourceCache::default(),
        soft_disk_limiter: crate::disk::soft::SoftDiskLimiter::new(Default::default()),
        monitoring_cache: crate::api::websocket::MonitoringSnapshotCache::default(),
        instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
        gateway_supervisor: crate::gateway::supervisor::GatewaySupervisor::default(),
        daemon_shutdown: crate::api::routes::DaemonShutdown::default(),
        instance_locks: crate::instances::locks::InstanceLocks::default(),
    })
}
