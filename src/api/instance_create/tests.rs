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
async fn create_request_allows_configured_image_override() {
    let state = test_state(Config {
        images: ImageConfig {
            postgres: "postgres:18.4".to_string(),
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let mut request = create_request(Protocol::Postgres);
    request.image = Some("postgres:18.4".to_string());

    let image = requested_or_configured_image(&state, &request).unwrap();

    assert_eq!(image, "postgres:18.4");
}

#[tokio::test]
async fn create_request_allows_protocol_allowlisted_image_override() {
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
    let mut request = create_request(Protocol::Postgres);
    request.image = Some("postgres:18.5".to_string());

    let image = requested_or_configured_image(&state, &request).unwrap();

    assert_eq!(image, "postgres:18.5");
}

#[tokio::test]
async fn create_request_rejects_unlisted_image_override_before_pull() {
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
    let mut request = create_request(Protocol::Postgres);
    request.image = Some("postgres:18.6".to_string());

    let error = requested_or_configured_image(&state, &request).unwrap_err();

    assert!(error.to_string().contains("is not allowed"));
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
async fn create_request_rejects_existing_redis_route_for_username() {
    let state = test_state(Config::default()).await;
    state
        .instances
        .upsert(sample_metadata(
            "inst_existing_redis",
            Protocol::Redis,
            "first_cache",
            "shared_user",
        ))
        .await;
    let mut request = create_request(Protocol::Redis);
    request.instance_id = "inst_new_redis".to_string();
    request.database = "second_cache".to_string();
    request.username = "shared_user".to_string();

    let error = reject_duplicate_instance(&state, &request)
        .await
        .unwrap_err();

    assert!(matches!(error, ApiError::Conflict(_)));
    assert!(
        error
            .to_string()
            .contains("redis route already exists for username shared_user")
    );
}

#[tokio::test]
async fn create_request_rejects_existing_valkey_route_for_username() {
    let state = test_state(Config::default()).await;
    state
        .instances
        .upsert(sample_metadata(
            "inst_existing_valkey",
            Protocol::Valkey,
            "first_cache",
            "shared_user",
        ))
        .await;
    let mut request = create_request(Protocol::Valkey);
    request.instance_id = "inst_new_valkey".to_string();
    request.database = "second_cache".to_string();
    request.username = "shared_user".to_string();

    let error = reject_duplicate_instance(&state, &request)
        .await
        .unwrap_err();

    assert!(matches!(error, ApiError::Conflict(_)));
    assert!(
        error
            .to_string()
            .contains("valkey route already exists for username shared_user")
    );
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

#[test]
fn allocation_guard_rejects_a_projected_limit_over_the_node_pool() {
    let error = enforce_resource_allocation(
        "memory",
        mib_to_bytes(7_000),
        0,
        mib_to_bytes(2_000),
        mib_to_bytes(8_000),
        mib_to_bytes(16_000),
        mib_to_bytes(512),
    )
    .unwrap_err();

    assert!(matches!(error, ApiError::ServiceUnavailable(_)));
    assert!(error.to_string().contains("projected allocation 9000 MiB"));
}

#[test]
fn allocation_guard_rejects_an_increase_that_breaches_actual_free_reserve() {
    let error = enforce_resource_allocation(
        "disk",
        mib_to_bytes(10_000),
        0,
        mib_to_bytes(1_500),
        mib_to_bytes(20_000),
        mib_to_bytes(3_000),
        mib_to_bytes(2_048),
    )
    .unwrap_err();

    assert!(matches!(error, ApiError::ServiceUnavailable(_)));
    assert!(
        error
            .to_string()
            .contains("safety reserve would be breached")
    );
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
