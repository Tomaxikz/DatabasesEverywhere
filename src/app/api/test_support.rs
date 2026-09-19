use std::{path::PathBuf, sync::Arc};

use sqlx::SqlitePool;

use crate::{
    api::http::router::{AppState, AppStateData, DaemonShutdown},
    auth::api_token::ApiToken,
    config::Config,
    instances::{manager::InstanceManager, state::InstanceStore},
    jobs::import_export::ImportExportJobs,
    runtime::docker::DockerRuntime,
};

/// Builds the common in-memory/offline API state used by handler tests.
pub(crate) fn state(
    config: Config,
    config_path: PathBuf,
    api_token: ApiToken,
    instances: InstanceStore,
    manager: InstanceManager,
    pool: SqlitePool,
) -> AppState {
    let config = Arc::new(crate::config::RuntimeConfig::new(config).unwrap());
    AppState::new(AppStateData {
        config: Arc::clone(&config),
        config_path,
        config_patches: crate::api::system::config::ConfigPatchCoordinator::default(),
        api_token,
        instances,
        manager,
        placements: crate::placement::PlacementRepository::new(pool.clone()),
        instance_locks: crate::instances::locks::InstanceLocks::default(),
        docker: DockerRuntime::offline_for_tests(&Default::default(), false)
            .with_startup_history(pool.clone()),
        import_export_jobs: ImportExportJobs::default(),
        import_uploads: crate::api::import_export::ImportUploadService::with_limits(
            crate::storage::import_uploads::ImportUploadRepository::new(pool),
            config.artifacts.import_upload_max_concurrent,
            2,
            config.daemon.limits.upload_inspections,
        ),
        api_rate_limiter: crate::api::http::limits::ApiRateLimiter::with_limits(
            config.security.api_rate_limit_per_minute,
            &config.daemon.limits,
        ),
        install_progress:
            crate::api::instances::progress::InstallProgressStore::with_creation_limit(
                config.daemon.limits.instance_creations,
            ),
        artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
        resource_cache: crate::api::monitoring::resources::ResourceCache::default(),
        soft_disk_limiter: crate::disk::soft::SoftDiskLimiter::new(
            config.disk.soft_scanner.clone(),
        ),
        monitoring_cache: crate::api::monitoring::websocket::MonitoringSnapshotCache::default(),
        instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
        daemon_shutdown: DaemonShutdown::default(),
    })
}

pub(crate) async fn database(config: Config) -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let pool = crate::storage::sqlite::connect(dir.path()).await.unwrap();
    let store = InstanceStore::default();
    let manager = InstanceManager::new(
        store.clone(),
        crate::storage::repositories::InstanceRepository::new(pool.clone()),
    );
    let state = state(
        config,
        dir.path().join("config.yml"),
        ApiToken::new("secret"),
        store,
        manager,
        pool,
    );
    (state, dir)
}
