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
    AppState::new(AppStateData {
        config: Arc::new(config),
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
        import_uploads: crate::api::import_export::ImportUploadService::new(
            crate::storage::import_uploads::ImportUploadRepository::new(pool),
            2,
        ),
        api_rate_limiter: crate::api::http::limits::ApiRateLimiter::default(),
        install_progress: crate::api::instances::progress::InstallProgressStore::default(),
        artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
        resource_cache: crate::api::monitoring::resources::ResourceCache::default(),
        soft_disk_limiter: crate::disk::soft::SoftDiskLimiter::new(Default::default()),
        monitoring_cache: crate::api::monitoring::websocket::MonitoringSnapshotCache::default(),
        instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
        gateway_supervisor: crate::gateway::supervisor::GatewaySupervisor::default(),
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
