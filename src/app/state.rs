//! App state the daemon builds once and shares with handlers and background
//! tasks, plus the shutdown fence for changes still in flight.

use std::{ops::Deref, path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::watch;
use tokio_util::task::{TaskTracker, task_tracker::TaskTrackerToken};

use crate::{
    auth::api_token::ApiToken,
    config::RuntimeConfig,
    gateway::supervisor::GatewaySupervisor,
    routes::http::{limits::ApiRateLimiter, policy::OriginPolicy},
    runtime::docker::DockerRuntime,
    server::{
        disk::soft::SoftDiskLimiter, jobs::import_export::ImportExportJobs, locks::InstanceLocks,
        manager::InstanceManager, placement::PlacementRepository, state::InstanceStore,
    },
    storage::backup_jobs::BackupJobRepository,
    subsystems::{
        artifacts::ArtifactDownloadTickets,
        import_export::ImportUploadService,
        instances::{InstanceRuntimeInfoCache, progress::InstallProgressStore},
        monitoring::{resources::ResourceCache, websocket::MonitoringSnapshotCache},
        system::config::ConfigPatchCoordinator,
    },
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateData>,
    origin_policy: Arc<OriginPolicy>,
    pub gateway_supervisor: GatewaySupervisor,
}

#[cfg_attr(test, derive(Clone))]
pub struct AppStateData {
    pub config: Arc<RuntimeConfig>,
    pub config_path: PathBuf,
    pub config_patches: ConfigPatchCoordinator,
    pub api_token: ApiToken,
    pub instances: InstanceStore,
    pub manager: InstanceManager,
    pub placements: PlacementRepository,
    pub instance_locks: InstanceLocks,
    pub docker: DockerRuntime,
    pub import_export_jobs: ImportExportJobs,
    /// Journal of online backup jobs, survives restarts.
    pub backup_jobs: BackupJobRepository,
    pub import_uploads: ImportUploadService,
    pub api_rate_limiter: ApiRateLimiter,
    pub install_progress: InstallProgressStore,
    pub artifact_downloads: ArtifactDownloadTickets,
    pub resource_cache: ResourceCache,
    pub soft_disk_limiter: SoftDiskLimiter,
    pub monitoring_cache: MonitoringSnapshotCache,
    pub instance_runtime_cache: InstanceRuntimeInfoCache,
    pub daemon_shutdown: DaemonShutdown,
}

impl AppState {
    pub fn new(data: AppStateData) -> Self {
        let origin_policy = Arc::new(OriginPolicy::from_config(&data.config));
        let gateway_supervisor = GatewaySupervisor::with_config(Arc::clone(&data.config));
        Self {
            inner: Arc::new(data),
            origin_policy,
            gateway_supervisor,
        }
    }

    pub fn origin_policy(&self) -> &OriginPolicy {
        &self.origin_policy
    }
}

impl Deref for AppState {
    type Target = AppStateData;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug, Clone)]
pub struct DaemonShutdown {
    stopping: watch::Sender<bool>,
    mutations: TaskTracker,
}

#[derive(Debug)]
pub(crate) struct MutationPermit {
    _token: TaskTrackerToken,
}

impl Default for DaemonShutdown {
    fn default() -> Self {
        Self {
            stopping: watch::Sender::new(false),
            mutations: TaskTracker::new(),
        }
    }
}

impl DaemonShutdown {
    pub fn trigger(&self) {
        self.stopping.send_replace(true);
        self.mutations.close();
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.stopping.subscribe()
    }

    pub fn is_triggered(&self) -> bool {
        *self.stopping.borrow()
    }

    pub(crate) fn try_admit_mutation(&self) -> Option<MutationPermit> {
        if self.is_triggered() {
            return None;
        }
        let token = self.mutations.token();
        // Shutdown may have started between the check and taking the token.
        if self.is_triggered() {
            return None;
        }
        Some(MutationPermit { _token: token })
    }

    /// For work that keeps running after its request is gone; a dropped
    /// client drops the request permit, not this one.
    pub(crate) fn try_admit_background_mutation(&self) -> Option<MutationPermit> {
        self.try_admit_mutation()
    }

    pub fn active_mutation_count(&self) -> usize {
        self.mutations.len()
    }

    /// Only finishes after [`Self::trigger`].
    pub async fn wait_for_mutation_drain(&self, deadline: Duration) -> bool {
        tokio::time::timeout(deadline, self.mutations.wait())
            .await
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_exports_share_the_same_shutdown_coordinator() {
        let shutdown = DaemonShutdown::default();
        let http: crate::routes::http::state::DaemonShutdown = shutdown.clone();
        let router: crate::routes::http::router::DaemonShutdown = http.clone();
        let permit = router.try_admit_mutation().unwrap();
        assert_eq!(shutdown.active_mutation_count(), 1);

        http.trigger();
        assert!(shutdown.is_triggered());
        assert!(router.try_admit_mutation().is_none());
        drop(permit);
        assert_eq!(shutdown.active_mutation_count(), 0);
    }

    #[tokio::test]
    async fn cloned_state_gateways_use_the_configured_shared_budget() {
        let settings = crate::config::Config {
            daemon: crate::config::DaemonConfig {
                sql_buffer_global_mib: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, _directory) = crate::subsystems::test_support::database(settings).await;
        let other = state.clone();
        assert!(Arc::ptr_eq(&state.config, &other.config));
        let first = state.gateway_supervisor.tenant_sessions().open("tenant-a");
        let second = other.gateway_supervisor.tenant_sessions().open("tenant-b");
        let reserved = first.query_budget().reserve(1024 * 1024).unwrap();
        assert_eq!(
            second.query_budget().reserve(1).err().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(reserved);
        assert!(second.query_budget().reserve(1024 * 1024).is_ok());
    }

    #[tokio::test]
    async fn shutdown_closes_mutation_admission_and_drains_existing_work() {
        let shutdown = DaemonShutdown::default();
        let mutation = shutdown.try_admit_mutation().unwrap();
        let background = shutdown.try_admit_background_mutation().unwrap();
        assert_eq!(shutdown.active_mutation_count(), 2);
        shutdown.trigger();
        assert!(shutdown.try_admit_mutation().is_none());
        assert!(shutdown.try_admit_background_mutation().is_none());

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            drop(mutation);
            tokio::task::yield_now().await;
            drop(background);
        });
        assert!(
            shutdown
                .wait_for_mutation_drain(Duration::from_secs(1))
                .await
        );
        assert_eq!(shutdown.active_mutation_count(), 0);
    }

    #[tokio::test]
    async fn the_drain_times_out_while_a_change_is_still_running() {
        let shutdown = DaemonShutdown::default();
        let _running = shutdown.try_admit_mutation().unwrap();
        shutdown.trigger();
        assert!(
            !shutdown
                .wait_for_mutation_drain(Duration::from_millis(20))
                .await
        );
        assert_eq!(shutdown.active_mutation_count(), 1);
    }
}
