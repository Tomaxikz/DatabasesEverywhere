use std::{
    ops::Deref,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::{Notify, watch};

use crate::{
    api::http::policy::OriginPolicy,
    auth::api_token::ApiToken,
    config::RuntimeConfig,
    instances::{manager::InstanceManager, state::InstanceStore},
    jobs::import_export::ImportExportJobs,
    runtime::docker::DockerRuntime,
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateData>,
    origin_policy: Arc<OriginPolicy>,
    pub gateway_supervisor: crate::gateway::supervisor::GatewaySupervisor,
}

#[cfg_attr(test, derive(Clone))]
pub struct AppStateData {
    pub config: Arc<RuntimeConfig>,
    pub config_path: PathBuf,
    pub config_patches: crate::api::system::config::ConfigPatchCoordinator,
    pub api_token: ApiToken,
    pub instances: InstanceStore,
    pub manager: InstanceManager,
    pub placements: crate::placement::PlacementRepository,
    pub instance_locks: crate::instances::locks::InstanceLocks,
    pub docker: DockerRuntime,
    pub import_export_jobs: ImportExportJobs,
    pub import_uploads: crate::api::import_export::ImportUploadService,
    pub api_rate_limiter: crate::api::http::limits::ApiRateLimiter,
    pub install_progress: crate::api::instances::progress::InstallProgressStore,
    pub artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets,
    pub resource_cache: crate::api::monitoring::resources::ResourceCache,
    pub soft_disk_limiter: crate::disk::soft::SoftDiskLimiter,
    pub monitoring_cache: crate::api::monitoring::websocket::MonitoringSnapshotCache,
    pub instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache,
    pub daemon_shutdown: DaemonShutdown,
}

impl AppState {
    pub fn new(data: AppStateData) -> Self {
        let origin_policy = Arc::new(OriginPolicy::from_config(&data.config));
        let gateway_supervisor =
            crate::gateway::supervisor::GatewaySupervisor::with_config(Arc::clone(&data.config));
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
    sender: watch::Sender<bool>,
    accepting_mutations: Arc<AtomicBool>,
    active_mutations: Arc<AtomicUsize>,
    mutation_drain: Arc<Notify>,
}

#[derive(Debug)]
pub(crate) struct MutationPermit {
    active: Arc<AtomicUsize>,
    drain: Arc<Notify>,
}

impl Default for DaemonShutdown {
    fn default() -> Self {
        let (sender, _) = watch::channel(false);
        Self {
            sender,
            accepting_mutations: Arc::new(AtomicBool::new(true)),
            active_mutations: Arc::default(),
            mutation_drain: Arc::default(),
        }
    }
}

impl DaemonShutdown {
    pub fn trigger(&self) {
        self.accepting_mutations.store(false, Ordering::Release);
        self.sender.send_replace(true);
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.sender.subscribe()
    }

    pub fn is_triggered(&self) -> bool {
        *self.sender.borrow()
    }

    pub(super) fn try_admit_mutation(&self) -> Option<MutationPermit> {
        if !self.accepting_mutations.load(Ordering::Acquire) {
            return None;
        }
        self.active_mutations.fetch_add(1, Ordering::AcqRel);
        if !self.accepting_mutations.load(Ordering::Acquire) {
            release_mutation(&self.active_mutations, &self.mutation_drain);
            return None;
        }
        Some(MutationPermit {
            active: Arc::clone(&self.active_mutations),
            drain: Arc::clone(&self.mutation_drain),
        })
    }

    /// Keeps detached daemon-owned mutation work inside the same shutdown
    /// fence as the HTTP request that started it. This is intentionally
    /// separate from request middleware because a disconnected client drops
    /// the request permit while its owned worker must continue safely.
    pub(crate) fn try_admit_background_mutation(&self) -> Option<MutationPermit> {
        self.try_admit_mutation()
    }

    pub fn active_mutation_count(&self) -> usize {
        self.active_mutations.load(Ordering::Acquire)
    }

    pub async fn wait_for_mutation_drain(&self, deadline: Duration) -> bool {
        let drained = async {
            loop {
                let notified = self.mutation_drain.notified();
                if self.active_mutation_count() == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(deadline, drained).await.is_ok()
    }
}

impl Drop for MutationPermit {
    fn drop(&mut self) {
        release_mutation(&self.active, &self.drain);
    }
}

fn release_mutation(active: &AtomicUsize, drain: &Notify) {
    let previous = active.fetch_sub(1, Ordering::AcqRel);
    debug_assert!(previous > 0, "active API mutation count underflow");
    if previous == 1 {
        drain.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn cloned_state_gateways_use_the_configured_shared_budget() {
        let settings = crate::config::Config {
            daemon: crate::config::DaemonConfig {
                sql_buffer_global_mib: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let (state, _directory) = crate::api::test_support::database(settings).await;
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

    use super::*;

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
}
