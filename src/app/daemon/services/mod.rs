//! Ownership and ordered shutdown of daemon background services.
//!
//! Maintenance tasks are cancellable. Lifecycle workers are drained after
//! admission closes so their metadata and filesystem operations can finish.

use std::time::Duration;

use tokio::task::JoinHandle;

use super::{
    ACTIVE_OPERATION_DRAIN_TIMEOUT, API_MUTATION_DRAIN_TIMEOUT, GATEWAY_CONNECTION_DRAIN_TIMEOUT,
    GATEWAY_CONNECTION_FORCE_CLOSE_TIMEOUT, WEBSOCKET_DRAIN_TIMEOUT,
};
use crate::state::AppState;

mod import_upload_sweeper;
mod managed_container_events;
mod managed_runtime_boot;
mod one_use_export_sweeper;
mod resource_sampler;
mod soft_disk_limits;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ServiceKind {
    Maintenance,
    Lifecycle,
}

pub(super) trait DaemonService: Send + Sync {
    fn name(&self) -> &'static str;
    fn kind(&self) -> ServiceKind;
    fn spawn(&self, state: AppState) -> JoinHandle<()>;
}

fn registry() -> Vec<Box<dyn DaemonService>> {
    vec![
        Box::new(one_use_export_sweeper::OneUseExportSweeper),
        Box::new(import_upload_sweeper::ImportUploadSweeper),
        Box::new(soft_disk_limits::SoftDiskLimits),
        Box::new(managed_container_events::ManagedContainerEvents),
        Box::new(managed_runtime_boot::ManagedRuntimeBoot),
    ]
}

struct ServiceHandle {
    name: &'static str,
    task: JoinHandle<()>,
}

pub(super) struct BackgroundServices {
    maintenance: Vec<ServiceHandle>,
    lifecycle: Vec<ServiceHandle>,
}

impl BackgroundServices {
    pub(super) fn start(state: &AppState) -> Self {
        resource_sampler::start(state);
        let services = registry();
        let spawn_kind = |kind: ServiceKind| -> Vec<ServiceHandle> {
            services
                .iter()
                .filter(|service| service.kind() == kind)
                .map(|service| ServiceHandle {
                    name: service.name(),
                    task: service.spawn(state.clone()),
                })
                .collect()
        };
        let maintenance = spawn_kind(ServiceKind::Maintenance);
        tracing::info!(
            phase = "service_start",
            "startup phase 5/5: background services launched"
        );
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            api = %state.config.api.bind_addr(),
            "DBEV is ready; the management API is accepting requests while managed databases finish recovery in the background"
        );
        let lifecycle = spawn_kind(ServiceKind::Lifecycle);

        Self {
            maintenance,
            lifecycle,
        }
    }

    pub(super) async fn shutdown(
        self,
        state: &AppState,
        api_server_error: bool,
    ) -> anyhow::Result<()> {
        let Self {
            maintenance,
            mut lifecycle,
        } = self;
        let daemon_shutdown = &state.daemon_shutdown;
        let shutdown_jobs = &state.import_export_jobs;
        let shutdown_creations = &state.install_progress;
        let gateway_supervisor = &state.gateway_supervisor;
        let shutdown_started = std::time::Instant::now();
        daemon_shutdown.trigger();
        shutdown_jobs.close_admission();
        shutdown_creations.close_creation_admission();
        gateway_supervisor.shutdown();
        tracing::info!(
            phase = "background_stop",
            api_server_error,
            active_import_export_jobs = shutdown_jobs.active_count(),
            active_instance_creations = shutdown_creations.active_creation_count(),
            active_mutations = daemon_shutdown.active_mutation_count(),
            active_websockets = state.api_rate_limiter.active_websocket_count(),
            active_gateway_connections = gateway_supervisor.active_connections(),
            "API listener stopped; shutting down daemon-owned background tasks"
        );
        for service in maintenance.into_iter().rev() {
            abort_and_wait(service.task).await;
        }
        let (
            jobs_drained,
            creations_drained,
            mutations_drained,
            websocket_drained,
            gateway_drain,
            lifecycle_drained,
        ) = tokio::join!(
            shutdown_jobs.wait_for_drain(ACTIVE_OPERATION_DRAIN_TIMEOUT),
            shutdown_creations.wait_for_creation_drain(ACTIVE_OPERATION_DRAIN_TIMEOUT),
            daemon_shutdown.wait_for_mutation_drain(API_MUTATION_DRAIN_TIMEOUT),
            state
                .api_rate_limiter
                .wait_for_websocket_drain(WEBSOCKET_DRAIN_TIMEOUT),
            gateway_supervisor.drain_connections(
                GATEWAY_CONNECTION_DRAIN_TIMEOUT,
                GATEWAY_CONNECTION_FORCE_CLOSE_TIMEOUT,
            ),
            futures::future::join_all(lifecycle.iter_mut().map(|service| {
                drain_daemon_task(
                    &mut service.task,
                    ACTIVE_OPERATION_DRAIN_TIMEOUT,
                    service.name,
                )
            })),
        );
        let drained = |name: &str| {
            lifecycle
                .iter()
                .zip(&lifecycle_drained)
                .find(|(service, _)| service.name == name)
                .is_none_or(|(_, drained)| *drained)
        };
        let container_events_drained = drained(managed_container_events::NAME);
        let runtime_boot_drained = drained(managed_runtime_boot::NAME);
        tracing::info!(
            phase = "drain_complete",
            elapsed_ms = shutdown_started.elapsed().as_millis(),
            jobs_drained,
            creations_drained,
            mutations_drained,
            container_events_drained,
            runtime_boot_drained,
            websocket_drained,
            gateway_connections_at_start = gateway_drain.active_at_start,
            gateway_connections_remaining = gateway_drain.remaining,
            gateway_connections_gracefully_drained = gateway_drain.gracefully_drained,
            "daemon shutdown drain finished; managed database containers were not stopped"
        );
        if !jobs_drained {
            anyhow::bail!(
                "timed out after {} seconds waiting for import/export jobs to finish safely",
                ACTIVE_OPERATION_DRAIN_TIMEOUT.as_secs()
            );
        }
        if !creations_drained {
            anyhow::bail!(
                "timed out after {} seconds waiting for instance creations to finish safely",
                ACTIVE_OPERATION_DRAIN_TIMEOUT.as_secs()
            );
        }
        if !mutations_drained {
            anyhow::bail!(
                "timed out after {} seconds waiting for active API mutations to finish",
                API_MUTATION_DRAIN_TIMEOUT.as_secs()
            );
        }
        if !container_events_drained || !runtime_boot_drained {
            anyhow::bail!(
                "timed out after {} seconds waiting for daemon-owned lifecycle work to finish safely",
                ACTIVE_OPERATION_DRAIN_TIMEOUT.as_secs()
            );
        }
        tracing::info!("active import/export jobs drained");
        tracing::info!("active instance creations drained");

        Ok(())
    }
}

async fn abort_and_wait(task: JoinHandle<()>) {
    task.abort();
    let _ = task.await;
}

async fn drain_daemon_task(
    task: &mut tokio::task::JoinHandle<()>,
    deadline: Duration,
    name: &'static str,
) -> bool {
    match tokio::time::timeout(deadline, &mut *task).await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            tracing::error!(%error, task = name, "daemon-owned lifecycle task stopped unexpectedly");
            false
        }
        Err(_) => {
            tracing::error!(
                task = name,
                timeout_seconds = deadline.as_secs(),
                "daemon-owned lifecycle task did not finish before the shutdown deadline"
            );
            task.abort();
            let _ = task.await;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn drain_distinguishes_completion_from_worker_failure() {
        let mut completed = tokio::spawn(async {});
        assert!(drain_daemon_task(&mut completed, Duration::from_secs(1), "test").await);

        let mut failed = tokio::spawn(async { panic!("test worker failure") });
        assert!(!drain_daemon_task(&mut failed, Duration::from_secs(1), "test").await);
    }

    #[tokio::test(start_paused = true)]
    async fn timed_out_worker_is_aborted_and_its_resources_released() {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(Arc::clone(&dropped));
        let mut worker = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });

        assert!(!drain_daemon_task(&mut worker, Duration::from_secs(1), "test").await);
        assert!(worker.is_finished());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn shutdown_closes_admission_and_drains_owned_mutations() {
        let (state, _directory) =
            crate::subsystems::test_support::database(Default::default()).await;
        let mutation = state
            .daemon_shutdown
            .try_admit_background_mutation()
            .unwrap();
        let mut shutdown = state.daemon_shutdown.subscribe();
        let lifecycle = tokio::spawn(async move {
            shutdown.wait_for(|stopped| *stopped).await.unwrap();
            drop(mutation);
        });
        let maintenance_released = Arc::new(AtomicBool::new(false));
        let guard = Dropped(Arc::clone(&maintenance_released));
        let handle = |name, task| ServiceHandle { name, task };
        let services = BackgroundServices {
            maintenance: vec![
                handle(
                    "one use export sweeper",
                    tokio::spawn(async move {
                        let _guard = guard;
                        std::future::pending::<()>().await;
                    }),
                ),
                handle(
                    "import upload sweeper",
                    tokio::spawn(std::future::pending()),
                ),
                handle("soft disk limits", tokio::spawn(std::future::pending())),
            ],
            lifecycle: vec![
                handle(managed_container_events::NAME, lifecycle),
                handle(managed_runtime_boot::NAME, tokio::spawn(async {})),
            ],
        };

        services.shutdown(&state, true).await.unwrap();

        assert!(maintenance_released.load(Ordering::SeqCst));
        assert!(state.daemon_shutdown.is_triggered());
        assert!(!state.import_export_jobs.is_accepting());
        assert!(
            state
                .daemon_shutdown
                .try_admit_background_mutation()
                .is_none()
        );
        assert_eq!(state.daemon_shutdown.active_mutation_count(), 0);
        assert!(matches!(
            state.install_progress.try_begin_creation(
                "test",
                crate::databases::protocol::Protocol::Postgres,
                "postgres:test"
            ),
            Err(crate::subsystems::instances::progress::BeginCreationError::ShuttingDown),
        ));
    }
}
