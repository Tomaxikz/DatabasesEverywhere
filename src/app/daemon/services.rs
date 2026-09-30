//! Ownership and ordered shutdown of daemon background services.
//!
//! Maintenance tasks are cancellable. Lifecycle workers are drained after
//! admission closes so their metadata and filesystem operations can finish.

use std::time::Duration;

use tokio::task::JoinHandle;

use super::{
    ACTIVE_OPERATION_DRAIN_TIMEOUT, API_MUTATION_DRAIN_TIMEOUT, GATEWAY_CONNECTION_DRAIN_TIMEOUT,
    GATEWAY_CONNECTION_FORCE_CLOSE_TIMEOUT, WEBSOCKET_DRAIN_TIMEOUT, finish_runtime_boot,
    monitor_container_events, monitor_soft_disk_limits,
};
use crate::state::AppState;

pub(super) struct BackgroundServices {
    one_use_export_sweeper: JoinHandle<()>,
    import_upload_sweeper: JoinHandle<()>,
    soft_disk_limits: JoinHandle<()>,
    managed_container_events: JoinHandle<()>,
    managed_runtime_boot: JoinHandle<()>,
}

impl BackgroundServices {
    pub(super) fn start(state: &AppState) -> Self {
        crate::api::monitoring::resources::start_resource_sampler(state.clone());
        let one_use_export_sweeper =
            tokio::spawn(crate::api::artifacts::run_export_sweeper(state.clone()));
        let import_upload_sweeper =
            tokio::spawn(crate::api::import_export::run_upload_sweeper(state.clone()));
        let soft_disk_limits = tokio::spawn(monitor_soft_disk_limits(state.clone()));
        tracing::info!(
            phase = "service_start",
            "startup phase 5/5: background services launched"
        );
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            api = %state.config.api.bind_addr(),
            "DBEV is ready; the management API is accepting requests while managed databases finish recovery in the background"
        );
        let managed_container_events = tokio::spawn(monitor_container_events(state.clone()));
        let managed_runtime_boot = tokio::spawn(finish_runtime_boot(state.clone()));

        Self {
            one_use_export_sweeper,
            import_upload_sweeper,
            soft_disk_limits,
            managed_container_events,
            managed_runtime_boot,
        }
    }

    pub(super) async fn shutdown(
        self,
        state: &AppState,
        api_server_error: bool,
    ) -> anyhow::Result<()> {
        let Self {
            one_use_export_sweeper,
            import_upload_sweeper,
            soft_disk_limits,
            mut managed_container_events,
            mut managed_runtime_boot,
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
        abort_and_wait(soft_disk_limits).await;
        abort_and_wait(one_use_export_sweeper).await;
        abort_and_wait(import_upload_sweeper).await;
        let (
            jobs_drained,
            creations_drained,
            mutations_drained,
            websocket_drained,
            gateway_drain,
            container_events_drained,
            runtime_boot_drained,
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
            drain_daemon_task(
                &mut managed_container_events,
                ACTIVE_OPERATION_DRAIN_TIMEOUT,
                "managed container event monitor",
            ),
            drain_daemon_task(
                &mut managed_runtime_boot,
                ACTIVE_OPERATION_DRAIN_TIMEOUT,
                "managed runtime boot",
            ),
        );
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
        let (state, _directory) = crate::api::test_support::database(Default::default()).await;
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
        let services = BackgroundServices {
            one_use_export_sweeper: tokio::spawn(async move {
                let _guard = guard;
                std::future::pending::<()>().await;
            }),
            import_upload_sweeper: tokio::spawn(std::future::pending()),
            soft_disk_limits: tokio::spawn(std::future::pending()),
            managed_container_events: lifecycle,
            managed_runtime_boot: tokio::spawn(async {}),
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
                crate::shared::protocol::Protocol::Postgres,
                "postgres:test"
            ),
            Err(crate::api::instances::progress::BeginCreationError::ShuttingDown),
        ));
    }
}
