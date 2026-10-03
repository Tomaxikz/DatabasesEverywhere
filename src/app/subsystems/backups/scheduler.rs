use super::*;

pub(crate) async fn backup_all_instances(state: &AppState) -> RunBackupResponse {
    let mut response = RunBackupResponse::default();
    for metadata in state.instances.list().await {
        let result = backup_instance(state, &metadata.instance_id).await;
        response.record(&metadata, result);
    }
    if response.failed.is_empty() {
        tracing::info!(
            event = "audit backup_pass_finished",
            status = response.status(),
            backups = response.backups.len(),
            skipped = response.skipped.len(),
            failed = response.failed.len(),
        );
    } else {
        tracing::error!(
            event = "audit backup_pass_finished",
            status = response.status(),
            backups = response.backups.len(),
            skipped = response.skipped.len(),
            failed = response.failed.len(),
            "backup pass finished with failures; not every instance has a new backup"
        );
    }
    response
}

pub fn start_scheduler(state: AppState) {
    if !state.config.backups.enabled {
        tracing::info!("automatic backups disabled");
        return;
    }
    let interval = Duration::from_secs(state.config.backups.interval_minutes.saturating_mul(60));
    let run_on_startup = state.config.backups.run_on_startup;
    let mut shutdown = state.gateway_supervisor.subscribe_shutdown();
    tokio::spawn(async move {
        tracing::info!(
            interval_minutes = state.config.backups.interval_minutes,
            run_on_startup,
            storage = state.config.backups.storage.driver.as_str(),
            "automatic backups enabled"
        );
        if run_on_startup && !*shutdown.borrow() {
            backup_all_instances(&state).await;
        }
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("automatic backup scheduler stopped");
                        break;
                    }
                }
                () = sleep(interval) => { backup_all_instances(&state).await; },
            }
        }
    });
}
