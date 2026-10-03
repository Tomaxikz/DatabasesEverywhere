use super::*;

pub fn start_resource_sampler(state: AppState) {
    sampler::start(state.clone());
    shared_disk::start(state.clone());
    activity::start(state.clone());
    crate::server::monitoring::start_engine_activity_sampler(state.clone());
    start_disk_usage_sampler(state);
}

pub(crate) async fn prime_shared_disk_quotas(state: &AppState) -> usize {
    shared_disk::prime(state).await
}

pub(super) fn start_disk_usage_sampler(state: AppState) {
    let mut shutdown = state.gateway_supervisor.subscribe_shutdown();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DISK_REFRESH_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("resource disk sampler stopped");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if state.resource_cache.has_active_monitors() {
                        state.resource_cache.refresh_all_disk_usage(&state).await;
                    }
                }
            }
        }
    });
}
