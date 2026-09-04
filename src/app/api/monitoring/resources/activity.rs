use std::{sync::Arc, time::Duration};

use tokio::time::MissedTickBehavior;

use super::{NetworkCounter, ResourceCache};
use crate::{
    api::{http::router::AppState, monitoring::activity::gateway_ops_available},
    monitoring::{ActivityBucket, ActivityCounter, ActivityCurrent},
    shared::{protocol::Protocol, time::now_unix},
    storage::activity::{ActivityRepository, ActivityStorageError},
};

const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

struct ActivityTarget {
    instance_id: String,
    generation: String,
    protocol: Protocol,
}

impl ResourceCache {
    pub(crate) fn with_activity_repository(mut self, repository: ActivityRepository) -> Self {
        self.activity_repository = Some(repository);
        self
    }

    pub(crate) async fn activity_counter(
        &self,
        instance_id: &str,
        instance_generation: &str,
    ) -> Arc<ActivityCounter> {
        self.activity.counter(instance_id, instance_generation)
    }

    pub(crate) async fn current_activity(
        &self,
        instance_id: &str,
        instance_generation: &str,
        sampled_at_unix: i64,
    ) -> ActivityCurrent {
        let (rx_bytes, tx_bytes) = self.network_usage(instance_id).await;
        self.activity.current_with_network(
            instance_id,
            instance_generation,
            sampled_at_unix,
            rx_bytes,
            tx_bytes,
        )
    }

    pub(crate) async fn activity_history(
        &self,
        instance_id: &str,
        instance_generation: &str,
        before: Option<i64>,
        limit: u16,
    ) -> Result<Vec<ActivityBucket>, ActivityStorageError> {
        let Some(repository) = &self.activity_repository else {
            return Ok(Vec::new());
        };
        repository
            .history(instance_id, instance_generation, before, limit)
            .await
    }

    async fn sample_activity(
        &self,
        sampled_at_unix: i64,
        targets: &[ActivityTarget],
        pending: &mut Vec<ActivityBucket>,
    ) -> Result<usize, ActivityStorageError> {
        let generations = targets
            .iter()
            .map(|target| (target.instance_id.clone(), target.generation.clone()))
            .collect::<Vec<_>>();
        let network = {
            let inner = self.inner.lock().await;
            targets
                .iter()
                .map(|target| {
                    (
                        target,
                        inner
                            .network
                            .get(&target.instance_id)
                            .map(NetworkCounter::snapshot)
                            .unwrap_or_default(),
                    )
                })
                .collect::<Vec<_>>()
        };
        self.activity.retain_generations(&generations);
        for (target, (rx_bytes, tx_bytes)) in network {
            let counter = self
                .activity
                .counter(&target.instance_id, &target.generation);
            if gateway_ops_available(target.protocol) {
                counter.mark_gateway_ops_available();
            }
            counter.observe_network(rx_bytes, tx_bytes);
        }

        if pending.is_empty() {
            *pending = self.activity.sample(sampled_at_unix);
        }
        if let Some(repository) = &self.activity_repository {
            repository.save(pending).await?;
        }
        let saved = pending.len();
        pending.clear();
        Ok(saved)
    }
}

pub(super) fn start(state: AppState) {
    let mut shutdown = state.gateway_supervisor.subscribe_shutdown();
    tokio::spawn(async move {
        // A failed SQLite write retains the exact prepared batch. We do not
        // advance sampling again until that batch is durably stored, so a
        // transient metadata outage cannot silently consume a minute.
        let mut pending = Vec::new();
        let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        let targets = current_targets(&state).await;
                        let had_pending = !pending.is_empty();
                        match state
                            .resource_cache
                            .sample_activity(now_unix(), &targets, &mut pending)
                            .await
                        {
                            Ok(_) if had_pending => {
                                // The first call durably drains the exact
                                // retry batch. A second call may persist an
                                // independently due final full-minute bucket.
                                if let Err(error) = state
                                    .resource_cache
                                    .sample_activity(now_unix(), &targets, &mut pending)
                                    .await
                                {
                                    tracing::warn!(%error, "failed to persist final tenant activity bucket");
                                }
                            }
                            Ok(_) => {}
                            Err(error) => {
                                tracing::warn!(%error, "failed to flush tenant activity during shutdown");
                            }
                        }
                        tracing::info!("tenant activity sampler stopped");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    let targets = current_targets(&state).await;
                    if let Err(error) = state
                        .resource_cache
                        .sample_activity(now_unix(), &targets, &mut pending)
                        .await
                    {
                        tracing::warn!(%error, "failed to persist tenant activity history");
                    }
                }
            }
        }
    });
}

async fn current_targets(state: &AppState) -> Vec<ActivityTarget> {
    state
        .instances
        .list()
        .await
        .into_iter()
        .map(|metadata| ActivityTarget {
            instance_id: metadata.instance_id,
            generation: metadata.created_at,
            protocol: metadata.protocol,
        })
        .collect()
}
