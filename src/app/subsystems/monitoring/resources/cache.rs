use super::disk::invalidate_disk_locked;
use super::network::NetworkCounter;
use super::runtime_metrics::docker_compatible_memory_usage;
use super::{
    CachedDiskUsage, CachedRuntimeStats, DISK_REFRESH_INTERVAL, INITIAL_DISK_SCAN_TIMEOUT,
    ResourceCache, ResourceMonitorGuard,
};
use crate::config::Config;
use bollard::models::ContainerStatsResponse;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::time::Instant;

impl ResourceCache {
    /// Invalidates samples tied to a physical runtime generation while keeping
    /// the logical tenant's network/activity counters alive. Existing gateway
    /// sessions may still hold those counters during reconcile or cutover.
    pub async fn invalidate_runtime(&self, instance_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.stats.remove(instance_id);
        inner.runtime_stats_workers.remove(instance_id);
        invalidate_disk_locked(&mut inner, instance_id);
    }

    /// Removes a logical metric identity after its route is fenced, sessions
    /// are drained, and durable instance metadata has been deleted.
    pub async fn remove_tenant(&self, instance_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.stats.remove(instance_id);
        inner.runtime_stats_workers.remove(instance_id);
        inner.network.remove(instance_id);
        invalidate_disk_locked(&mut inner, instance_id);
        drop(inner);
        self.activity.remove(instance_id);
    }

    /// Invalidates only storage telemetry. Shared-tenant operations use this
    /// for their physical pool so one tenant resize cannot tear down the
    /// pool's live CPU/memory sampler or reset unrelated network counters.
    pub(crate) async fn invalidate_disk(&self, instance_id: &str) {
        let mut inner = self.inner.lock().await;
        invalidate_disk_locked(&mut inner, instance_id);
    }

    pub(crate) async fn disk_usage(
        &self,
        config: &Config,
        instance_id: &str,
        path: PathBuf,
    ) -> Result<CachedDiskUsage, String> {
        // The Arc is also the cache generation. Deletion, migration, and
        // recreation remove it, so a late scan from the old identity cannot
        // repopulate the cache for the replacement.
        let refresh_lock = self.disk_refresh_lock(instance_id).await;
        if let Some(sample) = self
            .cached_disk_usage_for_lock(instance_id, &refresh_lock)
            .await
            && sample.sampled_at.elapsed() < DISK_REFRESH_INTERVAL
        {
            return Ok(sample);
        }

        if let Some(sample) = self.quota_disk_usage(config, instance_id, &path).await {
            return self
                .publish_disk_sample(instance_id, &refresh_lock, sample)
                .await;
        }

        if let Some(sample) = self
            .cached_disk_usage_for_lock(instance_id, &refresh_lock)
            .await
        {
            if sample.sampled_at.elapsed() < DISK_REFRESH_INTERVAL {
                return Ok(sample);
            }
            self.queue_disk_refresh(
                Arc::new(config.clone()),
                instance_id.to_string(),
                path,
                refresh_lock,
            )
            .await;
            return Ok(sample);
        }

        let _refresh = refresh_lock.lock().await;
        if let Some(sample) = self
            .cached_disk_usage_for_lock(instance_id, &refresh_lock)
            .await
        {
            return Ok(sample);
        }
        if self.disk_refresh_in_progress(instance_id).await {
            return Err("disk usage scan is still in progress".to_string());
        }
        if let Some(sample) = self.quota_disk_usage(config, instance_id, &path).await {
            return self
                .publish_disk_sample(instance_id, &refresh_lock, sample)
                .await;
        }

        match self
            .scan_directory(path.clone(), INITIAL_DISK_SCAN_TIMEOUT)
            .await
        {
            Ok(used_bytes) => {
                let sample = CachedDiskUsage {
                    used_bytes,
                    sampled_at: Instant::now(),
                };
                self.publish_disk_sample(instance_id, &refresh_lock, sample)
                    .await
            }
            Err(error) if error.kind() == ErrorKind::TimedOut => {
                self.queue_disk_refresh(
                    Arc::new(config.clone()),
                    instance_id.to_string(),
                    path,
                    refresh_lock.clone(),
                )
                .await;
                Err("disk usage scan is still in progress".to_string())
            }
            Err(error) => Err(error.to_string()),
        }
    }

    pub(crate) fn register_monitor(&self) -> ResourceMonitorGuard {
        self.active_monitors.fetch_add(1, Ordering::Relaxed);
        ResourceMonitorGuard {
            active_monitors: self.active_monitors.clone(),
        }
    }

    pub(super) fn has_active_monitors(&self) -> bool {
        self.active_monitors.load(Ordering::Relaxed) > 0
    }

    pub(crate) async fn network_counter(&self, instance_id: &str) -> NetworkCounter {
        let mut inner = self.inner.lock().await;
        inner
            .network
            .entry(instance_id.to_string())
            .or_default()
            .clone()
    }

    pub(crate) async fn network_usage(&self, instance_id: &str) -> (u64, u64) {
        let inner = self.inner.lock().await;
        inner
            .network
            .get(instance_id)
            .map(NetworkCounter::snapshot)
            .unwrap_or_default()
    }

    pub(super) async fn begin_runtime_stats_worker(&self, runtime_id: &str) -> u64 {
        let mut inner = self.inner.lock().await;
        inner.next_runtime_stats_worker = inner.next_runtime_stats_worker.wrapping_add(1).max(1);
        let worker = inner.next_runtime_stats_worker;
        inner
            .runtime_stats_workers
            .insert(runtime_id.to_string(), worker);
        worker
    }

    pub(super) async fn store_runtime_stats(
        &self,
        runtime_id: &str,
        worker: u64,
        cpu_usage_percent: Option<f64>,
        stats: &ContainerStatsResponse,
    ) -> bool {
        let sample = CachedRuntimeStats {
            cpu_usage_percent,
            memory_usage_bytes: docker_compatible_memory_usage(stats),
            sampled_at: Instant::now(),
        };
        let mut inner = self.inner.lock().await;
        if inner.runtime_stats_workers.get(runtime_id) != Some(&worker) {
            return false;
        }
        inner.stats.insert(runtime_id.to_string(), sample);
        true
    }

    pub(super) async fn finish_stats_worker(&self, runtime_id: &str, worker: u64) {
        let mut inner = self.inner.lock().await;
        if inner.runtime_stats_workers.get(runtime_id) == Some(&worker) {
            inner.runtime_stats_workers.remove(runtime_id);
        }
    }

    pub(super) async fn clear_runtime_stats(&self, runtime_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.runtime_stats_workers.remove(runtime_id);
        inner.stats.remove(runtime_id);
    }
}
