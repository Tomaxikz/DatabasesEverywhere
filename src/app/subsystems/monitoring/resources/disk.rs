use super::{
    BACKGROUND_DISK_SCAN_TIMEOUT, CachedDiskUsage, RESOURCE_FANOUT_LIMIT, ResourceCache,
    ResourceCacheInner,
};
use crate::config::Config;
use crate::routes::http::router::AppState;
use crate::server::disk::{DiskLimiter, soft::SoftDiskTarget};
use crate::server::metadata::{InstanceMetadata, InstanceStatus};
use crate::server::paths::InstancePaths;
use crate::server::placement::DeploymentMode;
use futures::StreamExt;
use std::io::Error as IoError;
use std::path::Path as FsPath;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

impl ResourceCache {
    /// Export admission must not reserve from that stale value, so this path always asks the active
    /// quota runtime or performs a bounded fresh directory scan before returning.
    pub(crate) async fn fresh_disk_usage(
        &self,
        config: &Config,
        instance_id: &str,
        path: PathBuf,
    ) -> Result<CachedDiskUsage, String> {
        let refresh_lock = self.disk_refresh_lock(instance_id).await;
        let _refresh = refresh_lock.lock().await;
        if let Some(sample) = self.quota_disk_usage(config, instance_id, &path).await {
            return self
                .publish_disk_sample(instance_id, &refresh_lock, sample)
                .await;
        }
        let used_bytes = self
            .scan_directory(path, BACKGROUND_DISK_SCAN_TIMEOUT)
            .await
            .map_err(|error| error.to_string())?;
        let sample = CachedDiskUsage {
            used_bytes,
            sampled_at: Instant::now(),
        };
        self.publish_disk_sample(instance_id, &refresh_lock, sample)
            .await
    }

    pub(super) async fn publish_disk_sample(
        &self,
        instance_id: &str,
        refresh_lock: &Arc<Mutex<()>>,
        sample: CachedDiskUsage,
    ) -> Result<CachedDiskUsage, String> {
        if !self
            .store_disk_usage_if_current_lock(instance_id, refresh_lock, sample)
            .await
        {
            return Err("disk usage cache was invalidated during sampling".to_string());
        }
        Ok(sample)
    }

    pub(super) async fn quota_disk_usage(
        &self,
        config: &Config,
        instance_id: &str,
        path: &FsPath,
    ) -> Option<CachedDiskUsage> {
        let disk_limiter =
            DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root());
        match disk_limiter.instance_usage_bytes(path).await {
            Ok(Some(used_bytes)) => Some(CachedDiskUsage {
                used_bytes,
                sampled_at: Instant::now(),
            }),
            Ok(None) => None,
            Err(error) => {
                tracing::debug!(
                    %instance_id,
                    %error,
                    "quota disk usage unavailable; falling back to cached directory usage"
                );
                None
            }
        }
    }

    pub(super) async fn cached_disk_usage(&self, instance_id: &str) -> Option<CachedDiskUsage> {
        let inner = self.inner.lock().await;
        inner.disk.get(instance_id).copied()
    }

    pub(super) async fn cached_disk_usage_for_lock(
        &self,
        instance_id: &str,
        refresh_lock: &Arc<Mutex<()>>,
    ) -> Option<CachedDiskUsage> {
        let inner = self.inner.lock().await;
        if !is_current_refresh_lock(&inner, instance_id, refresh_lock) {
            return None;
        }
        inner.disk.get(instance_id).copied()
    }

    pub(super) async fn store_disk_usage_if_current_lock(
        &self,
        instance_id: &str,
        refresh_lock: &Arc<Mutex<()>>,
        sample: CachedDiskUsage,
    ) -> bool {
        let mut inner = self.inner.lock().await;
        if !is_current_refresh_lock(&inner, instance_id, refresh_lock) {
            return false;
        }
        inner.disk.insert(instance_id.to_string(), sample);
        true
    }

    pub(super) async fn disk_refresh_lock(&self, instance_id: &str) -> Arc<Mutex<()>> {
        let mut inner = self.inner.lock().await;
        inner
            .disk_refresh_locks
            .entry(instance_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub(super) async fn store_disk_usage(&self, instance_id: String, sample: CachedDiskUsage) {
        let mut inner = self.inner.lock().await;
        inner.disk.insert(instance_id, sample);
    }

    pub(super) async fn disk_refresh_in_progress(&self, instance_id: &str) -> bool {
        self.inner
            .lock()
            .await
            .disk_refreshing
            .get(instance_id)
            .copied()
            .unwrap_or(false)
    }

    pub(super) async fn scan_directory(
        &self,
        path: PathBuf,
        budget: Duration,
    ) -> Result<u64, std::io::Error> {
        let _permit = self
            .disk_scan_permits
            .acquire()
            .await
            .map_err(|_| IoError::other("disk scan limiter closed"))?;
        crate::server::disk::usage::scan_directory(
            path,
            crate::server::disk::usage::ScanLimits {
                timeout: budget,
                ..Default::default()
            },
        )
        .await
        .map(|usage| usage.logical_bytes)
    }

    pub(super) async fn begin_disk_refresh(
        &self,
        instance_id: &str,
        refresh_lock: &Arc<Mutex<()>>,
    ) -> bool {
        let mut inner = self.inner.lock().await;
        let already_refreshing = inner
            .disk_refreshing
            .get(instance_id)
            .copied()
            .unwrap_or(false);
        if !is_current_refresh_lock(&inner, instance_id, refresh_lock) || already_refreshing {
            return false;
        }
        inner.disk_refreshing.insert(instance_id.to_string(), true);
        true
    }

    pub(super) async fn finish_disk_refresh(
        &self,
        instance_id: String,
        refresh_lock: &Arc<Mutex<()>>,
        result: Result<u64, std::io::Error>,
    ) -> Option<(String, std::io::Error)> {
        let mut inner = self.inner.lock().await;
        if !is_current_refresh_lock(&inner, &instance_id, refresh_lock) {
            return None;
        }
        inner.disk_refreshing.remove(&instance_id);
        match result {
            Ok(used_bytes) => {
                inner.disk.insert(
                    instance_id,
                    CachedDiskUsage {
                        used_bytes,
                        sampled_at: Instant::now(),
                    },
                );
                None
            }
            Err(error) => Some((instance_id, error)),
        }
    }

    pub(super) async fn queue_disk_refresh(
        &self,
        config: Arc<Config>,
        instance_id: String,
        path: PathBuf,
        refresh_lock: Arc<Mutex<()>>,
    ) {
        if !self.begin_disk_refresh(&instance_id, &refresh_lock).await {
            return;
        }

        let cache = self.clone();
        tokio::spawn(async move {
            let result =
                match DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
                    .instance_usage_bytes(&path)
                    .await
                {
                    Ok(Some(used_bytes)) => Ok(used_bytes),
                    Ok(None) => {
                        cache
                            .scan_directory(path, BACKGROUND_DISK_SCAN_TIMEOUT)
                            .await
                    }
                    Err(error) => {
                        tracing::debug!(
                            %instance_id,
                            %error,
                            "quota disk usage unavailable during background refresh"
                        );
                        cache
                            .scan_directory(path, BACKGROUND_DISK_SCAN_TIMEOUT)
                            .await
                    }
                };
            if let Some((instance_id, error)) = cache
                .finish_disk_refresh(instance_id, &refresh_lock, result)
                .await
            {
                tracing::warn!(
                    %instance_id,
                    %error,
                    "failed to refresh resource disk usage"
                );
            }
        });
    }

    pub async fn refresh_all_disk_usage(&self, state: &AppState) {
        let instances = state
            .instances
            .snapshots_matching(is_disk_sample_target)
            .await;
        let config = state.config.snapshot();
        futures::stream::iter(instances)
            .for_each_concurrent(RESOURCE_FANOUT_LIMIT, |metadata| {
                let config = Arc::clone(&config);
                async move {
                    let instance_id = &metadata.instance_id;
                    let paths = match InstancePaths::new(&config.paths, instance_id) {
                        Ok(paths) => paths,
                        Err(error) => {
                            tracing::debug!(
                                %instance_id,
                                %error,
                                "skipping resource disk sample for invalid instance path"
                            );
                            return;
                        }
                    };
                    if uses_dedicated_scanner(&metadata)
                        && state
                            .soft_disk_limiter
                            .has_fresh_measurement(&scanner_target(&metadata, paths.data.clone()))
                            .await
                    {
                        // Reports already use the scanner's physical bytes. Keep the
                        // logical-byte cache independent for callers such as export sizing.
                        return;
                    }
                    self.refresh_disk_usage_now(config, instance_id.clone(), paths.data)
                        .await;
                }
            })
            .await;
    }

    pub(super) async fn refresh_disk_usage_now(
        &self,
        config: Arc<Config>,
        instance_id: String,
        path: PathBuf,
    ) {
        let refresh_lock = self.disk_refresh_lock(&instance_id).await;
        if !self.begin_disk_refresh(&instance_id, &refresh_lock).await {
            return;
        }

        let result =
            match DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
                .instance_usage_bytes(&path)
                .await
            {
                Ok(Some(used_bytes)) => Ok(used_bytes),
                Ok(None) => {
                    self.scan_directory(path, BACKGROUND_DISK_SCAN_TIMEOUT)
                        .await
                }
                Err(error) => {
                    tracing::debug!(
                        %instance_id,
                        %error,
                        "quota disk usage unavailable during sampler refresh"
                    );
                    self.scan_directory(path, BACKGROUND_DISK_SCAN_TIMEOUT)
                        .await
                }
            };

        if let Some((instance_id, error)) = self
            .finish_disk_refresh(instance_id, &refresh_lock, result)
            .await
        {
            tracing::warn!(
                %instance_id,
                %error,
                "failed to refresh sampled disk usage"
            );
        }
    }
}

pub(super) fn is_current_refresh_lock(
    inner: &ResourceCacheInner,
    instance_id: &str,
    refresh_lock: &Arc<Mutex<()>>,
) -> bool {
    inner
        .disk_refresh_locks
        .get(instance_id)
        .is_some_and(|current| Arc::ptr_eq(current, refresh_lock))
}

pub(super) fn invalidate_disk_locked(inner: &mut ResourceCacheInner, instance_id: &str) {
    inner.disk.remove(instance_id);
    inner.disk_refreshing.remove(instance_id);
    // Any in-flight scan still holding the previous Arc will fail its identity check before it can
    // publish a result.
    inner.disk_refresh_locks.remove(instance_id);
}

pub(super) fn is_disk_sample_target(metadata: &InstanceMetadata) -> bool {
    metadata.deployment_mode == DeploymentMode::Dedicated
        && metadata.status == InstanceStatus::Running
}

pub(super) fn uses_dedicated_scanner(metadata: &InstanceMetadata) -> bool {
    metadata.deployment_mode == DeploymentMode::Dedicated
        && (metadata.limits.disk_enforcement_method == "soft_scanner"
            || (metadata.protocol == crate::databases::protocol::Protocol::Qdrant
                && metadata.limits.disk_enforcement_method == "fuse_quota"))
}

pub(super) fn scanner_target(metadata: &InstanceMetadata, data_path: PathBuf) -> SoftDiskTarget {
    SoftDiskTarget {
        instance_id: metadata.instance_id.clone(),
        created_at: metadata.created_at.clone(),
        protocol: metadata.protocol,
        data_path,
        limit_bytes: crate::utils::limits::mib_to_bytes(metadata.limits.disk_mib),
        durable_blocked: metadata.disk_limit_blocked,
    }
}
