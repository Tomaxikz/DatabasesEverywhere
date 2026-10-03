use super::*;

impl ResourceCache {
    /// Measure managed database bytes for a capacity-sensitive operation.
    ///
    /// Dashboard samples may be up to `DISK_REFRESH_INTERVAL` old, which is
    /// desirable for polling but can substantially overstate a database that
    /// was just truncated or restored. Export admission must not reserve from
    /// that stale value, so this path always asks the active quota runtime or
    /// performs a bounded fresh directory scan before returning.
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
        crate::instance::disk::usage::scan_directory(
            path,
            crate::instance::disk::usage::ScanLimits {
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
        let instances = state.instances.list().await;
        // Shared tenants have protocol-aware per-tenant sampling in
        // `shared_disk`. Walking a shared runtime root here duplicates that
        // work, cannot be attributed to a tenant, and turns one active monitor
        // into a full-pool scan every five seconds.
        let instance_ids = disk_sample_instance_ids(instances);
        futures::stream::iter(instance_ids)
            .map(|instance_id| {
                let cache = self.clone();
                let config = state.config.snapshot();
                async move {
                    let paths = match InstancePaths::new(&config.paths, &instance_id) {
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
                    cache
                        .refresh_disk_usage_now(config, instance_id, paths.data)
                        .await;
                }
            })
            .buffer_unordered(RESOURCE_FANOUT_LIMIT)
            .collect::<Vec<_>>()
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
    // Removing the Arc advances the sampling generation. Any in-flight scan
    // still holding the previous Arc will fail its identity check before it
    // can publish a result.
    inner.disk_refresh_locks.remove(instance_id);
}

pub(super) fn disk_sample_instance_ids(
    instances: Vec<InstanceMetadata>,
) -> std::collections::HashSet<String> {
    instances
        .into_iter()
        .filter(|metadata| {
            metadata.deployment_mode == DeploymentMode::Dedicated
                && metadata.status == InstanceStatus::Running
        })
        .map(|metadata| metadata.instance_id)
        .collect()
}
