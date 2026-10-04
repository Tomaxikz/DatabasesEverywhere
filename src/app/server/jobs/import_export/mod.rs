use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::{Notify, OwnedSemaphorePermit, RwLock, Semaphore, broadcast};

use crate::storage::import_export_jobs::{ImportExportJobRepository, ImportExportJobStorageError};
pub use crate::utils::time::now_rfc3339;
#[cfg(test)]
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
#[cfg(test)]
use std::{fs::File, path::Path, time::Instant};
#[cfg(test)]
use tar::{Archive, Builder, EntryType};

mod scheduler;
pub use scheduler::{
    ExecutionPermit, ImportExportScheduler, JobEstimateInput, JobResourceCost,
    SchedulerAcquireError, SchedulerCapacity, SchedulerMode, SchedulerSnapshot,
    conservative_import_input_bytes, protocol_uses_logical_dumps, protocol_uses_native_compression,
};

mod create;
mod error;
mod extract;
mod model;
pub(crate) mod selection;

pub use self::create::{
    DataArchiveSourcePolicy, create_bounded_archive, create_bounded_archive_with_policy,
};
pub use self::error::{ImportExportError, JobParseError};
pub use self::extract::extract_bounded_archive;
pub use self::model::{ImportExportAction, ImportExportJob, ImportExportStatus};

#[cfg(test)]
use self::create::{
    append_bounded_archive_file, create_archive_blocking, create_bounded_archive_blocking,
};
#[cfg(test)]
use self::extract::{
    DeadlineBoundedReader, extract_archive_blocking, extract_archive_entries,
    extract_bounded_archive_blocking, validate_archive_blocking, validate_archive_path,
};

pub const MAX_DATA_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_DATA_ARCHIVE_ENTRIES: usize = 100_000;
const DATA_ARCHIVE_ENTRY_DISK_OVERHEAD_BYTES: u64 = 16 * 1024;
const MAX_DATA_ARCHIVE_DEPTH: usize = 64;
const DATA_ARCHIVE_OPERATION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_CACHED_JOBS: usize = 2_048;
const MAX_PERSISTED_COMPLETED_JOBS: u32 = 10_000;
const JOB_EVENT_CHANNEL_CAPACITY: usize = 256;
const MAX_LISTED_JOBS: u32 = 500;
const ARCHIVE_GZIP_LEVEL: u32 = 3;
const ARCHIVE_COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
struct ArchiveLimits {
    bytes: u64,
    entries: usize,
    depth: usize,
    deadline: Duration,
}

const DATA_ARCHIVE_LIMITS: ArchiveLimits = ArchiveLimits {
    bytes: MAX_DATA_ARCHIVE_BYTES,
    entries: MAX_DATA_ARCHIVE_ENTRIES,
    depth: MAX_DATA_ARCHIVE_DEPTH,
    deadline: DATA_ARCHIVE_OPERATION_TIMEOUT,
};

#[derive(Debug, Clone)]
pub struct ImportExportJobs {
    inner: Arc<RwLock<HashMap<String, ImportExportJob>>>,
    repository: Option<ImportExportJobRepository>,
    events: broadcast::Sender<ImportExportJob>,
    admission: Arc<Semaphore>,
    max_admitted_jobs_per_instance: usize,
    admitted_by_instance: Arc<Mutex<HashMap<String, InstanceAdmission>>>,
    execution_scheduler: ImportExportScheduler,
    accepting: Arc<AtomicBool>,
    active_jobs: Arc<AtomicUsize>,
    drain_notify: Arc<Notify>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobAdmissionError {
    GlobalCapacity,
    InstanceCapacity,
    ShuttingDown,
}

#[derive(Debug)]
pub struct ImportExportJobPermit {
    _global: OwnedSemaphorePermit,
    admitted_by_instance: Arc<Mutex<HashMap<String, InstanceAdmission>>>,
    instance_id: String,
    active_jobs: Arc<AtomicUsize>,
    drain_notify: Arc<Notify>,
}

#[derive(Debug, Default)]
struct InstanceAdmission {
    count: usize,
    exclusive: bool,
}

impl Default for ImportExportJobs {
    fn default() -> Self {
        Self::new(None, &crate::config::ArtifactConfig::default())
    }
}

impl ImportExportJobs {
    pub fn with_repo_and_config(
        repository: ImportExportJobRepository,
        artifacts: &crate::config::ArtifactConfig,
    ) -> Self {
        Self::new(Some(repository), artifacts)
    }

    fn new(
        repository: Option<ImportExportJobRepository>,
        artifacts: &crate::config::ArtifactConfig,
    ) -> Self {
        let (events, _) = broadcast::channel(JOB_EVENT_CHANNEL_CAPACITY);
        let scheduler_config = &artifacts.import_export_scheduler;
        let capacity = SchedulerCapacity::detect(
            scheduler_config,
            artifacts.import_upload_max_bytes,
            artifacts.import_upload_max_total_bytes,
        );
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            repository,
            events,
            admission: Arc::new(Semaphore::new(scheduler_config.max_queued_jobs)),
            max_admitted_jobs_per_instance: scheduler_config.max_queued_jobs_per_instance,
            admitted_by_instance: Arc::default(),
            execution_scheduler: ImportExportScheduler::new(capacity, scheduler_config),
            accepting: Arc::new(AtomicBool::new(true)),
            active_jobs: Arc::default(),
            drain_notify: Arc::default(),
        }
    }

    pub fn try_admit(&self, instance_id: &str) -> Result<ImportExportJobPermit, JobAdmissionError> {
        self.try_admit_kind(instance_id, false)
    }

    /// Admit a synchronous maintenance operation only when the instance
    /// has no queued data operation. While held, ordinary jobs are also
    /// rejected so secrets and backup requests cannot pile up behind it.
    pub fn try_admit_exclusive(
        &self,
        instance_id: &str,
    ) -> Result<ImportExportJobPermit, JobAdmissionError> {
        self.try_admit_kind(instance_id, true)
    }

    fn try_admit_kind(
        &self,
        instance_id: &str,
        exclusive: bool,
    ) -> Result<ImportExportJobPermit, JobAdmissionError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(JobAdmissionError::ShuttingDown);
        }
        let global =
            Arc::clone(&self.admission)
                .try_acquire_owned()
                .map_err(|error| match error {
                    tokio::sync::TryAcquireError::Closed => JobAdmissionError::ShuttingDown,
                    tokio::sync::TryAcquireError::NoPermits => JobAdmissionError::GlobalCapacity,
                })?;
        let mut admitted = lock_unpoisoned(&self.admitted_by_instance);
        if !self.accepting.load(Ordering::Acquire) {
            return Err(JobAdmissionError::ShuttingDown);
        }
        let instance = admitted.entry(instance_id.to_string()).or_default();
        let blocked_by_exclusivity = instance.exclusive || (exclusive && instance.count > 0);
        let at_instance_limit = instance.count >= self.max_admitted_jobs_per_instance;
        if blocked_by_exclusivity || at_instance_limit {
            return Err(JobAdmissionError::InstanceCapacity);
        }
        instance.count += 1;
        instance.exclusive = exclusive;
        self.active_jobs.fetch_add(1, Ordering::AcqRel);
        drop(admitted);
        Ok(ImportExportJobPermit {
            _global: global,
            admitted_by_instance: Arc::clone(&self.admitted_by_instance),
            instance_id: instance_id.to_string(),
            active_jobs: Arc::clone(&self.active_jobs),
            drain_notify: Arc::clone(&self.drain_notify),
        })
    }

    pub fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }

    pub fn active_count(&self) -> usize {
        self.active_jobs.load(Ordering::Acquire)
    }

    pub fn close_admission(&self) {
        let _admitted = lock_unpoisoned(&self.admitted_by_instance);
        self.accepting.store(false, Ordering::Release);
        self.admission.close();
        self.execution_scheduler.close();
    }

    pub async fn acquire_execution(
        &self,
        cost: JobResourceCost,
    ) -> Result<ExecutionPermit, SchedulerAcquireError> {
        self.execution_scheduler.acquire(cost).await
    }

    pub fn scheduler_snapshot(&self) -> SchedulerSnapshot {
        self.execution_scheduler.snapshot()
    }

    pub async fn wait_for_drain(&self, deadline: Duration) -> bool {
        let drained = async {
            loop {
                let notified = self.drain_notify.notified();
                if self.active_jobs.load(Ordering::Acquire) == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(deadline, drained).await.is_ok()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ImportExportJob> {
        self.events.subscribe()
    }

    pub async fn insert(&self, job: ImportExportJob) -> Result<(), ImportExportJobStorageError> {
        if let Some(repository) = &self.repository {
            repository.insert(&job).await?;
        }
        self.cache_durable_job(job).await;
        Ok(())
    }

    pub async fn cache_durable_job(&self, job: ImportExportJob) {
        let mut cache = self.inner.write().await;
        cache.insert(job.job_id.clone(), job.clone());
        prune_job_cache(&mut cache);
        drop(cache);
        self.publish(job);
    }

    pub async fn get(
        &self,
        job_id: &str,
    ) -> Result<Option<ImportExportJob>, ImportExportJobStorageError> {
        if let Some(repository) = &self.repository {
            return repository.get(job_id).await;
        }
        Ok(self.inner.read().await.get(job_id).cloned())
    }

    pub async fn list(
        &self,
        instance_id: Option<&str>,
        status: Option<ImportExportStatus>,
        limit: u32,
    ) -> Result<Vec<ImportExportJob>, ImportExportJobStorageError> {
        if let Some(repository) = &self.repository {
            return repository.list(instance_id, status, limit).await;
        }

        let mut jobs: Vec<_> = self
            .inner
            .read()
            .await
            .values()
            .filter(|job| instance_id.is_none_or(|instance_id| job.instance_id == instance_id))
            .filter(|job| status.is_none_or(|status| job.status == status))
            .cloned()
            .collect();
        jobs.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        jobs.truncate(limit.clamp(1, MAX_LISTED_JOBS) as usize);
        Ok(jobs)
    }

    pub async fn count_by_status(
        &self,
    ) -> Result<HashMap<ImportExportStatus, u64>, ImportExportJobStorageError> {
        if let Some(repository) = &self.repository {
            return Ok(repository.count_by_status().await?.into_iter().collect());
        }

        let mut counts = HashMap::new();
        for job in self.inner.read().await.values() {
            *counts.entry(job.status).or_insert(0) += 1;
        }
        Ok(counts)
    }

    /// Returns every active export destination tracked by this daemon.
    ///
    /// Active jobs are never evicted by `prune_job_cache`, so this avoids
    /// the public list endpoint's pagination limit when protecting
    /// one-use outputs from the expiry sweeper.
    pub async fn active_export_paths(&self) -> Vec<String> {
        self.inner
            .read()
            .await
            .values()
            .filter(|job| {
                job.action == ImportExportAction::Export
                    && job.status == ImportExportStatus::Running
            })
            .filter_map(|job| job.artifact_path.clone())
            .collect()
    }

    pub async fn delete_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<u64, ImportExportJobStorageError> {
        let deleted = if let Some(repository) = &self.repository {
            repository.delete_for_instance(instance_id).await?
        } else {
            self.inner
                .read()
                .await
                .values()
                .filter(|job| job.instance_id == instance_id)
                .count() as u64
        };
        self.inner
            .write()
            .await
            .retain(|_, job| job.instance_id != instance_id);
        Ok(deleted)
    }

    pub async fn update_status(
        &self,
        job_id: &str,
        status: ImportExportStatus,
        artifact_path: Option<String>,
        error: Option<String>,
    ) -> Result<(), ImportExportJobStorageError> {
        let mut job = if let Some(repository) = &self.repository {
            repository.get(job_id).await?
        } else {
            self.inner.read().await.get(job_id).cloned()
        }
        .ok_or_else(|| ImportExportJobStorageError::NotFound {
            job_id: job_id.to_string(),
        })?;
        job.status = status;
        if artifact_path.is_some() {
            job.artifact_path = artifact_path;
        }
        job.error = error;
        job.updated_at = now_rfc3339();

        if let Some(repository) = &self.repository {
            repository.update_status(&job).await?;
        }
        self.cache_durable_job(job).await;
        if status.is_completed()
            && let Some(repository) = &self.repository
            && let Err(error) = repository
                .prune_completed(MAX_PERSISTED_COMPLETED_JOBS)
                .await
        {
            tracing::warn!(%error, "failed to prune completed import/export jobs");
        }
        Ok(())
    }

    fn publish(&self, job: ImportExportJob) {
        if self.events.receiver_count() > 0 {
            let _ = self.events.send(job);
        }
    }
}

impl Drop for ImportExportJobPermit {
    fn drop(&mut self) {
        let mut admitted = lock_unpoisoned(&self.admitted_by_instance);
        if let Some(instance) = admitted.get_mut(&self.instance_id) {
            instance.count = instance.count.saturating_sub(1);
            if instance.count == 0 {
                admitted.remove(&self.instance_id);
            }
        }
        drop(admitted);
        if self.active_jobs.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.drain_notify.notify_one();
        }
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn prune_job_cache(cache: &mut HashMap<String, ImportExportJob>) {
    let excess = cache.len().saturating_sub(MAX_CACHED_JOBS);
    if excess == 0 {
        return;
    }
    let mut completed = cache
        .values()
        .filter(|job| job.status.is_completed())
        .map(|job| (job.updated_at.clone(), job.job_id.clone()))
        .collect::<Vec<_>>();
    completed.sort_unstable();
    for (_, job_id) in completed.into_iter().take(excess) {
        cache.remove(&job_id);
    }
}

#[cfg(test)]
mod tests;
