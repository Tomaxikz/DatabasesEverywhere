pub mod artifacts {
    use std::path::{Path, PathBuf};

    pub fn artifact_path(root: &Path, job_id: &str) -> PathBuf {
        root.join(job_id)
    }
}

pub mod import_export {
    use std::{
        collections::HashMap,
        fs::{File, OpenOptions},
        io::{Read, Write},
        path::{Component, Path, PathBuf},
        sync::{
            Arc, Mutex, MutexGuard,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use flate2::{Compression, read::GzDecoder, write::GzEncoder};
    use serde::{Deserialize, Serialize};
    use tar::{Archive, Builder, EntryType};
    use tokio::sync::{Notify, OwnedSemaphorePermit, RwLock, Semaphore, broadcast};

    pub use crate::shared::time::now_rfc3339;
    use crate::storage::import_export_jobs::{
        ImportExportJobRepository, ImportExportJobStorageError,
    };

    const MAX_DATA_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
    const MAX_DATA_ARCHIVE_ENTRIES: usize = 100_000;
    const MAX_DATA_ARCHIVE_DEPTH: usize = 64;
    const DATA_ARCHIVE_OPERATION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
    const MAX_ADMITTED_JOBS: usize = 64;
    const MAX_ADMITTED_JOBS_PER_INSTANCE: usize = 2;
    const MAX_CACHED_JOBS: usize = 2_048;
    const MAX_PERSISTED_COMPLETED_JOBS: u32 = 10_000;

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

    #[derive(Debug, Clone, Serialize)]
    pub struct ImportExportJob {
        pub job_id: String,
        pub instance_id: String,
        pub action: ImportExportAction,
        pub status: ImportExportStatus,
        pub artifact_path: Option<String>,
        pub error: Option<String>,
        pub created_at: String,
        pub updated_at: String,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
    #[serde(rename_all = "snake_case")]
    pub enum ImportExportAction {
        Import,
        Export,
    }

    impl ImportExportAction {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Import => "import",
                Self::Export => "export",
            }
        }

        pub fn parse(value: &str) -> Result<Self, JobParseError> {
            match value {
                "import" => Ok(Self::Import),
                "export" => Ok(Self::Export),
                value => Err(JobParseError::UnknownAction(value.to_string())),
            }
        }
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
    #[serde(rename_all = "snake_case")]
    pub enum ImportExportStatus {
        Queued,
        Running,
        Succeeded,
        Failed,
    }

    impl ImportExportStatus {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Queued => "queued",
                Self::Running => "running",
                Self::Succeeded => "succeeded",
                Self::Failed => "failed",
            }
        }

        pub fn parse(value: &str) -> Result<Self, JobParseError> {
            match value {
                "queued" => Ok(Self::Queued),
                "running" => Ok(Self::Running),
                "succeeded" => Ok(Self::Succeeded),
                "failed" => Ok(Self::Failed),
                value => Err(JobParseError::UnknownStatus(value.to_string())),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ImportExportJobs {
        inner: Arc<RwLock<HashMap<String, ImportExportJob>>>,
        repository: Option<ImportExportJobRepository>,
        events: broadcast::Sender<ImportExportJob>,
        admission: Arc<Semaphore>,
        admitted_by_instance: Arc<Mutex<HashMap<String, usize>>>,
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
        admitted_by_instance: Arc<Mutex<HashMap<String, usize>>>,
        instance_id: String,
        active_jobs: Arc<AtomicUsize>,
        drain_notify: Arc<Notify>,
    }

    impl Default for ImportExportJobs {
        fn default() -> Self {
            let (events, _) = broadcast::channel(256);
            Self {
                inner: Arc::new(RwLock::new(HashMap::new())),
                repository: None,
                events,
                admission: Arc::new(Semaphore::new(MAX_ADMITTED_JOBS)),
                admitted_by_instance: Arc::default(),
                accepting: Arc::new(AtomicBool::new(true)),
                active_jobs: Arc::default(),
                drain_notify: Arc::default(),
            }
        }
    }

    impl ImportExportJobs {
        pub fn with_repository(repository: ImportExportJobRepository) -> Self {
            let (events, _) = broadcast::channel(256);
            Self {
                inner: Arc::new(RwLock::new(HashMap::new())),
                repository: Some(repository),
                events,
                admission: Arc::new(Semaphore::new(MAX_ADMITTED_JOBS)),
                admitted_by_instance: Arc::default(),
                accepting: Arc::new(AtomicBool::new(true)),
                active_jobs: Arc::default(),
                drain_notify: Arc::default(),
            }
        }

        pub fn try_admit(
            &self,
            instance_id: &str,
        ) -> Result<ImportExportJobPermit, JobAdmissionError> {
            if !self.accepting.load(Ordering::Acquire) {
                return Err(JobAdmissionError::ShuttingDown);
            }
            let global = Arc::clone(&self.admission)
                .try_acquire_owned()
                .map_err(|error| match error {
                    tokio::sync::TryAcquireError::Closed => JobAdmissionError::ShuttingDown,
                    tokio::sync::TryAcquireError::NoPermits => JobAdmissionError::GlobalCapacity,
                })?;
            let mut admitted = lock_unpoisoned(&self.admitted_by_instance);
            if !self.accepting.load(Ordering::Acquire) {
                return Err(JobAdmissionError::ShuttingDown);
            }
            let count = admitted.entry(instance_id.to_string()).or_default();
            if *count >= MAX_ADMITTED_JOBS_PER_INSTANCE {
                return Err(JobAdmissionError::InstanceCapacity);
            }
            *count += 1;
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

        pub fn close_admission(&self) {
            let _admitted = lock_unpoisoned(&self.admitted_by_instance);
            self.accepting.store(false, Ordering::Release);
            self.admission.close();
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

        pub async fn insert(
            &self,
            job: ImportExportJob,
        ) -> Result<(), ImportExportJobStorageError> {
            if let Some(repository) = &self.repository {
                repository.insert(&job).await?;
            }
            let mut cache = self.inner.write().await;
            cache.insert(job.job_id.clone(), job.clone());
            prune_job_cache(&mut cache);
            drop(cache);
            self.publish(job);
            Ok(())
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
            jobs.truncate(limit.clamp(1, 500) as usize);
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
            let mut cache = self.inner.write().await;
            cache.insert(job.job_id.clone(), job.clone());
            prune_job_cache(&mut cache);
            drop(cache);
            self.publish(job);
            if matches!(
                status,
                ImportExportStatus::Succeeded | ImportExportStatus::Failed
            ) && let Some(repository) = &self.repository
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
            if let Some(count) = admitted.get_mut(&self.instance_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
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
            .filter(|job| {
                matches!(
                    job.status,
                    ImportExportStatus::Succeeded | ImportExportStatus::Failed
                )
            })
            .map(|job| (job.updated_at.clone(), job.job_id.clone()))
            .collect::<Vec<_>>();
        completed.sort_unstable();
        for (_, job_id) in completed.into_iter().take(excess) {
            cache.remove(&job_id);
        }
    }

    pub async fn create_data_archive(
        data_dir: PathBuf,
        artifact_path: PathBuf,
    ) -> Result<(), ImportExportError> {
        tokio::task::spawn_blocking(move || create_data_archive_blocking(&data_dir, &artifact_path))
            .await
            .map_err(|error| ImportExportError::Join(error.to_string()))?
    }

    pub async fn extract_data_archive(
        artifact_path: PathBuf,
        data_parent: PathBuf,
        expected_root: String,
    ) -> Result<(), ImportExportError> {
        tokio::task::spawn_blocking(move || {
            extract_data_archive_blocking(&artifact_path, &data_parent, &expected_root)
        })
        .await
        .map_err(|error| ImportExportError::Join(error.to_string()))?
    }

    pub async fn validate_data_archive(
        artifact_path: PathBuf,
        expected_root: String,
    ) -> Result<(), ImportExportError> {
        tokio::task::spawn_blocking(move || {
            validate_archive_blocking(&artifact_path, &expected_root)
        })
        .await
        .map_err(|error| ImportExportError::Join(error.to_string()))?
    }

    fn create_data_archive_blocking(
        data_dir: &Path,
        artifact_path: &Path,
    ) -> Result<(), ImportExportError> {
        let parent = artifact_path.parent().ok_or_else(|| {
            ImportExportError::InvalidArchive("artifact has no parent".to_string())
        })?;
        create_private_dir_all(parent)?;
        let file = create_private_file(artifact_path)?;
        let root_name = data_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ImportExportError::InvalidArchive("invalid data dir".to_string()))?;
        let result = (|| {
            let encoder = GzEncoder::new(file, Compression::new(3));
            let mut builder = Builder::new(encoder);
            builder.follow_symlinks(false);
            append_archive_tree(&mut builder, data_dir, Path::new(root_name))?;
            let encoder = builder.into_inner()?;
            encoder.finish()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(artifact_path);
        }
        result
    }

    fn extract_data_archive_blocking(
        artifact_path: &Path,
        data_parent: &Path,
        expected_root: &str,
    ) -> Result<(), ImportExportError> {
        create_private_dir_all(data_parent)?;
        let file = File::open(artifact_path)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        extract_archive_entries(
            &mut archive,
            data_parent,
            expected_root,
            DATA_ARCHIVE_LIMITS,
        )?;
        Ok(())
    }

    fn validate_archive_blocking(
        artifact_path: &Path,
        expected_root: &str,
    ) -> Result<(), ImportExportError> {
        let file = File::open(artifact_path)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        let started = Instant::now();
        let mut entries = 0_usize;
        let mut bytes = 0_u64;
        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?;
            entries += 1;
            validate_archive_limits(started, entries, bytes, DATA_ARCHIVE_LIMITS)?;
            validate_archive_path(&path, expected_root, DATA_ARCHIVE_LIMITS.depth)?;
            validate_entry_type(entry.header().entry_type())?;
            bytes = bytes.checked_add(entry.header().size()?).ok_or_else(|| {
                ImportExportError::InvalidArchive("archive size overflow".to_string())
            })?;
            validate_archive_limits(started, entries, bytes, DATA_ARCHIVE_LIMITS)?;
        }
        Ok(())
    }

    fn validate_archive_path(
        path: &Path,
        expected_root: &str,
        max_depth: usize,
    ) -> Result<(), ImportExportError> {
        let mut components = path.components();
        let first = components
            .next()
            .ok_or_else(|| ImportExportError::InvalidArchive("empty archive path".to_string()))?;
        if !matches!(first, Component::Normal(name) if name.to_str() == Some(expected_root)) {
            return Err(ImportExportError::InvalidArchive(format!(
                "archive entry must be under {expected_root}"
            )));
        }
        let mut depth = 1_usize;
        for component in components {
            if !matches!(component, Component::Normal(_)) {
                return Err(ImportExportError::InvalidArchive(format!(
                    "unsafe archive path {}",
                    path.display()
                )));
            }
            depth += 1;
            if depth > max_depth {
                return Err(ImportExportError::InvalidArchive(format!(
                    "archive path depth exceeds {max_depth}"
                )));
            }
        }
        Ok(())
    }

    fn validate_entry_type(entry_type: EntryType) -> Result<(), ImportExportError> {
        if entry_type.is_file() || entry_type.is_dir() {
            Ok(())
        } else {
            Err(ImportExportError::InvalidArchive(
                "archive may only contain files and directories".to_string(),
            ))
        }
    }

    fn extract_archive_entries<R: Read>(
        archive: &mut Archive<R>,
        data_parent: &Path,
        expected_root: &str,
        limits: ArchiveLimits,
    ) -> Result<(), ImportExportError> {
        ensure_real_directory(data_parent)?;
        let started = Instant::now();
        let mut entries = 0_usize;
        let mut bytes = 0_u64;
        for entry in archive.entries()? {
            let mut entry = entry?;
            entries += 1;
            validate_archive_limits(started, entries, bytes, limits)?;
            let path = entry.path()?.to_path_buf();
            validate_archive_path(&path, expected_root, limits.depth)?;
            let entry_type = entry.header().entry_type();
            validate_entry_type(entry_type)?;
            let entry_size = entry.header().size()?;
            bytes = bytes.checked_add(entry_size).ok_or_else(|| {
                ImportExportError::InvalidArchive("archive size overflow".to_string())
            })?;
            validate_archive_limits(started, entries, bytes, limits)?;
            let target = data_parent.join(&path);
            if !target.starts_with(data_parent) {
                return Err(ImportExportError::InvalidArchive(format!(
                    "unsafe archive path {}",
                    path.display()
                )));
            }
            if entry_type.is_dir() {
                create_private_dir_all(&target)?;
                continue;
            }
            if let Some(parent) = target.parent() {
                create_private_dir_all(parent)?;
            }
            let mut output = create_private_file(&target)?;
            copy_archive_entry(&mut entry, &mut output, entry_size, started, limits)?;
            output.flush()?;
        }
        Ok(())
    }

    fn validate_archive_limits(
        started: Instant,
        entries: usize,
        bytes: u64,
        limits: ArchiveLimits,
    ) -> Result<(), ImportExportError> {
        if entries > limits.entries {
            return Err(ImportExportError::InvalidArchive(format!(
                "archive has more than {} entries",
                limits.entries
            )));
        }
        if bytes > limits.bytes {
            return Err(ImportExportError::InvalidArchive(format!(
                "archive expands beyond {} bytes",
                limits.bytes
            )));
        }
        if started.elapsed() > limits.deadline {
            return Err(ImportExportError::InvalidArchive(
                "archive operation exceeded time limit".to_string(),
            ));
        }
        Ok(())
    }

    fn copy_archive_entry<R: Read, W: Write>(
        reader: &mut R,
        writer: &mut W,
        expected_size: u64,
        started: Instant,
        limits: ArchiveLimits,
    ) -> Result<(), ImportExportError> {
        let mut remaining = expected_size;
        let mut buffer = [0_u8; 64 * 1024];
        while remaining > 0 {
            validate_archive_limits(started, 0, expected_size - remaining, limits)?;
            let wanted =
                usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
            let read = reader.read(&mut buffer[..wanted])?;
            if read == 0 {
                return Err(ImportExportError::InvalidArchive(
                    "archive entry ended before its declared size".to_string(),
                ));
            }
            writer.write_all(&buffer[..read])?;
            remaining -= read as u64;
        }
        Ok(())
    }

    fn append_archive_tree<W: Write>(
        builder: &mut Builder<W>,
        data_dir: &Path,
        archive_root: &Path,
    ) -> Result<(), ImportExportError> {
        let root_metadata = std::fs::symlink_metadata(data_dir)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(ImportExportError::InvalidArchive(
                "data root must be a real directory".to_string(),
            ));
        }

        builder.append_dir(archive_root, data_dir)?;
        let started = Instant::now();
        let mut entries = 1_usize;
        let mut bytes = 0_u64;
        let mut pending = vec![(data_dir.to_path_buf(), archive_root.to_path_buf())];
        while let Some((source_dir, archive_dir)) = pending.pop() {
            let mut children = Vec::new();
            for child in std::fs::read_dir(&source_dir)? {
                validate_archive_limits(
                    started,
                    entries.saturating_add(children.len()).saturating_add(1),
                    bytes,
                    DATA_ARCHIVE_LIMITS,
                )?;
                children.push(child?);
            }
            children.sort_by_key(std::fs::DirEntry::file_name);
            for child in children {
                entries += 1;
                validate_archive_limits(started, entries, bytes, DATA_ARCHIVE_LIMITS)?;
                let source = child.path();
                let archive_path = archive_dir.join(child.file_name());
                validate_archive_path_depth(&archive_path, DATA_ARCHIVE_LIMITS.depth)?;
                let metadata = std::fs::symlink_metadata(&source)?;
                if metadata.file_type().is_symlink() {
                    return Err(ImportExportError::InvalidArchive(format!(
                        "data archive refuses symbolic link {}",
                        source.display()
                    )));
                }
                if metadata.is_dir() {
                    builder.append_dir(&archive_path, &source)?;
                    pending.push((source, archive_path));
                    continue;
                }
                if !metadata.is_file() {
                    return Err(ImportExportError::InvalidArchive(format!(
                        "data archive refuses special file {}",
                        source.display()
                    )));
                }

                bytes = bytes.checked_add(metadata.len()).ok_or_else(|| {
                    ImportExportError::InvalidArchive("archive size overflow".to_string())
                })?;
                validate_archive_limits(started, entries, bytes, DATA_ARCHIVE_LIMITS)?;
                let file = open_verified_regular_file(&source, &metadata)?;
                append_bounded_archive_file(
                    builder,
                    &archive_path,
                    file,
                    &metadata,
                    started,
                    DATA_ARCHIVE_LIMITS,
                )?;
            }
        }
        Ok(())
    }

    fn append_bounded_archive_file<W: Write>(
        builder: &mut Builder<W>,
        archive_path: &Path,
        file: File,
        metadata: &std::fs::Metadata,
        started: Instant,
        limits: ArchiveLimits,
    ) -> Result<(), ImportExportError> {
        let expected_size = metadata.len();
        let mut header = tar::Header::new_gnu();
        header.set_metadata(metadata);
        header.set_entry_type(EntryType::Regular);
        header.set_size(expected_size);
        let mut reader = DeadlineBoundedReader {
            inner: file,
            remaining: expected_size,
            started,
            deadline: limits.deadline,
        };
        builder.append_data(&mut header, archive_path, &mut reader)?;
        if reader.remaining != 0 {
            return Err(ImportExportError::InvalidArchive(format!(
                "data file shrank while archiving {}",
                archive_path.display()
            )));
        }
        Ok(())
    }

    struct DeadlineBoundedReader<R> {
        inner: R,
        remaining: u64,
        started: Instant,
        deadline: Duration,
    }

    impl<R: Read> Read for DeadlineBoundedReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.started.elapsed() > self.deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "archive operation exceeded time limit",
                ));
            }
            if self.remaining == 0 || buffer.is_empty() {
                return Ok(0);
            }
            let wanted =
                usize::try_from(self.remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
            let read = self.inner.read(&mut buffer[..wanted])?;
            self.remaining = self.remaining.saturating_sub(read as u64);
            Ok(read)
        }
    }

    fn validate_archive_path_depth(path: &Path, max_depth: usize) -> Result<(), ImportExportError> {
        let depth = path
            .components()
            .filter(|component| matches!(component, Component::Normal(_)))
            .count();
        if depth > max_depth {
            return Err(ImportExportError::InvalidArchive(format!(
                "archive path depth exceeds {max_depth}"
            )));
        }
        Ok(())
    }

    fn open_verified_regular_file(
        path: &Path,
        expected: &std::fs::Metadata,
    ) -> Result<File, ImportExportError> {
        let file = File::open(path)?;
        let opened = file.metadata()?;
        let current = std::fs::symlink_metadata(path)?;
        if current.file_type().is_symlink()
            || !opened.is_file()
            || opened.len() != expected.len()
            || current.len() != expected.len()
            || !same_file_identity(expected, &opened)
            || !same_file_identity(&opened, &current)
        {
            return Err(ImportExportError::InvalidArchive(format!(
                "data file changed while archiving {}",
                path.display()
            )));
        }
        Ok(file)
    }

    #[cfg(unix)]
    fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;

        left.dev() == right.dev() && left.ino() == right.ino()
    }

    #[cfg(not(unix))]
    fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
        left.is_file() == right.is_file()
            && left.len() == right.len()
            && left.modified().ok() == right.modified().ok()
    }

    fn ensure_real_directory(path: &Path) -> Result<(), ImportExportError> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ImportExportError::InvalidArchive(format!(
                "archive destination must be a real directory: {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn create_private_dir_all(path: &Path) -> Result<(), ImportExportError> {
        std::fs::create_dir_all(path)?;
        ensure_real_directory(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn create_private_file(path: &Path) -> Result<File, ImportExportError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }
        Ok(options.open(path)?)
    }

    #[derive(Debug, thiserror::Error)]
    pub enum ImportExportError {
        #[error("io failed: {0}")]
        Io(#[from] std::io::Error),
        #[error("task failed: {0}")]
        Join(String),
        #[error("invalid archive: {0}")]
        InvalidArchive(String),
    }

    #[derive(Debug, thiserror::Error)]
    pub enum JobParseError {
        #[error("unknown import/export action {0}")]
        UnknownAction(String),
        #[error("unknown import/export status {0}")]
        UnknownStatus(String),
    }

    #[cfg(test)]
    mod tests {
        use std::io::Cursor;

        use super::*;

        #[test]
        fn rejects_archive_path_traversal() {
            let error =
                validate_archive_path(Path::new("data/../evil.txt"), "data", 64).unwrap_err();

            assert!(matches!(error, ImportExportError::InvalidArchive(_)));
        }

        #[test]
        fn accepts_archive_under_expected_root() {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("good.tar.gz");
            write_archive(&archive, "data/file.txt", b"ok");

            validate_archive_blocking(&archive, "data").unwrap();
        }

        #[test]
        fn extracts_archive_entries_without_unpack() {
            let dir = tempfile::tempdir().unwrap();
            let archive_path = dir.path().join("data.tar.gz");
            let target = dir.path().join("target");
            write_archive(&archive_path, "data/file.txt", b"ok");

            extract_data_archive_blocking(&archive_path, &target, "data").unwrap();

            assert_eq!(std::fs::read(target.join("data/file.txt")).unwrap(), b"ok");
        }

        #[test]
        fn physical_extraction_enforces_expansion_limit() {
            let dir = tempfile::tempdir().unwrap();
            let archive_path = dir.path().join("data.tar.gz");
            let target = dir.path().join("target");
            std::fs::create_dir(&target).unwrap();
            write_archive(&archive_path, "data/file.txt", b"too large");
            let file = File::open(&archive_path).unwrap();
            let decoder = GzDecoder::new(file);
            let mut archive = Archive::new(decoder);
            let limits = ArchiveLimits {
                bytes: 4,
                entries: 10,
                depth: 10,
                deadline: Duration::from_secs(10),
            };

            let error = extract_archive_entries(&mut archive, &target, "data", limits).unwrap_err();

            assert!(error.to_string().contains("expands beyond"));
        }

        #[cfg(unix)]
        #[test]
        fn physical_backup_rejects_source_symlinks() {
            use std::os::unix::fs::symlink;

            let dir = tempfile::tempdir().unwrap();
            let data = dir.path().join("data");
            let artifacts = dir.path().join("artifacts");
            std::fs::create_dir(&data).unwrap();
            std::fs::create_dir(&artifacts).unwrap();
            let secret = dir.path().join("secret");
            std::fs::write(&secret, b"host secret").unwrap();
            symlink(&secret, data.join("escape")).unwrap();
            let artifact = artifacts.join("backup.tar.gz");

            let error = create_data_archive_blocking(&data, &artifact).unwrap_err();

            assert!(error.to_string().contains("refuses symbolic link"));
            assert!(!artifact.exists());
        }

        #[cfg(unix)]
        #[test]
        fn physical_backup_artifact_is_owner_only() {
            use std::os::unix::fs::PermissionsExt;

            let dir = tempfile::tempdir().unwrap();
            let data = dir.path().join("data");
            let artifact = dir.path().join("backup.tar.gz");
            std::fs::create_dir(&data).unwrap();
            std::fs::write(data.join("file"), b"contents").unwrap();

            create_data_archive_blocking(&data, &artifact).unwrap();

            assert_eq!(
                std::fs::metadata(artifact).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        #[test]
        fn physical_backup_reader_ignores_concurrent_file_growth() {
            use std::fs::OpenOptions;

            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("source");
            std::fs::write(&source, b"ok").unwrap();
            let file = File::open(&source).unwrap();
            let metadata = file.metadata().unwrap();
            OpenOptions::new()
                .append(true)
                .open(&source)
                .unwrap()
                .write_all(b"host-secret")
                .unwrap();
            let mut archive_bytes = Vec::new();
            let mut builder = Builder::new(&mut archive_bytes);

            append_bounded_archive_file(
                &mut builder,
                Path::new("data/source"),
                file,
                &metadata,
                Instant::now(),
                DATA_ARCHIVE_LIMITS,
            )
            .unwrap();
            builder.finish().unwrap();
            drop(builder);

            let mut archive = Archive::new(Cursor::new(archive_bytes));
            let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents).unwrap();
            assert_eq!(contents, b"ok");
        }

        #[test]
        fn physical_backup_reader_enforces_deadline_inside_file_copy() {
            let mut reader = DeadlineBoundedReader {
                inner: Cursor::new(b"contents"),
                remaining: 8,
                started: Instant::now().checked_sub(Duration::from_secs(2)).unwrap(),
                deadline: Duration::from_secs(1),
            };
            let mut byte = [0_u8; 1];

            let error = reader.read(&mut byte).unwrap_err();

            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        }

        #[test]
        fn import_export_admission_bounds_global_and_per_instance_waiters() {
            let jobs = ImportExportJobs::default();
            let first = jobs.try_admit("inst-one").unwrap();
            let second = jobs.try_admit("inst-one").unwrap();
            assert_eq!(
                jobs.try_admit("inst-one").unwrap_err(),
                JobAdmissionError::InstanceCapacity
            );

            let mut other_permits = Vec::new();
            for index in 2..MAX_ADMITTED_JOBS {
                other_permits.push(jobs.try_admit(&format!("inst-{index}")).unwrap());
            }
            assert_eq!(
                jobs.try_admit("over-global-limit").unwrap_err(),
                JobAdmissionError::GlobalCapacity
            );

            drop(first);
            assert!(jobs.try_admit("inst-one").is_ok());
            drop(second);
            drop(other_permits);
        }

        #[tokio::test]
        async fn shutdown_closes_admission_and_waits_for_existing_jobs() {
            let jobs = ImportExportJobs::default();
            let permit = jobs.try_admit("inst-one").unwrap();

            jobs.close_admission();

            assert_eq!(
                jobs.try_admit("inst-two").unwrap_err(),
                JobAdmissionError::ShuttingDown
            );
            assert!(!jobs.wait_for_drain(Duration::from_millis(10)).await);
            drop(permit);
            assert!(jobs.wait_for_drain(Duration::from_millis(100)).await);
        }

        #[tokio::test]
        async fn publishes_import_export_job_events() {
            let jobs = ImportExportJobs::default();
            let mut events = jobs.subscribe();
            let job = ImportExportJob {
                job_id: "job-1".to_string(),
                instance_id: "inst-1".to_string(),
                action: ImportExportAction::Export,
                status: ImportExportStatus::Queued,
                artifact_path: None,
                error: None,
                created_at: now_rfc3339(),
                updated_at: now_rfc3339(),
            };

            jobs.insert(job).await.unwrap();

            let event = events.recv().await.unwrap();
            assert_eq!(event.job_id, "job-1");
            assert_eq!(event.status, ImportExportStatus::Queued);

            jobs.update_status(
                "job-1",
                ImportExportStatus::Succeeded,
                Some("exports/job-1.sql".to_string()),
                None,
            )
            .await
            .unwrap();

            let event = events.recv().await.unwrap();
            assert_eq!(event.job_id, "job-1");
            assert_eq!(event.status, ImportExportStatus::Succeeded);
            assert_eq!(event.artifact_path.as_deref(), Some("exports/job-1.sql"));
        }

        fn write_archive(path: &Path, entry_path: &str, contents: &[u8]) {
            let file = File::create(path).unwrap();
            let encoder = GzEncoder::new(file, Compression::default());
            let mut builder = Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_path(entry_path).unwrap();
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder
                .append(&header, Cursor::new(contents.to_vec()))
                .unwrap();
            builder.into_inner().unwrap().finish().unwrap();
        }
    }
}

pub mod recovery {
    #[derive(Debug, Clone)]
    pub struct RecoveryJob {
        pub job_id: String,
        pub instance_id: String,
        pub reason: String,
    }
}
