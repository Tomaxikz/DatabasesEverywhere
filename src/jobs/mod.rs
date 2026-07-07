pub mod artifacts {
    use std::path::{Path, PathBuf};

    pub fn artifact_path(root: &Path, job_id: &str) -> PathBuf {
        root.join(job_id)
    }
}

pub mod import_export {
    use std::{
        collections::HashMap,
        fs::File,
        io::{Read, Write},
        path::{Component, Path, PathBuf},
        sync::Arc,
    };

    use flate2::{Compression, read::GzDecoder, write::GzEncoder};
    use serde::{Deserialize, Serialize};
    use tar::{Archive, Builder, EntryType};
    use tokio::sync::{RwLock, broadcast};

    pub use crate::shared::time::now_rfc3339;
    use crate::storage::import_export_jobs::ImportExportJobRepository;

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
    }

    impl Default for ImportExportJobs {
        fn default() -> Self {
            let (events, _) = broadcast::channel(256);
            Self {
                inner: Arc::new(RwLock::new(HashMap::new())),
                repository: None,
                events,
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
            }
        }

        pub fn subscribe(&self) -> broadcast::Receiver<ImportExportJob> {
            self.events.subscribe()
        }

        pub async fn insert(&self, job: ImportExportJob) {
            self.inner
                .write()
                .await
                .insert(job.job_id.clone(), job.clone());
            self.persist_insert(&job).await;
            self.publish(job);
        }

        pub async fn get(&self, job_id: &str) -> Option<ImportExportJob> {
            if let Some(job) = self.inner.read().await.get(job_id).cloned() {
                return Some(job);
            }

            let Some(repository) = &self.repository else {
                return None;
            };
            match repository.get(job_id).await {
                Ok(Some(job)) => {
                    self.inner
                        .write()
                        .await
                        .insert(job.job_id.clone(), job.clone());
                    Some(job)
                }
                Ok(None) => None,
                Err(error) => {
                    tracing::warn!(%error, %job_id, "failed to read import/export job from sqlite");
                    None
                }
            }
        }

        pub async fn list(
            &self,
            instance_id: Option<&str>,
            status: Option<ImportExportStatus>,
            limit: u32,
        ) -> Vec<ImportExportJob> {
            if let Some(repository) = &self.repository {
                match repository.list(instance_id, status, limit).await {
                    Ok(jobs) => {
                        let mut cache = self.inner.write().await;
                        for job in &jobs {
                            cache.insert(job.job_id.clone(), job.clone());
                        }
                        return jobs;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to list import/export jobs from sqlite");
                    }
                }
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
            jobs
        }

        pub async fn count_by_status(&self) -> HashMap<ImportExportStatus, u64> {
            if let Some(repository) = &self.repository {
                match repository.count_by_status().await {
                    Ok(counts) => return counts.into_iter().collect(),
                    Err(error) => {
                        tracing::warn!(%error, "failed to count import/export jobs from sqlite");
                    }
                }
            }

            let mut counts = HashMap::new();
            for job in self.inner.read().await.values() {
                *counts.entry(job.status).or_insert(0) += 1;
            }
            counts
        }

        pub async fn update_status(
            &self,
            job_id: &str,
            status: ImportExportStatus,
            artifact_path: Option<String>,
            error: Option<String>,
        ) {
            let mut job_to_persist = None;
            if let Some(job) = self.inner.write().await.get_mut(job_id) {
                job.status = status;
                if artifact_path.is_some() {
                    job.artifact_path = artifact_path;
                }
                job.error = error;
                job.updated_at = now_rfc3339();
                job_to_persist = Some(job.clone());
            }
            if let Some(job) = job_to_persist {
                self.persist_update(&job).await;
                self.publish(job);
            }
        }

        fn publish(&self, job: ImportExportJob) {
            if self.events.receiver_count() > 0 {
                let _ = self.events.send(job);
            }
        }

        async fn persist_insert(&self, job: &ImportExportJob) {
            if let Some(repository) = &self.repository
                && let Err(error) = repository.insert(job).await
            {
                tracing::warn!(%error, job_id = %job.job_id, "failed to persist import/export job");
            }
        }

        async fn persist_update(&self, job: &ImportExportJob) {
            if let Some(repository) = &self.repository
                && let Err(error) = repository.update_status(job).await
            {
                tracing::warn!(%error, job_id = %job.job_id, "failed to persist import/export job status");
            }
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
        std::fs::create_dir_all(parent)?;
        let file = File::create(artifact_path)?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        let root_name = data_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ImportExportError::InvalidArchive("invalid data dir".to_string()))?;
        builder.append_dir_all(root_name, data_dir)?;
        let encoder = builder.into_inner()?;
        encoder.finish()?;
        Ok(())
    }

    fn extract_data_archive_blocking(
        artifact_path: &Path,
        data_parent: &Path,
        expected_root: &str,
    ) -> Result<(), ImportExportError> {
        validate_archive_blocking(artifact_path, expected_root)?;
        let file = File::open(artifact_path)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        extract_archive_entries(&mut archive, data_parent, expected_root)?;
        Ok(())
    }

    fn validate_archive_blocking(
        artifact_path: &Path,
        expected_root: &str,
    ) -> Result<(), ImportExportError> {
        let file = File::open(artifact_path)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?;
            validate_archive_path(&path, expected_root)?;
            validate_entry_type(entry.header().entry_type())?;
        }
        Ok(())
    }

    fn validate_archive_path(path: &Path, expected_root: &str) -> Result<(), ImportExportError> {
        let mut components = path.components();
        let first = components
            .next()
            .ok_or_else(|| ImportExportError::InvalidArchive("empty archive path".to_string()))?;
        if !matches!(first, Component::Normal(name) if name.to_str() == Some(expected_root)) {
            return Err(ImportExportError::InvalidArchive(format!(
                "archive entry must be under {expected_root}"
            )));
        }
        for component in components {
            if !matches!(component, Component::Normal(_)) {
                return Err(ImportExportError::InvalidArchive(format!(
                    "unsafe archive path {}",
                    path.display()
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
    ) -> Result<(), ImportExportError> {
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();
            validate_archive_path(&path, expected_root)?;
            let entry_type = entry.header().entry_type();
            validate_entry_type(entry_type)?;
            let target = data_parent.join(&path);
            if !target.starts_with(data_parent) {
                return Err(ImportExportError::InvalidArchive(format!(
                    "unsafe archive path {}",
                    path.display()
                )));
            }
            if entry_type.is_dir() {
                std::fs::create_dir_all(target)?;
                continue;
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut output = File::create(target)?;
            std::io::copy(&mut entry, &mut output)?;
            output.flush()?;
        }
        Ok(())
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
            let error = validate_archive_path(Path::new("data/../evil.txt"), "data").unwrap_err();

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

            jobs.insert(job).await;

            let event = events.recv().await.unwrap();
            assert_eq!(event.job_id, "job-1");
            assert_eq!(event.status, ImportExportStatus::Queued);

            jobs.update_status(
                "job-1",
                ImportExportStatus::Succeeded,
                Some("exports/job-1.sql".to_string()),
                None,
            )
            .await;

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
