use std::{
    collections::HashMap,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde::Serialize;
use tokio::sync::Notify;

use crate::{
    api::{api_response::ApiError, public_diagnostic::PublicDiagnostic},
    runtime::docker::DockerImagePullProgress,
    shared::{protocol::Protocol, time::now_rfc3339},
};

const MAX_INSTALL_PROGRESS_ENTRIES: usize = 2_048;
const MAX_PROGRESS_TEXT_CHARS: usize = 2_048;
const MAX_ADMITTED_CREATIONS: usize = 64;

#[derive(Debug, Clone)]
pub struct InstallProgressStore {
    inner: Arc<RwLock<HashMap<String, InstallProgress>>>,
    accepting: Arc<AtomicBool>,
    active_creations: Arc<AtomicUsize>,
    drain_notify: Arc<Notify>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginCreationError {
    AlreadyRunning,
    Capacity,
    ShuttingDown,
}

#[derive(Debug)]
pub struct CreationPermit {
    active_creations: Arc<AtomicUsize>,
    drain_notify: Arc<Notify>,
}

impl Default for InstallProgressStore {
    fn default() -> Self {
        Self {
            inner: Arc::default(),
            accepting: Arc::new(AtomicBool::new(true)),
            active_creations: Arc::default(),
            drain_notify: Arc::default(),
        }
    }
}

impl InstallProgressStore {
    pub fn begin(&self, instance_id: &str, protocol: Protocol, image: &str) {
        let progress = creation_progress(instance_id, protocol, image);
        let mut entries = self.inner.write().expect("install progress lock poisoned");
        if entries.get(instance_id).is_some_and(|existing| {
            existing.action == "create" && existing.status == InstallProgressStatus::Running
        }) {
            return;
        }
        let _ = set_progress(&mut entries, progress);
    }

    pub fn try_begin_creation(
        &self,
        instance_id: &str,
        protocol: Protocol,
        image: &str,
    ) -> Result<CreationPermit, BeginCreationError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(BeginCreationError::ShuttingDown);
        }
        let mut entries = self.inner.write().expect("install progress lock poisoned");
        if !self.accepting.load(Ordering::Acquire) {
            return Err(BeginCreationError::ShuttingDown);
        }
        if entries
            .get(instance_id)
            .is_some_and(|progress| progress.status == InstallProgressStatus::Running)
        {
            return Err(BeginCreationError::AlreadyRunning);
        }
        if self.active_creations.load(Ordering::Acquire) >= MAX_ADMITTED_CREATIONS {
            return Err(BeginCreationError::Capacity);
        }
        if !set_progress(
            &mut entries,
            creation_progress(instance_id, protocol, image),
        ) {
            return Err(BeginCreationError::Capacity);
        }
        self.active_creations.fetch_add(1, Ordering::AcqRel);
        Ok(CreationPermit {
            active_creations: Arc::clone(&self.active_creations),
            drain_notify: Arc::clone(&self.drain_notify),
        })
    }

    pub fn get(&self, instance_id: &str) -> Option<InstallProgress> {
        self.inner
            .read()
            .expect("install progress lock poisoned")
            .get(instance_id)
            .cloned()
    }

    pub fn close_creation_admission(&self) {
        let _entries = self.inner.write().expect("install progress lock poisoned");
        self.accepting.store(false, Ordering::Release);
    }

    pub async fn wait_for_creation_drain(&self, deadline: Duration) -> bool {
        let drained = async {
            loop {
                let notified = self.drain_notify.notified();
                if self.active_creations.load(Ordering::Acquire) == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(deadline, drained).await.is_ok()
    }

    pub fn fail_if_running_api_error(
        &self,
        instance_id: &str,
        context: &'static str,
        error: &ApiError,
    ) {
        self.fail_if_running_diagnostic(
            instance_id,
            PublicDiagnostic::from_api_error(context, error),
        );
    }

    pub fn fail_if_running_internal(
        &self,
        instance_id: &str,
        context: &'static str,
        cause: impl std::fmt::Display,
    ) {
        self.fail_if_running_diagnostic(instance_id, PublicDiagnostic::internal(context, cause));
    }

    fn fail_if_running_diagnostic(&self, instance_id: &str, diagnostic: PublicDiagnostic) {
        self.update(instance_id, |progress| {
            if progress.status != InstallProgressStatus::Running {
                return;
            }
            apply_failure(progress, diagnostic);
        });
    }

    pub fn begin_image_update(&self, instance_id: &str, protocol: Protocol, image: &str) {
        self.set(InstallProgress {
            instance_id: instance_id.to_string(),
            protocol: protocol.to_string(),
            action: "image_update".to_string(),
            status: InstallProgressStatus::Running,
            stage: "queued".to_string(),
            message: "queued image update".to_string(),
            image: Some(bounded_progress_text(image)),
            layer: None,
            current: None,
            total: None,
            percent: None,
            diagnostic: None,
            updated_at: now_rfc3339(),
        });
    }

    pub fn begin_major_upgrade(&self, instance_id: &str, protocol: Protocol, image: &str) {
        self.set(InstallProgress {
            instance_id: instance_id.to_string(),
            protocol: protocol.to_string(),
            action: "major_upgrade".to_string(),
            status: InstallProgressStatus::Running,
            stage: "queued".to_string(),
            message: "queued major version migration".to_string(),
            image: Some(bounded_progress_text(image)),
            layer: None,
            current: None,
            total: None,
            percent: None,
            diagnostic: None,
            updated_at: now_rfc3339(),
        });
    }

    pub fn stage(&self, instance_id: &str, stage: &str, message: impl Into<String>) {
        self.update(instance_id, |progress| {
            progress.status = InstallProgressStatus::Running;
            progress.stage = bounded_progress_text(stage);
            progress.message = bounded_progress_text(&message.into());
            progress.layer = None;
            progress.current = None;
            progress.total = None;
            progress.percent = None;
            progress.diagnostic = None;
            progress.updated_at = now_rfc3339();
        });
    }

    pub fn docker_pull(&self, instance_id: &str, event: DockerImagePullProgress) {
        self.update(instance_id, |progress| {
            progress.status = InstallProgressStatus::Running;
            progress.stage = "pull_image".to_string();
            progress.message = bounded_progress_text(&event.status);
            progress.image = Some(bounded_progress_text(&event.image));
            progress.layer = event
                .layer
                .filter(|layer| !layer.is_empty())
                .map(|layer| bounded_progress_text(&layer));
            progress.current = event.current;
            progress.total = event.total;
            progress.percent = percent(event.current, event.total);
            progress.diagnostic = None;
            progress.updated_at = now_rfc3339();
        });
    }

    pub fn complete(&self, instance_id: &str, message: impl Into<String>) {
        self.update(instance_id, |progress| {
            progress.status = InstallProgressStatus::Completed;
            progress.stage = "completed".to_string();
            progress.message = bounded_progress_text(&message.into());
            progress.layer = None;
            progress.current = None;
            progress.total = None;
            progress.percent = Some(100.0);
            progress.diagnostic = None;
            progress.updated_at = now_rfc3339();
        });
    }

    pub fn fail_api_error(&self, instance_id: &str, context: &'static str, error: &ApiError) {
        self.fail_diagnostic(
            instance_id,
            PublicDiagnostic::from_api_error(context, error),
        );
    }

    pub fn fail_internal(
        &self,
        instance_id: &str,
        context: &'static str,
        cause: impl std::fmt::Display,
    ) {
        self.fail_diagnostic(instance_id, PublicDiagnostic::internal(context, cause));
    }

    pub fn fail_public(&self, instance_id: &str, code: &'static str, message: impl Into<String>) {
        self.fail_diagnostic(instance_id, PublicDiagnostic::public(code, message));
    }

    fn fail_diagnostic(&self, instance_id: &str, diagnostic: PublicDiagnostic) {
        self.update(instance_id, |progress| apply_failure(progress, diagnostic));
    }

    pub fn list(&self) -> Vec<InstallProgress> {
        let mut values = self
            .inner
            .read()
            .expect("install progress lock poisoned")
            .values()
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
        values
    }

    fn set(&self, progress: InstallProgress) {
        let mut entries = self.inner.write().expect("install progress lock poisoned");
        let _ = set_progress(&mut entries, progress);
    }

    fn update(&self, instance_id: &str, update: impl FnOnce(&mut InstallProgress)) {
        let mut progress = self.inner.write().expect("install progress lock poisoned");
        if let Some(progress) = progress.get_mut(instance_id) {
            update(progress);
        }
    }
}

impl Drop for CreationPermit {
    fn drop(&mut self) {
        if self.active_creations.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.drain_notify.notify_one();
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallProgress {
    pub instance_id: String,
    pub protocol: String,
    pub action: String,
    pub status: InstallProgressStatus,
    pub stage: String,
    pub message: String,
    pub image: Option<String>,
    pub layer: Option<String>,
    pub current: Option<u64>,
    pub total: Option<u64>,
    pub percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<PublicDiagnostic>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallProgressStatus {
    Running,
    Completed,
    Failed,
}

fn creation_progress(instance_id: &str, protocol: Protocol, image: &str) -> InstallProgress {
    InstallProgress {
        instance_id: instance_id.to_string(),
        protocol: protocol.to_string(),
        action: "create".to_string(),
        status: InstallProgressStatus::Running,
        stage: "queued".to_string(),
        message: "queued instance creation".to_string(),
        image: Some(bounded_progress_text(image)),
        layer: None,
        current: None,
        total: None,
        percent: None,
        diagnostic: None,
        updated_at: now_rfc3339(),
    }
}

fn set_progress(entries: &mut HashMap<String, InstallProgress>, progress: InstallProgress) -> bool {
    if entries.len() >= MAX_INSTALL_PROGRESS_ENTRIES && !entries.contains_key(&progress.instance_id)
    {
        let candidate = entries
            .values()
            .filter(|entry| entry.status != InstallProgressStatus::Running)
            .min_by_key(|entry| &entry.updated_at)
            .map(|entry| entry.instance_id.clone());
        let Some(instance_id) = candidate else {
            return false;
        };
        entries.remove(&instance_id);
    }
    entries.insert(progress.instance_id.clone(), progress);
    true
}

fn percent(current: Option<u64>, total: Option<u64>) -> Option<f64> {
    let current = current?;
    let total = total?;
    if total == 0 {
        return None;
    }
    Some(((current as f64 / total as f64) * 100.0).clamp(0.0, 100.0))
}

fn bounded_progress_text(value: &str) -> String {
    value.chars().take(MAX_PROGRESS_TEXT_CHARS).collect()
}

fn apply_failure(progress: &mut InstallProgress, diagnostic: PublicDiagnostic) {
    progress.status = InstallProgressStatus::Failed;
    progress.stage = "failed".to_string();
    progress.message = bounded_progress_text(&diagnostic.message);
    progress.layer = None;
    progress.current = None;
    progress.total = None;
    progress.percent = None;
    progress.diagnostic = Some(diagnostic);
    progress.updated_at = now_rfc3339();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_store_and_text_are_bounded() {
        let store = InstallProgressStore::default();
        for index in 0..=MAX_INSTALL_PROGRESS_ENTRIES {
            store.begin(
                &format!("inst-{index}"),
                Protocol::Postgres,
                "postgres:test",
            );
            store.complete(&format!("inst-{index}"), "done");
        }

        assert_eq!(store.list().len(), MAX_INSTALL_PROGRESS_ENTRIES);
        assert_eq!(
            bounded_progress_text(&"x".repeat(MAX_PROGRESS_TEXT_CHARS + 1)).len(),
            MAX_PROGRESS_TEXT_CHARS
        );
    }

    #[test]
    fn internal_progress_failure_exposes_only_public_diagnostic() {
        let store = InstallProgressStore::default();
        store.begin("inst-one", Protocol::Postgres, "postgres:test");
        store.fail_internal(
            "inst-one",
            "instance creation",
            "password=hunter2 /var/lib/private",
        );

        let encoded = serde_json::to_string(&store.get("inst-one").unwrap()).unwrap();
        assert!(encoded.contains("internal_error"));
        assert!(!encoded.contains("hunter2"));
        assert!(!encoded.contains("/var/lib/private"));
    }

    #[tokio::test]
    async fn creation_admission_is_single_instance_and_drains_on_shutdown() {
        let store = InstallProgressStore::default();
        let permit = store
            .try_begin_creation("inst-one", Protocol::Postgres, "postgres:test")
            .unwrap();

        assert_eq!(
            store
                .try_begin_creation("inst-one", Protocol::Postgres, "postgres:test")
                .unwrap_err(),
            BeginCreationError::AlreadyRunning
        );
        assert!(store.get("inst-one").is_some());
        assert!(
            !store
                .wait_for_creation_drain(Duration::from_millis(10))
                .await
        );

        store.close_creation_admission();
        assert_eq!(
            store
                .try_begin_creation("inst-two", Protocol::Postgres, "postgres:test")
                .unwrap_err(),
            BeginCreationError::ShuttingDown
        );
        drop(permit);
        assert!(
            store
                .wait_for_creation_drain(Duration::from_millis(100))
                .await
        );
    }

    #[test]
    fn creation_admission_is_bounded() {
        let store = InstallProgressStore::default();
        let permits = (0..MAX_ADMITTED_CREATIONS)
            .map(|index| {
                store
                    .try_begin_creation(
                        &format!("inst-{index}"),
                        Protocol::Postgres,
                        "postgres:test",
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            store
                .try_begin_creation("inst-overflow", Protocol::Postgres, "postgres:test")
                .unwrap_err(),
            BeginCreationError::Capacity
        );
        drop(permits);
    }
}
