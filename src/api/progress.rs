use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use serde::Serialize;

use crate::{
    runtime::docker::DockerImagePullProgress,
    shared::{protocol::Protocol, time::now_rfc3339},
};

#[derive(Debug, Clone, Default)]
pub struct InstallProgressStore {
    inner: Arc<RwLock<HashMap<String, InstallProgress>>>,
}

impl InstallProgressStore {
    pub fn begin(&self, instance_id: &str, protocol: Protocol, image: &str) {
        self.set(InstallProgress {
            instance_id: instance_id.to_string(),
            protocol: protocol.to_string(),
            action: "create".to_string(),
            status: InstallProgressStatus::Running,
            stage: "queued".to_string(),
            message: "queued instance creation".to_string(),
            image: Some(image.to_string()),
            layer: None,
            current: None,
            total: None,
            percent: None,
            updated_at: now_rfc3339(),
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
            image: Some(image.to_string()),
            layer: None,
            current: None,
            total: None,
            percent: None,
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
            image: Some(image.to_string()),
            layer: None,
            current: None,
            total: None,
            percent: None,
            updated_at: now_rfc3339(),
        });
    }

    pub fn stage(&self, instance_id: &str, stage: &str, message: impl Into<String>) {
        self.update(instance_id, |progress| {
            progress.status = InstallProgressStatus::Running;
            progress.stage = stage.to_string();
            progress.message = message.into();
            progress.layer = None;
            progress.current = None;
            progress.total = None;
            progress.percent = None;
            progress.updated_at = now_rfc3339();
        });
    }

    pub fn docker_pull(&self, instance_id: &str, event: DockerImagePullProgress) {
        self.update(instance_id, |progress| {
            progress.status = InstallProgressStatus::Running;
            progress.stage = "pull_image".to_string();
            progress.message = event.status;
            progress.image = Some(event.image);
            progress.layer = event.layer.filter(|layer| !layer.is_empty());
            progress.current = event.current;
            progress.total = event.total;
            progress.percent = percent(event.current, event.total);
            progress.updated_at = now_rfc3339();
        });
    }

    pub fn complete(&self, instance_id: &str, message: impl Into<String>) {
        self.update(instance_id, |progress| {
            progress.status = InstallProgressStatus::Completed;
            progress.stage = "completed".to_string();
            progress.message = message.into();
            progress.layer = None;
            progress.current = None;
            progress.total = None;
            progress.percent = Some(100.0);
            progress.updated_at = now_rfc3339();
        });
    }

    pub fn fail(&self, instance_id: &str, message: impl Into<String>) {
        self.update(instance_id, |progress| {
            progress.status = InstallProgressStatus::Failed;
            progress.stage = "failed".to_string();
            progress.message = message.into();
            progress.layer = None;
            progress.current = None;
            progress.total = None;
            progress.percent = None;
            progress.updated_at = now_rfc3339();
        });
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
        self.inner
            .write()
            .expect("install progress lock poisoned")
            .insert(progress.instance_id.clone(), progress);
    }

    fn update(&self, instance_id: &str, update: impl FnOnce(&mut InstallProgress)) {
        let mut progress = self.inner.write().expect("install progress lock poisoned");
        if let Some(progress) = progress.get_mut(instance_id) {
            update(progress);
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
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallProgressStatus {
    Running,
    Completed,
    Failed,
}

fn percent(current: Option<u64>, total: Option<u64>) -> Option<f64> {
    let current = current?;
    let total = total?;
    if total == 0 {
        return None;
    }
    Some(((current as f64 / total as f64) * 100.0).clamp(0.0, 100.0))
}
