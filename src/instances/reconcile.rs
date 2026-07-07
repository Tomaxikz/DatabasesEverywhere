use crate::{
    instances::{
        manager::InstanceManager,
        metadata::{InstanceMetadata, InstanceStatus},
    },
    runtime::docker::{DockerContainerStatus, DockerRuntime},
    shared::{backend::BackendEndpoint, time::now_rfc3339},
    storage::repositories::RepositoryError,
};

#[derive(Debug, Clone, Default)]
pub struct ReconcileSummary {
    pub checked: usize,
    pub running: usize,
    pub stopped: usize,
    pub failed: usize,
}

pub async fn reconcile_all(
    manager: &InstanceManager,
    docker: &DockerRuntime,
) -> Result<ReconcileSummary, RepositoryError> {
    let instances = manager.store().list().await;
    let mut summary = ReconcileSummary::default();

    for metadata in instances {
        summary.checked += 1;
        let reconciled = reconcile_metadata(metadata, docker).await;
        match reconciled.status {
            InstanceStatus::Running => summary.running += 1,
            InstanceStatus::Stopped => summary.stopped += 1,
            InstanceStatus::Failed => summary.failed += 1,
            InstanceStatus::Creating | InstanceStatus::Deleting => {}
        }
        manager.upsert(reconciled).await?;
    }

    Ok(summary)
}

pub async fn reconcile_one(
    mut metadata: InstanceMetadata,
    docker: &DockerRuntime,
) -> InstanceMetadata {
    metadata.updated_at = now_rfc3339();
    reconcile_metadata(metadata, docker).await
}

async fn reconcile_metadata(
    mut metadata: InstanceMetadata,
    docker: &DockerRuntime,
) -> InstanceMetadata {
    match docker
        .inspect_instance(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(inspection) => {
            metadata.status = match inspection.status {
                DockerContainerStatus::Running => InstanceStatus::Running,
                DockerContainerStatus::Starting => InstanceStatus::Creating,
                DockerContainerStatus::Stopped => InstanceStatus::Stopped,
                DockerContainerStatus::Failed => InstanceStatus::Failed,
            };
            if let (InstanceStatus::Running, Some(host)) = (metadata.status, inspection.network_ip)
                && !docker.uses_rootless_podman()
                && let BackendEndpoint::DockerTcp {
                    host: current_host, ..
                } = &mut metadata.backend
            {
                *current_host = host;
            }
        }
        Err(error) if error.is_not_found() => {
            metadata.status = InstanceStatus::Failed;
        }
        Err(error) => {
            tracing::warn!(%error, instance_id = %metadata.instance_id, "failed to reconcile instance");
            metadata.status = InstanceStatus::Failed;
        }
    }
    metadata.updated_at = now_rfc3339();
    metadata
}
