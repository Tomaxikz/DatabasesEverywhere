use crate::{
    instances::{
        manager::InstanceManager,
        metadata::{InstanceMetadata, InstanceStatus},
    },
    runtime::docker::{DockerContainerStatus, DockerRuntime},
    shared::{backend::BackendEndpoint, time::now_rfc3339},
};

#[derive(Debug, Clone, Default)]
pub struct ReconcileSummary {
    pub checked: usize,
    pub booting: usize,
    pub running: usize,
    pub stopped: usize,
    pub failed: usize,
    pub quarantined: usize,
}

pub async fn reconcile_all(
    manager: &InstanceManager,
    docker: &DockerRuntime,
) -> Result<ReconcileSummary, anyhow::Error> {
    let instances = manager.store().list().await;
    let mut summary = ReconcileSummary::default();

    for metadata in instances {
        summary.checked += 1;
        let reconciled = if metadata.status == InstanceStatus::Quarantined {
            stop_quarantined_instance(&metadata, docker).await?;
            metadata
        } else {
            reconcile_metadata(metadata, docker).await
        };
        match reconciled.status {
            InstanceStatus::Booting => summary.booting += 1,
            InstanceStatus::Running => summary.running += 1,
            InstanceStatus::Stopped => summary.stopped += 1,
            InstanceStatus::Failed => summary.failed += 1,
            InstanceStatus::Quarantined => summary.quarantined += 1,
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
    if metadata.status == InstanceStatus::Quarantined {
        return metadata;
    }
    metadata.updated_at = now_rfc3339();
    reconcile_metadata(metadata, docker).await
}

async fn stop_quarantined_instance(
    metadata: &InstanceMetadata,
    docker: &DockerRuntime,
) -> Result<(), anyhow::Error> {
    match docker
        .inspect_instance(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(inspection)
            if matches!(
                inspection.status,
                DockerContainerStatus::Running | DockerContainerStatus::Starting
            ) =>
        {
            docker
                .stop(metadata.protocol, &metadata.instance_id)
                .await?;
            tracing::warn!(
                event = "audit quarantined_instance_stopped",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                "stopped a quarantined instance before opening gateways"
            );
        }
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
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
            let socket_backend = matches!(metadata.backend, BackendEndpoint::UnixSocket { .. });
            if inspection.network_mode.as_deref() != Some("none") || !socket_backend {
                if matches!(
                    inspection.status,
                    DockerContainerStatus::Running | DockerContainerStatus::Starting
                ) && let Err(error) = docker.stop(metadata.protocol, &metadata.instance_id).await
                {
                    tracing::error!(
                        %error,
                        instance_id = %metadata.instance_id,
                        "failed to stop legacy networked container during quarantine"
                    );
                }
                tracing::warn!(
                    event = "audit legacy_networked_instance_quarantined",
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    network_mode = ?inspection.network_mode,
                    socket_backend,
                    "quarantined instance that does not satisfy network-none socket isolation; recreate it before reopening gateways"
                );
                metadata.status = InstanceStatus::Quarantined;
                metadata.updated_at = now_rfc3339();
                return metadata;
            }
            metadata.status = classify_container_status(inspection.status);
            metadata.runtime.network_mode = "none".to_string();
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

pub fn classify_container_status(status: DockerContainerStatus) -> InstanceStatus {
    match status {
        DockerContainerStatus::Running => InstanceStatus::Running,
        DockerContainerStatus::Starting => InstanceStatus::Booting,
        DockerContainerStatus::Stopped => InstanceStatus::Stopped,
        DockerContainerStatus::Failed => InstanceStatus::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_live_container_statuses_for_the_api() {
        assert_eq!(
            classify_container_status(DockerContainerStatus::Starting),
            InstanceStatus::Booting
        );
        assert_eq!(
            classify_container_status(DockerContainerStatus::Running),
            InstanceStatus::Running
        );
        assert_eq!(
            classify_container_status(DockerContainerStatus::Stopped),
            InstanceStatus::Stopped
        );
        assert_eq!(
            classify_container_status(DockerContainerStatus::Failed),
            InstanceStatus::Failed
        );
    }
}
