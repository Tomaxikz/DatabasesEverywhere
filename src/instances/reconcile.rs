use futures::StreamExt;

use crate::{
    instances::{
        manager::InstanceManager,
        metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus, RuntimeKind},
    },
    runtime::docker::{DockerContainerStatus, DockerError, DockerRuntime},
    shared::{backend::BackendEndpoint, time::now_rfc3339},
};

const RECONCILE_CONCURRENCY: usize = 8;

pub async fn validate_configured_runtime(
    manager: &InstanceManager,
    docker: &DockerRuntime,
) -> Result<(), anyhow::Error> {
    let configured = RuntimeKind::from(docker.engine());
    let mismatches = runtime_kind_mismatches(&manager.store().list().await, configured);
    if mismatches.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "refusing to switch container engines while managed instances exist: daemon.engine={} but {} instance(s) belong to {} (examples: {}). Migrate or remove those instances with the original engine before changing daemon.engine",
        configured.as_str(),
        mismatches.len(),
        mismatches[0].1.as_str(),
        mismatches
            .iter()
            .take(5)
            .map(|(instance_id, _)| instance_id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn runtime_kind_mismatches(
    instances: &[InstanceMetadata],
    configured: RuntimeKind,
) -> Vec<(String, RuntimeKind)> {
    instances
        .iter()
        .filter(|metadata| runtime_kind_mismatch(metadata.runtime.kind, configured))
        .map(|metadata| (metadata.instance_id.clone(), metadata.runtime.kind))
        .collect()
}

fn runtime_kind_mismatch(actual: RuntimeKind, configured: RuntimeKind) -> bool {
    actual != configured
}

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
    let outcomes = futures::stream::iter(instances)
        .map(|metadata| reconcile_one(metadata, docker))
        .buffer_unordered(RECONCILE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut summary = ReconcileSummary::default();

    for reconciled in outcomes {
        summary.checked += 1;
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
        metadata.desired_state = DesiredInstanceState::Stopped;
    }
    if metadata.desired_state == DesiredInstanceState::Stopped
        || metadata.status == InstanceStatus::Quarantined
    {
        if let Err(error) = stop_inactive_instance(&metadata, docker).await {
            tracing::error!(
                %error,
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                desired_state = metadata.desired_state.as_str(),
                "failed to enforce inactive instance state during reconciliation"
            );
            if metadata.status != InstanceStatus::Quarantined {
                metadata.status = InstanceStatus::Failed;
                metadata.updated_at = now_rfc3339();
            }
            return metadata;
        }
        if metadata.status == InstanceStatus::Quarantined {
            return metadata;
        }
    }
    metadata.updated_at = now_rfc3339();
    reconcile_metadata(metadata, docker).await
}

async fn stop_inactive_instance(
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
            match docker.stop(metadata.protocol, &metadata.instance_id).await {
                Ok(_) => tracing::warn!(
                    event = "audit inactive_instance_stopped",
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    desired_state = metadata.desired_state.as_str(),
                    quarantined = metadata.status == InstanceStatus::Quarantined,
                    "stopped an instance whose durable desired state is inactive"
                ),
                Err(error) if inactive_stop_error_is_benign(&error) => tracing::debug!(
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    "inactive instance container was already not running"
                ),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn inactive_stop_error_is_benign(error: &DockerError) -> bool {
    error.is_not_running()
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
                metadata.desired_state = DesiredInstanceState::Stopped;
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
        // `created` means the replacement exists but has never been started.
        // Classifying it as stopped lets durable desired-running boot recovery
        // issue the missing start instead of stranding it as Booting forever.
        DockerContainerStatus::Created => InstanceStatus::Stopped,
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
            classify_container_status(DockerContainerStatus::Created),
            InstanceStatus::Stopped
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

    #[test]
    fn detects_engine_switches_before_reconciliation_can_mutate_status() {
        assert!(runtime_kind_mismatch(
            RuntimeKind::Docker,
            RuntimeKind::Podman
        ));
        assert!(!runtime_kind_mismatch(
            RuntimeKind::Podman,
            RuntimeKind::Podman
        ));
    }

    #[test]
    fn created_container_stop_response_satisfies_inactive_reconciliation() {
        let error = DockerError::Api(bollard::errors::Error::DockerResponseServerError {
            status_code: 304,
            message: "container is already stopped".to_string(),
        });

        assert!(inactive_stop_error_is_benign(&error));
    }
}
