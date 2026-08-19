use futures::StreamExt;
use std::os::unix::fs::FileTypeExt;

use crate::{
    api::{
        instances::{
            major_upgrade::{
                ImageVersionChange, classify_image_update, ensure_major_upgrade_supported,
            },
            update_instance_image_locked,
        },
        routes::AppState,
    },
    constants::MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
    instances::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus},
    shared::time::now_rfc3339,
};

use super::probe_instance_compatibility;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CompatibilityBootSummary {
    pub(crate) checked: usize,
    pub(crate) attestations_reused: usize,
    pub(crate) probed: usize,
    pub(crate) images_upgraded: usize,
    pub(crate) failed: usize,
}

#[derive(Debug)]
struct InstanceBootOutcome {
    reused: bool,
    probed: bool,
    upgraded: bool,
    failed: bool,
}

pub(crate) async fn reconcile_managed_compatibility_on_boot(
    state: &AppState,
) -> CompatibilityBootSummary {
    let instances = state
        .instances
        .list()
        .await
        .into_iter()
        .filter(|metadata| {
            metadata.desired_state == DesiredInstanceState::Running
                && metadata.status == InstanceStatus::Running
        })
        .collect::<Vec<_>>();

    let outcomes = futures::stream::iter(instances)
        .map(|snapshot| reconcile_one(state, snapshot))
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut summary = CompatibilityBootSummary::default();
    for outcome in outcomes {
        summary.checked += 1;
        summary.attestations_reused += usize::from(outcome.reused);
        summary.probed += usize::from(outcome.probed);
        summary.images_upgraded += usize::from(outcome.upgraded);
        summary.failed += usize::from(outcome.failed);
    }
    summary
}

async fn reconcile_one(state: &AppState, snapshot: InstanceMetadata) -> InstanceBootOutcome {
    let operation = state.instance_locks.lock(&snapshot.instance_id).await;
    let Some(metadata) = state.instances.get(&snapshot.instance_id).await else {
        return InstanceBootOutcome {
            reused: false,
            probed: false,
            upgraded: false,
            failed: false,
        };
    };
    if metadata.desired_state != DesiredInstanceState::Running
        || metadata.status != InstanceStatus::Running
    {
        return InstanceBootOutcome {
            reused: false,
            probed: false,
            upgraded: false,
            failed: false,
        };
    }

    let configured_image = state
        .config
        .images
        .configured_for_protocol(metadata.protocol)
        .to_string();
    let current_image = match state
        .docker
        .container_image(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(Some(image)) => image,
        Ok(None) => {
            isolate_failure(
                state,
                &metadata,
                "managed container image could not be inspected",
            )
            .await;
            return failed_outcome(false);
        }
        Err(error) => {
            isolate_failure(
                state,
                &metadata,
                &format!("managed container image inspection failed: {error}"),
            )
            .await;
            return failed_outcome(false);
        }
    };

    let runtime_spec_upgrade = runtime_spec_upgrade_required(&metadata).await;
    if current_image != configured_image || runtime_spec_upgrade {
        if runtime_spec_upgrade && current_image == configured_image {
            tracing::info!(
                event = "audit boot_runtime_spec_upgrade_started",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                image = %configured_image,
                "reconstructing a managed container once to install newly required private runtime sockets"
            );
        }
        let change = match classify_image_update(
            metadata.protocol,
            &current_image,
            &configured_image,
        ) {
            Ok(change) => change,
            Err(error) => {
                tracing::error!(
                    event = "audit boot_image_upgrade_rejected",
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    from_image = %current_image,
                    to_image = %configured_image,
                    %error,
                    "configured boot image upgrade could not be classified; retaining the current container"
                );
                let mut outcome =
                    attest_without_upgrade(state, metadata, false, Some(operation)).await;
                outcome.failed = true;
                return outcome;
            }
        };
        let major_upgrade = change == ImageVersionChange::Major;
        if major_upgrade && ensure_major_upgrade_supported(metadata.protocol).is_err() {
            tracing::error!(
                event = "audit boot_major_upgrade_unsupported",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                from_image = %current_image,
                to_image = %configured_image,
                "configured image crosses a major version that DBEV cannot migrate automatically; retaining the current compatible image"
            );
            let mut outcome = attest_without_upgrade(state, metadata, false, Some(operation)).await;
            outcome.failed = true;
            return outcome;
        }
        let instance_id = metadata.instance_id.clone();
        match update_instance_image_locked(
            state.clone(),
            operation,
            metadata,
            current_image,
            configured_image,
            major_upgrade,
            None,
        )
        .await
        {
            Ok(_) => {
                // Both image-update strategies force a compatibility probe
                // before committing and republishing the replacement. Do not
                // drop the operation lock and perform a redundant second
                // probe: an API mutation could otherwise replace the
                // container between those two checks.
                InstanceBootOutcome {
                    reused: false,
                    probed: true,
                    upgraded: true,
                    failed: false,
                }
            }
            Err(error) => {
                tracing::error!(
                    event = "audit boot_image_upgrade_failed",
                    %instance_id,
                    %error,
                    "configured boot image upgrade failed safely; continuing daemon boot for other instances"
                );
                let restored_operation = state.instance_locks.lock(&instance_id).await;
                if let Some(restored) = state.instances.get(&instance_id).await
                    && restored.status == InstanceStatus::Running
                    && restored.desired_state == DesiredInstanceState::Running
                {
                    let mut outcome =
                        attest_without_upgrade(state, restored, false, Some(restored_operation))
                            .await;
                    outcome.failed = true;
                    return outcome;
                }
                failed_outcome(false)
            }
        }
    } else {
        attest_without_upgrade(state, metadata, false, Some(operation)).await
    }
}

async fn runtime_spec_upgrade_required(metadata: &InstanceMetadata) -> bool {
    if metadata.protocol != crate::shared::protocol::Protocol::Qdrant {
        return false;
    }
    let crate::shared::backend::BackendEndpoint::UnixSocket { socket_path } = &metadata.backend
    else {
        return true;
    };
    let Some(http_socket) =
        crate::shared::backend::qdrant_http_socket_path(std::path::Path::new(socket_path))
    else {
        return true;
    };
    match tokio::fs::symlink_metadata(&http_socket).await {
        Ok(metadata) if metadata.file_type().is_socket() => !matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                tokio::net::UnixStream::connect(http_socket),
            )
            .await,
            Ok(Ok(_))
        ),
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => true,
    }
}

async fn attest_without_upgrade(
    state: &AppState,
    metadata: InstanceMetadata,
    upgraded: bool,
    _operation: Option<tokio::sync::OwnedMutexGuard<()>>,
) -> InstanceBootOutcome {
    match probe_instance_compatibility(&state.manager, &state.docker, &metadata, false).await {
        Ok(outcome) if outcome.compatible => InstanceBootOutcome {
            reused: outcome.reused,
            probed: !outcome.reused,
            upgraded,
            failed: false,
        },
        Ok(outcome) => {
            let reason = outcome
                .diagnostic
                .unwrap_or_else(|| "database engine version is unsupported".to_string());
            isolate_failure(state, &metadata, &reason).await;
            failed_outcome(upgraded)
        }
        Err(error) => {
            isolate_failure(
                state,
                &metadata,
                &format!("database compatibility probe failed: {error}"),
            )
            .await;
            failed_outcome(upgraded)
        }
    }
}

fn failed_outcome(upgraded: bool) -> InstanceBootOutcome {
    InstanceBootOutcome {
        reused: false,
        probed: false,
        upgraded,
        failed: true,
    }
}

async fn isolate_failure(state: &AppState, metadata: &InstanceMetadata, reason: &str) {
    let mut failed = metadata.clone();
    failed.status = InstanceStatus::Failed;
    // Keep operator intent so a corrected image/configuration is retried on a
    // later daemon boot; Failed instances are not published to route indexes.
    failed.desired_state = DesiredInstanceState::Running;
    failed.updated_at = now_rfc3339();
    state.instances.upsert(failed.clone()).await;
    let persistence = state.manager.upsert(failed).await;
    let stop = state
        .docker
        .stop(metadata.protocol, &metadata.instance_id)
        .await;
    tracing::error!(
        event = "audit compatibility_instance_isolated",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        %reason,
        persistence_error = persistence.as_ref().err().map(ToString::to_string),
        stop_error = stop.as_ref().err().map(ToString::to_string),
        "isolated an incompatible or unprobeable database instance; other gateway routes remain eligible"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        instances::metadata::{
            DatabaseIdentity, PublicEndpoint, RuntimeKind, RuntimeMetadata, SCHEMA_VERSION,
        },
        shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
    };

    #[tokio::test]
    async fn qdrant_runtime_spec_upgrade_is_required_only_until_rest_socket_is_live() {
        let directory = tempfile::tempdir().unwrap();
        let grpc_socket = directory.path().join("qdrant-grpc.sock");
        let http_socket = directory.path().join("qdrant-http.sock");
        let qdrant = metadata(Protocol::Qdrant, grpc_socket.display().to_string());
        assert!(runtime_spec_upgrade_required(&qdrant).await);

        let listener = tokio::net::UnixListener::bind(http_socket).unwrap();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        assert!(!runtime_spec_upgrade_required(&qdrant).await);
        accept.abort();

        let postgres = metadata(Protocol::Postgres, "/tmp/postgres.sock".to_string());
        assert!(!runtime_spec_upgrade_required(&postgres).await);
    }

    fn metadata(protocol: Protocol, socket_path: String) -> InstanceMetadata {
        InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: format!("inst_{protocol}"),
            protocol,
            status: InstanceStatus::Running,
            desired_state: DesiredInstanceState::Running,
            disk_limit_blocked: false,
            public: PublicEndpoint {
                host: "db.example.test".to_string(),
                port: protocol.default_container_port(),
            },
            backend: BackendEndpoint::UnixSocket { socket_path },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: format!("dbe-{protocol}"),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: "app".to_string(),
                username: "tenant".to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mysql_native_password_sha1_stage2: None,
            mysql_root_password: None,
            mongodb_root_password: None,
            postgres_admin_password: None,
            tenant_password: Some("secret".to_string()),
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-08-19T00:00:00Z".to_string(),
            updated_at: "2026-08-19T00:00:00Z".to_string(),
        }
    }
}
