use super::super::{FAIL_CLOSED_STOP_TIMEOUT, LOGICAL_ROLLBACK_READINESS_TIMEOUT};
use crate::{
    api::{
        http::{response::ApiError, router::AppState},
        import_export::remote::ImportMode,
    },
    instances::metadata::{InstanceMetadata, InstanceStatus},
    placement::DeploymentMode,
};
use serde::Serialize;
use std::{path::Path as FsPath, time::Duration};

fn shared_tenant(metadata: &InstanceMetadata) -> crate::placement::tenant::TenantTarget<'_> {
    crate::placement::tenant::TenantTarget {
        database: &metadata.database.name,
        username: &metadata.database.username,
    }
}

async fn shared_runtime(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<crate::placement::EngineRuntime, ApiError> {
    state
        .placements
        .get(metadata.runtime_id())
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to load shared runtime: {error}")))?
        .ok_or_else(|| {
            ApiError::Runtime(format!(
                "shared runtime {} is missing",
                metadata.runtime_id()
            ))
        })
}

pub(super) async fn check_shared_rollback_objects(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    if metadata.deployment_mode != DeploymentMode::Shared {
        return Ok(());
    }
    let runtime = shared_runtime(state, metadata).await?;
    match crate::placement::tenant::check_rollback_objects(
        &state.docker,
        &runtime,
        shared_tenant(metadata),
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(error @ crate::placement::tenant::TenantEngineError::RollbackGap { .. }) => {
            Err(ApiError::Conflict(error.to_string()))
        }
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to verify the shared tenant rollback catalog: {error}"
        ))),
    }
}

pub(super) async fn restore_import_target_route(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    if metadata.deployment_mode == DeploymentMode::Shared {
        let runtime = shared_runtime(state, metadata).await?;
        let password = metadata.tenant_password.as_deref().ok_or_else(|| {
            ApiError::Conflict(
                "the encrypted shared-tenant credential is missing; the import target remains fenced"
                    .to_string(),
            )
        })?;
        crate::placement::tenant::open_verified(
            &state.docker,
            &runtime,
            shared_tenant(metadata),
            password,
        )
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to re-enable and verify the shared tenant: {error}"
            ))
        })?;
    }
    state.instances.upsert(metadata.clone()).await;
    Ok(())
}

pub(super) async fn fail_quiesced_setup(
    state: &AppState,
    metadata: &InstanceMetadata,
    cause: ApiError,
) -> ApiError {
    match restore_import_target_route(state, metadata).await {
        Ok(()) => cause,
        Err(route_error) => {
            let quarantine = quarantine_uncertain_import(state, &metadata.instance_id).await;
            ApiError::Runtime(format!(
                "logical import setup failed: {cause}; target route recovery failed: {route_error}; target was failed closed{}",
                quarantine_suffix(&quarantine)
            ))
        }
    }
}

pub(super) async fn fence_import_target(
    state: &AppState,
    metadata: &InstanceMetadata,
    operation_timeout: Option<Duration>,
) -> Result<(), ApiError> {
    let drained = crate::instances::sessions::fence_and_wait(
        &state.instances,
        &state.gateway_supervisor.tenant_sessions(),
        &metadata.instance_id,
        FAIL_CLOSED_STOP_TIMEOUT,
    )
    .await;
    if !drained {
        return Err(ApiError::Runtime(
            "gateway sessions did not drain before the logical import generation fence".to_string(),
        ));
    }
    if metadata.deployment_mode == DeploymentMode::Shared {
        let runtime = shared_runtime(state, metadata).await?;
        let target = shared_tenant(metadata);
        crate::placement::tenant::fence(&state.docker, &runtime, target)
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to terminate and fence the shared tenant before rollback: {error}"
                ))
            })?;
        // The gateway route remains fenced. Re-enable only the database role so
        // DBE can apply the tenant-scoped rollback with the tenant credential.
        crate::placement::tenant::unfence(&state.docker, &runtime, target)
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to enable the fenced shared tenant for rollback: {error}"
                ))
            })?;
        return Ok(());
    }
    // A Docker transport/attach failure can leave the command running even after its client future
    // is gone. A confirmed stop is the process-generation fence: rollback is only safe after the
    // old database process is dead and a fresh one has reached startup readiness.
    stop_import_target(state, metadata, "before logical import rollback")
        .await
        .map_err(ApiError::Runtime)?;

    tokio::time::timeout(
        FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.start(metadata.protocol, metadata.runtime_id()),
    )
    .await
    .map_err(|_| {
        ApiError::Runtime("timed out restarting target before logical import rollback".to_string())
    })?
    .map_err(|error| {
        ApiError::Runtime(format!(
            "failed to restart target before logical import rollback: {error}"
        ))
    })?;

    let readiness_timeout = operation_timeout
        .unwrap_or(LOGICAL_ROLLBACK_READINESS_TIMEOUT)
        .min(LOGICAL_ROLLBACK_READINESS_TIMEOUT);
    state
        .docker
        .wait_until_ready(metadata.protocol, metadata.runtime_id(), readiness_timeout)
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "target did not become ready before logical import rollback: {error}"
            ))
        })
        .map(|_| ())
}

pub(crate) async fn quarantine_uncertain_import(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    let mut metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    metadata.status = InstanceStatus::Quarantined;
    metadata.desired_state = crate::instances::metadata::DesiredInstanceState::Stopped;
    metadata.updated_at = crate::jobs::import_export::now_rfc3339();

    // Remove gateway routes synchronously in memory before any Docker or SQLite wait. Existing
    // connections are cut off by the stop/kill below; new connections can no longer resolve.
    state.instances.upsert(metadata.clone()).await;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state
        .resource_cache
        .invalidate_runtime(&metadata.instance_id)
        .await;
    state.monitoring_cache.invalidate().await;

    let (runtime_result, persistence_result) = tokio::join!(
        stop_import_target(
            state,
            &metadata,
            "after an import lost durable commit or rollback certainty",
        ),
        state.manager.upsert(metadata.clone()),
    );
    let persistence_result =
        persistence_result.map_err(|error| format!("failed to persist quarantine: {error}"));

    tracing::error!(
        event = "audit uncertain_import_instance_quarantined",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        runtime_stopped = runtime_result.is_ok(),
        quarantine_persisted = persistence_result.is_ok(),
        "an import lost durable commit or rollback certainty; removed gateway routes and quarantined the target"
    );

    match (runtime_result, persistence_result) {
        (Ok(()), Ok(())) => Ok(()),
        (runtime, persistence) => {
            let mut failures = Vec::new();
            if let Err(error) = runtime {
                failures.push(error);
            }
            if let Err(error) = persistence {
                failures.push(error);
            }
            Err(ApiError::Runtime(failures.join("; ")))
        }
    }
}

async fn stop_import_target(
    state: &AppState,
    metadata: &InstanceMetadata,
    reason: &'static str,
) -> Result<(), String> {
    if metadata.deployment_mode == DeploymentMode::Shared {
        crate::api::instances::route_fence::fence(state, &metadata.instance_id).await;
        let runtime = shared_runtime(state, metadata)
            .await
            .map_err(|error| error.to_string())?;
        return crate::placement::tenant::fence(&state.docker, &runtime, shared_tenant(metadata))
            .await
            .map_err(|error| format!("failed to fence the shared tenant: {error}"));
    }
    let stop = tokio::time::timeout(
        FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.stop(metadata.protocol, metadata.runtime_id()),
    )
    .await;
    match stop {
        Ok(Ok(_)) => return Ok(()),
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => return Ok(()),
        Ok(Err(error)) => {
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %error,
                %reason,
                "graceful stop failed; forcing target shutdown"
            );
        }
        Err(_) => {
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %reason,
                "graceful stop timed out; forcing target shutdown"
            );
        }
    }

    match tokio::time::timeout(
        FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.kill(metadata.protocol, metadata.runtime_id()),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => Ok(()),
        Ok(Err(error)) => Err(format!(
            "failed to stop or kill quarantined target: {error}"
        )),
        Err(_) => Err("timed out stopping and killing quarantined target".to_string()),
    }
}

pub(super) fn quarantine_suffix(result: &Result<(), ApiError>) -> String {
    match result {
        Ok(()) => " and quarantined".to_string(),
        Err(error) => format!(
            " in memory and quarantined, but complete shutdown/persistence reported: {error}"
        ),
    }
}

pub(super) async fn commit_recovery_manifest(path: &FsPath) -> Result<(), ApiError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::shared::files::remove_private_file_durable(&path))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to commit import recovery metadata: {error}"
            ))
        })?
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to commit import recovery metadata: {error}"
            ))
        })
}

#[derive(Serialize)]
struct LogicalRecoveryManifest<'a> {
    schema_version: u32,
    recovery_kind: &'static str,
    instance_id: &'a str,
    protocol: &'static str,
    import_mode: ImportMode,
    rollback_file: &'a str,
    created_at: String,
}

pub(super) async fn write_logical_recovery_manifest(
    path: &FsPath,
    metadata: &InstanceMetadata,
    rollback_path: &FsPath,
    mode: ImportMode,
) -> Result<(), ApiError> {
    let durable_rollback = rollback_path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::shared::files::sync_private_file(&durable_rollback))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to sync rollback data: {error}")))?
        .map_err(|error| ApiError::Runtime(format!("failed to sync rollback data: {error}")))?;
    let rollback_file = rollback_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ApiError::Runtime("invalid rollback file name".to_string()))?;
    let manifest = serde_json::to_vec_pretty(&LogicalRecoveryManifest {
        schema_version: 1,
        recovery_kind: "logical_remote_import",
        instance_id: &metadata.instance_id,
        protocol: metadata.protocol.as_str(),
        import_mode: mode,
        rollback_file,
        created_at: crate::jobs::import_export::now_rfc3339(),
    })
    .map_err(|error| ApiError::Runtime(format!("failed to encode recovery manifest: {error}")))?;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        crate::shared::files::atomic_write_private(&path, &manifest)
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to write recovery manifest: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("failed to write recovery manifest: {error}")))
}
