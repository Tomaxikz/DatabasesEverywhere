use super::super::docker_error;
use super::super::normal_image_update::{image_quarantine_summary, quarantine_image_update};
use super::super::runtime_info::{fail_image_update_api, fail_image_update_runtime};
use crate::databases::engine::LifecycleFlow;
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::server::metadata::InstanceMetadata;
use crate::subsystems::instances::create::{flow_maintenance_credential, run_tenant_auth_step};
use std::time::Duration;

const SOURCE_READINESS_TIMEOUT: Duration = Duration::from_secs(180);

pub(super) async fn quiesce_upgrade_source(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
) -> Result<(), ApiError> {
    // Removing the route blocks new sessions. Restarting the source then
    // terminates every already-established gateway session before the dump,
    // so writes cannot race the logical snapshot and disappear at cutover.
    crate::subsystems::instances::route_fence::fence(state, &metadata.instance_id).await;
    state
        .docker
        .restart(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)?;
    verify_upgrade_source(state, metadata, password).await
}

async fn verify_upgrade_source(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
) -> Result<(), ApiError> {
    state
        .docker
        .wait_until_ready(
            metadata.protocol,
            &metadata.instance_id,
            SOURCE_READINESS_TIMEOUT,
        )
        .await
        .map_err(docker_error)?;
    harden_upgrade_credentials(state, metadata, password, "before major-upgrade export").await?;
    let compatibility = crate::server::compatibility::probe_instance_compatibility(
        &state.manager,
        &state.docker,
        metadata,
        false,
    )
    .await
    .map_err(|error| {
        ApiError::Runtime(format!(
            "source compatibility verification failed before major-upgrade export: {error}"
        ))
    })?;
    if !compatibility.compatible {
        return Err(ApiError::Conflict(compatibility.diagnostic.unwrap_or_else(
            || "source database version is unsupported".to_string(),
        )));
    }
    Ok(())
}

pub(super) async fn harden_upgrade_target(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
) -> Result<(), ApiError> {
    harden_upgrade_credentials(state, metadata, password, "after major-upgrade cutover").await
}

async fn harden_upgrade_credentials(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
    phase: &'static str,
) -> Result<(), ApiError> {
    let flow = LifecycleFlow::UpgradeHarden(phase);
    let Some(plan) = metadata.protocol.engine().tenant_auth_plan(flow) else {
        return Ok(());
    };
    let maintenance_password = flow_maintenance_credential(metadata, flow)?;
    run_tenant_auth_step(state, metadata, plan.step, password, maintenance_password).await
}

pub(super) async fn restore_upgrade_route(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
    original_error: ApiError,
) -> ApiError {
    let original_message = original_error.to_string();
    match verify_upgrade_source(state, metadata, password).await {
        Ok(()) => {
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
            tracing::warn!(
                event = "audit instance_major_upgrade_pre_cutover_restored",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                error = %original_message,
                "major upgrade failed before cutover; the verified source route was restored without changing its data"
            );
            fail_image_update_api(state, &metadata.instance_id, original_error)
        }
        Err(recovery_error) => {
            let quarantine = quarantine_image_update(
                state,
                metadata,
                "major-upgrade source could not be reverified after a pre-cutover failure",
            )
            .await;
            fail_image_update_runtime(
                state,
                &metadata.instance_id,
                format!(
                    "major upgrade failed before cutover ({original_message}), source recovery failed ({recovery_error}); {}",
                    image_quarantine_summary(&quarantine)
                ),
            )
        }
    }
}
