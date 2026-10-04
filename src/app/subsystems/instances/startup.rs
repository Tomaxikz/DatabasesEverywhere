use super::lifecycle::LifecycleAction;
use super::normal_image_update;
use super::password::verify_resp_credential;
use super::start_checks::{check_disk_method, persisted_disk_limiter, soft_scanner_required};
use super::{STARTUP_READINESS_TIMEOUT, docker_error};
use crate::databases::engine::{CredentialKind, LifecycleFlow};
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::runtime::docker::DockerError;
use crate::server::metadata::InstanceMetadata;
use crate::server::paths::InstancePaths;
use crate::subsystems::instances::create::{
    flow_maintenance_credential, missing_credential_error, run_tenant_auth_step,
};
use crate::utils::limits::mib_to_bytes;
use crate::utils::time::now_rfc3339;

pub(super) async fn prepare_dedicated_start(
    state: &AppState,
    metadata: &mut InstanceMetadata,
) -> Result<(), ApiError> {
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let disk_limiter = persisted_disk_limiter(state, metadata);
    disk_limiter
        .check_method_change(&metadata.limits.disk_enforcement_method)
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    check_disk_method(&disk_limiter, metadata)?;
    let expected_data_source = disk_limiter
        .container_data_path(&paths.data)
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    match state
        .docker
        .verify_data_bind(
            metadata.protocol,
            &metadata.instance_id,
            &expected_data_source,
        )
        .await
    {
        Ok(()) => {}
        Err(error @ DockerError::DiskBindSourceMismatch { .. }) => {
            return Err(ApiError::Conflict(error.to_string()));
        }
        Err(error) => return Err(docker_error(error)),
    }
    if soft_scanner_required(state, metadata) {
        let snapshot = state
            .soft_disk_limiter
            .ensure_start_allowed(&crate::server::disk::soft::SoftDiskTarget {
                instance_id: metadata.instance_id.clone(),
                created_at: metadata.created_at.clone(),
                protocol: metadata.protocol,
                data_path: paths.data.clone(),
                limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
                durable_blocked: metadata.disk_limit_blocked,
            })
            .await
            .map_err(ApiError::Conflict)?;
        if metadata.disk_limit_blocked && !snapshot.blocked {
            metadata.disk_limit_blocked = false;
            metadata.updated_at = now_rfc3339();
            state
                .manager
                .upsert(metadata.clone())
                .await
                .map_err(|error| {
                    ApiError::Runtime(format!(
                        "failed to clear recovered disk-limit block: {error}"
                    ))
                })?;
        }
    }
    disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(())
}

pub(super) async fn recreate_with_current_console_policy(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<InstanceMetadata, ApiError> {
    let image = state
        .docker
        .container_recreation_image(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)?
        .ok_or_else(|| {
            ApiError::Conflict(
                "console-policy repair cannot preserve the installed image; update the image explicitly first".into(),
            )
        })?;
    let response = normal_image_update::update_instance_image_normal(
        state.clone(),
        metadata.clone(),
        image.clone(),
        image,
        None,
    )
    .await?;
    Ok(response.instance)
}

pub(super) async fn run_lifecycle_command(
    state: &AppState,
    metadata: &InstanceMetadata,
    action: LifecycleAction,
) -> Result<(), ApiError> {
    let docker = &state.docker;
    let protocol = metadata.protocol;
    let instance_id = metadata.instance_id.as_str();
    match action {
        LifecycleAction::Start => docker.start(protocol, instance_id).await,
        LifecycleAction::Stop => docker.stop(protocol, instance_id).await,
        LifecycleAction::Restart => docker.restart(protocol, instance_id).await,
        LifecycleAction::Kill => docker.kill(protocol, instance_id).await,
    }
    .map_err(docker_error)?;
    Ok(())
}

pub(super) async fn verify_startup_readiness(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    state
        .docker
        .wait_until_ready(
            metadata.protocol,
            &metadata.instance_id,
            STARTUP_READINESS_TIMEOUT,
        )
        .await
        .map_err(docker_error)?;
    harden_on_start(state, metadata).await?;
    verify_resp_credential(state, metadata).await?;
    let compatibility = crate::server::compatibility::probe_instance_compatibility(
        &state.manager,
        &state.docker,
        metadata,
        false,
    )
    .await
    .map_err(|error| {
        ApiError::Runtime(format!(
            "database compatibility attestation failed during activation: {error}"
        ))
    })?;
    if !compatibility.compatible {
        return Err(ApiError::Conflict(compatibility.diagnostic.unwrap_or_else(
            || "database engine version is unsupported".to_string(),
        )));
    }
    Ok(())
}

pub(super) async fn harden_on_start(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    let flow = LifecycleFlow::StartHarden;
    let Some(plan) = metadata.protocol.engine().tenant_auth_plan(flow) else {
        return Ok(());
    };
    let Some(password) = metadata.tenant_password.as_deref() else {
        return Err(missing_credential_error(
            metadata.protocol,
            flow,
            CredentialKind::Tenant,
        ));
    };
    let maintenance_password = flow_maintenance_credential(metadata, flow)?;
    run_tenant_auth_step(state, metadata, plan.step, password, maintenance_password).await
}

pub(super) async fn rollback_runtime_state(
    state: &AppState,
    metadata: &InstanceMetadata,
    should_be_running: bool,
) -> String {
    let result = if should_be_running {
        state
            .docker
            .start(metadata.protocol, &metadata.instance_id)
            .await
    } else {
        state
            .docker
            .stop(metadata.protocol, &metadata.instance_id)
            .await
    };
    match result {
        Ok(_) => "completed".to_string(),
        Err(error) if !should_be_running && error.is_not_running() => "completed".to_string(),
        Err(error) => {
            tracing::error!(
                event = "audit lifecycle_rollback_failed",
                instance_id = %metadata.instance_id,
                %error,
                "runtime may require operator reconciliation"
            );
            format!("failed: {error}")
        }
    }
}
