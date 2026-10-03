use std::{future::Future, time::Duration};

use secrecy::SecretString;
use tokio::time::sleep;

use crate::{
    databases::{
        self,
        engine::{
            CredentialKind, DedicatedSpecInput, LifecycleFlow, LifecycleRejection, PostLaunchStep,
            RouteIdentity, TenantAuthStep,
        },
    },
    instance::disk::DiskLimiter,
    instance::{
        metadata::{
            DatabaseIdentity, InstanceMetadata, InstanceStatus, PublicEndpoint, RuntimeKind,
            RuntimeMetadata, SCHEMA_VERSION,
        },
        paths::InstancePaths,
    },
    routes::http::{policy::DestructiveActionPolicy, response::ApiError, router::AppState},
    runtime::docker::{DockerImagePullProgress, DockerInstanceSpec, DockerRuntime, ExecRecovery},
    subsystems::{
        instances::{
            docker_error,
            images::{check_image_allowed, validate_image},
            requests::{
                CreateInstanceRequest, limits_from_request, validate_create_config,
                validate_create_request,
            },
        },
        monitoring::resources::{read_host_cpu_cores, read_host_disk, read_host_memory},
    },
    utils::{
        backend::BackendEndpoint,
        limits::{bytes_to_mib_ceil, mib_to_bytes},
        logs::summarize_failure_logs,
        protocol::Protocol,
        redaction,
        shell::sh_quote,
        time::now_rfc3339,
    },
};

pub(crate) mod dedicated;
mod mongodb;
mod mysql_hardening;
pub(crate) mod shared;

pub(crate) use dedicated::{
    attest as attest_dedicated_target, build as build_dedicated_target,
    launch as launch_dedicated_target,
};
pub(crate) use shared::{build_shared_metadata, claim_runtime as claim_shared_runtime};

pub(crate) use mongodb::bootstrap_root as bootstrap_mongodb_root;
pub(crate) use mongodb::provision_tenant as provision_mongodb_tenant_user;

#[cfg(test)]
use mysql_hardening::failed_auth_metadata;
pub(crate) use mysql_hardening::{
    harden_mysql_accounts, harden_mysql_tenant_auth, verify_mysql_root_auth,
};

const DATABASE_READINESS_TIMEOUT: Duration = Duration::from_secs(120);
const READINESS_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const FAILURE_LOG_SUMMARY_MAX_CHARS: usize = 4_000;

mod allocation;
mod cleanup;
mod conflicts;
mod launch;
mod tenant_auth;
pub(crate) use allocation::*;
use cleanup::*;
use conflicts::*;
pub(crate) use launch::*;
pub(crate) use tenant_auth::*;

pub async fn create_instance_from_request(
    state: &AppState,
    mut request: CreateInstanceRequest,
) -> Result<InstanceMetadata, ApiError> {
    request.owner =
        request
            .server_id
            .as_ref()
            .map(|server_id| crate::instance::placement::PoolOwner {
                panel_id: state.config.token_id.clone(),
                server_id: server_id.clone(),
            });
    if let Some(owner) = &request.owner {
        owner.check().map_err(ApiError::BadRequest)?;
    }
    validate_create_request(&request)?;
    validate_create_config(&state.config, &request)?;
    if request.deployment_mode == crate::instance::placement::DeploymentMode::Shared
        && !state.gateway_supervisor.is_ready()
    {
        return Err(ApiError::ServiceUnavailable(
            "shared tenant creation is unavailable until database gateway recovery completes"
                .to_string(),
        ));
    }
    let _creation =
        if request.deployment_mode == crate::instance::placement::DeploymentMode::Dedicated {
            Some(state.instance_locks.lock_creation().await)
        } else {
            None
        };
    let _operation = state.instance_locks.lock(&request.instance_id).await;
    reject_duplicate_instance(state, &request).await?;
    handle_stale_instance_resources(state, &request).await?;
    let requested_limits = request
        .limits
        .as_ref()
        .map(limits_from_request)
        .unwrap_or_default();
    if request.deployment_mode == crate::instance::placement::DeploymentMode::Shared {
        return shared::create(state, request).await;
    }
    enforce_node_allocation_policy(state, &requested_limits, None).await?;

    let cleanup = CreateFailureCleanup::new(state, request.protocol, request.instance_id.clone());
    match dedicated::create(state, request).await {
        Ok(metadata) => Ok(metadata),
        Err(error) => {
            cleanup.run(&error).await;
            Err(error)
        }
    }
}

pub(crate) async fn prepare_instance_container_user(
    docker: &DockerRuntime,
    paths: &InstancePaths,
    protocol: Protocol,
) -> Result<String, crate::instance::paths::InstancePathError> {
    if let Some(user) = docker.rootless_podman_container_user(protocol) {
        let (uid, gid) = docker
            .rootless_podman_host_owner()
            .ok_or(crate::instance::paths::InstancePathError::MissingRuntimeOwner)?;
        paths.apply_rootless_owner(uid, gid).await?;
        Ok(user.to_string())
    } else {
        paths.apply_container_owner().await?;
        paths.container_user().await
    }
}

pub(crate) fn resolve_image(
    state: &AppState,
    request: &CreateInstanceRequest,
) -> Result<String, ApiError> {
    let image = request
        .image
        .as_deref()
        .map(validate_image)
        .transpose()?
        .map(str::to_string)
        .unwrap_or_else(|| {
            state
                .config
                .images
                .configured_for_protocol(request.protocol)
                .to_string()
        });
    check_image_allowed(state, request.protocol, &image)?;
    Ok(image)
}

fn fail_bad_request(
    state: &AppState,
    instance_id: &str,
    error: impl std::fmt::Display,
) -> ApiError {
    state
        .install_progress
        .fail_public(instance_id, "bad_request", error.to_string());
    ApiError::BadRequest(error.to_string())
}

fn fail_runtime(state: &AppState, instance_id: &str, error: impl std::fmt::Display) -> ApiError {
    state
        .install_progress
        .fail_internal(instance_id, "instance creation", &error);
    ApiError::Runtime(error.to_string())
}

fn public_port(state: &AppState, protocol: Protocol) -> u16 {
    let bind = protocol.engine().listener(&state.config).bind;
    bind.rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or_else(|| protocol.engine().default_container_port())
}

pub(crate) fn protocol_pids_limit(state: &AppState, protocol: Protocol) -> i64 {
    protocol
        .engine()
        .pids_limit(&state.config.security.pids_limits)
        .unwrap_or(state.config.security.pids_limit)
}

pub(crate) fn backend_endpoint(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<BackendEndpoint, ApiError> {
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    Ok(BackendEndpoint::UnixSocket {
        socket_path: crate::utils::backend::backend_socket_path(&paths.sockets, protocol)
            .display()
            .to_string(),
    })
}

#[cfg(test)]
mod tests;
