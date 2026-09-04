use std::time::Duration;

use axum::extract::State;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use super::{docker_error, image_update_spec};
use crate::{
    api::{
        http::{
            policy::ApiRequestContext,
            response::{ApiError, ApiJson, ApiPath, ApiResponse, ApiResult},
            router::AppState,
        },
        instances::{
            create::{
                launch_container_from_spec, prepare_instance_container_user, protocol_pids_limit,
            },
            requests::validate_database_password,
        },
    },
    auth::scopes,
    disk::DiskLimiter,
    instances::{
        metadata::{InstanceMetadata, InstanceStatus},
        paths::InstancePaths,
    },
    runtime::docker::{DockerContainerStatus, DockerInstanceSpec},
    shared::{files::read_bounded_private_file, protocol::Protocol, time::now_rfc3339},
};

#[cfg(test)]
use crate::api::instances::requests::MAX_PASSWORD_CHARACTERS;

const MAX_ACL_FILE_BYTES: u64 = 64 * 1024;
const ROTATION_READINESS_TIMEOUT: Duration = Duration::from_secs(30);
const PASSWORD_EXEC_TIMEOUT: Duration = Duration::from_secs(30);

mod rotation;
mod supervision;
use rotation::*;
use supervision::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetInstancePasswordRequest {
    pub password: String,
}

pub(crate) async fn verify_resp_credential(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Valkey) {
        let password = metadata.tenant_password.as_deref().ok_or_else(|| {
            ApiError::Conflict("the current RESP credential is missing".to_string())
        })?;
        verify_tenant_credential(state, metadata, &SecretString::from(password.to_string()))
            .await?;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct ResetInstancePasswordResponse {
    pub instance: InstanceMetadata,
    pub restarted: bool,
}

#[derive(Default)]
struct PreviousCredential {
    environment: Option<SecretString>,
    maintenance: Option<SecretString>,
    maintenance_username: Option<String>,
    native_password_verifier: Option<String>,
    mysql_auth_plugin: Option<String>,
    mysql_auth_string_b64: Option<SecretString>,
    acl: Option<Vec<u8>>,
}

pub async fn reset_instance_password(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiJson(request): ApiJson<ResetInstancePasswordRequest>,
) -> ApiResult<ResetInstancePasswordResponse> {
    auth.require_scope(scopes::INSTANCES_WRITE)?;
    let permit = state
        .import_export_jobs
        .try_admit_exclusive(&instance_id)
        .map_err(|error| match error {
            crate::jobs::import_export::JobAdmissionError::GlobalCapacity => {
                ApiError::ServiceUnavailable(
                    "database maintenance queue is at capacity; retry later".to_string(),
                )
            }
            crate::jobs::import_export::JobAdmissionError::InstanceCapacity => {
                ApiError::Conflict(format!(
                    "another database maintenance operation is already running for {instance_id}"
                ))
            }
            crate::jobs::import_export::JobAdmissionError::ShuttingDown => {
                ApiError::ServiceUnavailable(
                    "daemon shutdown has started; password resets are not accepted".to_string(),
                )
            }
        })?;
    let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
    let worker_instance_id = instance_id.clone();
    tokio::spawn(async move {
        let recovery_state = state.clone();
        let worker_state = state.clone();
        let recovery_instance_id = worker_instance_id.clone();
        let result = run_password_worker(
            &state.instance_locks,
            &worker_instance_id,
            reset_instance_password_inner(worker_state, instance_id, request),
            move |error| async move {
                let quarantine_summary = recover_password_panic(
                    &recovery_state,
                    &recovery_instance_id,
                )
                .await;
                tracing::error!(
                    event = "audit instance_password_reset_worker_failed",
                    instance_id = %recovery_instance_id,
                    %error,
                    "password reset worker failed unexpectedly"
                );
                Err(ApiError::Runtime(format!(
                    "password reset worker failed unexpectedly; {quarantine_summary}; repair or recover it before retrying"
                )))
            },
        )
        .await;
        drop(permit);
        let _ = result_sender.send(result);
    });
    result_receiver.await.map_err(|_| {
        ApiError::Runtime("password reset worker stopped before producing a result".to_string())
    })?
}

async fn reset_instance_password_inner(
    state: AppState,
    instance_id: String,
    request: ResetInstancePasswordRequest,
) -> ApiResult<ResetInstancePasswordResponse> {
    let new_password = SecretString::from(request.password);
    let mut metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    super::deployment::ensure_no_active_migration(&state, &instance_id).await?;
    let _execution = state
        .import_export_jobs
        .acquire_execution(crate::jobs::import_export::JobResourceCost::estimate(
            crate::jobs::import_export::JobEstimateInput {
                protocol: metadata.protocol,
                input_size_bytes: 1,
                rollback_size_bytes: 0,
                wipe: false,
                compressed: false,
                export: false,
            },
        ))
        .await
        .map_err(|error| match error {
            crate::jobs::import_export::SchedulerAcquireError::Closed => {
                ApiError::ServiceUnavailable("daemon shutdown has started".to_string())
            }
            crate::jobs::import_export::SchedulerAcquireError::InsufficientCapacity => {
                ApiError::Conflict(
                    "password maintenance exceeds a fixed dynamic import/export scheduler budget"
                        .to_string(),
                )
            }
        })?;
    validate_password(metadata.protocol, &new_password)?;
    if metadata.deployment_mode == crate::placement::DeploymentMode::Shared {
        return super::shared::reset_password(&state, metadata, new_password).await;
    }
    require_resettable_instance(&state, &metadata).await?;
    ensure_qdrant_route_is_available(&state, &metadata, &new_password).await?;

    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    // Existing instances must keep using the bind source recorded in durable
    // metadata. In particular, RESP ACL files must be read and replaced
    // through a live FuseQuota mount rather than by mutating its raw backing
    // directory behind the helper's cache.
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_persisted_method(&metadata.limits.disk_enforcement_method);
    let credential_data_path = disk_limiter
        .container_data_path(&paths.data)
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let previous = capture_previous_credential(&state, &metadata, &credential_data_path).await?;
    if !requires_container_recreation(metadata.protocol, &previous) {
        attest_password_reset_target(&state, &metadata).await?;
        return reset_live_password(
            &state,
            metadata,
            &paths,
            &credential_data_path,
            &new_password,
            &previous,
        )
        .await;
    }
    let previous_metadata = metadata.clone();
    let image = state
        .docker
        .container_recreation_image(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)?
        .ok_or_else(|| {
            ApiError::Conflict(
                "the current image reference no longer resolves to the exact running image; restore that local tag or perform an explicit image update before resetting the password"
                    .to_string(),
            )
        })?;
    let project_id = state
        .docker
        .container_project_id(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)?;
    disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let container_data_path = disk_limiter
        .container_data_path(&paths.data)
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let container_user = prepare_instance_container_user(&state.docker, &paths, metadata.protocol)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;

    let new_spec_password = spec_password(metadata.protocol, &new_password, &previous, false)?;
    let old_spec_password = spec_password(metadata.protocol, &new_password, &previous, true)?;
    let mut new_spec = image_update_spec(
        &metadata,
        &paths,
        container_data_path.clone(),
        &image,
        new_spec_password,
        protocol_pids_limit(&state, metadata.protocol),
    )
    .await?;
    let mut old_spec = image_update_spec(
        &metadata,
        &paths,
        container_data_path,
        &image,
        old_spec_password,
        protocol_pids_limit(&state, metadata.protocol),
    )
    .await?;
    for spec in [&mut new_spec, &mut old_spec] {
        spec.user = Some(container_user.clone());
        spec.project_id.clone_from(&project_id);
    }

    let recreation_started = Instant::now();
    tracing::info!(
        event = "audit instance_password_reset_recreation_started",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        "recreating instance to apply its startup-managed credential"
    );
    delete_managed_container(&state, metadata.protocol, &metadata.instance_id).await?;
    super::route_fence::fence(&state, &metadata.instance_id).await;
    let result = reset_password(
        &state,
        &metadata,
        &paths,
        &credential_data_path,
        &new_spec,
        &new_password,
    )
    .await;

    if let Err(error) = result {
        return rollback_or_fail(
            &state,
            &metadata,
            &paths,
            &credential_data_path,
            &old_spec,
            &previous,
            error,
        )
        .await;
    }

    if let Err(error) = attest_password_reset_target(&state, &metadata).await {
        return rollback_or_fail(
            &state,
            &metadata,
            &paths,
            &credential_data_path,
            &old_spec,
            &previous,
            error,
        )
        .await;
    }

    let qdrant_route_secret = state.config.websocket_jwt_secret();
    apply_new_route_auth(&mut metadata, &new_password, &previous, qdrant_route_secret);
    metadata.status = InstanceStatus::Running;
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state
        .manager
        .upsert_recovered_secrets(metadata.clone())
        .await
    {
        let commit_error = error.to_string();
        match resolve_password_metadata_commit(&state, &previous_metadata, &metadata).await {
            PasswordMetadataCommitResolution::Committed => {
                state.instances.upsert(metadata.clone()).await;
                tracing::warn!(
                    event = "audit instance_password_reset_commit_ack_lost",
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    error = %commit_error,
                    "password reset metadata was durably committed despite a failed commit acknowledgement"
                );
            }
            PasswordMetadataCommitResolution::Previous => {
                return rollback_or_fail(
                    &state,
                    &previous_metadata,
                    &paths,
                    &credential_data_path,
                    &old_spec,
                    &previous,
                    ApiError::Runtime(format!(
                        "failed to persist rotated instance authentication: {commit_error}"
                    )),
                )
                .await;
            }
            PasswordMetadataCommitResolution::Uncertain { reason, persisted } => {
                return fail_uncertain_password_commit(
                    &state,
                    &metadata,
                    persisted.as_deref(),
                    &commit_error,
                    &reason,
                )
                .await;
            }
        }
    }

    invalidate_password_caches(&state, &metadata).await;
    tracing::info!(
        event = "audit instance_password_reset_recreation_ready",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        elapsed_ms = recreation_started.elapsed().as_millis(),
        "recreated instance is ready with its replacement credential"
    );
    tracing::info!(
        event = "audit instance_password_reset",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        "instance password reset completed"
    );

    Ok(ApiResponse::ok(ResetInstancePasswordResponse {
        instance: metadata,
        restarted: true,
    }))
}

fn requires_container_recreation(protocol: Protocol, previous: &PreviousCredential) -> bool {
    match protocol {
        // Both services read their public credential from immutable container
        // startup configuration and have no safe live reload mechanism.
        Protocol::Clickhouse | Protocol::Qdrant => true,
        // The running server must authenticate ACL LOAD with the current
        // tenant. Legacy instances have no protected plaintext credential and
        // therefore need one recreation before later rotations can be live.
        Protocol::Redis | Protocol::Valkey => previous.environment.is_none(),
        Protocol::Postgres | Protocol::Mariadb | Protocol::Mysql | Protocol::Mongodb => false,
    }
}

fn validate_password(protocol: Protocol, password: &SecretString) -> Result<(), ApiError> {
    validate_database_password(protocol, password.expose_secret())
}

async fn require_resettable_instance(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    if metadata.desired_state != crate::instances::metadata::DesiredInstanceState::Running {
        return Err(ApiError::Conflict(
            "password reset requires the instance desired state to be running".to_string(),
        ));
    }
    let recoverable_failed_instance = metadata.status == InstanceStatus::Failed
        && metadata.desired_state == crate::instances::metadata::DesiredInstanceState::Running;
    if metadata.status != InstanceStatus::Running && !recoverable_failed_instance {
        return Err(ApiError::Conflict(format!(
            "password reset requires a running instance or a failed running instance awaiting credential recovery; current status is {}",
            metadata.status.as_str()
        )));
    }
    let inspection = state
        .docker
        .inspect_instance(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)?;
    if inspection.status != DockerContainerStatus::Running {
        return Err(ApiError::Conflict(
            "password reset requires a running managed container; reconcile the instance first"
                .to_string(),
        ));
    }
    if !recoverable_failed_instance {
        state
            .docker
            .wait_until_ready(
                metadata.protocol,
                &metadata.instance_id,
                Duration::from_secs(10),
            )
            .await
            .map_err(|error| {
                ApiError::Conflict(format!(
                    "the current database credential is not ready for rotation: {error}"
                ))
            })?;
    }
    Ok(())
}

async fn ensure_qdrant_route_is_available(
    state: &AppState,
    metadata: &InstanceMetadata,
    new_password: &SecretString,
) -> Result<(), ApiError> {
    if metadata.protocol != Protocol::Qdrant {
        return Ok(());
    }
    let route_key = crate::protocols::qdrant::route_key_fingerprint(
        state.config.websocket_jwt_secret(),
        new_password.expose_secret(),
    );
    if state.instances.list().await.iter().any(|existing| {
        existing.instance_id != metadata.instance_id
            && existing.route_key_sha256.as_deref() == Some(route_key.as_str())
    }) {
        return Err(ApiError::Conflict(
            "the requested qdrant API key is already assigned to another instance".to_string(),
        ));
    }
    Ok(())
}

async fn capture_previous_credential(
    state: &AppState,
    metadata: &InstanceMetadata,
    credential_data_path: &std::path::Path,
) -> Result<PreviousCredential, ApiError> {
    let mut previous = PreviousCredential {
        environment: metadata
            .tenant_password
            .as_ref()
            .map(|password| SecretString::from(password.clone())),
        ..PreviousCredential::default()
    };
    capture_maintenance_credential(state, metadata, &mut previous).await?;
    let environment_keys = credential_environment_keys(metadata.protocol);
    if previous.environment.is_none() && !environment_keys.is_empty() {
        for key in environment_keys {
            let value = state
                .docker
                .container_environment_value(metadata.protocol, &metadata.instance_id, key)
                .await
                .map_err(docker_error)?
                .filter(|value| !value.expose_secret().is_empty());
            if value.is_some() {
                previous.environment = value;
                break;
            }
        }
        if previous.environment.is_none() && metadata.protocol != Protocol::Postgres {
            return Err(ApiError::Conflict(format!(
                "the current {} credential is unavailable from the managed container; the instance cannot be safely rolled back",
                metadata.protocol
            )));
        }
    }
    previous.native_password_verifier = match metadata.protocol {
        Protocol::Postgres => Some(capture_postgres_verifier(state, metadata, &previous).await?),
        Protocol::Mariadb => metadata.mariadb_native_password_sha1_stage2.clone(),
        Protocol::Mysql => metadata.mysql_native_password_sha1_stage2.clone(),
        _ => None,
    };
    if metadata.protocol == Protocol::Mariadb && previous.native_password_verifier.is_none() {
        return Err(ApiError::Conflict(format!(
            "the stored {} password verifier is missing; the instance cannot be safely rolled back",
            metadata.protocol
        )));
    }
    if metadata.protocol == Protocol::Mysql {
        let (plugin, authentication_string_b64) =
            capture_mysql_tenant_auth(state, metadata, &previous).await?;
        previous.mysql_auth_plugin = Some(plugin);
        previous.mysql_auth_string_b64 = Some(authentication_string_b64);
    }
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Valkey) {
        let path = credential_data_path.join("users.acl");
        previous.acl = Some(
            tokio::task::spawn_blocking(move || {
                read_bounded_private_file(&path, MAX_ACL_FILE_BYTES)
            })
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to read current ACL: {error}")))?
            .map_err(|error| {
                ApiError::Conflict(format!(
                    "the current database ACL cannot be captured for rollback: {error}"
                ))
            })?,
        );
    }
    Ok(previous)
}

fn credential_environment_keys(protocol: Protocol) -> &'static [&'static str] {
    match protocol {
        Protocol::Postgres => &["DBE_POSTGRES_PASSWORD"],
        Protocol::Mongodb => &["DBE_MONGO_PASSWORD"],
        Protocol::Clickhouse => &["CLICKHOUSE_PASSWORD"],
        Protocol::Qdrant => &["QDRANT__SERVICE__API_KEY"],
        Protocol::Redis | Protocol::Valkey | Protocol::Mariadb | Protocol::Mysql => &[],
    }
}

fn spec_password(
    protocol: Protocol,
    new_password: &SecretString,
    previous: &PreviousCredential,
    previous_value: bool,
) -> Result<Option<SecretString>, ApiError> {
    if matches!(protocol, Protocol::Redis | Protocol::Valkey) {
        return Ok(None);
    }
    if protocol == Protocol::Mysql {
        // MySQL tenant authentication is provisioned from its verifier; the
        // container specification intentionally contains only the root secret.
        return Ok(Some(new_password.clone()));
    }
    if previous_value {
        return previous.environment.clone().map(Some).ok_or_else(|| {
            ApiError::Conflict(format!(
                "the current {protocol} credential is unavailable for rollback"
            ))
        });
    }
    Ok(Some(new_password.clone()))
}

async fn reset_password(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    credential_data_path: &std::path::Path,
    new_spec: &DockerInstanceSpec,
    new_password: &SecretString,
) -> Result<(), ApiError> {
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Valkey) {
        write_resp_acl(
            metadata.protocol,
            credential_data_path,
            &metadata.database.username,
            new_password,
        )
        .await?;
        paths
            .restore_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    }

    let no_progress = |_event| {};
    // Every protocol reaching this path gets its credential from material
    // prepared before startup: Redis/Valkey read the rewritten ACL, while
    // ClickHouse/Qdrant read immutable container configuration. In particular,
    // the ClickHouse image creates an XML-backed user that cannot be changed
    // with ALTER USER. The launch readiness probe authenticates with the new
    // container environment before this function can return success.
    launch_container_from_spec(
        state,
        new_spec,
        metadata.protocol,
        &metadata.instance_id,
        &no_progress,
        false,
        || async { Ok(()) },
    )
    .await
    .map_err(|error| error.into_api_error())?;

    verify_tenant_credential(state, metadata, new_password).await
}

async fn attest_password_reset_target(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    let outcome = crate::compatibility::probe_instance_compatibility(
        &state.manager,
        &state.docker,
        metadata,
        true,
    )
    .await
    .map_err(|error| {
        ApiError::Runtime(format!(
            "database compatibility probe failed before password rotation: {error}"
        ))
    })?;
    if outcome.compatible {
        Ok(())
    } else {
        Err(ApiError::Conflict(outcome.diagnostic.unwrap_or_else(
            || "database version is outside the supported compatibility matrix".to_string(),
        )))
    }
}

#[cfg(test)]
mod tests;
