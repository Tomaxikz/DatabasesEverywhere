use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::extract::State;
use base64::Engine;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, sleep};

use super::{docker_error, instance_image_update_spec};
use crate::{
    api::{
        api_response::{ApiError, ApiJson, ApiPath, ApiResponse, ApiResult},
        instance_create::{
            launch_container_from_spec, prepare_instance_container_user, protocol_pids_limit,
        },
        instance_requests::validate_database_password,
        routes::AppState,
        security_policy::ApiRequestContext,
    },
    auth::scopes,
    databases,
    disk::DiskLimiter,
    instances::{metadata::InstanceMetadata, metadata::InstanceStatus, paths::InstancePaths},
    runtime::docker::{DockerContainerStatus, DockerInstanceSpec},
    shared::{
        files::read_private_regular_file_bounded, protocol::Protocol, shell::sh_quote,
        time::now_rfc3339,
    },
};

#[cfg(test)]
use crate::api::instance_requests::MAX_PASSWORD_CHARACTERS;

const MAX_ACL_FILE_BYTES: u64 = 64 * 1024;
const ROTATION_READINESS_TIMEOUT: Duration = Duration::from_secs(30);
const PASSWORD_EXEC_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetInstancePasswordRequest {
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct ResetInstancePasswordResponse {
    pub instance: InstanceMetadata,
    pub restarted: bool,
}

#[derive(Default)]
struct PreviousCredential {
    environment: Option<SecretString>,
    native_password_verifier: Option<String>,
    acl: Option<Vec<u8>>,
}

struct ResetExecution<'a> {
    paths: &'a InstancePaths,
    credential_data_path: &'a std::path::Path,
    new_spec: &'a DockerInstanceSpec,
    new_password: &'a SecretString,
}

struct RollbackContext<'a> {
    paths: &'a InstancePaths,
    credential_data_path: &'a std::path::Path,
    old_spec: &'a DockerInstanceSpec,
    previous: &'a PreviousCredential,
}

struct InPlaceResetContext<'a> {
    state: &'a AppState,
    metadata: &'a InstanceMetadata,
    paths: &'a InstancePaths,
    credential_data_path: &'a std::path::Path,
    new_password: &'a SecretString,
    previous: &'a PreviousCredential,
}

enum PasswordMetadataCommitResolution {
    Committed,
    Previous,
    Uncertain {
        reason: String,
        persisted: Option<Box<InstanceMetadata>>,
    },
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
        let result = match tokio::spawn(reset_instance_password_inner(state, instance_id, request))
            .await
        {
            Ok(result) => result,
            Err(error) => {
                let mut quarantine_summary =
                    "the instance metadata was unavailable for quarantine".to_string();
                if let Some(metadata) = recovery_state.instances.get(&worker_instance_id).await {
                    let quarantine = quarantine_instance(&recovery_state, &metadata).await;
                    quarantine_summary = password_quarantine_summary(&quarantine);
                }
                tracing::error!(
                    event = "audit instance_password_reset_worker_failed",
                    instance_id = %worker_instance_id,
                    %error,
                    "password reset worker failed unexpectedly"
                );
                Err(ApiError::Runtime(format!(
                    "password reset worker failed unexpectedly; {quarantine_summary}; repair or recover it before retrying"
                )))
            }
        };
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
    let _operation = state.instance_locks.lock(&instance_id).await;
    let mut metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
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
        return reset_password_in_place(
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
    let mut new_spec = instance_image_update_spec(
        &metadata,
        &paths,
        container_data_path.clone(),
        &image,
        new_spec_password,
        protocol_pids_limit(&state, metadata.protocol),
    )
    .await?;
    let mut old_spec = instance_image_update_spec(
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
    let result = perform_password_reset(
        &state,
        &metadata,
        ResetExecution {
            paths: &paths,
            credential_data_path: &credential_data_path,
            new_spec: &new_spec,
            new_password: &new_password,
        },
    )
    .await;

    if let Err(error) = result {
        return rollback_or_fail(
            &state,
            &metadata,
            RollbackContext {
                paths: &paths,
                credential_data_path: &credential_data_path,
                old_spec: &old_spec,
                previous: &previous,
            },
            error,
        )
        .await;
    }

    apply_new_route_auth(&mut metadata, &new_password);
    metadata.status = InstanceStatus::Running;
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state.manager.upsert(metadata.clone()).await {
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
                    RollbackContext {
                        paths: &paths,
                        credential_data_path: &credential_data_path,
                        old_spec: &old_spec,
                        previous: &previous,
                    },
                    ApiError::Runtime(format!(
                        "failed to persist rotated instance authentication: {commit_error}"
                    )),
                )
                .await;
            }
            PasswordMetadataCommitResolution::Uncertain { reason, persisted } => {
                return fail_password_metadata_commit_uncertain(
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

async fn resolve_password_metadata_commit(
    state: &AppState,
    previous: &InstanceMetadata,
    intended: &InstanceMetadata,
) -> PasswordMetadataCommitResolution {
    match state.manager.get_persisted(&intended.instance_id).await {
        Ok(Some(persisted)) => classify_password_metadata_commit(persisted, previous, intended),
        Ok(None) => PasswordMetadataCommitResolution::Uncertain {
            reason: "the durable instance metadata row is missing".to_string(),
            persisted: None,
        },
        Err(error) => PasswordMetadataCommitResolution::Uncertain {
            reason: format!("the durable metadata read failed: {error}"),
            persisted: None,
        },
    }
}

fn classify_password_metadata_commit(
    persisted: InstanceMetadata,
    previous: &InstanceMetadata,
    intended: &InstanceMetadata,
) -> PasswordMetadataCommitResolution {
    match super::major_upgrade::classify_major_upgrade_commit(&persisted, previous, intended) {
        super::major_upgrade::MajorUpgradeCommitResolution::Committed => {
            PasswordMetadataCommitResolution::Committed
        }
        super::major_upgrade::MajorUpgradeCommitResolution::NotCommitted => {
            PasswordMetadataCommitResolution::Previous
        }
        super::major_upgrade::MajorUpgradeCommitResolution::Uncertain(reason) => {
            PasswordMetadataCommitResolution::Uncertain {
                reason,
                persisted: Some(Box::new(persisted)),
            }
        }
    }
}

async fn fail_password_metadata_commit_uncertain(
    state: &AppState,
    intended: &InstanceMetadata,
    persisted: Option<&InstanceMetadata>,
    commit_error: &str,
    reason: &str,
) -> ApiResult<ResetInstancePasswordResponse> {
    let quarantine_basis = persisted.unwrap_or(intended);
    let quarantine = quarantine_instance(state, quarantine_basis).await;
    let quarantine_summary = password_quarantine_summary(&quarantine);
    tracing::error!(
        event = "audit instance_password_reset_commit_uncertain",
        instance_id = %intended.instance_id,
        protocol = %intended.protocol,
        error = %commit_error,
        %reason,
        "password reset runtime completed but durable metadata could not be classified; instance was quarantined without attempting a credential rollback"
    );
    Err(ApiError::Runtime(format!(
        "password reset runtime completed, but metadata persistence failed ({commit_error}) and durable commit state is uncertain ({reason}); {quarantine_summary}"
    )))
}

async fn reset_password_in_place(
    state: &AppState,
    mut metadata: InstanceMetadata,
    paths: &InstancePaths,
    credential_data_path: &std::path::Path,
    new_password: &SecretString,
    previous: &PreviousCredential,
) -> ApiResult<ResetInstancePasswordResponse> {
    let previous_metadata = metadata.clone();
    let new_verifier = native_password_verifier(metadata.protocol, new_password);
    let credential_changed = Arc::new(AtomicBool::new(false));
    {
        let context = InPlaceResetContext {
            state,
            metadata: &previous_metadata,
            paths,
            credential_data_path,
            new_password,
            previous,
        };
        if let Err(error) = perform_in_place_password_reset(
            &context,
            new_verifier.as_deref(),
            Arc::clone(&credential_changed),
        )
        .await
        {
            return rollback_in_place_or_fail(
                &context,
                credential_changed.load(Ordering::Acquire),
                error,
            )
            .await;
        }
    }

    apply_new_route_auth(&mut metadata, new_password);
    metadata.status = InstanceStatus::Running;
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state.manager.upsert(metadata.clone()).await {
        let commit_error = error.to_string();
        match resolve_password_metadata_commit(state, &previous_metadata, &metadata).await {
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
                let context = InPlaceResetContext {
                    state,
                    metadata: &previous_metadata,
                    paths,
                    credential_data_path,
                    new_password,
                    previous,
                };
                return rollback_in_place_or_fail(
                    &context,
                    credential_changed.load(Ordering::Acquire),
                    ApiError::Runtime(format!(
                        "failed to persist rotated instance authentication: {commit_error}"
                    )),
                )
                .await;
            }
            PasswordMetadataCommitResolution::Uncertain { reason, persisted } => {
                return fail_password_metadata_commit_uncertain(
                    state,
                    &metadata,
                    persisted.as_deref(),
                    &commit_error,
                    &reason,
                )
                .await;
            }
        }
    }

    invalidate_password_caches(state, &metadata).await;
    tracing::info!(
        event = "audit instance_password_reset",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        restarted = false,
        "instance password reset completed in place"
    );
    Ok(ApiResponse::ok(ResetInstancePasswordResponse {
        instance: metadata,
        restarted: false,
    }))
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
    if metadata.status != InstanceStatus::Running {
        return Err(ApiError::Conflict(format!(
            "password reset requires a running instance; current status is {}",
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
    let route_key = crate::protocols::qdrant::route_key_sha256(new_password.expose_secret());
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
        if previous.environment.is_none() {
            return Err(ApiError::Conflict(format!(
                "the current {} credential is unavailable from the managed container; the instance cannot be safely rolled back",
                metadata.protocol
            )));
        }
    }
    previous.native_password_verifier = match metadata.protocol {
        Protocol::Mariadb => metadata.mariadb_native_password_sha1_stage2.clone(),
        Protocol::Mysql => metadata.mysql_native_password_sha1_stage2.clone(),
        _ => None,
    };
    if matches!(metadata.protocol, Protocol::Mariadb | Protocol::Mysql)
        && previous.native_password_verifier.is_none()
    {
        return Err(ApiError::Conflict(format!(
            "the stored {} password verifier is missing; the instance cannot be safely rolled back",
            metadata.protocol
        )));
    }
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Valkey) {
        let path = credential_data_path.join("users.acl");
        previous.acl = Some(
            tokio::task::spawn_blocking(move || {
                read_private_regular_file_bounded(&path, MAX_ACL_FILE_BYTES)
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

fn native_password_verifier(protocol: Protocol, password: &SecretString) -> Option<String> {
    matches!(protocol, Protocol::Mariadb | Protocol::Mysql).then(|| {
        crate::protocols::mariadb::native_password_sha1_stage2_hex(password.expose_secret())
    })
}

async fn perform_in_place_password_reset(
    context: &InPlaceResetContext<'_>,
    new_verifier: Option<&str>,
    credential_changed: Arc<AtomicBool>,
) -> Result<(), ApiError> {
    if matches!(
        context.metadata.protocol,
        Protocol::Redis | Protocol::Valkey
    ) {
        write_resp_acl(
            context.metadata.protocol,
            context.credential_data_path,
            &context.metadata.database.username,
            context.new_password,
        )
        .await?;
        context
            .paths
            .reapply_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        activate_resp_acl(
            context.state,
            context.metadata,
            context.previous.environment.as_ref().ok_or_else(|| {
                ApiError::Conflict(
                    "the current RESP credential is unavailable for live ACL rotation".to_string(),
                )
            })?,
        )
        .await?;
        credential_changed.store(true, Ordering::Release);
    } else {
        rotate_database_password_to_container_environment(
            context.state,
            context.metadata,
            new_verifier,
            Some(context.new_password),
        )
        .await?;
        credential_changed.store(true, Ordering::Release);
    }
    validate_rotated_credential(context.state, context.metadata, context.new_password).await
}

async fn rollback_in_place_or_fail(
    context: &InPlaceResetContext<'_>,
    credential_changed: bool,
    original_error: ApiError,
) -> ApiResult<ResetInstancePasswordResponse> {
    let original_message = original_error.to_string();
    let rollback = rollback_in_place_password_reset(context, credential_changed).await;
    match rollback {
        Ok(()) => {
            context
                .state
                .instances
                .upsert(context.metadata.clone())
                .await;
            invalidate_password_caches(context.state, context.metadata).await;
            tracing::warn!(
                event = "audit instance_password_reset_rolled_back",
                instance_id = %context.metadata.instance_id,
                protocol = %context.metadata.protocol,
                error = %original_message,
                "in-place password reset failed and the previous credential was restored"
            );
            Err(original_error)
        }
        Err(rollback_error) => {
            let rollback_message = rollback_error.to_string();
            let quarantine = quarantine_instance(context.state, context.metadata).await;
            let quarantine_summary = password_quarantine_summary(&quarantine);
            tracing::error!(
                event = "audit instance_password_reset_rollback_failed",
                instance_id = %context.metadata.instance_id,
                protocol = %context.metadata.protocol,
                error = %original_message,
                rollback_error = %rollback_message,
                "in-place password reset and rollback both failed"
            );
            Err(ApiError::Runtime(format!(
                "password reset failed ({original_message}) and rollback failed ({rollback_message}); {quarantine_summary}"
            )))
        }
    }
}

async fn rollback_in_place_password_reset(
    context: &InPlaceResetContext<'_>,
    credential_changed: bool,
) -> Result<(), ApiError> {
    if matches!(
        context.metadata.protocol,
        Protocol::Redis | Protocol::Valkey
    ) {
        let acl = context.previous.acl.as_deref().ok_or_else(|| {
            ApiError::Runtime("previous RESP ACL was not captured for rollback".to_string())
        })?;
        restore_resp_acl(context.metadata.protocol, context.credential_data_path, acl).await?;
        context
            .paths
            .reapply_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        let previous_password = context.previous.environment.as_ref().ok_or_else(|| {
            ApiError::Runtime("previous RESP credential was not captured for rollback".to_string())
        })?;
        let (first_password, fallback_password) = if credential_changed {
            (context.new_password, previous_password)
        } else {
            (previous_password, context.new_password)
        };
        if activate_resp_acl(context.state, context.metadata, first_password)
            .await
            .is_err()
        {
            // A timed-out ACL LOAD may have completed just before the runtime
            // recovered the exec by restarting the container. Try the other
            // known credential so rollback remains deterministic in either
            // state.
            activate_resp_acl(context.state, context.metadata, fallback_password).await?;
        }
        return Ok(());
    }

    rotate_database_password_to_container_environment(
        context.state,
        context.metadata,
        context.previous.native_password_verifier.as_deref(),
        context.previous.environment.as_ref(),
    )
    .await
}

async fn activate_resp_acl(
    state: &AppState,
    metadata: &InstanceMetadata,
    current_password: &SecretString,
) -> Result<(), ApiError> {
    let command = match metadata.protocol {
        Protocol::Redis => {
            "redis-cli -s /run/dbev/redis.sock --user \"$DBE_TENANT_USER\" -a \"$DBE_CURRENT_PASSWORD\" --no-auth-warning ACL LOAD >/dev/null"
        }
        Protocol::Valkey => {
            "valkey-cli -s /run/dbev/valkey.sock --user \"$DBE_TENANT_USER\" -a \"$DBE_CURRENT_PASSWORD\" --no-auth-warning ACL LOAD >/dev/null"
        }
        _ => {
            return Err(ApiError::Runtime(
                "ACL activation requested for a non-RESP database".to_string(),
            ));
        }
    };
    let tenant_user = SecretString::from(metadata.database.username.clone());
    state
        .docker
        .exec_shell_with_secret_env_timeout(
            metadata.protocol,
            &metadata.instance_id,
            command,
            &[
                ("DBE_TENANT_USER", &tenant_user),
                ("DBE_CURRENT_PASSWORD", current_password),
            ],
            PASSWORD_EXEC_TIMEOUT,
        )
        .await
        .map_err(|error| ApiError::Runtime(format!("database ACL reload failed: {error}")))?;
    Ok(())
}

async fn perform_password_reset(
    state: &AppState,
    metadata: &InstanceMetadata,
    execution: ResetExecution<'_>,
) -> Result<(), ApiError> {
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Valkey) {
        write_resp_acl(
            metadata.protocol,
            execution.credential_data_path,
            &metadata.database.username,
            execution.new_password,
        )
        .await?;
        execution
            .paths
            .reapply_data_owner()
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
        execution.new_spec,
        metadata.protocol,
        &metadata.instance_id,
        &no_progress,
        false,
        || async { Ok(()) },
    )
    .await
    .map_err(|error| error.into_api_error())?;

    validate_rotated_credential(state, metadata, execution.new_password).await
}

async fn rotate_database_password_to_container_environment(
    state: &AppState,
    metadata: &InstanceMetadata,
    native_password_verifier: Option<&str>,
    target_password: Option<&SecretString>,
) -> Result<(), ApiError> {
    wait_for_rotation_admin(state, metadata).await?;
    let script = match metadata.protocol {
        Protocol::Postgres => postgres_rotation_script(&metadata.database.username),
        Protocol::Mariadb => mysql_family_rotation_script(
            metadata.protocol,
            &metadata.database.name,
            &metadata.database.username,
            native_password_verifier.ok_or_else(|| {
                ApiError::Runtime("mariadb replacement verifier is missing".to_string())
            })?,
        )?,
        Protocol::Mysql => mysql_rotation_script(&metadata.database.username)?,
        Protocol::Mongodb => mongodb_rotation_script(metadata)?,
        Protocol::Redis | Protocol::Valkey | Protocol::Clickhouse | Protocol::Qdrant => {
            return Err(ApiError::Runtime(format!(
                "{} credentials are managed through recreated startup configuration, not live SQL",
                metadata.protocol
            )));
        }
    };
    let mysql_password_b64 = if metadata.protocol == Protocol::Mysql {
        target_password.map(|password| {
            SecretString::from(
                base64::engine::general_purpose::STANDARD
                    .encode(password.expose_secret().as_bytes()),
            )
        })
    } else {
        None
    };
    let postgres_admin_password = if metadata.protocol == Protocol::Postgres {
        Some(SecretString::from(
            metadata.postgres_admin_password.clone().ok_or_else(|| {
                ApiError::Conflict(
                    "the encrypted PostgreSQL administrator credential is missing; restart the daemon to migrate this legacy instance before rotating its password"
                        .to_string(),
                )
            })?,
        ))
    } else {
        None
    };
    let mut environment = Vec::with_capacity(3);
    if let Some(password) = target_password {
        environment.push(("DBE_ROTATED_PASSWORD", password));
    }
    if let Some(password_b64) = mysql_password_b64.as_ref() {
        environment.push(("DBE_ROTATED_PASSWORD_B64", password_b64));
    }
    if let Some(admin_password) = postgres_admin_password.as_ref() {
        environment.push(("DBE_POSTGRES_ADMIN_PASSWORD", admin_password));
    }
    state
        .docker
        .exec_shell_with_secret_env_timeout(
            metadata.protocol,
            &metadata.instance_id,
            &script,
            &environment,
            PASSWORD_EXEC_TIMEOUT,
        )
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("database password rotation failed: {error}"))
        })?;
    Ok(())
}

async fn wait_for_rotation_admin(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    let postgres_admin_password = if metadata.protocol == Protocol::Postgres {
        Some(SecretString::from(
            metadata.postgres_admin_password.clone().ok_or_else(|| {
                ApiError::Conflict(
                    "the encrypted PostgreSQL administrator credential is missing; restart the daemon to migrate this legacy instance before rotating its password"
                        .to_string(),
                )
            })?,
        ))
    } else {
        None
    };
    let command = match metadata.protocol {
        Protocol::Postgres => {
            "test \"$(cat /proc/1/comm)\" = postgres && PGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -Atqc 'SELECT 1' >/dev/null"
                .to_string()
        }
        Protocol::Mariadb => "root_password=\"${DBE_MARIADB_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}\"; MYSQL_PWD=\"$root_password\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -u root -N -B -e 'SELECT 1' >/dev/null".to_string(),
        Protocol::Mysql => "test \"$(cat /proc/1/comm)\" = mysqld && MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root -N -B -e 'SELECT 1' >/dev/null".to_string(),
        Protocol::Mongodb => "mongosh --quiet --host 127.0.0.1 --username \"$DBE_MONGO_ROOT_USER\" --password \"$DBE_MONGO_ROOT_PASSWORD\" --authenticationDatabase admin admin --eval 'db.adminCommand({ ping: 1 }).ok' >/dev/null".to_string(),
        Protocol::Redis | Protocol::Valkey | Protocol::Clickhouse | Protocol::Qdrant => {
            return Err(ApiError::Runtime(format!(
                "{} does not support live password rotation",
                metadata.protocol
            )));
        }
    };
    let deadline = Instant::now() + ROTATION_READINESS_TIMEOUT;
    let mut last_error = String::new();
    let environment = postgres_admin_password
        .as_ref()
        .map(|password| vec![("DBE_POSTGRES_ADMIN_PASSWORD", password)])
        .unwrap_or_default();
    while Instant::now() < deadline {
        match tokio::time::timeout(
            Duration::from_secs(5),
            state.docker.exec_readiness_probe_with_secret_env(
                metadata.protocol,
                &metadata.instance_id,
                &command,
                &environment,
            ),
        )
        .await
        {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(error)) => {
                last_error = error.to_string();
                sleep(Duration::from_secs(1)).await;
            }
            Err(_) => {
                last_error = "administrator readiness attempt exceeded 5 seconds".to_string();
            }
        }
    }
    Err(ApiError::Runtime(format!(
        "database administrator connection did not become ready for password rotation: {last_error}"
    )))
}

fn postgres_rotation_script(username: &str) -> String {
    let sql = databases::postgres::provision::reset_tenant_password_sql(username);
    format!(
        "set -eu\n{{ printf '%s\\n' '\\getenv tenant_password DBE_ROTATED_PASSWORD'; printf '%s\\n' {}; }} | PGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -v ON_ERROR_STOP=1\n",
        sh_quote(&sql)
    )
}

fn mysql_family_rotation_script(
    protocol: Protocol,
    database: &str,
    username: &str,
    verifier: &str,
) -> Result<String, ApiError> {
    let sql = match protocol {
        Protocol::Mariadb => {
            databases::mariadb::provision::tenant_user_sql(database, username, verifier)
                .map_err(|error| ApiError::Runtime(error.to_string()))?
        }
        _ => {
            return Err(ApiError::Runtime(
                "invalid mysql-family password rotation protocol".to_string(),
            ));
        }
    };
    let command = if protocol == Protocol::Mariadb {
        "MYSQL_PWD=\"${DBE_MARIADB_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -u root"
    } else {
        "MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root"
    };
    Ok(format!(
        "set -eu\nprintf %s {} | {command}\n",
        sh_quote(&sql)
    ))
}

fn mysql_rotation_script(username: &str) -> Result<String, ApiError> {
    let sql = databases::mysql::provision::reset_tenant_password_sql(username);
    let (before_password, after_password) =
        databases::mysql::provision::password_sql_fragments(&sql)
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(format!(
        "set -eu\n{{ printf %s {}; printf %s \"$DBE_ROTATED_PASSWORD_B64\"; printf %s {}; }} | MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -uroot\n",
        sh_quote(before_password),
        sh_quote(after_password),
    ))
}

fn mongodb_rotation_script(metadata: &InstanceMetadata) -> Result<String, ApiError> {
    let javascript = databases::mongodb::provision::update_user_password_from_env_script(
        &metadata.database.name,
        &metadata.database.username,
    )
    .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(format!(
        "set -eu\nmongosh --quiet --host 127.0.0.1 --username \"$DBE_MONGO_ROOT_USER\" --password \"$DBE_MONGO_ROOT_PASSWORD\" --authenticationDatabase admin admin --eval {}\n",
        sh_quote(&javascript)
    ))
}

async fn validate_rotated_credential(
    state: &AppState,
    metadata: &InstanceMetadata,
    new_password: &SecretString,
) -> Result<(), ApiError> {
    let script = match metadata.protocol {
        Protocol::Postgres => format!(
            "PGPASSWORD=\"$DBE_ROTATED_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -Atqc 'SELECT 1' >/dev/null",
            sh_quote(&metadata.database.username),
            sh_quote(&metadata.database.name),
        ),
        Protocol::Redis => format!(
            "redis-cli -s /run/dbev/redis.sock --user {} -a \"$DBE_ROTATED_PASSWORD\" --no-auth-warning ping >/dev/null",
            sh_quote(&metadata.database.username),
        ),
        Protocol::Valkey => format!(
            "valkey-cli -s /run/dbev/valkey.sock --user {} -a \"$DBE_ROTATED_PASSWORD\" --no-auth-warning ping >/dev/null",
            sh_quote(&metadata.database.username),
        ),
        Protocol::Mariadb => "MYSQL_PWD=\"$DBE_ROTATED_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" \"$MARIADB_DATABASE\" -N -B -e 'SELECT 1' >/dev/null".to_string(),
        Protocol::Mysql => format!(
            "MYSQL_PWD=\"$DBE_ROTATED_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u {} {} -e 'SELECT 1' >/dev/null",
            sh_quote(&metadata.database.username),
            sh_quote(&metadata.database.name),
        ),
        Protocol::Mongodb => "mongosh --quiet --host 127.0.0.1 --username \"$DBE_MONGO_USER\" --password \"$DBE_ROTATED_PASSWORD\" --authenticationDatabase \"$DBE_MONGO_DATABASE\" \"$DBE_MONGO_DATABASE\" --eval 'db.runCommand({ ping: 1 }).ok' >/dev/null".to_string(),
        Protocol::Clickhouse => "clickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$DBE_ROTATED_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query 'SELECT 1' >/dev/null".to_string(),
        // Qdrant reads the new API key from its immutable container
        // configuration. Its startup readiness probe confirms the authenticated
        // gRPC listener is accepting connections before metadata is committed.
        Protocol::Qdrant => return Ok(()),
    };
    state
        .docker
        .exec_shell_with_secret_env_timeout(
            metadata.protocol,
            &metadata.instance_id,
            &script,
            &[("DBE_ROTATED_PASSWORD", new_password)],
            PASSWORD_EXEC_TIMEOUT,
        )
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "rotated database credential validation failed: {error}"
            ))
        })?;
    Ok(())
}

async fn write_resp_acl(
    protocol: Protocol,
    data_path: &std::path::Path,
    username: &str,
    password: &SecretString,
) -> Result<(), ApiError> {
    match protocol {
        Protocol::Redis => {
            databases::redis::provision::write_acl_file(data_path, username, password)
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))
        }
        Protocol::Valkey => {
            databases::valkey::provision::write_acl_file(data_path, username, password)
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))
        }
        _ => Err(ApiError::Runtime(
            "ACL rotation requested for a non-RESP database".to_string(),
        )),
    }
}

async fn restore_resp_acl(
    protocol: Protocol,
    data_path: &std::path::Path,
    acl: &[u8],
) -> Result<(), ApiError> {
    match protocol {
        Protocol::Redis => databases::redis::provision::restore_acl_file(data_path, acl)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string())),
        Protocol::Valkey => databases::valkey::provision::restore_acl_file(data_path, acl)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string())),
        _ => Err(ApiError::Runtime(
            "ACL rollback requested for a non-RESP database".to_string(),
        )),
    }
}

async fn rollback_or_fail(
    state: &AppState,
    metadata: &InstanceMetadata,
    rollback: RollbackContext<'_>,
    original_error: ApiError,
) -> ApiResult<ResetInstancePasswordResponse> {
    let original_message = original_error.to_string();
    match rollback_password_reset(
        state,
        metadata,
        rollback.paths,
        rollback.credential_data_path,
        rollback.old_spec,
        rollback.previous,
    )
    .await
    {
        Ok(()) => {
            state.instances.upsert(metadata.clone()).await;
            invalidate_password_caches(state, metadata).await;
            tracing::warn!(
                event = "audit instance_password_reset_rolled_back",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                error = %original_message,
                "instance password reset failed and the previous credential was restored"
            );
            Err(original_error)
        }
        Err(rollback_error) => {
            let rollback_message = rollback_error.to_string();
            let quarantine = quarantine_instance(state, metadata).await;
            let quarantine_summary = password_quarantine_summary(&quarantine);
            tracing::error!(
                event = "audit instance_password_reset_rollback_failed",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                error = %original_message,
                rollback_error = %rollback_message,
                "instance password reset and rollback both failed"
            );
            Err(ApiError::Runtime(format!(
                "password reset failed ({original_message}) and rollback failed ({rollback_message}); {quarantine_summary}"
            )))
        }
    }
}

async fn rollback_password_reset(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    credential_data_path: &std::path::Path,
    old_spec: &DockerInstanceSpec,
    previous: &PreviousCredential,
) -> Result<(), ApiError> {
    delete_managed_container(state, metadata.protocol, &metadata.instance_id).await?;
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Valkey) {
        let acl = previous.acl.as_deref().ok_or_else(|| {
            ApiError::Runtime("previous RESP ACL was not captured for rollback".to_string())
        })?;
        restore_resp_acl(metadata.protocol, credential_data_path, acl).await?;
        paths
            .reapply_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    }

    let no_progress = |_event| {};
    // The old spec (and restored RESP ACL above) is the rollback. Its normal
    // launch readiness probe authenticates with the old credential, so a
    // rollback cannot be reported as successful while authentication is stale.
    launch_container_from_spec(
        state,
        old_spec,
        metadata.protocol,
        &metadata.instance_id,
        &no_progress,
        false,
        || async { Ok(()) },
    )
    .await
    .map_err(|error| error.into_api_error())?;
    Ok(())
}

async fn delete_managed_container(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), ApiError> {
    match state.docker.delete(protocol, instance_id).await {
        Ok(_) => Ok(()),
        Err(error) if error.is_not_found() => Ok(()),
        Err(error) => Err(docker_error(error)),
    }
}

fn apply_new_route_auth(metadata: &mut InstanceMetadata, password: &SecretString) {
    metadata.tenant_password = Some(password.expose_secret().to_string());
    match metadata.protocol {
        Protocol::Mariadb => {
            metadata.mariadb_native_password_sha1_stage2 =
                Some(crate::protocols::mariadb::native_password_sha1_stage2_hex(
                    password.expose_secret(),
                ));
        }
        Protocol::Mysql => {
            metadata.mysql_native_password_sha1_stage2 =
                Some(crate::protocols::mariadb::native_password_sha1_stage2_hex(
                    password.expose_secret(),
                ));
        }
        Protocol::Qdrant => {
            metadata.route_key_sha256 = Some(crate::protocols::qdrant::route_key_sha256(
                password.expose_secret(),
            ));
        }
        Protocol::Postgres
        | Protocol::Redis
        | Protocol::Valkey
        | Protocol::Mongodb
        | Protocol::Clickhouse => {}
    }
}

async fn invalidate_password_caches(state: &AppState, metadata: &InstanceMetadata) {
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.resource_cache.remove(&metadata.instance_id).await;
    state.monitoring_cache.invalidate().await;
}

async fn quarantine_instance(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    // Persist fail-closed intent before touching the runtime. If the process
    // crashes after this commit, boot reconciliation still refuses to restart
    // or route an instance whose active credential is uncertain.
    let quarantined = quarantined_metadata(metadata);
    // Remove routes in this process before waiting on SQLite or Docker. Even
    // when durable quarantine fails, an uncertain credential must never stay
    // reachable through the gateway for the remainder of this daemon run.
    state.instances.upsert(quarantined.clone()).await;
    let persistence_error = state.manager.upsert(quarantined).await.err().map(|error| {
        tracing::error!(
            instance_id = %metadata.instance_id,
            error = %error,
            "failed to persist quarantine after password reset rollback failure; runtime stop will still be attempted"
        );
        format!("failed to persist password-reset quarantine: {error}")
    });
    let runtime_error = match state
        .docker
        .stop(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(_) => None,
        Err(error) if error.is_not_found() || error.is_not_running() => None,
        Err(error) => {
            tracing::error!(
                instance_id = %metadata.instance_id,
                %error,
                "failed to stop instance while quarantining an uncertain password rotation"
            );
            Some(format!(
                "failed to stop password-reset quarantine target: {error}"
            ))
        }
    };
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.resource_cache.remove(&metadata.instance_id).await;
    state.monitoring_cache.invalidate().await;

    let failures = [persistence_error, runtime_error]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ApiError::Runtime(failures.join("; ")))
    }
}

fn password_quarantine_summary(result: &Result<(), ApiError>) -> String {
    match result {
        Ok(()) => "the instance was stopped and quarantined".to_string(),
        Err(error) => format!(
            "gateway routes were removed, but complete shutdown or durable quarantine failed: {error}"
        ),
    }
}

fn quarantined_metadata(metadata: &InstanceMetadata) -> InstanceMetadata {
    let mut quarantined = metadata.clone();
    quarantined.status = InstanceStatus::Quarantined;
    quarantined.desired_state = crate::instances::metadata::DesiredInstanceState::Stopped;
    quarantined.updated_at = now_rfc3339();
    quarantined
}

#[cfg(test)]
mod tests;
