use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::extract::State;
use http::HeaderValue;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::{Instant, sleep};

use super::{docker_error, instance_image_update_spec};
use crate::{
    api::{
        api_response::{ApiError, ApiJson, ApiPath, ApiResponse, ApiResult},
        instance_create::{
            launch_container_from_spec, prepare_instance_container_user, protocol_pids_limit,
        },
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

const MAX_PASSWORD_CHARACTERS: usize = 4 * 1024;
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
    new_spec: &'a DockerInstanceSpec,
    new_password: &'a SecretString,
    new_verifier: Option<&'a str>,
    previous: &'a PreviousCredential,
    credential_changed: Arc<AtomicBool>,
}

struct RollbackContext<'a> {
    paths: &'a InstancePaths,
    old_spec: &'a DockerInstanceSpec,
    new_password: &'a SecretString,
    previous: &'a PreviousCredential,
    credential_changed: bool,
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
        .try_admit(&instance_id)
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
                if let Some(metadata) = recovery_state.instances.get(&worker_instance_id).await {
                    quarantine_instance(&recovery_state, &metadata).await;
                }
                tracing::error!(
                    event = "audit instance_password_reset_worker_failed",
                    instance_id = %worker_instance_id,
                    %error,
                    "password reset worker failed unexpectedly"
                );
                Err(ApiError::Runtime(
                    "password reset worker failed unexpectedly; the instance was quarantined and must be repaired or recovered before retrying".to_string(),
                ))
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
    validate_password(metadata.protocol, &new_password)?;
    require_resettable_instance(&state, &metadata).await?;
    ensure_qdrant_route_is_available(&state, &metadata, &new_password).await?;

    let previous = capture_previous_credential(&state, &metadata).await?;
    if !requires_container_recreation(metadata.protocol, &previous) {
        return reset_password_in_place(&state, metadata, &new_password, &previous).await;
    }
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
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
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

    delete_managed_container(&state, metadata.protocol, &metadata.instance_id).await?;
    let credential_changed = Arc::new(AtomicBool::new(false));
    let new_verifier = native_password_verifier(metadata.protocol, &new_password);
    let result = perform_password_reset(
        &state,
        &metadata,
        ResetExecution {
            paths: &paths,
            new_spec: &new_spec,
            new_password: &new_password,
            new_verifier: new_verifier.as_deref(),
            previous: &previous,
            credential_changed: Arc::clone(&credential_changed),
        },
    )
    .await;

    if let Err(error) = result {
        return rollback_or_fail(
            &state,
            &metadata,
            RollbackContext {
                paths: &paths,
                old_spec: &old_spec,
                new_password: &new_password,
                previous: &previous,
                credential_changed: credential_changed.load(Ordering::Acquire),
            },
            error,
        )
        .await;
    }

    apply_new_route_auth(&mut metadata, &new_password);
    metadata.status = InstanceStatus::Running;
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state.manager.upsert(metadata.clone()).await {
        return rollback_or_fail(
            &state,
            &metadata,
            RollbackContext {
                paths: &paths,
                old_spec: &old_spec,
                new_password: &new_password,
                previous: &previous,
                credential_changed: credential_changed.load(Ordering::Acquire),
            },
            ApiError::Runtime(format!(
                "failed to persist rotated instance authentication: {error}"
            )),
        )
        .await;
    }

    invalidate_password_caches(&state, &metadata).await;
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

async fn reset_password_in_place(
    state: &AppState,
    mut metadata: InstanceMetadata,
    new_password: &SecretString,
    previous: &PreviousCredential,
) -> ApiResult<ResetInstancePasswordResponse> {
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let new_verifier = native_password_verifier(metadata.protocol, new_password);
    let credential_changed = Arc::new(AtomicBool::new(false));
    if let Err(error) = perform_in_place_password_reset(
        state,
        &metadata,
        &paths,
        new_password,
        new_verifier.as_deref(),
        previous,
        Arc::clone(&credential_changed),
    )
    .await
    {
        return rollback_in_place_or_fail(
            state,
            &metadata,
            &paths,
            new_password,
            previous,
            credential_changed.load(Ordering::Acquire),
            error,
        )
        .await;
    }

    apply_new_route_auth(&mut metadata, new_password);
    metadata.status = InstanceStatus::Running;
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state.manager.upsert(metadata.clone()).await {
        return rollback_in_place_or_fail(
            state,
            &metadata,
            &paths,
            new_password,
            previous,
            credential_changed.load(Ordering::Acquire),
            ApiError::Runtime(format!(
                "failed to persist rotated instance authentication: {error}"
            )),
        )
        .await;
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
    let password = password.expose_secret();
    if password.is_empty() {
        return Err(ApiError::BadRequest(
            "password must not be empty".to_string(),
        ));
    }
    if password.chars().count() > MAX_PASSWORD_CHARACTERS {
        return Err(ApiError::BadRequest(format!(
            "password must not exceed {MAX_PASSWORD_CHARACTERS} characters"
        )));
    }
    if password
        .bytes()
        .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err(ApiError::BadRequest(
            "password must contain no NUL bytes or line breaks".to_string(),
        ));
    }
    if protocol == Protocol::Qdrant && HeaderValue::from_str(password).is_err() {
        return Err(ApiError::BadRequest(
            "qdrant password contains characters that are invalid in an API-key header".to_string(),
        ));
    }
    Ok(())
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
        let path = InstancePaths::new(&state.config.paths, &metadata.instance_id)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?
            .data
            .join("users.acl");
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
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    new_password: &SecretString,
    new_verifier: Option<&str>,
    previous: &PreviousCredential,
    credential_changed: Arc<AtomicBool>,
) -> Result<(), ApiError> {
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Valkey) {
        write_resp_acl(
            metadata.protocol,
            &paths.data,
            &metadata.database.username,
            new_password,
        )
        .await?;
        paths
            .reapply_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        activate_resp_acl(
            state,
            metadata,
            previous.environment.as_ref().ok_or_else(|| {
                ApiError::Conflict(
                    "the current RESP credential is unavailable for live ACL rotation".to_string(),
                )
            })?,
        )
        .await?;
        credential_changed.store(true, Ordering::Release);
    } else {
        rotate_database_password_to_container_environment(
            state,
            metadata,
            new_verifier,
            None,
            Some(new_password),
        )
        .await?;
        credential_changed.store(true, Ordering::Release);
    }
    validate_rotated_credential(state, metadata, new_password).await
}

async fn rollback_in_place_or_fail(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    new_password: &SecretString,
    previous: &PreviousCredential,
    credential_changed: bool,
    original_error: ApiError,
) -> ApiResult<ResetInstancePasswordResponse> {
    let original_message = original_error.to_string();
    let rollback = rollback_in_place_password_reset(
        state,
        metadata,
        paths,
        new_password,
        previous,
        credential_changed,
    )
    .await;
    match rollback {
        Ok(()) => {
            tracing::warn!(
                event = "audit instance_password_reset_rolled_back",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                error = %original_message,
                "in-place password reset failed and the previous credential was restored"
            );
            Err(original_error)
        }
        Err(rollback_error) => {
            let rollback_message = rollback_error.to_string();
            quarantine_instance(state, metadata).await;
            tracing::error!(
                event = "audit instance_password_reset_rollback_failed",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                error = %original_message,
                rollback_error = %rollback_message,
                "in-place password reset and rollback both failed"
            );
            Err(ApiError::Runtime(format!(
                "password reset failed ({original_message}) and rollback failed ({rollback_message}); instance was quarantined"
            )))
        }
    }
}

async fn rollback_in_place_password_reset(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    new_password: &SecretString,
    previous: &PreviousCredential,
    credential_changed: bool,
) -> Result<(), ApiError> {
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Valkey) {
        let acl = previous.acl.as_deref().ok_or_else(|| {
            ApiError::Runtime("previous RESP ACL was not captured for rollback".to_string())
        })?;
        restore_resp_acl(metadata.protocol, &paths.data, acl).await?;
        paths
            .reapply_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        let previous_password = previous.environment.as_ref().ok_or_else(|| {
            ApiError::Runtime("previous RESP credential was not captured for rollback".to_string())
        })?;
        let (first_password, fallback_password) = if credential_changed {
            (new_password, previous_password)
        } else {
            (previous_password, new_password)
        };
        if activate_resp_acl(state, metadata, first_password)
            .await
            .is_err()
        {
            // A timed-out ACL LOAD may have completed just before the runtime
            // recovered the exec by restarting the container. Try the other
            // known credential so rollback remains deterministic in either
            // state.
            activate_resp_acl(state, metadata, fallback_password).await?;
        }
        return Ok(());
    }

    rotate_database_password_to_container_environment(
        state,
        metadata,
        previous.native_password_verifier.as_deref(),
        (metadata.protocol == Protocol::Clickhouse).then_some(new_password),
        previous.environment.as_ref(),
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
            &execution.paths.data,
            &metadata.database.username,
            execution.new_password,
        )
        .await?;
        execution
            .paths
            .reapply_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        execution.credential_changed.store(true, Ordering::Release);
    }

    let no_progress = |_event| {};
    let changed_after_start = Arc::clone(&execution.credential_changed);
    launch_container_from_spec(
        state,
        execution.new_spec,
        metadata.protocol,
        &metadata.instance_id,
        &no_progress,
        false,
        || async {
            if !matches!(
                metadata.protocol,
                Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
            ) {
                rotate_database_password_to_container_environment(
                    state,
                    metadata,
                    execution.new_verifier,
                    execution.previous.environment.as_ref(),
                    Some(execution.new_password),
                )
                .await?;
                changed_after_start.store(true, Ordering::Release);
            }
            Ok(())
        },
    )
    .await
    .map_err(|error| error.into_api_error())?;

    validate_rotated_credential(state, metadata, execution.new_password).await
}

async fn rotate_database_password_to_container_environment(
    state: &AppState,
    metadata: &InstanceMetadata,
    native_password_verifier: Option<&str>,
    clickhouse_current_password: Option<&SecretString>,
    clickhouse_target_password: Option<&SecretString>,
) -> Result<(), ApiError> {
    wait_for_rotation_admin(state, metadata, clickhouse_current_password).await?;
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
        Protocol::Mysql => mysql_family_rotation_script(
            metadata.protocol,
            &metadata.database.name,
            &metadata.database.username,
            native_password_verifier.ok_or_else(|| {
                ApiError::Runtime("mysql replacement verifier is missing".to_string())
            })?,
        )?,
        Protocol::Mongodb => mongodb_rotation_script(metadata)?,
        Protocol::Clickhouse => clickhouse_rotation_script(
            &metadata.database.username,
            clickhouse_target_password.ok_or_else(|| {
                ApiError::Runtime("replacement clickhouse credential is missing".to_string())
            })?,
        ),
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => return Ok(()),
    };
    let mut environment = Vec::with_capacity(2);
    if let Some(password) = clickhouse_target_password {
        environment.push(("DBE_ROTATED_PASSWORD", password));
    }
    if metadata.protocol == Protocol::Clickhouse {
        environment.push((
            "DBE_CURRENT_PASSWORD",
            clickhouse_current_password.ok_or_else(|| {
                ApiError::Runtime("current clickhouse credential is missing".to_string())
            })?,
        ));
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
    clickhouse_current_password: Option<&SecretString>,
) -> Result<(), ApiError> {
    let command = match metadata.protocol {
        Protocol::Postgres => {
            "psql -X -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -Atqc 'SELECT 1' >/dev/null"
                .to_string()
        }
        Protocol::Mariadb => "root_password=\"${DBE_MARIADB_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}\"; MYSQL_PWD=\"$root_password\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -u root -N -B -e 'SELECT 1' >/dev/null".to_string(),
        Protocol::Mysql => "test \"$(cat /proc/1/comm)\" = mysqld && MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root -N -B -e 'SELECT 1' >/dev/null".to_string(),
        Protocol::Mongodb => "mongosh --quiet --host 127.0.0.1 --username \"$DBE_MONGO_ROOT_USER\" --password \"$DBE_MONGO_ROOT_PASSWORD\" --authenticationDatabase admin admin --eval 'db.adminCommand({ ping: 1 }).ok' >/dev/null".to_string(),
        Protocol::Clickhouse => "clickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$DBE_CURRENT_PASSWORD\" --query 'SELECT 1' >/dev/null".to_string(),
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => return Ok(()),
    };
    let deadline = Instant::now() + ROTATION_READINESS_TIMEOUT;
    let mut last_error = String::new();
    while Instant::now() < deadline {
        let environment = clickhouse_current_password
            .map(|password| vec![("DBE_CURRENT_PASSWORD", password)])
            .unwrap_or_default();
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
        "set -eu\nprintf %s {} | psql -X -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -v ON_ERROR_STOP=1 -v tenant_password=\"$DBE_ROTATED_PASSWORD\"\n",
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
        Protocol::Mysql => {
            databases::mysql::provision::tenant_user_sql(database, username, verifier)
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

fn clickhouse_rotation_script(username: &str, target_password: &SecretString) -> String {
    let username = format!("`{}`", username.replace('`', "``"));
    let password_hash = format!(
        "{:x}",
        Sha256::digest(target_password.expose_secret().as_bytes())
    );
    let query = format!("ALTER USER {username} IDENTIFIED WITH sha256_hash BY '{password_hash}'");
    format!(
        "set -eu\nclickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$DBE_CURRENT_PASSWORD\" --query {}\n",
        sh_quote(&query),
    )
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
        rollback.old_spec,
        rollback.new_password,
        rollback.previous,
        rollback.credential_changed,
    )
    .await
    {
        Ok(()) => {
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
            quarantine_instance(state, metadata).await;
            tracing::error!(
                event = "audit instance_password_reset_rollback_failed",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                error = %original_message,
                rollback_error = %rollback_message,
                "instance password reset and rollback both failed"
            );
            Err(ApiError::Runtime(format!(
                "password reset failed ({original_message}) and rollback failed ({rollback_message}); instance was quarantined"
            )))
        }
    }
}

async fn rollback_password_reset(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    old_spec: &DockerInstanceSpec,
    new_password: &SecretString,
    previous: &PreviousCredential,
    credential_changed: bool,
) -> Result<(), ApiError> {
    delete_managed_container(state, metadata.protocol, &metadata.instance_id).await?;
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Valkey) {
        let acl = previous.acl.as_deref().ok_or_else(|| {
            ApiError::Runtime("previous RESP ACL was not captured for rollback".to_string())
        })?;
        restore_resp_acl(metadata.protocol, &paths.data, acl).await?;
        paths
            .reapply_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    }

    let no_progress = |_event| {};
    launch_container_from_spec(
        state,
        old_spec,
        metadata.protocol,
        &metadata.instance_id,
        &no_progress,
        false,
        || async {
            if metadata.protocol == Protocol::Clickhouse {
                let previous_password = previous.environment.as_ref().ok_or_else(|| {
                    ApiError::Runtime(
                        "previous clickhouse credential was not captured for rollback".to_string(),
                    )
                })?;
                if wait_for_clickhouse_credential_state(
                    state,
                    metadata,
                    previous_password,
                    new_password,
                )
                .await?
                    == ClickhouseCredentialState::Replacement
                {
                    rotate_database_password_to_container_environment(
                        state,
                        metadata,
                        None,
                        Some(new_password),
                        Some(previous_password),
                    )
                    .await?;
                }
            } else if credential_changed
                && !matches!(
                    metadata.protocol,
                    Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
                )
            {
                rotate_database_password_to_container_environment(
                    state,
                    metadata,
                    previous.native_password_verifier.as_deref(),
                    (metadata.protocol == Protocol::Clickhouse).then_some(new_password),
                    previous.environment.as_ref(),
                )
                .await?;
            }
            Ok(())
        },
    )
    .await
    .map_err(|error| error.into_api_error())?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClickhouseCredentialState {
    Previous,
    Replacement,
}

async fn wait_for_clickhouse_credential_state(
    state: &AppState,
    metadata: &InstanceMetadata,
    previous_password: &SecretString,
    replacement_password: &SecretString,
) -> Result<ClickhouseCredentialState, ApiError> {
    let command = "clickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$DBE_CURRENT_PASSWORD\" --query 'SELECT 1' >/dev/null";
    let deadline = Instant::now() + ROTATION_READINESS_TIMEOUT;
    let mut last_error = String::new();
    while Instant::now() < deadline {
        for (state_name, password) in [
            (ClickhouseCredentialState::Previous, previous_password),
            (ClickhouseCredentialState::Replacement, replacement_password),
        ] {
            let environment = [("DBE_CURRENT_PASSWORD", password)];
            let probe = state.docker.exec_readiness_probe_with_secret_env(
                metadata.protocol,
                &metadata.instance_id,
                command,
                &environment,
            );
            match tokio::time::timeout(Duration::from_secs(5), probe).await {
                Ok(Ok(_)) => return Ok(state_name),
                Ok(Err(error)) => last_error = error.to_string(),
                Err(_) => last_error = "credential probe exceeded 5 seconds".to_string(),
            }
        }
        sleep(Duration::from_millis(250)).await;
    }
    Err(ApiError::Runtime(format!(
        "clickhouse did not accept either known credential during rollback: {last_error}"
    )))
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

async fn quarantine_instance(state: &AppState, metadata: &InstanceMetadata) {
    // Persist fail-closed intent before touching the runtime. If the process
    // crashes after this commit, boot reconciliation still refuses to restart
    // or route an instance whose active credential is uncertain.
    let quarantined = quarantined_metadata(metadata);
    if let Err(error) = state.manager.upsert(quarantined).await {
        tracing::error!(
            instance_id = %metadata.instance_id,
            error = %error,
            "failed to persist quarantine after password reset rollback failure; runtime stop will still be attempted"
        );
    }
    if let Err(error) = state
        .docker
        .stop(metadata.protocol, &metadata.instance_id)
        .await
        && !error.is_not_found()
    {
        tracing::error!(
            instance_id = %metadata.instance_id,
            %error,
            "failed to stop instance while quarantining an uncertain password rotation"
        );
    }
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.resource_cache.remove(&metadata.instance_id).await;
    state.monitoring_cache.invalidate().await;
}

fn quarantined_metadata(metadata: &InstanceMetadata) -> InstanceMetadata {
    let mut quarantined = metadata.clone();
    quarantined.status = InstanceStatus::Quarantined;
    quarantined.desired_state = crate::instances::metadata::DesiredInstanceState::Stopped;
    quarantined.updated_at = now_rfc3339();
    quarantined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_validation_rejects_empty_multiline_and_oversized_secrets() {
        assert!(validate_password(Protocol::Postgres, &SecretString::from("")).is_err());
        assert!(
            validate_password(Protocol::Postgres, &SecretString::from("line1\nline2")).is_err()
        );
        assert!(
            validate_password(
                Protocol::Postgres,
                &SecretString::from("x".repeat(MAX_PASSWORD_CHARACTERS + 1)),
            )
            .is_err()
        );
    }

    #[test]
    fn mariadb_rollback_uses_the_persisted_native_verifier_not_stale_environment() {
        assert!(credential_environment_keys(Protocol::Mariadb).is_empty());
    }

    #[test]
    fn qdrant_password_must_be_a_valid_header_value() {
        assert!(validate_password(Protocol::Qdrant, &SecretString::from("valid-api-key")).is_ok());
        assert!(validate_password(Protocol::Qdrant, &SecretString::from("invalid\u{7f}")).is_err());
    }

    #[test]
    fn clickhouse_rotation_sends_only_the_new_password_hash_in_sql() {
        let script = clickhouse_rotation_script("app_user", &SecretString::from("new-secret"));

        assert!(script.contains("IDENTIFIED WITH sha256_hash"));
        assert!(!script.contains("new-secret"));
    }

    #[test]
    fn route_auth_updates_only_protocol_specific_hidden_material() {
        let mut metadata = test_metadata(Protocol::Qdrant);
        apply_new_route_auth(&mut metadata, &SecretString::from("new-key"));

        assert_eq!(
            metadata.route_key_sha256.as_deref(),
            Some(crate::protocols::qdrant::route_key_sha256("new-key").as_str())
        );
        assert!(metadata.mariadb_native_password_sha1_stage2.is_none());
        assert_eq!(metadata.tenant_password.as_deref(), Some("new-key"));
    }

    #[test]
    fn only_immutable_or_legacy_protocol_credentials_require_recreation() {
        let current_resp = PreviousCredential {
            environment: Some(SecretString::from("current-password")),
            acl: Some(b"user dbe_health on nopass -@all +ping\n".to_vec()),
            ..PreviousCredential::default()
        };
        let legacy_resp = PreviousCredential {
            acl: Some(b"user dbe_health on nopass -@all +ping\n".to_vec()),
            ..PreviousCredential::default()
        };

        assert!(!requires_container_recreation(
            Protocol::Postgres,
            &current_resp
        ));
        assert!(!requires_container_recreation(
            Protocol::Mongodb,
            &current_resp
        ));
        assert!(!requires_container_recreation(
            Protocol::Redis,
            &current_resp
        ));
        assert!(requires_container_recreation(Protocol::Redis, &legacy_resp));
        assert!(requires_container_recreation(
            Protocol::Clickhouse,
            &current_resp
        ));
        assert!(requires_container_recreation(
            Protocol::Qdrant,
            &current_resp
        ));
    }

    #[test]
    fn uncertain_rotation_is_quarantined_and_stopped_for_boot() {
        let metadata = test_metadata(Protocol::Mongodb);

        let quarantined = quarantined_metadata(&metadata);

        assert_eq!(quarantined.status, InstanceStatus::Quarantined);
        assert_eq!(
            quarantined.desired_state,
            crate::instances::metadata::DesiredInstanceState::Stopped
        );
    }

    fn test_metadata(protocol: Protocol) -> InstanceMetadata {
        InstanceMetadata {
            schema_version: crate::instances::metadata::SCHEMA_VERSION,
            instance_id: "inst_password_test".to_string(),
            protocol,
            status: InstanceStatus::Running,
            desired_state: crate::instances::metadata::DesiredInstanceState::Running,
            public: crate::instances::metadata::PublicEndpoint {
                host: "db.example.test".to_string(),
                port: 1234,
            },
            backend: crate::shared::backend::BackendEndpoint::UnixSocket {
                socket_path: "/run/dbev/test.sock".to_string(),
            },
            runtime: crate::instances::metadata::RuntimeMetadata {
                kind: crate::instances::metadata::RuntimeKind::Docker,
                container_name: "dbe-test".to_string(),
                network_mode: "none".to_string(),
            },
            database: crate::instances::metadata::DatabaseIdentity {
                name: "app_db".to_string(),
                username: "app_user".to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mysql_native_password_sha1_stage2: None,
            mysql_root_password: None,
            mongodb_root_password: None,
            tenant_password: None,
            limits: crate::shared::limits::InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }
}
