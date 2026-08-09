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
const ROTATION_READINESS_TIMEOUT: Duration = Duration::from_secs(120);

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

    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.resource_cache.remove(&metadata.instance_id).await;
    state.monitoring_cache.invalidate().await;
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
    let mut previous = PreviousCredential::default();
    let environment_keys = credential_environment_keys(metadata.protocol);
    if !environment_keys.is_empty() {
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
        Protocol::Mariadb => &["DBE_MARIADB_PASSWORD", "MARIADB_PASSWORD"],
        Protocol::Mongodb => &["DBE_MONGO_PASSWORD"],
        Protocol::Clickhouse => &["CLICKHOUSE_PASSWORD"],
        Protocol::Qdrant => &["QDRANT__SERVICE__API_KEY"],
        Protocol::Redis | Protocol::Valkey | Protocol::Mysql => &[],
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
            clickhouse_current_password.ok_or_else(|| {
                ApiError::Runtime("current clickhouse credential is missing".to_string())
            })?,
            clickhouse_target_password.ok_or_else(|| {
                ApiError::Runtime("replacement clickhouse credential is missing".to_string())
            })?,
        ),
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => return Ok(()),
    };
    state
        .docker
        .exec_shell(metadata.protocol, &metadata.instance_id, &script)
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
        Protocol::Clickhouse => format!(
            "export DBE_CURRENT_PASSWORD={}\nclickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$DBE_CURRENT_PASSWORD\" --query 'SELECT 1' >/dev/null",
            sh_quote(
                clickhouse_current_password
                    .ok_or_else(|| ApiError::Runtime("current clickhouse credential is missing".to_string()))?
                    .expose_secret()
            )
        ),
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => return Ok(()),
    };
    let deadline = Instant::now() + ROTATION_READINESS_TIMEOUT;
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match state
            .docker
            .exec_readiness_probe(metadata.protocol, &metadata.instance_id, &command)
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_secs(1)).await;
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
        "set -eu\nprintf %s {} | psql -X -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -v ON_ERROR_STOP=1 -v tenant_password=\"$DBE_POSTGRES_PASSWORD\"\n",
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

fn clickhouse_rotation_script(
    username: &str,
    current_password: &SecretString,
    target_password: &SecretString,
) -> String {
    let username = format!("`{}`", username.replace('`', "``"));
    let password_hash = format!(
        "{:x}",
        Sha256::digest(target_password.expose_secret().as_bytes())
    );
    let query = format!("ALTER USER {username} IDENTIFIED WITH sha256_hash BY '{password_hash}'");
    format!(
        "set -eu\nexport DBE_CURRENT_PASSWORD={}\nclickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$DBE_CURRENT_PASSWORD\" --query {}\n",
        sh_quote(current_password.expose_secret()),
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
            "PGPASSWORD=\"$DBE_POSTGRES_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -Atqc 'SELECT 1' >/dev/null",
            sh_quote(&metadata.database.username),
            sh_quote(&metadata.database.name),
        ),
        Protocol::Redis => format!(
            "redis-cli -s /run/dbev/redis.sock --user {} -a {} --no-auth-warning ping >/dev/null",
            sh_quote(&metadata.database.username),
            sh_quote(new_password.expose_secret()),
        ),
        Protocol::Valkey => format!(
            "valkey-cli -s /run/dbev/valkey.sock --user {} -a {} --no-auth-warning ping >/dev/null",
            sh_quote(&metadata.database.username),
            sh_quote(new_password.expose_secret()),
        ),
        Protocol::Mariadb => "tenant_password=\"${DBE_MARIADB_PASSWORD:-${MARIADB_PASSWORD:-}}\"; MYSQL_PWD=\"$tenant_password\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" \"$MARIADB_DATABASE\" -N -B -e 'SELECT 1' >/dev/null".to_string(),
        Protocol::Mysql => format!(
            "MYSQL_PWD={} mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u {} {} -e 'SELECT 1' >/dev/null",
            sh_quote(new_password.expose_secret()),
            sh_quote(&metadata.database.username),
            sh_quote(&metadata.database.name),
        ),
        Protocol::Mongodb => "mongosh --quiet --host 127.0.0.1 --username \"$DBE_MONGO_USER\" --password \"$DBE_MONGO_PASSWORD\" --authenticationDatabase \"$DBE_MONGO_DATABASE\" \"$DBE_MONGO_DATABASE\" --eval 'db.runCommand({ ping: 1 }).ok' >/dev/null".to_string(),
        Protocol::Clickhouse => "clickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query 'SELECT 1' >/dev/null".to_string(),
        // Qdrant reads the new API key from its immutable container
        // configuration. Its startup readiness probe confirms the authenticated
        // gRPC listener is accepting connections before metadata is committed.
        Protocol::Qdrant => return Ok(()),
    };
    state
        .docker
        .exec_shell(metadata.protocol, &metadata.instance_id, &script)
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
            mark_instance_failed(state, metadata).await;
            tracing::error!(
                event = "audit instance_password_reset_rollback_failed",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                error = %original_message,
                rollback_error = %rollback_message,
                "instance password reset and rollback both failed"
            );
            Err(ApiError::Runtime(format!(
                "password reset failed ({original_message}) and rollback failed ({rollback_message}); instance was marked failed"
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
            if credential_changed
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

async fn mark_instance_failed(state: &AppState, metadata: &InstanceMetadata) {
    let mut failed = metadata.clone();
    failed.status = InstanceStatus::Failed;
    failed.updated_at = now_rfc3339();
    if let Err(error) = state.manager.upsert(failed).await {
        tracing::error!(
            instance_id = %metadata.instance_id,
            error = %error,
            "failed to persist failed status after password reset rollback failure"
        );
    }
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.resource_cache.remove(&metadata.instance_id).await;
    state.monitoring_cache.invalidate().await;
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
    fn mariadb_password_capture_prefers_dbev_env_and_supports_legacy_env() {
        assert_eq!(
            credential_environment_keys(Protocol::Mariadb),
            &["DBE_MARIADB_PASSWORD", "MARIADB_PASSWORD"]
        );
    }

    #[test]
    fn qdrant_password_must_be_a_valid_header_value() {
        assert!(validate_password(Protocol::Qdrant, &SecretString::from("valid-api-key")).is_ok());
        assert!(validate_password(Protocol::Qdrant, &SecretString::from("invalid\u{7f}")).is_err());
    }

    #[test]
    fn clickhouse_rotation_sends_only_the_new_password_hash_in_sql() {
        let script = clickhouse_rotation_script(
            "app_user",
            &SecretString::from("old-secret"),
            &SecretString::from("new-secret"),
        );

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
    }

    fn test_metadata(protocol: Protocol) -> InstanceMetadata {
        InstanceMetadata {
            schema_version: crate::instances::metadata::SCHEMA_VERSION,
            instance_id: "inst_password_test".to_string(),
            protocol,
            status: InstanceStatus::Running,
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
            limits: crate::shared::limits::InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }
}
