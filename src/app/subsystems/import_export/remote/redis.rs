use std::{
    future::Future,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use secrecy::SecretString;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::time::Instant;

use crate::{
    databases::protocol::Protocol,
    routes::http::{response::ApiError, router::AppState},
    server::jobs::import_export::create_bounded_archive,
    server::paths::InstancePaths,
    subsystems::{
        import_export::{check_restore_layout, rollback_from_archive},
        instances::{LifecycleAction, change_instance_state_locked},
    },
    utils::backend::backend_socket_path,
};

use super::{
    ImportMode, REMOTE_IMPORT_LIMITER, RemoteImportSource, commit_recovery_manifest,
    redis_resp::{
        RedisRelayError, RedisRespError, RedisRestoreExpiration, RespConnection, RespLimits,
    },
    staging_directory, sync_recovery_file,
};

const REDIS_SCAN_COUNT: u32 = 1_000;
const MAX_REDIS_CONTROL_BULK_BYTES: usize = 1024 * 1024;
const MAX_REDIS_CONTROL_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REDIS_VALUE_BYTES: usize = 512 * 1024 * 1024;
const MAX_REDIS_DUMP_OVERHEAD_BYTES: usize = 1024 * 1024;
const MAX_REDIS_DUMP_BYTES: usize = MAX_REDIS_VALUE_BYTES + MAX_REDIS_DUMP_OVERHEAD_BYTES;
const MAX_REDIS_ACL_FILE_BYTES: u64 = 1024 * 1024;
const PRIVATE_TARGET_READINESS_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_VALKEY_COMPATIBLE_REDIS_VERSION: (u32, u32) = (7, 2);

#[derive(Serialize)]
struct RedisRecoveryManifest<'a> {
    schema_version: u32,
    recovery_kind: &'static str,
    instance_id: &'a str,
    protocol: &'static str,
    import_mode: ImportMode,
    rollback_file: &'static str,
    created_at: String,
}

fn operation_deadlines(started: Instant, timeout: Duration) -> (Instant, Instant) {
    let operation_deadline = started + timeout;
    let rollback_budget = timeout / 4;
    let work_deadline = operation_deadline - rollback_budget;
    (work_deadline, operation_deadline)
}

fn remaining_redis_timeout(
    deadline: Instant,
    maximum: Duration,
    phase: &'static str,
) -> Result<Duration, ApiError> {
    remaining_redis_timeout_at(Instant::now(), deadline, maximum, phase)
}

fn remaining_redis_timeout_at(
    now: Instant,
    deadline: Instant,
    maximum: Duration,
    phase: &'static str,
) -> Result<Duration, ApiError> {
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        return Err(operation_timeout_error(phase));
    }
    Ok(maximum.min(remaining))
}

async fn redis_with_deadline<T>(
    deadline: Instant,
    phase: &'static str,
    operation: impl Future<Output = Result<T, ApiError>>,
) -> Result<T, ApiError> {
    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| operation_timeout_error(phase))?
}

fn operation_timeout_error(phase: &'static str) -> ApiError {
    ApiError::ServiceUnavailable(format!("remote RESP import timed out during {phase}"))
}

pub(crate) async fn import_resp(
    state: &AppState,
    instance_id: &str,
    source: &RemoteImportSource,
    mode: ImportMode,
    target_protocol: Protocol,
) -> Result<(), ApiError> {
    let _permit = REMOTE_IMPORT_LIMITER
        .acquire(state.config.security.remote_import.max_concurrent_jobs)
        .await;
    let policy = &state.config.security.remote_import;
    let operation_timeout = Duration::from_secs(policy.operation_timeout_seconds);
    let (work_deadline, operation_deadline) =
        operation_deadlines(Instant::now(), operation_timeout);
    let connect_timeout = Duration::from_secs(policy.connect_timeout_seconds);
    let limits = RespLimits {
        max_bulk_len: MAX_REDIS_CONTROL_BULK_BYTES,
        max_response_bytes: MAX_REDIS_CONTROL_RESPONSE_BYTES,
        ..RespLimits::default()
    };
    // Validate credentials and topology before stopping the managed target. Do not retain this
    // socket while a potentially large rollback archive is created: remote idle timeouts could
    // otherwise make the first SCAN fail after the target has already been prepared.
    drop(
        connect_redis_source(
            source,
            connect_timeout,
            work_deadline,
            limits,
            "source preflight",
        )
        .await?,
    );

    let (paths, staging) = redis_with_deadline(work_deadline, "target preflight", async {
        let metadata = state
            .instances
            .get(instance_id)
            .await
            .ok_or(ApiError::NotFound)?;
        if metadata.protocol != target_protocol {
            return Err(ApiError::BadRequest(format!(
                "{} remote import requires a {} target instance",
                target_protocol.as_str(),
                target_protocol.as_str()
            )));
        }
        let paths =
            InstancePaths::new(&state.config.paths, instance_id).map_err(ApiError::bad_request)?;
        check_restore_layout(state, &metadata, &paths)?;
        let staging = staging_directory(state).await?;
        Ok((paths, staging))
    })
    .await?;
    let rollback_file = match target_protocol {
        Protocol::Redis => "rollback.redis.tar.gz",
        Protocol::Valkey => "rollback.valkey.tar.gz",
        _ => unreachable!("RESP import target is Redis or Valkey"),
    };
    let rollback = staging.join(rollback_file);
    let recovery_manifest = staging.join("recovery-manifest.json");

    if let Err(error) = redis_with_deadline(
        work_deadline,
        "target stop",
        change_instance_state_locked(state, instance_id, LifecycleAction::Stop),
    )
    .await
    {
        return recover_redis_prep(state, instance_id, &staging, operation_deadline, error).await;
    }

    let original_acl = match redis_with_deadline(work_deadline, "rollback preparation", async {
        create_bounded_archive(
            paths.data.clone(),
            rollback.clone(),
            policy.max_staged_bytes,
        )
        .await
        .map_err(ApiError::runtime_context(
            "failed to create RESP rollback archive",
        ))?;
        validate_rollback_archive(&rollback, policy.max_staged_bytes).await?;
        let original_acl = read_acl_file(&paths.data.join("users.acl")).await?;
        sync_recovery_file(&rollback).await?;
        write_recovery_manifest(
            &recovery_manifest,
            instance_id,
            target_protocol,
            rollback_file,
            mode,
        )
        .await?;
        Ok(original_acl)
    })
    .await
    {
        Ok(original_acl) => original_acl,
        Err(error) => {
            return recover_redis_prep(state, instance_id, &staging, operation_deadline, error)
                .await;
        }
    };
    let temporary_username = format!("dbe_import_{}", uuid::Uuid::new_v4().simple());
    let temporary_password = SecretString::from(format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    ));
    let temporary_acl =
        append_temporary_acl(&original_acl, &temporary_username, &temporary_password);
    let preserve_acl_owner = true;

    let primary = redis_with_deadline(work_deadline, "target import", async {
        replace_acl_file(&paths, &temporary_acl, preserve_acl_owner).await?;
        start_private_redis(state, instance_id, target_protocol, work_deadline).await?;
        let socket = backend_socket_path(&paths.sockets, target_protocol);
        let target_io_timeout =
            remaining_redis_timeout(work_deadline, operation_timeout, "target connection")?;
        let target_connect_timeout = connect_timeout.min(target_io_timeout);
        let mut target = RespConnection::connect_unix_limited(
            &socket,
            target_connect_timeout,
            target_io_timeout,
            target_io_timeout,
            limits,
        )
        .await
        .map_err(target_error)?;
        target
            .auth(Some(&temporary_username), &temporary_password)
            .await
            .map_err(target_error)?;
        target.ping().await.map_err(target_error)?;
        let cluster_info = target.info_cluster().await.map_err(target_error)?;
        check_standalone(&cluster_info, false)?;
        let mut remote = connect_redis_source(
            source,
            connect_timeout,
            work_deadline,
            limits,
            "source reconnect",
        )
        .await?;
        let source_info = remote.info_server().await.map_err(source_error)?;
        let target_info = target.info_server().await.map_err(target_error)?;
        check_redis_versions(target_protocol, &source_info, &target_info)?;
        if mode == ImportMode::Wipe {
            target.flushdb().await.map_err(target_error)?;
        }

        copy_redis_keys(&mut remote, &mut target).await?;

        replace_acl_file(&paths, &original_acl, preserve_acl_owner).await?;
        target.acl_load().await.map_err(target_error)?;
        drop(target);
        change_instance_state_locked(state, instance_id, LifecycleAction::Start)
            .await
            .map(|_| ())
    })
    .await;

    match primary {
        Ok(()) => {
            if let Err(error) = redis_with_deadline(
                operation_deadline,
                "recovery commit",
                commit_recovery_manifest(&recovery_manifest),
            )
            .await
            {
                let quarantine = quarantine_target(state, instance_id).await;
                return Err(ApiError::Runtime(format!(
                    "{target_protocol} import was applied, but its recovery commit marker could not be removed: {error}; {quarantine}; rollback staging was retained at {}",
                    staging.display()
                )));
            }
            cleanup_staging_until(&staging, operation_deadline).await;
            Ok(())
        }
        Err(primary_error) => {
            match redis_with_deadline(
                operation_deadline,
                "rollback",
                rollback_redis_target(state, instance_id, target_protocol, &paths, &rollback),
            )
            .await
            {
                Ok(()) => {
                    if let Err(commit_error) = redis_with_deadline(
                        operation_deadline,
                        "rollback recovery commit",
                        commit_recovery_manifest(&recovery_manifest),
                    )
                    .await
                    {
                        let quarantine = quarantine_target(state, instance_id).await;
                        return Err(ApiError::Runtime(format!(
                            "{target_protocol} remote import failed: {primary_error}; rollback succeeded, but recovery metadata could not be committed: {commit_error}; {quarantine}; staging was retained at {}",
                            staging.display()
                        )));
                    }
                    cleanup_staging_until(&staging, operation_deadline).await;
                    Err(primary_error)
                }
                Err(rollback_error) => {
                    let quarantine = quarantine_target(state, instance_id).await;
                    Err(ApiError::Runtime(format!(
                        "{target_protocol} remote import failed: {primary_error}; rollback failed: {rollback_error}; {quarantine}; rollback archive retained at {}",
                        rollback.display()
                    )))
                }
            }
        }
    }
}

async fn quarantine_target(state: &AppState, instance_id: &str) -> String {
    match crate::subsystems::import_export::quarantine_uncertain_import(state, instance_id).await {
        Ok(()) => "target was stopped and quarantined".to_string(),
        Err(error) => format!(
            "gateway routes were removed and the target was quarantined in memory, but complete shutdown/persistence reported: {error}"
        ),
    }
}

async fn write_recovery_manifest(
    path: &Path,
    instance_id: &str,
    protocol: Protocol,
    rollback_file: &'static str,
    mode: ImportMode,
) -> Result<(), ApiError> {
    let recovery_kind = match protocol {
        Protocol::Redis => "redis_remote_import",
        Protocol::Valkey => "valkey_remote_import",
        _ => unreachable!("RESP recovery target is Redis or Valkey"),
    };
    let contents = serde_json::to_vec_pretty(&RedisRecoveryManifest {
        schema_version: 1,
        recovery_kind,
        instance_id,
        protocol: protocol.as_str(),
        import_mode: mode,
        rollback_file,
        created_at: crate::server::jobs::import_export::now_rfc3339(),
    })
    .map_err(ApiError::runtime_context(
        "failed to encode RESP recovery manifest",
    ))?;
    let path = path.to_path_buf();
    crate::routes::http::response::run_blocking(
        "failed to write RESP recovery manifest",
        move || crate::io::files::atomic_write_private(&path, &contents),
    )
    .await
}

async fn connect_redis_source(
    source: &RemoteImportSource,
    connect_timeout: Duration,
    deadline: Instant,
    limits: RespLimits,
    phase: &'static str,
) -> Result<RespConnection, ApiError> {
    let io_timeout = remaining_redis_timeout(deadline, Duration::MAX, phase)?;
    let connect_timeout = connect_timeout.min(io_timeout);
    redis_with_deadline(deadline, phase, async {
        let mut remote = RespConnection::connect_source_limited(
            &source.endpoint,
            connect_timeout,
            io_timeout,
            io_timeout,
            limits,
        )
        .await
        .map_err(source_error)?;
        if let Some(password) = source.password.as_ref() {
            remote
                .auth(source.username.as_deref(), password)
                .await
                .map_err(source_error)?;
        }
        remote.ping().await.map_err(source_error)?;
        let info = remote.info_server().await.map_err(source_error)?;
        check_redis_version(&info)?;
        let cluster_info = remote.info_cluster().await.map_err(source_error)?;
        check_standalone(&cluster_info, true)?;
        remote
            .select(source.database_index)
            .await
            .map_err(source_error)?;
        Ok(remote)
    })
    .await
}

async fn validate_rollback_archive(path: &Path, max_bytes: u64) -> Result<(), ApiError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(ApiError::runtime_context(
            "failed to inspect RESP rollback archive",
        ))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        let _ = tokio::fs::remove_file(path).await;
        return Err(ApiError::Runtime(
            "RESP rollback archive failed staging validation".to_string(),
        ));
    }
    Ok(())
}

async fn recover_redis_prep(
    state: &AppState,
    instance_id: &str,
    staging: &Path,
    deadline: Instant,
    primary_error: ApiError,
) -> Result<(), ApiError> {
    match redis_with_deadline(
        deadline,
        "target restart after preparation failure",
        async {
            change_instance_state_locked(state, instance_id, LifecycleAction::Start)
                .await
                .map(|_| ())
        },
    )
    .await
    {
        Ok(()) => {
            cleanup_staging_until(staging, deadline).await;
            Err(primary_error)
        }
        Err(restart_error) => Err(ApiError::Runtime(format!(
            "{primary_error}; target restart also failed: {restart_error}; recovery staging retained at {}",
            staging.display()
        ))),
    }
}

async fn cleanup_redis_staging(staging: &Path) {
    if let Err(error) = tokio::fs::remove_dir_all(staging).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            path = %staging.display(),
            %error,
            "failed to remove RESP import staging directory"
        );
    }
}

async fn cleanup_staging_until(staging: &Path, deadline: Instant) {
    if tokio::time::timeout_at(deadline, cleanup_redis_staging(staging))
        .await
        .is_err()
    {
        tracing::warn!(
            path = %staging.display(),
            "RESP import staging cleanup exceeded the operation deadline and was retained"
        );
    }
}

async fn copy_redis_keys(
    source: &mut RespConnection,
    target: &mut RespConnection,
) -> Result<(), ApiError> {
    let mut cursor = 0_u64;
    loop {
        let page = source
            .scan(cursor, REDIS_SCAN_COUNT)
            .await
            .map_err(source_error)?;
        for key in page.keys {
            let ttl = source.pttl(&key).await.map_err(source_error)?;
            let Some(expiration) = redis_restore_expiration(ttl, SystemTime::now())? else {
                continue;
            };
            // PTTL and DUMP are separate Redis operations. Operators must quiesce source writes
            // during migration so a concurrently replaced value cannot inherit the prior TTL.
            let _restored = source
                .relay_restore_replace(target, &key, expiration, MAX_REDIS_DUMP_BYTES)
                .await
                .map_err(relay_error)?;
        }
        cursor = page.next_cursor;
        if cursor == 0 {
            return Ok(());
        }
    }
}

fn redis_restore_expiration(
    ttl_milliseconds: i64,
    now: SystemTime,
) -> Result<Option<RedisRestoreExpiration>, ApiError> {
    match ttl_milliseconds {
        -2 => Ok(None),
        -1 => Ok(Some(RedisRestoreExpiration::Persistent)),
        value if value >= 0 => {
            let remaining_milliseconds = u64::try_from(value)
                .map_err(|_| {
                    ApiError::BadRequest(
                        "remote RESP source returned an invalid PTTL value".to_string(),
                    )
                })?
                .max(1);
            let now_milliseconds = now
                .duration_since(UNIX_EPOCH)
                .map_err(|_| {
                    ApiError::Runtime(
                        "system clock is before the Unix epoch; cannot preserve RESP key expiration"
                            .to_string(),
                    )
                })?
                .as_millis();
            let now_milliseconds = u64::try_from(now_milliseconds).map_err(|_| {
                ApiError::Runtime(
                    "system clock is too large to preserve RESP key expiration".to_string(),
                )
            })?;
            let deadline = now_milliseconds
                .checked_add(remaining_milliseconds)
                .ok_or_else(|| {
                    ApiError::BadRequest("remote RESP key expiration is too large".to_string())
                })?;
            Ok(Some(RedisRestoreExpiration::AbsoluteUnixMilliseconds(
                deadline,
            )))
        }
        value => Err(ApiError::BadRequest(format!(
            "remote RESP source returned invalid PTTL value {value}"
        ))),
    }
}

async fn rollback_redis_target(
    state: &AppState,
    instance_id: &str,
    protocol: Protocol,
    paths: &InstancePaths,
    rollback: &Path,
) -> Result<(), ApiError> {
    if let Err(error) = state.docker.stop(protocol, instance_id).await
        && !error.is_not_running()
        && !error.is_not_found()
    {
        return Err(ApiError::Runtime(format!(
            "failed to stop {protocol} before rollback: {error}"
        )));
    }
    rollback_from_archive(state, instance_id, paths.clone(), rollback).await
}

async fn start_private_redis(
    state: &AppState,
    instance_id: &str,
    protocol: Protocol,
    deadline: Instant,
) -> Result<(), ApiError> {
    redis_with_deadline(deadline, "private target startup", async {
        state
            .docker
            .start(protocol, instance_id)
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to start private {protocol} import target: {error}"
                ))
            })?;
        let readiness_timeout = remaining_redis_timeout(
            deadline,
            PRIVATE_TARGET_READINESS_TIMEOUT,
            "private target readiness",
        )?;
        state
            .docker
            .wait_until_ready(protocol, instance_id, readiness_timeout)
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "private {protocol} import target was not ready: {error}"
                ))
            })
            .map(|_| ())
    })
    .await
}

async fn read_acl_file(path: &Path) -> Result<Vec<u8>, ApiError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(ApiError::runtime_context(
            "failed to inspect managed RESP ACL file",
        ))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_REDIS_ACL_FILE_BYTES
    {
        return Err(ApiError::Runtime(
            "managed RESP ACL path is not a safe regular file".to_string(),
        ));
    }
    tokio::fs::read(path)
        .await
        .map_err(ApiError::runtime_context("failed to read managed RESP ACL"))
}

fn append_temporary_acl(original: &[u8], username: &str, password: &SecretString) -> Vec<u8> {
    use secrecy::ExposeSecret;

    let hash = hex::encode(Sha256::digest(password.expose_secret().as_bytes()));
    let mut acl = original.to_vec();
    if !acl.ends_with(b"\n") {
        acl.push(b'\n');
    }
    acl.extend_from_slice(format!("user {username} on #{hash} ~* &* +@all\n").as_bytes());
    acl
}

async fn replace_acl_file(
    paths: &InstancePaths,
    contents: &[u8],
    preserve_owner: bool,
) -> Result<(), ApiError> {
    use tokio::io::AsyncWriteExt;

    let target = paths.data.join("users.acl");
    let metadata = read_acl_metadata(&target).await?;
    let temporary = paths
        .data
        .join(format!(".users.acl.{}", uuid::Uuid::new_v4().simple()));
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .await
        .map_err(ApiError::runtime_context(
            "failed to create temporary RESP ACL",
        ))?;
    file.write_all(contents)
        .await
        .map_err(ApiError::runtime_context(
            "failed to write temporary RESP ACL",
        ))?;
    apply_acl_metadata(&file, metadata, preserve_owner).await?;
    file.sync_all().await.map_err(ApiError::runtime_context(
        "failed to sync temporary RESP ACL",
    ))?;
    drop(file);
    if let Err(error) = tokio::fs::rename(&temporary, &target).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(ApiError::Runtime(format!(
            "failed to install temporary RESP ACL: {error}"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RedisAclMetadata {
    uid: u32,
    gid: u32,
    mode: u32,
}

async fn read_acl_metadata(path: &Path) -> Result<RedisAclMetadata, ApiError> {
    use std::os::unix::fs::MetadataExt;

    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    let file = options.open(path).await.map_err(ApiError::runtime_context(
        "failed to open managed RESP ACL metadata safely",
    ))?;
    let metadata = file.metadata().await.map_err(ApiError::runtime_context(
        "failed to inspect managed RESP ACL metadata",
    ))?;
    if !metadata.is_file() {
        return Err(ApiError::Runtime(
            "managed RESP ACL path is not a safe regular file".to_string(),
        ));
    }
    Ok(RedisAclMetadata {
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
    })
}

async fn apply_acl_metadata(
    file: &tokio::fs::File,
    metadata: RedisAclMetadata,
    preserve_owner: bool,
) -> Result<(), ApiError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if preserve_owner {
        let current = file.metadata().await.map_err(ApiError::runtime_context(
            "failed to inspect temporary RESP ACL ownership",
        ))?;
        if current.uid() != metadata.uid || current.gid() != metadata.gid {
            rustix::fs::fchown(
                file,
                Some(rustix::process::Uid::from_raw(metadata.uid)),
                Some(rustix::process::Gid::from_raw(metadata.gid)),
            )
            .map_err(ApiError::runtime_context(
                "failed to preserve managed RESP ACL ownership",
            ))?;
        }
    }
    file.set_permissions(std::fs::Permissions::from_mode(metadata.mode))
        .await
        .map_err(ApiError::runtime_context(
            "failed to preserve managed RESP ACL permissions",
        ))
}

fn check_redis_version(info: &[u8]) -> Result<(), ApiError> {
    let server = parse_resp_server_version(info).ok_or_else(|| {
        ApiError::BadRequest("remote RESP INFO did not report a valid server version".to_string())
    })?;
    if server.family == RespServerFamily::Redis && server.version < (2, 6, 0) {
        return Err(ApiError::BadRequest(
            "remote Redis version does not support DUMP/RESTORE import".to_string(),
        ));
    }
    Ok(())
}

fn check_redis_versions(
    target_protocol: Protocol,
    source: &[u8],
    target: &[u8],
) -> Result<(), ApiError> {
    let source = parse_resp_server_version(source).ok_or_else(|| {
        ApiError::BadRequest("remote RESP INFO did not report a valid server version".to_string())
    })?;
    let target = parse_resp_server_version(target).ok_or_else(|| {
        ApiError::Runtime("managed RESP INFO did not report a valid server version".to_string())
    })?;

    match target_protocol {
        Protocol::Redis => {
            if target.family != RespServerFamily::Redis {
                return Err(ApiError::Runtime(
                    "managed Redis target identified itself as Valkey".to_string(),
                ));
            }
            if source.family != RespServerFamily::Redis {
                return Err(ApiError::BadRequest(
                    "Valkey-to-Redis remote import is not guaranteed to be serialization-compatible; import into a Valkey target instead"
                        .to_string(),
                ));
            }
            if target.version < (5, 0, 0) {
                return Err(ApiError::Runtime(
                    "managed Redis target does not support expiration-preserving RESTORE ABSTTL"
                        .to_string(),
                ));
            }
            if target.version < source.version {
                return Err(ApiError::BadRequest(
                    "managed Redis target must be the same or a newer version than the remote source for DUMP/RESTORE compatibility"
                        .to_string(),
                ));
            }
        }
        Protocol::Valkey => {
            if target.family != RespServerFamily::Valkey {
                return Err(ApiError::Runtime(
                    "managed Valkey target did not identify itself as Valkey".to_string(),
                ));
            }
            match source.family {
                RespServerFamily::Valkey if target.version < source.version => {
                    return Err(ApiError::BadRequest(
                        "managed Valkey target must be the same or a newer version than the remote Valkey source for DUMP/RESTORE compatibility"
                            .to_string(),
                    ));
                }
                RespServerFamily::Redis
                    if (source.version.0, source.version.1)
                        > MAX_VALKEY_COMPATIBLE_REDIS_VERSION =>
                {
                    return Err(ApiError::BadRequest(
                        "Valkey accepts Redis OSS persistence data only through version 7.2; use a Redis 7.2-or-older source or database-specific migration tooling"
                            .to_string(),
                    ));
                }
                RespServerFamily::Redis | RespServerFamily::Valkey => {}
            }
        }
        _ => unreachable!("RESP import target is Redis or Valkey"),
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RespServerFamily {
    Redis,
    Valkey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RespServerVersion {
    family: RespServerFamily,
    version: (u32, u32, u32),
}

fn parse_resp_server_version(info: &[u8]) -> Option<RespServerVersion> {
    let info = std::str::from_utf8(info).ok()?;
    let server_name = unique_info_value(info, "server_name:")?;
    let valkey_version = unique_info_value(info, "valkey_version:")?;
    let redis_version = unique_info_value(info, "redis_version:")?;
    let identifies_as_valkey = server_name.is_some_and(|name| name.eq_ignore_ascii_case("valkey"))
        || valkey_version.is_some();
    if server_name.is_some_and(|name| !name.eq_ignore_ascii_case("valkey"))
        && valkey_version.is_some()
    {
        return None;
    }
    let (family, version) = if identifies_as_valkey {
        (RespServerFamily::Valkey, valkey_version?)
    } else {
        (RespServerFamily::Redis, redis_version?)
    };
    Some(RespServerVersion {
        family,
        version: parse_semver_triplet(version)?,
    })
}

fn unique_info_value<'a>(info: &'a str, prefix: &str) -> Option<Option<&'a str>> {
    let mut values = info
        .lines()
        .filter_map(|line| line.strip_prefix(prefix).map(str::trim));
    let value = values.next();
    if values.next().is_some() {
        None
    } else {
        Some(value)
    }
}

fn parse_semver_triplet(version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts
        .next()?
        .split(|character: char| !character.is_ascii_digit())
        .next()
        .filter(|value| !value.is_empty())?
        .parse()
        .ok()?;
    Some((major, minor, patch))
}

fn check_standalone(info: &[u8], source: bool) -> Result<(), ApiError> {
    match parse_redis_cluster_enabled(info) {
        Some(false) => Ok(()),
        Some(true) if source => Err(ApiError::BadRequest(
            "remote RESP cluster mode is unsupported because SCAN on one endpoint can omit keys stored on other nodes; use a standalone source or cluster migration tooling"
                .to_string(),
        )),
        Some(true) => Err(ApiError::Runtime(
            "managed RESP target unexpectedly has cluster mode enabled; remote key import requires a standalone target"
                .to_string(),
        )),
        None if source => Err(ApiError::BadRequest(
            "remote RESP INFO cluster response is invalid".to_string(),
        )),
        None => Err(ApiError::Runtime(
            "managed RESP INFO cluster response is invalid".to_string(),
        )),
    }
}

fn parse_redis_cluster_enabled(info: &[u8]) -> Option<bool> {
    let info = std::str::from_utf8(info).ok()?;
    let mut enabled = None;
    for line in info.lines() {
        let Some(value) = line.strip_prefix("cluster_enabled:") else {
            continue;
        };
        if enabled.is_some() {
            return None;
        }
        enabled = match value.trim() {
            "0" => Some(false),
            "1" => Some(true),
            _ => return None,
        };
    }
    enabled
}

fn source_error(error: RedisRespError) -> ApiError {
    ApiError::BadRequest(format!(
        "remote RESP source failed: {}",
        redis_error_summary(&error)
    ))
}

fn target_error(error: RedisRespError) -> ApiError {
    ApiError::Runtime(format!(
        "managed RESP import target failed: {}",
        redis_error_summary(&error)
    ))
}

fn relay_error(error: RedisRelayError) -> ApiError {
    match error {
        RedisRelayError::Source(error) => source_error(error),
        RedisRelayError::Target(error) => target_error(error),
    }
}

fn redis_error_summary(error: &RedisRespError) -> &'static str {
    match error {
        RedisRespError::NoResolvedAddresses => "no validated address was available",
        RedisRespError::Timeout { .. } => "the operation timed out",
        RedisRespError::Connect { .. } => "the connection failed",
        RedisRespError::InvalidTlsServerName(_) => "the TLS server name was invalid",
        RedisRespError::Io(_) => "an I/O operation failed",
        RedisRespError::Protocol(_) => "an invalid protocol response was received",
        RedisRespError::LimitExceeded { .. } => "a response exceeded a safety limit",
        RedisRespError::Server(_) => "the server rejected a required command",
        RedisRespError::UnexpectedResponse { .. } => "an unexpected response was received",
        RedisRespError::InvalidArgument(_) => "an internal command argument was invalid",
    }
}

#[cfg(test)]
mod tests;
