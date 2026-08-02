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
    api::{
        api_response::ApiError,
        import_export::replace_data_from_archive,
        instances::{LifecycleAction, lifecycle_instance_locked},
        routes::AppState,
    },
    instances::paths::InstancePaths,
    jobs::import_export::create_data_archive_bounded,
    shared::protocol::Protocol,
};

use super::{
    ImportMode, REMOTE_IMPORT_LIMITER, RemoteImportSource, commit_recovery_manifest,
    redis_resp::{
        RedisRelayError, RedisRespError, RedisRestoreExpiration, RespConnection, RespLimits,
    },
    remote_staging_directory, sync_recovery_file,
};

const REDIS_SCAN_COUNT: u32 = 1_000;
const MAX_REDIS_CONTROL_BULK_BYTES: usize = 1024 * 1024;
const MAX_REDIS_CONTROL_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REDIS_VALUE_BYTES: usize = 512 * 1024 * 1024;
const MAX_REDIS_DUMP_OVERHEAD_BYTES: usize = 1024 * 1024;
const MAX_REDIS_DUMP_BYTES: usize = MAX_REDIS_VALUE_BYTES + MAX_REDIS_DUMP_OVERHEAD_BYTES;

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

fn redis_operation_deadlines(started: Instant, timeout: Duration) -> (Instant, Instant) {
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
        return Err(redis_operation_timeout_error(phase));
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
        .map_err(|_| redis_operation_timeout_error(phase))?
}

fn redis_operation_timeout_error(phase: &'static str) -> ApiError {
    ApiError::ServiceUnavailable(format!("remote redis import timed out during {phase}"))
}

pub async fn import_redis(
    state: &AppState,
    instance_id: &str,
    source: &RemoteImportSource,
    mode: ImportMode,
) -> Result<(), ApiError> {
    let _permit = REMOTE_IMPORT_LIMITER
        .acquire(state.config.security.remote_import.max_concurrent_jobs)
        .await;
    let policy = &state.config.security.remote_import;
    let operation_timeout = Duration::from_secs(policy.operation_timeout_seconds);
    let (work_deadline, operation_deadline) =
        redis_operation_deadlines(Instant::now(), operation_timeout);
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
        if metadata.protocol != Protocol::Redis {
            return Err(ApiError::BadRequest(
                "redis remote import requires a redis target instance".to_string(),
            ));
        }
        let paths = InstancePaths::new(&state.config.paths, instance_id)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        let staging = remote_staging_directory(state).await?;
        Ok((paths, staging))
    })
    .await?;
    let rollback = staging.join("rollback.redis.tar.gz");
    let recovery_manifest = staging.join("recovery-manifest.json");

    if let Err(error) = redis_with_deadline(
        work_deadline,
        "target stop",
        lifecycle_instance_locked(state, instance_id, LifecycleAction::Stop),
    )
    .await
    {
        return restart_redis_after_preparation_failure(
            state,
            instance_id,
            &staging,
            operation_deadline,
            error,
        )
        .await;
    }

    let original_acl = match redis_with_deadline(work_deadline, "rollback preparation", async {
        create_data_archive_bounded(
            paths.data.clone(),
            rollback.clone(),
            policy.max_staged_bytes,
        )
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("failed to create redis rollback archive: {error}"))
        })?;
        validate_redis_rollback_archive(&rollback, policy.max_staged_bytes).await?;
        let original_acl = read_acl_file(&paths.data.join("users.acl")).await?;
        sync_recovery_file(&rollback).await?;
        write_redis_recovery_manifest(&recovery_manifest, instance_id, mode).await?;
        Ok(original_acl)
    })
    .await
    {
        Ok(original_acl) => original_acl,
        Err(error) => {
            return restart_redis_after_preparation_failure(
                state,
                instance_id,
                &staging,
                operation_deadline,
                error,
            )
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
        start_private_redis(state, instance_id, work_deadline).await?;
        let socket = paths.sockets.join("redis.sock");
        let target_io_timeout =
            remaining_redis_timeout(work_deadline, operation_timeout, "target connection")?;
        let target_connect_timeout = connect_timeout.min(target_io_timeout);
        let mut target = RespConnection::connect_unix_with_options(
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
        ensure_redis_standalone(&cluster_info, false)?;
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
        ensure_redis_versions_compatible(&source_info, &target_info)?;
        if mode == ImportMode::Wipe {
            target.flushdb().await.map_err(target_error)?;
        }

        copy_redis_keys(&mut remote, &mut target).await?;

        replace_acl_file(&paths, &original_acl, preserve_acl_owner).await?;
        target.acl_load().await.map_err(target_error)?;
        drop(target);
        lifecycle_instance_locked(state, instance_id, LifecycleAction::Start)
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
                let quarantine = crate::api::import_export::quarantine_after_uncertain_import(
                    state,
                    instance_id,
                )
                .await;
                let quarantine = match quarantine {
                    Ok(()) => "target was stopped and quarantined".to_string(),
                    Err(error) => format!(
                        "gateway routes were removed and the target was quarantined in memory, but complete shutdown/persistence reported: {error}"
                    ),
                };
                return Err(ApiError::Runtime(format!(
                    "redis import was applied, but its recovery commit marker could not be removed: {error}; {quarantine}; rollback staging was retained at {}",
                    staging.display()
                )));
            }
            cleanup_redis_staging_until(&staging, operation_deadline).await;
            Ok(())
        }
        Err(primary_error) => {
            match redis_with_deadline(
                operation_deadline,
                "rollback",
                rollback_redis_target(state, instance_id, &paths, &rollback),
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
                        let quarantine =
                            crate::api::import_export::quarantine_after_uncertain_import(
                                state,
                                instance_id,
                            )
                            .await;
                        let quarantine = match quarantine {
                            Ok(()) => "target was stopped and quarantined".to_string(),
                            Err(error) => format!(
                                "gateway routes were removed and the target was quarantined in memory, but complete shutdown/persistence reported: {error}"
                            ),
                        };
                        return Err(ApiError::Runtime(format!(
                            "redis remote import failed: {primary_error}; rollback succeeded, but recovery metadata could not be committed: {commit_error}; {quarantine}; staging was retained at {}",
                            staging.display()
                        )));
                    }
                    cleanup_redis_staging_until(&staging, operation_deadline).await;
                    Err(primary_error)
                }
                Err(rollback_error) => {
                    let quarantine = crate::api::import_export::quarantine_after_uncertain_import(
                        state,
                        instance_id,
                    )
                    .await;
                    let quarantine = match quarantine {
                        Ok(()) => "target was stopped and quarantined".to_string(),
                        Err(error) => format!(
                            "gateway routes were removed and the target was quarantined in memory, but complete shutdown/persistence reported: {error}"
                        ),
                    };
                    Err(ApiError::Runtime(format!(
                        "redis remote import failed: {primary_error}; rollback failed: {rollback_error}; {quarantine}; rollback archive retained at {}",
                        rollback.display()
                    )))
                }
            }
        }
    }
}

async fn write_redis_recovery_manifest(
    path: &Path,
    instance_id: &str,
    mode: ImportMode,
) -> Result<(), ApiError> {
    let contents = serde_json::to_vec_pretty(&RedisRecoveryManifest {
        schema_version: 1,
        recovery_kind: "redis_remote_import",
        instance_id,
        protocol: "redis",
        import_mode: mode,
        rollback_file: "rollback.redis.tar.gz",
        created_at: crate::jobs::import_export::now_rfc3339(),
    })
    .map_err(|error| {
        ApiError::Runtime(format!("failed to encode redis recovery manifest: {error}"))
    })?;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        crate::shared::files::atomic_write_private(&path, &contents)
    })
    .await
    .map_err(|error| {
        ApiError::Runtime(format!("failed to write redis recovery manifest: {error}"))
    })?
    .map_err(|error| ApiError::Runtime(format!("failed to write redis recovery manifest: {error}")))
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
        let mut remote = RespConnection::connect_source_with_options(
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
        ensure_supported_redis_version(&info)?;
        let cluster_info = remote.info_cluster().await.map_err(source_error)?;
        ensure_redis_standalone(&cluster_info, true)?;
        remote
            .select(source.database_index)
            .await
            .map_err(source_error)?;
        Ok(remote)
    })
    .await
}

async fn validate_redis_rollback_archive(path: &Path, max_bytes: u64) -> Result<(), ApiError> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        ApiError::Runtime(format!("failed to inspect redis rollback archive: {error}"))
    })?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        let _ = tokio::fs::remove_file(path).await;
        return Err(ApiError::Runtime(
            "redis rollback archive failed staging validation".to_string(),
        ));
    }
    Ok(())
}

async fn restart_redis_after_preparation_failure(
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
            lifecycle_instance_locked(state, instance_id, LifecycleAction::Start)
                .await
                .map(|_| ())
        },
    )
    .await
    {
        Ok(()) => {
            cleanup_redis_staging_until(staging, deadline).await;
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
            "failed to remove redis import staging directory"
        );
    }
}

async fn cleanup_redis_staging_until(staging: &Path, deadline: Instant) {
    if tokio::time::timeout_at(deadline, cleanup_redis_staging(staging))
        .await
        .is_err()
    {
        tracing::warn!(
            path = %staging.display(),
            "redis import staging cleanup exceeded the operation deadline and was retained"
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
                .relay_dump_to_restore_replace(target, &key, expiration, MAX_REDIS_DUMP_BYTES)
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
                    ApiError::BadRequest("remote redis returned an invalid PTTL value".to_string())
                })?
                .max(1);
            let now_milliseconds = now
                .duration_since(UNIX_EPOCH)
                .map_err(|_| {
                    ApiError::Runtime(
                        "system clock is before the Unix epoch; cannot preserve redis key expiration"
                            .to_string(),
                    )
                })?
                .as_millis();
            let now_milliseconds = u64::try_from(now_milliseconds).map_err(|_| {
                ApiError::Runtime(
                    "system clock is too large to preserve redis key expiration".to_string(),
                )
            })?;
            let deadline = now_milliseconds
                .checked_add(remaining_milliseconds)
                .ok_or_else(|| {
                    ApiError::BadRequest("remote redis key expiration is too large".to_string())
                })?;
            Ok(Some(RedisRestoreExpiration::AbsoluteUnixMilliseconds(
                deadline,
            )))
        }
        value => Err(ApiError::BadRequest(format!(
            "remote redis returned invalid PTTL value {value}"
        ))),
    }
}

async fn rollback_redis_target(
    state: &AppState,
    instance_id: &str,
    paths: &InstancePaths,
    rollback: &Path,
) -> Result<(), ApiError> {
    if let Err(error) = state.docker.stop(Protocol::Redis, instance_id).await
        && !error.is_not_running()
        && !error.is_not_found()
    {
        return Err(ApiError::Runtime(format!(
            "failed to stop redis before rollback: {error}"
        )));
    }
    replace_data_from_archive(paths.clone(), rollback).await?;
    crate::api::import_export::reapply_instance_data_owner(state, paths).await?;
    lifecycle_instance_locked(state, instance_id, LifecycleAction::Start)
        .await
        .map(|_| ())
}

async fn start_private_redis(
    state: &AppState,
    instance_id: &str,
    deadline: Instant,
) -> Result<(), ApiError> {
    redis_with_deadline(deadline, "private target startup", async {
        state
            .docker
            .start(Protocol::Redis, instance_id)
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to start private redis import target: {error}"
                ))
            })?;
        let readiness_timeout = remaining_redis_timeout(
            deadline,
            Duration::from_secs(120),
            "private target readiness",
        )?;
        state
            .docker
            .wait_until_ready(Protocol::Redis, instance_id, readiness_timeout)
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "private redis import target was not ready: {error}"
                ))
            })
            .map(|_| ())
    })
    .await
}

async fn read_acl_file(path: &Path) -> Result<Vec<u8>, ApiError> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        ApiError::Runtime(format!("failed to inspect managed redis ACL file: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(ApiError::Runtime(
            "managed redis ACL path is not a safe regular file".to_string(),
        ));
    }
    tokio::fs::read(path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to read managed redis ACL: {error}")))
}

fn append_temporary_acl(original: &[u8], username: &str, password: &SecretString) -> Vec<u8> {
    use secrecy::ExposeSecret;

    let digest = Sha256::digest(password.expose_secret().as_bytes());
    let mut hash = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hash, "{byte:02x}");
    }
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
    #[cfg(unix)]
    let metadata = read_acl_metadata(&target).await?;
    let temporary = paths
        .data
        .join(format!(".users.acl.{}", uuid::Uuid::new_v4().simple()));
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).await.map_err(|error| {
        ApiError::Runtime(format!("failed to create temporary redis ACL: {error}"))
    })?;
    file.write_all(contents).await.map_err(|error| {
        ApiError::Runtime(format!("failed to write temporary redis ACL: {error}"))
    })?;
    #[cfg(unix)]
    apply_acl_metadata(&file, metadata, preserve_owner).await?;
    #[cfg(not(unix))]
    let _ = preserve_owner;
    file.sync_all().await.map_err(|error| {
        ApiError::Runtime(format!("failed to sync temporary redis ACL: {error}"))
    })?;
    drop(file);
    if let Err(error) = tokio::fs::rename(&temporary, &target).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(ApiError::Runtime(format!(
            "failed to install temporary redis ACL: {error}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RedisAclMetadata {
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(unix)]
async fn read_acl_metadata(path: &Path) -> Result<RedisAclMetadata, ApiError> {
    use std::os::unix::fs::MetadataExt;

    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    let file = options.open(path).await.map_err(|error| {
        ApiError::Runtime(format!(
            "failed to open managed redis ACL metadata safely: {error}"
        ))
    })?;
    let metadata = file.metadata().await.map_err(|error| {
        ApiError::Runtime(format!(
            "failed to inspect managed redis ACL metadata: {error}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(ApiError::Runtime(
            "managed redis ACL path is not a safe regular file".to_string(),
        ));
    }
    Ok(RedisAclMetadata {
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
    })
}

#[cfg(unix)]
async fn apply_acl_metadata(
    file: &tokio::fs::File,
    metadata: RedisAclMetadata,
    preserve_owner: bool,
) -> Result<(), ApiError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if preserve_owner {
        let current = file.metadata().await.map_err(|error| {
            ApiError::Runtime(format!(
                "failed to inspect temporary redis ACL ownership: {error}"
            ))
        })?;
        if current.uid() != metadata.uid || current.gid() != metadata.gid {
            rustix::fs::fchown(
                file,
                Some(rustix::process::Uid::from_raw(metadata.uid)),
                Some(rustix::process::Gid::from_raw(metadata.gid)),
            )
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to preserve managed redis ACL ownership: {error}"
                ))
            })?;
        }
    }
    file.set_permissions(std::fs::Permissions::from_mode(metadata.mode))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to preserve managed redis ACL permissions: {error}"
            ))
        })
}

fn ensure_supported_redis_version(info: &[u8]) -> Result<(), ApiError> {
    let version = parse_redis_version(info).ok_or_else(|| {
        ApiError::BadRequest("remote redis INFO did not report a valid server version".to_string())
    })?;
    if version < (2, 6, 0) {
        return Err(ApiError::BadRequest(
            "remote redis version does not support DUMP/RESTORE import".to_string(),
        ));
    }
    Ok(())
}

fn ensure_redis_versions_compatible(source: &[u8], target: &[u8]) -> Result<(), ApiError> {
    let source = parse_redis_version(source).ok_or_else(|| {
        ApiError::BadRequest("remote redis INFO did not report a valid server version".to_string())
    })?;
    let target = parse_redis_version(target).ok_or_else(|| {
        ApiError::Runtime("managed redis INFO did not report a valid server version".to_string())
    })?;
    if target < (5, 0, 0) {
        return Err(ApiError::Runtime(
            "managed redis target does not support expiration-preserving RESTORE ABSTTL"
                .to_string(),
        ));
    }
    if target < source {
        return Err(ApiError::BadRequest(
            "managed redis target must be the same or a newer version than the remote source for DUMP/RESTORE compatibility"
                .to_string(),
        ));
    }
    Ok(())
}

fn parse_redis_version(info: &[u8]) -> Option<(u32, u32, u32)> {
    let info = std::str::from_utf8(info).ok()?;
    let version = info
        .lines()
        .find_map(|line| line.strip_prefix("redis_version:"))?
        .trim();
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

fn ensure_redis_standalone(info: &[u8], source: bool) -> Result<(), ApiError> {
    match parse_redis_cluster_enabled(info) {
        Some(false) => Ok(()),
        Some(true) if source => Err(ApiError::BadRequest(
            "remote redis cluster mode is unsupported because SCAN on one endpoint can omit keys stored on other nodes; use a standalone source or Redis cluster migration tooling"
                .to_string(),
        )),
        Some(true) => Err(ApiError::Runtime(
            "managed redis target unexpectedly has cluster mode enabled; remote key import requires a standalone target"
                .to_string(),
        )),
        None if source => Err(ApiError::BadRequest(
            "remote redis INFO cluster response is invalid".to_string(),
        )),
        None => Err(ApiError::Runtime(
            "managed redis INFO cluster response is invalid".to_string(),
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
        "remote redis source failed: {}",
        redis_error_summary(&error)
    ))
}

fn target_error(error: RedisRespError) -> ApiError {
    ApiError::Runtime(format!(
        "managed redis import target failed: {}",
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
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn temporary_acl_contains_only_a_hash() {
        let password = SecretString::from("very-secret-password");
        let acl = append_temporary_acl(b"user default off\n", "dbe_import_test", &password);
        let acl = String::from_utf8(acl).unwrap();
        assert!(acl.contains("user dbe_import_test on #"));
        assert!(!acl.contains(password.expose_secret()));
    }

    #[test]
    fn hostile_redis_errors_are_not_exposed() {
        let hostile = "ERR attacker-controlled\r\njob-log-injection";

        let source = source_error(RedisRespError::Server(hostile.to_string())).to_string();
        let target = target_error(RedisRespError::Server(hostile.to_string())).to_string();

        assert!(!source.contains(hostile));
        assert!(!target.contains(hostile));
        assert!(!source.contains("job-log-injection"));
        assert!(!target.contains("job-log-injection"));
    }

    #[test]
    fn unsupported_remote_version_is_not_exposed() {
        let hostile = b"redis_version:1.0.0-attacker-controlled\r\n";

        let error = ensure_supported_redis_version(hostile).unwrap_err();

        assert!(!error.to_string().contains("attacker-controlled"));
    }

    #[test]
    fn redis_version_preflight_requires_a_compatible_absttl_target() {
        assert_eq!(
            parse_redis_version(b"# Server\r\nredis_version:8.2.1\r\n"),
            Some((8, 2, 1))
        );
        assert_eq!(
            parse_redis_version(b"redis_version:8.2.1-rc1\r\n"),
            Some((8, 2, 1))
        );
        assert!(
            ensure_redis_versions_compatible(
                b"redis_version:7.2.4\r\n",
                b"redis_version:8.0.0\r\n"
            )
            .is_ok()
        );
        assert!(
            ensure_redis_versions_compatible(
                b"redis_version:8.0.1\r\n",
                b"redis_version:8.0.0\r\n"
            )
            .unwrap_err()
            .to_string()
            .contains("same or a newer version")
        );
        assert!(
            ensure_redis_versions_compatible(
                b"redis_version:4.0.14\r\n",
                b"redis_version:4.0.14\r\n"
            )
            .unwrap_err()
            .to_string()
            .contains("ABSTTL")
        );
    }

    #[test]
    fn redis_cluster_preflight_parses_only_unambiguous_info() {
        assert_eq!(
            parse_redis_cluster_enabled(b"# Cluster\r\ncluster_enabled:0\r\n"),
            Some(false)
        );
        assert_eq!(
            parse_redis_cluster_enabled(b"# Cluster\r\ncluster_enabled:1\r\n"),
            Some(true)
        );
        assert_eq!(parse_redis_cluster_enabled(b"# Cluster\r\n"), None);
        assert_eq!(
            parse_redis_cluster_enabled(b"cluster_enabled:0\r\ncluster_enabled:1\r\n"),
            None
        );
        assert_eq!(
            parse_redis_cluster_enabled(b"cluster_enabled:attacker-controlled\r\n"),
            None
        );
    }

    #[test]
    fn redis_expiration_uses_an_absolute_deadline_and_handles_missing_keys() {
        let now = UNIX_EPOCH + Duration::from_millis(10_000);

        assert_eq!(redis_restore_expiration(-2, now).unwrap(), None);
        assert_eq!(
            redis_restore_expiration(-1, now).unwrap(),
            Some(RedisRestoreExpiration::Persistent)
        );
        assert_eq!(
            redis_restore_expiration(250, now).unwrap(),
            Some(RedisRestoreExpiration::AbsoluteUnixMilliseconds(10_250))
        );
        assert_eq!(
            redis_restore_expiration(0, now).unwrap(),
            Some(RedisRestoreExpiration::AbsoluteUnixMilliseconds(10_001))
        );
        assert!(redis_restore_expiration(-3, now).is_err());
    }

    #[test]
    fn redis_deadlines_reserve_the_final_quarter_for_rollback() {
        let started = Instant::now();
        let (work_deadline, operation_deadline) =
            redis_operation_deadlines(started, Duration::from_secs(100));

        assert_eq!(
            work_deadline.duration_since(started),
            Duration::from_secs(75)
        );
        assert_eq!(
            operation_deadline.duration_since(work_deadline),
            Duration::from_secs(25)
        );
    }

    #[test]
    fn redis_remaining_timeout_is_capped_and_rejects_expired_deadlines() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(10);

        assert_eq!(
            remaining_redis_timeout_at(now, deadline, Duration::from_secs(3), "test phase")
                .unwrap(),
            Duration::from_secs(3)
        );
        assert_eq!(
            remaining_redis_timeout_at(now, deadline, Duration::from_secs(30), "test phase")
                .unwrap(),
            Duration::from_secs(10)
        );
        assert!(remaining_redis_timeout_at(now, now, Duration::MAX, "test phase").is_err());
    }

    #[tokio::test]
    async fn redis_absolute_deadline_cancels_an_unfinished_phase() {
        let error = redis_with_deadline(
            Instant::now(),
            "deadline test",
            std::future::pending::<Result<(), ApiError>>(),
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("remote redis import timed out during deadline test")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn acl_metadata_helper_preserves_mode_and_existing_owner() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        let existing = directory.path().join("users.acl");
        let temporary = directory.path().join(".users.acl.test");
        tokio::fs::write(&existing, b"user default off\n")
            .await
            .unwrap();
        tokio::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o640))
            .await
            .unwrap();
        let expected = read_acl_metadata(&existing).await.unwrap();
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
            .unwrap();

        apply_acl_metadata(&file, expected, true).await.unwrap();

        let actual = file.metadata().await.unwrap();
        assert_eq!(actual.uid(), expected.uid);
        assert_eq!(actual.gid(), expected.gid);
        assert_eq!(actual.mode() & 0o7777, expected.mode);
    }
}
