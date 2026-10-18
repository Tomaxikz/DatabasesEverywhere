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

    let error = check_redis_version(hostile).unwrap_err();

    assert!(!error.to_string().contains("attacker-controlled"));
}

#[test]
fn redis_version_preflight_requires_a_compatible_absttl_target() {
    assert_eq!(
        parse_resp_server_version(b"# Server\r\nredis_version:8.2.1\r\n"),
        Some(RespServerVersion {
            family: RespServerFamily::Redis,
            version: (8, 2, 1),
        })
    );
    assert_eq!(
        parse_resp_server_version(b"redis_version:8.2.1-rc1\r\n"),
        Some(RespServerVersion {
            family: RespServerFamily::Redis,
            version: (8, 2, 1),
        })
    );
    assert!(
        check_redis_versions(
            Protocol::Redis,
            b"redis_version:7.2.4\r\n",
            b"redis_version:8.0.0\r\n"
        )
        .is_ok()
    );
    assert!(
        check_redis_versions(
            Protocol::Redis,
            b"redis_version:8.0.1\r\n",
            b"redis_version:8.0.0\r\n"
        )
        .unwrap_err()
        .to_string()
        .contains("same or a newer version")
    );
    assert!(
        check_redis_versions(
            Protocol::Redis,
            b"redis_version:4.0.14\r\n",
            b"redis_version:4.0.14\r\n"
        )
        .unwrap_err()
        .to_string()
        .contains("ABSTTL")
    );
}

#[test]
fn valkey_version_preflight_uses_the_native_version_and_guards_redis_compatibility() {
    let valkey_9 = b"server_name:valkey\r\nvalkey_version:9.1.1\r\nredis_version:7.2.4\r\n";
    assert_eq!(
        parse_resp_server_version(valkey_9),
        Some(RespServerVersion {
            family: RespServerFamily::Valkey,
            version: (9, 1, 1),
        })
    );
    assert!(check_redis_versions(Protocol::Valkey, b"redis_version:7.2.4\r\n", valkey_9,).is_ok());
    assert!(
        check_redis_versions(Protocol::Valkey, b"redis_version:8.0.0\r\n", valkey_9,)
            .unwrap_err()
            .to_string()
            .contains("through version 7.2")
    );
    assert!(
        check_redis_versions(Protocol::Redis, valkey_9, b"redis_version:8.0.0\r\n",)
            .unwrap_err()
            .to_string()
            .contains("Valkey-to-Redis")
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
        operation_deadlines(started, Duration::from_secs(100));

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
        remaining_redis_timeout_at(now, deadline, Duration::from_secs(3), "test phase").unwrap(),
        Duration::from_secs(3)
    );
    assert_eq!(
        remaining_redis_timeout_at(now, deadline, Duration::from_secs(30), "test phase").unwrap(),
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
            .contains("remote RESP import timed out during deadline test")
    );
}

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
