use super::*;
use crate::databases::engine::{validate_header_safe_secret, validate_line_safe_secret};
use crate::databases::mongodb::transfer::validate_mongodb_credentials;

#[test]
fn remote_secrets_have_a_small_utf8_byte_limit() {
    let exact = SecretString::from("x".repeat(MAX_REMOTE_SECRET_BYTES));
    let oversized = SecretString::from("é".repeat(MAX_REMOTE_SECRET_BYTES / 2 + 1));
    assert!(validate_secret_size("source.password", Some(&exact)).is_ok());
    assert!(validate_secret_size("source.api_key", Some(&oversized)).is_err());
    assert!(validate_secret_size("source.password", None).is_ok());
}

#[test]
fn remote_job_admission_is_nonblocking_bounded_and_releases() {
    let admission = RemoteJobAdmission::default();
    let first = admission.try_acquire("instance-a", 4).unwrap();
    assert!(admission.try_acquire("instance-a", 4).is_none());
    let second = admission.try_acquire("instance-b", 4).unwrap();
    let third = admission.try_acquire("instance-c", 4).unwrap();
    let fourth = admission.try_acquire("instance-d", 4).unwrap();
    assert!(admission.try_acquire("instance-e", 4).is_none());
    drop(first);
    let replacement = admission.try_acquire("instance-e", 4).unwrap();
    drop((second, third, fourth, replacement));
    let state = admission
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(state.active, 0);
    assert!(state.instances.is_empty());
}

#[test]
fn mongodb_authentication_database_requires_complete_credentials() {
    let password = SecretString::from("secret".to_string());

    assert!(validate_mongodb_credentials(None, None, Some("admin")).is_err());
    assert!(validate_mongodb_credentials(Some("user"), None, Some("admin")).is_err());
    assert!(validate_mongodb_credentials(None, Some(&password), Some("admin")).is_err());
    assert!(validate_mongodb_credentials(Some("user"), Some(&password), Some("admin")).is_ok());
    assert!(validate_mongodb_credentials(None, None, None).is_ok());
}

#[test]
fn mongodb_database_names_follow_linux_server_rules() {
    assert!(validate_mongodb_database_name("source.database", "analytics", false).is_ok());
    assert!(validate_mongodb_database_name("source.database", "tenant*archive", false).is_ok());
    assert!(validate_mongodb_database_name("source.database", &"界".repeat(21), false).is_ok());
    assert!(validate_mongodb_database_name("source.database", &"a".repeat(63), false).is_ok());

    assert!(validate_mongodb_database_name("source.database", "", false).is_err());
    assert!(validate_mongodb_database_name("source.database", &"界".repeat(22), false).is_err());
    assert!(validate_mongodb_database_name("source.database", &"a".repeat(64), false).is_err());
    for character in ['\0', '/', '\\', '.', ' ', '"', '$'] {
        let value = format!("invalid{character}name");
        assert!(
            validate_mongodb_database_name("source.database", &value, false).is_err(),
            "{value:?} should be rejected"
        );
    }
}

#[test]
fn mongodb_authentication_database_allows_only_the_external_special_name() {
    assert!(
        validate_mongodb_database_name("source.authentication_database", "$external", true).is_ok()
    );
    assert!(
        validate_mongodb_database_name("source.authentication_database", "tenant$external", true)
            .is_err()
    );
    assert!(validate_mongodb_database_name("source.database", "$external", false).is_err());
}

#[test]
fn sql_password_rejects_config_file_line_injection() {
    for password in ["nul\0byte", "new\nline", "carriage\rreturn"] {
        let password = SecretString::from(password.to_string());
        assert!(validate_line_safe_secret("source.password", &password).is_err());
    }
    let password = SecretString::from("spaces and ! punctuation are allowed".to_string());
    assert!(validate_line_safe_secret("source.password", &password).is_ok());
}

#[test]
fn mysql_family_database_names_follow_the_server_identifier_limit() {
    assert!(crate::databases::mysql::transfer::mysql_database_name(
        &"é".repeat(64)
    ));
    assert!(!crate::databases::mysql::transfer::mysql_database_name(
        &"é".repeat(65)
    ));
}

#[test]
fn qdrant_api_key_must_be_a_valid_http_header_value() {
    let valid = SecretString::from("opaque-api-key_123".to_string());
    let invalid = SecretString::from("header\r\ninjection".to_string());

    assert!(validate_header_safe_secret("source.api_key", &valid).is_ok());
    let error = validate_header_safe_secret("source.api_key", &invalid).unwrap_err();
    assert!(!error.to_string().contains("header\r\ninjection"));
}

#[tokio::test]
async fn credential_cleanup_preserves_the_staged_dump() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let dump = root.join("source.postgres.sql");
    tokio::fs::write(&dump, b"select 1;").await.unwrap();
    for name in REMOTE_CREDENTIAL_FILES {
        tokio::fs::write(root.join(name), b"secret").await.unwrap();
    }

    remove_credential_files(root).await.unwrap();

    assert!(dump.is_file());
    for name in REMOTE_CREDENTIAL_FILES {
        assert!(!root.join(name).exists());
    }
}

#[tokio::test]
async fn startup_cleanup_preserves_manifest_backed_recovery_staging() {
    let directory = tempfile::tempdir().unwrap();
    let staging_root = directory.path().join("remote-import");
    let job = staging_root.join("01234567-89ab-4def-8123-456789abcdef");
    let unrelated_job = staging_root.join("not-a-generated-job");
    tokio::fs::create_dir_all(job.join("nested")).await.unwrap();
    tokio::fs::create_dir_all(&unrelated_job).await.unwrap();
    for name in REMOTE_CREDENTIAL_FILES {
        tokio::fs::write(job.join(name), b"secret").await.unwrap();
    }
    let preserved = [
        "source.postgres.sql",
        "source-0.snapshot",
        "rollback-0.snapshot",
        "rollback.redis.tar.gz",
        "rollback.valkey.tar.gz",
    ];
    for name in preserved {
        tokio::fs::write(job.join(name), b"recovery data")
            .await
            .unwrap();
    }
    tokio::fs::write(job.join("nested").join("pgpass"), b"nested secret")
        .await
        .unwrap();
    tokio::fs::write(job.join("recovery-manifest.json"), b"retained manifest")
        .await
        .unwrap();
    tokio::fs::write(unrelated_job.join("pgpass"), b"unrelated")
        .await
        .unwrap();

    let summary = cleanup_stale_import_secrets(directory.path(), true).await;

    assert_eq!(summary.job_directories, 1);
    assert_eq!(summary.removed_files, REMOTE_CREDENTIAL_FILES.len());
    assert_eq!(summary.removed_directories, 0);
    assert_eq!(summary.errors, 0);
    for name in REMOTE_CREDENTIAL_FILES {
        assert!(!job.join(name).exists());
    }
    for name in preserved {
        assert!(job.join(name).is_file());
    }
    assert!(job.join("nested").join("pgpass").is_file());
    assert!(unrelated_job.join("pgpass").is_file());
}

#[tokio::test]
async fn startup_credential_cleanup_never_follows_job_or_file_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let staging_root = directory.path().join("remote-import");
    tokio::fs::create_dir_all(&staging_root).await.unwrap();

    let outside_job = outside.path().join("job");
    tokio::fs::create_dir(&outside_job).await.unwrap();
    tokio::fs::write(outside_job.join("pgpass"), b"outside secret")
        .await
        .unwrap();
    symlink(
        &outside_job,
        staging_root.join("01234567-89ab-4def-8123-456789abcdef"),
    )
    .unwrap();

    let real_job = staging_root.join("11234567-89ab-4def-8123-456789abcdef");
    tokio::fs::create_dir(&real_job).await.unwrap();
    tokio::fs::write(
        real_job.join("recovery-manifest.json"),
        b"retained manifest",
    )
    .await
    .unwrap();
    let outside_file = outside.path().join("credential");
    tokio::fs::write(&outside_file, b"outside file secret")
        .await
        .unwrap();
    symlink(&outside_file, real_job.join("pgpass")).unwrap();

    let summary = cleanup_stale_import_secrets(directory.path(), true).await;

    assert_eq!(summary.removed_files, 0);
    assert_eq!(summary.errors, 0);
    assert!(summary.skipped_entries >= 2);
    assert!(outside_job.join("pgpass").is_file());
    assert!(outside_file.is_file());
    assert!(real_job.join("pgpass").is_symlink());
}

#[tokio::test]
async fn startup_cleanup_removes_only_orphaned_generated_staging_when_authorized() {
    let directory = tempfile::tempdir().unwrap();
    let staging_root = directory.path().join("remote-import");
    let orphan = staging_root.join("01234567-89ab-4def-8123-456789abcdef");
    tokio::fs::create_dir_all(&orphan).await.unwrap();
    tokio::fs::write(orphan.join("source.mysql.sql"), b"customer dump")
        .await
        .unwrap();

    let deferred = cleanup_stale_import_secrets(directory.path(), false).await;
    assert_eq!(deferred.removed_directories, 0);
    assert!(orphan.is_dir());

    let removed = cleanup_stale_import_secrets(directory.path(), true).await;
    assert_eq!(removed.removed_directories, 1);
    assert!(!orphan.exists());
}

#[tokio::test]
async fn dropped_staging_guard_schedules_cancellation_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("cancelled");
    tokio::fs::create_dir(&root).await.unwrap();
    tokio::fs::write(root.join("credential"), b"secret")
        .await
        .unwrap();
    {
        let _guard = RemoteStagingGuard::new(root.clone());
    }

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while root.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
