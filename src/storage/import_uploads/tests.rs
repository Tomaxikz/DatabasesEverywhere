use super::*;
use crate::storage::{migrations, sqlite};

const CREATED: &str = "2026-08-10T10:00:00Z";
const LATER: &str = "2026-08-10T10:01:00Z";
const EXPIRES: &str = "2026-08-10T11:00:00Z";
const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn migration_creates_constraints_and_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    seed_instance(&pool, "inst").await;

    let table: String = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'import_uploads'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(table, "import_uploads");

    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'import_uploads'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(indexes.contains(&"idx_import_uploads_instance_active".to_string()));
    assert!(indexes.contains(&"idx_import_uploads_expiry".to_string()));
    assert!(indexes.contains(&"uq_import_uploads_claimed_job".to_string()));
    assert!(indexes.contains(&"uq_import_uploads_stored_filename".to_string()));

    let invalid = sqlx::query(
        r#"
        INSERT INTO import_uploads (
            upload_id, instance_id, original_filename, stored_filename, protocol, state,
            size_bytes, created_at, updated_at, expires_at
        ) VALUES ('bad', 'inst', 'dump.sql', 'bad/path', 'postgres', 'uploading', 1, ?1, ?1, ?2)
        "#,
    )
    .bind(CREATED)
    .bind(EXPIRES)
    .execute(&pool)
    .await;
    assert!(invalid.is_err());

    sqlx::query(
        r#"
        INSERT INTO import_uploads (
            upload_id, instance_id, original_filename, stored_filename, protocol, state,
            size_bytes, created_at, updated_at, expires_at
        ) VALUES ('cascade', 'inst', 'dump.sql', 'cascade.dump', 'postgres', 'uploading', 1, ?1, ?1, ?2)
        "#,
    )
    .bind(CREATED)
    .bind(EXPIRES)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM instance_metadata WHERE instance_id = 'inst'")
        .execute(&pool)
        .await
        .unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM import_uploads WHERE instance_id = 'inst'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn creates_and_reads_with_instance_isolation() {
    let repository = repository().await;
    let upload = repository.create(sample_new()).await.unwrap();

    assert_eq!(upload.state, ImportUploadState::Uploading);
    assert_eq!(
        repository.get("inst_abc", "upl_1").await.unwrap(),
        Some(upload)
    );
    assert!(
        repository
            .get("inst_other", "upl_1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .list_active_for_instance("inst_other", 100)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn rejects_duplicate_upload_ids() {
    let repository = repository().await;
    repository.create(sample_new()).await.unwrap();
    let mut duplicate = sample_new();
    duplicate.instance_id = "inst_other".to_string();

    let error = repository.create(duplicate).await.unwrap_err();
    assert!(matches!(
        error,
        ImportUploadStorageError::AlreadyExists { upload_id } if upload_id == "upl_1"
    ));
}

#[tokio::test]
async fn enforces_lifecycle_and_exact_job_claim() {
    let repository = repository().await;
    repository.create(sample_new()).await.unwrap();
    assert!(
        repository
            .mark_uploaded("inst_abc", "upl_1", 42, SHA256, LATER)
            .await
            .unwrap()
    );
    assert!(
        repository
            .mark_ready("inst_abc", "upl_1", None, "2026-08-10T10:02:00Z")
            .await
            .unwrap()
    );
    assert!(
        repository
            .mark_processing("inst_abc", "upl_1", "2026-08-10T10:03:00Z")
            .await
            .unwrap()
    );
    assert!(
        repository
            .restore_ready_after_processing(
                "inst_abc",
                "upl_1",
                Some(ImportUploadArchiveFormat::Plain),
                Some(r#"{"tables":["public.items"]}"#),
                None,
                "2026-08-10T10:04:00Z",
            )
            .await
            .unwrap()
    );
    assert!(
        repository
            .claim_ready_for_job("inst_abc", "upl_1", "job_1", "2026-08-10T10:05:00Z",)
            .await
            .unwrap()
    );
    assert!(
        !repository
            .mark_consumed("inst_abc", "upl_1", "job_wrong", "2026-08-10T10:06:00Z",)
            .await
            .unwrap()
    );
    assert!(
        repository
            .release_claim_after_failed_job(
                "inst_abc",
                "upl_1",
                "job_1",
                "native restore failed",
                "2026-08-10T10:06:00Z",
            )
            .await
            .unwrap()
    );
    assert!(
        repository
            .claim_ready_for_job("inst_abc", "upl_1", "job_2", "2026-08-10T10:07:00Z",)
            .await
            .unwrap()
    );
    assert!(
        repository
            .mark_consumed("inst_abc", "upl_1", "job_2", "2026-08-10T10:08:00Z",)
            .await
            .unwrap()
    );
    let stored = repository.get("inst_abc", "upl_1").await.unwrap().unwrap();
    assert_eq!(stored.state, ImportUploadState::Consumed);
    assert_eq!(stored.claimed_job_id.as_deref(), Some("job_2"));
}

#[tokio::test]
async fn only_one_concurrent_claim_wins() {
    let repository = repository().await;
    make_ready(&repository).await;
    let first_repository = repository.clone();
    let second_repository = repository.clone();
    let first = tokio::spawn(async move {
        first_repository
            .claim_ready_for_job("inst_abc", "upl_1", "job_a", LATER)
            .await
            .unwrap()
    });
    let second = tokio::spawn(async move {
        second_repository
            .claim_ready_for_job("inst_abc", "upl_1", "job_b", LATER)
            .await
            .unwrap()
    });
    let outcomes = [first.await.unwrap(), second.await.unwrap()];

    assert_eq!(outcomes.into_iter().filter(|claimed| *claimed).count(), 1);
    let stored = repository.get("inst_abc", "upl_1").await.unwrap().unwrap();
    assert_eq!(stored.state, ImportUploadState::Importing);
}

#[tokio::test]
async fn concurrent_admission_cannot_exceed_instance_count() {
    let repository = repository().await;
    let mut second = sample_new();
    second.upload_id = "upl_2".to_string();
    second.stored_filename = "upl_2.dump".to_string();
    let first_repository = repository.clone();
    let second_repository = repository.clone();
    let first = tokio::spawn(async move {
        first_repository
            .insert_if_within_limits(sample_new(), 1, 1_000)
            .await
            .unwrap()
    });
    let second = tokio::spawn(async move {
        second_repository
            .insert_if_within_limits(second, 1, 1_000)
            .await
            .unwrap()
    });
    let outcomes = [first.await.unwrap(), second.await.unwrap()];

    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ImportUploadAdmission::Admitted(_)))
            .count(),
        1
    );
    assert_eq!(repository.active_usage(None).await.unwrap().active_count, 1);
}

#[tokio::test]
async fn admission_reserves_declared_bytes_and_actual_size_must_match() {
    let repository = repository().await;
    let admitted = repository
        .insert_if_within_limits(sample_new(), 10, 42)
        .await
        .unwrap();
    assert!(matches!(admitted, ImportUploadAdmission::Admitted(_)));
    let mut second = sample_new();
    second.upload_id = "upl_2".to_string();
    second.stored_filename = "upl_2.dump".to_string();
    assert!(matches!(
        repository
            .insert_if_within_limits(second, 10, 84)
            .await
            .unwrap(),
        ImportUploadAdmission::Admitted(_)
    ));
    assert!(
        !repository
            .mark_uploaded("inst_abc", "upl_1", 41, SHA256, LATER)
            .await
            .unwrap()
    );
    assert!(
        repository
            .mark_uploaded("inst_abc", "upl_1", 42, SHA256, LATER)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn expiry_skips_importing_and_prevents_late_claims() {
    let repository = repository().await;
    make_ready(&repository).await;
    let mut expired = sample_new();
    expired.upload_id = "upl_expired".to_string();
    expired.stored_filename = "upl_expired.dump".to_string();
    expired.size_bytes = 10;
    expired.expires_at = "2026-08-10T10:00:30Z".to_string();
    repository.create(expired).await.unwrap();
    repository
        .mark_uploaded(
            "inst_abc",
            "upl_expired",
            10,
            SHA256,
            "2026-08-10T10:00:10Z",
        )
        .await
        .unwrap();
    repository
        .mark_ready("inst_abc", "upl_expired", None, "2026-08-10T10:00:20Z")
        .await
        .unwrap();
    assert!(
        repository
            .claim_ready_for_job("inst_abc", "upl_1", "job_active", LATER)
            .await
            .unwrap()
    );
    assert!(
        !repository
            .claim_ready_for_job("inst_abc", "upl_expired", "job_late", LATER)
            .await
            .unwrap()
    );

    let expired = repository
        .list_expired("2026-08-10T11:30:00Z", 100)
        .await
        .unwrap();
    assert_eq!(
        expired
            .iter()
            .map(|upload| upload.upload_id.as_str())
            .collect::<Vec<_>>(),
        vec!["upl_expired"]
    );
}

#[tokio::test]
async fn active_usage_keeps_consumed_bytes_reserved_until_deletion() {
    let repository = repository().await;
    make_ready(&repository).await;
    let mut foreign = sample_new();
    foreign.upload_id = "upl_2".to_string();
    foreign.instance_id = "inst_other".to_string();
    foreign.stored_filename = "upl_2.dump".to_string();
    foreign.size_bytes = 100;
    repository.create(foreign).await.unwrap();
    repository
        .mark_uploaded("inst_other", "upl_2", 100, SHA256, LATER)
        .await
        .unwrap();
    repository
        .mark_ready("inst_other", "upl_2", None, "2026-08-10T10:02:00Z")
        .await
        .unwrap();
    repository
        .claim_ready_for_job("inst_other", "upl_2", "job_2", "2026-08-10T10:03:00Z")
        .await
        .unwrap();
    repository
        .mark_consumed("inst_other", "upl_2", "job_2", "2026-08-10T10:04:00Z")
        .await
        .unwrap();

    assert_eq!(
        repository.active_usage(None).await.unwrap(),
        ImportUploadUsage {
            active_count: 2,
            active_bytes: 142,
        }
    );
    assert_eq!(
        repository.active_usage(Some("inst_other")).await.unwrap(),
        ImportUploadUsage {
            active_count: 1,
            active_bytes: 100,
        }
    );
}

#[tokio::test]
async fn reconciles_interrupted_imports_to_requested_state() {
    let repository = repository().await;
    make_ready(&repository).await;
    repository
        .claim_ready_for_job("inst_abc", "upl_1", "job_1", LATER)
        .await
        .unwrap();

    assert!(
        !repository
            .reconcile_interrupted_importing(
                "inst_abc",
                "upl_1",
                "job_wrong",
                InterruptedImportDisposition::Ready,
                "daemon restarted",
                "2026-08-10T10:02:00Z",
            )
            .await
            .unwrap()
    );

    assert!(
        repository
            .reconcile_interrupted_importing(
                "inst_abc",
                "upl_1",
                "job_1",
                InterruptedImportDisposition::Ready,
                "daemon restarted",
                "2026-08-10T10:02:00Z",
            )
            .await
            .unwrap()
    );
    let stored = repository.get("inst_abc", "upl_1").await.unwrap().unwrap();
    assert_eq!(stored.state, ImportUploadState::Ready);
    assert!(stored.claimed_job_id.is_none());
    assert_eq!(stored.last_error.as_deref(), Some("daemon restarted"));

    repository
        .claim_ready_for_job("inst_abc", "upl_1", "job_2", "2026-08-10T10:03:00Z")
        .await
        .unwrap();
    repository
        .reconcile_interrupted_importing(
            "inst_abc",
            "upl_1",
            "job_2",
            InterruptedImportDisposition::Failed,
            "recovery policy rejected retry",
            "2026-08-10T10:04:00Z",
        )
        .await
        .unwrap();
    assert_eq!(
        repository
            .get("inst_abc", "upl_1")
            .await
            .unwrap()
            .unwrap()
            .state,
        ImportUploadState::Failed
    );
}

#[tokio::test]
async fn deletion_is_scoped_and_refuses_active_imports() {
    let repository = repository().await;
    make_ready(&repository).await;
    let mut partial = sample_new();
    partial.upload_id = "upl_partial".to_string();
    partial.stored_filename = "upl_partial.dump".to_string();
    repository.create(partial).await.unwrap();
    assert!(
        !repository
            .abort_uploading("inst_other", "upl_partial")
            .await
            .unwrap()
    );
    assert!(
        repository
            .abort_uploading("inst_abc", "upl_partial")
            .await
            .unwrap()
    );
    assert!(
        !repository
            .claim_for_deletion("inst_other", "upl_1", LATER)
            .await
            .unwrap()
    );
    repository
        .claim_ready_for_job("inst_abc", "upl_1", "job_1", LATER)
        .await
        .unwrap();
    assert!(
        !repository
            .claim_for_deletion("inst_abc", "upl_1", "2026-08-10T10:02:00Z")
            .await
            .unwrap()
    );
    repository
        .mark_consumed("inst_abc", "upl_1", "job_1", "2026-08-10T10:02:00Z")
        .await
        .unwrap();
    assert!(
        repository
            .claim_for_deletion("inst_abc", "upl_1", "2026-08-10T10:03:00Z")
            .await
            .unwrap()
    );
    assert!(
        repository
            .finalize_delete("inst_abc", "upl_1")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn transient_catalog_failure_restores_importable_ready_state() {
    let repository = repository().await;
    make_ready(&repository).await;
    assert!(
        repository
            .mark_processing("inst_abc", "upl_1", "2026-08-10T10:03:00Z")
            .await
            .unwrap()
    );
    assert!(
        repository
            .restore_ready_after_processing(
                "inst_abc",
                "upl_1",
                None,
                None,
                Some("catalog helper timed out"),
                "2026-08-10T10:04:00Z",
            )
            .await
            .unwrap()
    );

    let upload = repository.get("inst_abc", "upl_1").await.unwrap().unwrap();
    assert_eq!(upload.state, ImportUploadState::Ready);
    assert_eq!(
        upload.archive_format,
        Some(ImportUploadArchiveFormat::Plain)
    );
    assert_eq!(
        upload.last_error.as_deref(),
        Some("catalog helper timed out")
    );
}

#[tokio::test]
async fn lists_recoverable_states_and_deletes_instance_rows() {
    let repository = repository().await;
    make_ready(&repository).await;
    let mut uploading = sample_new();
    uploading.upload_id = "upl_0".to_string();
    uploading.stored_filename = "upl_0.dump".to_string();
    repository.create(uploading).await.unwrap();
    let mut uploaded = sample_new();
    uploaded.upload_id = "upl_2".to_string();
    uploaded.stored_filename = "upl_2.dump".to_string();
    repository.create(uploaded).await.unwrap();
    repository
        .mark_uploaded("inst_abc", "upl_2", 42, SHA256, LATER)
        .await
        .unwrap();
    make_consumed(&repository, "upl_4", "job_4", false).await;
    make_consumed(&repository, "upl_5", "job_5", true).await;

    let recoverable = repository.list_recoverable(100).await.unwrap();
    assert_eq!(
        recoverable
            .iter()
            .map(|upload| upload.upload_id.as_str())
            .collect::<Vec<_>>(),
        vec!["upl_0", "upl_2", "upl_4", "upl_5"]
    );
    let first_page = repository.list_recoverable_after(None, 2).await.unwrap();
    let second_page = repository
        .list_recoverable_after(Some(&first_page[1].upload_id), 2)
        .await
        .unwrap();
    assert_eq!(
        first_page
            .iter()
            .chain(&second_page)
            .map(|upload| upload.upload_id.as_str())
            .collect::<Vec<_>>(),
        vec!["upl_0", "upl_2", "upl_4", "upl_5"]
    );
    assert!(
        repository
            .list_recoverable_after(Some(&second_page[1].upload_id), 2)
            .await
            .unwrap()
            .is_empty()
    );

    let terminal_first = repository
        .list_terminal_cleanup_after(None, 1)
        .await
        .unwrap();
    let terminal_second = repository
        .list_terminal_cleanup_after(Some(&terminal_first[0].upload_id), 1)
        .await
        .unwrap();
    assert_eq!(terminal_first[0].upload_id, "upl_4");
    assert_eq!(terminal_second[0].upload_id, "upl_5");
    assert_eq!(terminal_first[0].state, ImportUploadState::Consumed);
    assert_eq!(terminal_second[0].state, ImportUploadState::Deleting);
    assert_eq!(
        repository
            .list_nonterminal_recovery_after(None, "2026-08-10T10:05:00Z", 120, 100)
            .await
            .unwrap()
            .iter()
            .map(|upload| upload.upload_id.as_str())
            .collect::<Vec<_>>(),
        vec!["upl_0", "upl_2"]
    );
    assert_eq!(
        repository
            .list_nonterminal_recovery_after(None, "2026-08-10T10:02:00Z", 120, 100)
            .await
            .unwrap()
            .iter()
            .map(|upload| upload.upload_id.as_str())
            .collect::<Vec<_>>(),
        vec!["upl_0"]
    );

    assert_eq!(repository.delete_for_instance("inst_abc").await.unwrap(), 5);
    assert!(
        repository
            .list_active_for_instance("inst_abc", 100)
            .await
            .unwrap()
            .is_empty()
    );
}

#[test]
fn parsing_is_strict_and_input_validation_rejects_paths() {
    assert!(ImportUploadState::parse("READY").is_err());
    assert!(parse_protocol("postgresql").is_err());
    assert!(ImportUploadArchiveFormat::parse("tgz").is_err());
    let mut upload = sample_new().into_upload();
    upload.original_filename = "../dump.sql".to_string();
    assert!(matches!(
        validate_upload(&upload),
        Err(ImportUploadValidationError::InvalidOriginalFilename)
    ));
}

async fn repository() -> ImportUploadRepository {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    migrations::run(&pool).await.unwrap();
    seed_instance(&pool, "inst_abc").await;
    seed_instance(&pool, "inst_other").await;
    ImportUploadRepository::new(pool)
}

async fn seed_instance(pool: &SqlitePool, instance_id: &str) {
    sqlx::query(
        r#"
        INSERT INTO instance_metadata (
            instance_id, schema_version, protocol, status, public_host, public_port,
            backend_kind, runtime_kind, container_name, network, database_name,
            database_username, limits_json, metadata_json, created_at, updated_at
        ) VALUES (?1, 1, 'postgres', 'stopped', '127.0.0.1', 15432,
                  'unix_socket', 'docker', ?2, 'dbev', ?3, ?4, '{}', '{}', ?5, ?5)
        "#,
    )
    .bind(instance_id)
    .bind(format!("container_{instance_id}"))
    .bind(format!("db_{instance_id}"))
    .bind(format!("user_{instance_id}"))
    .bind(CREATED)
    .execute(pool)
    .await
    .unwrap();
}

async fn make_ready(repository: &ImportUploadRepository) {
    repository.create(sample_new()).await.unwrap();
    repository
        .mark_uploaded("inst_abc", "upl_1", 42, SHA256, LATER)
        .await
        .unwrap();
    repository
        .mark_ready("inst_abc", "upl_1", None, "2026-08-10T10:02:00Z")
        .await
        .unwrap();
}

async fn make_consumed(
    repository: &ImportUploadRepository,
    upload_id: &str,
    job_id: &str,
    deleting: bool,
) {
    let mut upload = sample_new();
    upload.upload_id = upload_id.to_string();
    upload.stored_filename = format!("{upload_id}.dump");
    repository.create(upload).await.unwrap();
    repository
        .mark_uploaded("inst_abc", upload_id, 42, SHA256, LATER)
        .await
        .unwrap();
    repository
        .mark_ready("inst_abc", upload_id, None, "2026-08-10T10:02:00Z")
        .await
        .unwrap();
    repository
        .claim_ready_for_job("inst_abc", upload_id, job_id, "2026-08-10T10:03:00Z")
        .await
        .unwrap();
    repository
        .mark_consumed("inst_abc", upload_id, job_id, "2026-08-10T10:04:00Z")
        .await
        .unwrap();
    if deleting {
        repository
            .claim_for_deletion("inst_abc", upload_id, "2026-08-10T10:05:00Z")
            .await
            .unwrap();
    }
}

fn sample_new() -> NewImportUpload {
    NewImportUpload {
        upload_id: "upl_1".to_string(),
        instance_id: "inst_abc".to_string(),
        original_filename: "dump.sql".to_string(),
        stored_filename: "upl_1.dump".to_string(),
        protocol: Protocol::Postgres,
        archive_format: Some(ImportUploadArchiveFormat::Plain),
        size_bytes: 42,
        created_at: CREATED.to_string(),
        expires_at: EXPIRES.to_string(),
    }
}
