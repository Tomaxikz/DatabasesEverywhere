use super::*;
use crate::storage::{migrations, test_support};
use std::sync::atomic::Ordering;

#[test]
fn disk_reservation_guard_releases_exactly_once() {
    let filesystem = FilesystemIdentity("test-device".to_string());
    let totals = Arc::new(StdMutex::new(HashMap::from([(filesystem.clone(), 4096)])));
    let guard = DiskCapacityReservation {
        filesystem,
        bytes: 4096,
        totals: totals.clone(),
    };
    drop(guard);
    assert!(
        totals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    );
}

#[test]
fn disk_capacity_includes_other_in_flight_uploads_and_reserve() {
    assert_eq!(
        required_disk_capacity(1024, 2048).unwrap(),
        DISK_SAFETY_RESERVE_BYTES + 3072
    );
    assert!(required_disk_capacity(u64::MAX, 1).is_err());
}

#[tokio::test]
async fn output_reservations_share_capacity_without_consuming_staging_slots() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_lazy("sqlite::memory:")
        .unwrap();
    let service = ImportUploadService::new(ImportUploadRepository::new(pool), 1);
    let directory = tempfile::tempdir().unwrap();
    let staging = service
        .staging_admission
        .clone()
        .try_acquire_owned()
        .unwrap();

    let first = service
        .reserve_output_capacity(directory.path(), 1024)
        .await
        .unwrap();
    let second = service
        .reserve_output_capacity(directory.path(), 2048)
        .await
        .unwrap();
    assert_eq!(reserved_total(&service), 3072);
    assert!(
        service
            .staging_admission
            .clone()
            .try_acquire_owned()
            .is_err()
    );
    drop(first);
    assert_eq!(reserved_total(&service), 2048);
    drop(second);
    assert_eq!(reserved_total(&service), 0);
    drop(staging);
}

#[tokio::test]
async fn output_roots_on_the_same_device_are_identified_as_one_filesystem() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_lazy("sqlite::memory:")
        .unwrap();
    let service = ImportUploadService::new(ImportUploadRepository::new(pool), 1);
    let directory = tempfile::tempdir().unwrap();
    let staging = directory.path().join("staging");
    tokio::fs::create_dir(&staging).await.unwrap();

    assert!(
        service
            .output_roots_share_filesystem(directory.path(), &staging)
            .await
            .unwrap()
    );
}

#[test]
fn filesystem_reservation_totals_aggregate_only_matching_identities() {
    let first = FilesystemIdentity("device-a".to_string());
    let same = first.clone();
    let different = FilesystemIdentity("device-b".to_string());
    let totals = HashMap::from([(first, 1024), (different.clone(), 2048)]);
    assert_eq!(totals.get(&same).copied(), Some(1024));
    assert_eq!(totals.get(&different).copied(), Some(2048));
}

fn reserved_total(service: &ImportUploadService) -> u64 {
    service
        .reserved_disk_bytes_by_filesystem
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
        .copied()
        .sum()
}

#[tokio::test]
async fn expensive_upload_work_has_separate_small_global_limits() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_lazy("sqlite::memory:")
        .unwrap();
    let service = ImportUploadService::new(ImportUploadRepository::new(pool), 32);
    let first = service
        .inspection_admission
        .clone()
        .try_acquire_owned()
        .unwrap();
    let second = service
        .inspection_admission
        .clone()
        .try_acquire_owned()
        .unwrap();
    assert!(
        service
            .inspection_admission
            .clone()
            .try_acquire_owned()
            .is_err()
    );
    assert!(service.admission.clone().try_acquire_owned().is_ok());
    drop((first, second));

    let first = service
        .staging_admission
        .clone()
        .try_acquire_owned()
        .unwrap();
    let second = service
        .staging_admission
        .clone()
        .try_acquire_owned()
        .unwrap();
    assert!(
        service
            .staging_admission
            .clone()
            .try_acquire_owned()
            .is_err()
    );
    drop((first, second));
    tokio::task::yield_now().await;
}

#[tokio::test]
async fn cancelled_inspection_waiter_does_not_release_worker_guards() {
    let locks = crate::instances::locks::InstanceLocks::default();
    let instance_operation = locks.lock("inst_inspection").await;
    let admission = Arc::new(Semaphore::new(1));
    let inspection_permit = admission.clone().try_acquire_owned().unwrap();
    let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_completed = completed.clone();

    let caller = tokio::spawn(async move {
        spawn_owned_inspection(instance_operation, inspection_permit, async move {
            let _ = started_sender.send(());
            let _ = release_receiver.await;
            worker_completed.store(true, Ordering::Release);
            Ok::<(), ApiError>(())
        })
        .await
    });
    started_receiver.await.unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());

    assert!(admission.clone().try_acquire_owned().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), locks.lock("inst_inspection"))
            .await
            .is_err()
    );

    release_sender.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !completed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(permit) = admission.clone().try_acquire_owned() {
                drop(permit);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), locks.lock("inst_inspection"))
        .await
        .unwrap();
}

#[tokio::test]
async fn upload_body_idle_timeout_returns_request_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let partial = dir.path().join("upload.partial");
    let body = Body::from_stream(futures::stream::pending::<
        Result<bytes::Bytes, std::io::Error>,
    >());

    let error = receive_upload_body(body, &partial, 1, None, Duration::from_millis(20))
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        ApiError::RequestRejected { status, .. } if status == StatusCode::REQUEST_TIMEOUT
    ));
}

#[tokio::test]
async fn upload_body_chunk_before_idle_deadline_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let partial = dir.path().join("upload.partial");
    let stream = futures::stream::once(async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"abc"))
    });

    let digest = receive_upload_body(
        Body::from_stream(stream),
        &partial,
        3,
        None,
        Duration::from_millis(100),
    )
    .await
    .unwrap();

    assert_eq!(
        digest,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(tokio::fs::read(partial).await.unwrap(), b"abc");
}

#[tokio::test]
async fn cancelled_upload_waiter_keeps_guards_until_worker_commits() {
    let (repository, upload, directory, partial_path, final_path) = upload_worker_fixture().await;
    let admission = Arc::new(Semaphore::new(1));
    let admission_permit = admission.clone().try_acquire_owned().unwrap();
    let locks = crate::instances::locks::InstanceLocks::default();
    let instance_operation = locks.lock("inst").await;
    let filesystem = FilesystemIdentity("upload-worker-device".to_string());
    let totals = Arc::new(StdMutex::new(HashMap::from([(filesystem.clone(), 3)])));
    let guards = Arc::new(UploadWorkerGuards::new(
        admission_permit,
        instance_operation,
        DiskCapacityReservation {
            filesystem,
            bytes: 3,
            totals: totals.clone(),
        },
    ));
    let recovery = UploadWorkerRecovery::new(
        repository.clone(),
        upload,
        partial_path.clone(),
        final_path.clone(),
    );
    let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
    let body = Body::from_stream(futures::stream::once(async move {
        let _ = started_sender.send(());
        release_receiver.await.map_err(std::io::Error::other)?;
        Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"abc"))
    }));
    let worker = spawn_upload_worker(
        recovery,
        guards,
        body,
        UploadWorkerOptions {
            declared_size: 3,
            expected_sha256: None,
            idle_timeout: Duration::from_secs(2),
            total_timeout: Duration::from_secs(2),
        },
    );
    let caller = tokio::spawn(worker);

    started_receiver.await.unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(admission.clone().try_acquire_owned().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), locks.lock("inst"))
            .await
            .is_err()
    );
    assert_eq!(
        totals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .copied()
            .sum::<u64>(),
        3
    );

    release_sender.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let ready = repository
                .get("inst", "upl_worker")
                .await
                .unwrap()
                .is_some_and(|upload| upload.state == ImportUploadState::Ready);
            if ready && final_path.exists() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(tokio::fs::read(&final_path).await.unwrap(), b"abc");
    assert!(!partial_path.exists());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if admission.clone().try_acquire_owned().is_ok()
                && totals
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_empty()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), locks.lock("inst"))
        .await
        .unwrap();
    drop(directory);
}

#[tokio::test]
async fn panicking_upload_worker_durably_cleans_files_and_row() {
    let (repository, upload, _directory, partial_path, final_path) = upload_worker_fixture().await;
    std::fs::write(&final_path, b"orphan").unwrap();
    let admission = Arc::new(Semaphore::new(1));
    let locks = crate::instances::locks::InstanceLocks::default();
    let filesystem = FilesystemIdentity("panic-worker-device".to_string());
    let totals = Arc::new(StdMutex::new(HashMap::from([(filesystem.clone(), 3)])));
    let guards = Arc::new(UploadWorkerGuards::new(
        admission.clone().try_acquire_owned().unwrap(),
        locks.lock("inst").await,
        DiskCapacityReservation {
            filesystem,
            bytes: 3,
            totals: totals.clone(),
        },
    ));
    let recovery = UploadWorkerRecovery::new(
        repository.clone(),
        upload,
        partial_path.clone(),
        final_path.clone(),
    );
    let body = Body::from_stream(futures::stream::once(async {
        panic!("injected upload worker panic");
        #[allow(unreachable_code)]
        Ok::<_, std::io::Error>(bytes::Bytes::new())
    }));

    let error = spawn_upload_worker(
        recovery,
        guards,
        body,
        UploadWorkerOptions {
            declared_size: 3,
            expected_sha256: None,
            idle_timeout: Duration::from_secs(2),
            total_timeout: Duration::from_secs(2),
        },
    )
    .await
    .unwrap()
    .unwrap_err();

    assert!(matches!(error, ApiError::Runtime(_)));
    assert!(
        repository
            .get("inst", "upl_worker")
            .await
            .unwrap()
            .is_none()
    );
    assert!(!partial_path.exists());
    assert!(!final_path.exists());
    assert!(admission.try_acquire_owned().is_ok());
    assert!(
        totals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    );
    tokio::time::timeout(Duration::from_secs(1), locks.lock("inst"))
        .await
        .unwrap();
}

async fn upload_worker_fixture() -> (
    ImportUploadRepository,
    ImportUpload,
    tempfile::TempDir,
    PathBuf,
    PathBuf,
) {
    const CREATED: &str = "2026-08-10T10:00:00Z";
    const EXPIRES: &str = "2026-08-10T11:00:00Z";
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    migrations::run(&pool).await.unwrap();
    test_support::seed_dedicated_instance(&pool, "inst", CREATED).await;
    let repository = ImportUploadRepository::new(pool);
    let upload = repository
        .create(NewImportUpload {
            upload_id: "upl_worker".to_string(),
            instance_id: "inst".to_string(),
            original_filename: "dump.sql".to_string(),
            stored_filename: "upl_worker.upload".to_string(),
            protocol: Protocol::Postgres,
            archive_format: Some(ImportUploadArchiveFormat::Plain),
            size_bytes: 3,
            created_at: CREATED.to_string(),
            expires_at: EXPIRES.to_string(),
        })
        .await
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let partial_path = directory.path().join(".upl_worker.upload.partial");
    let final_path = directory.path().join("upl_worker.upload");
    (repository, upload, directory, partial_path, final_path)
}

#[tokio::test]
async fn retryable_inspection_retains_detected_wrapper_for_hardening() {
    const CREATED: &str = "2026-08-10T10:00:00Z";
    const EXPIRES: &str = "2026-08-10T11:00:00Z";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    migrations::run(&pool).await.unwrap();
    test_support::seed_dedicated_instance(&pool, "inst", CREATED).await;
    let repository = ImportUploadRepository::new(pool);
    repository
        .create(NewImportUpload {
            upload_id: "upl".to_string(),
            instance_id: "inst".to_string(),
            original_filename: "dump".to_string(),
            stored_filename: "upl.dump".to_string(),
            protocol: Protocol::Postgres,
            archive_format: None,
            size_bytes: 42,
            created_at: CREATED.to_string(),
            expires_at: EXPIRES.to_string(),
        })
        .await
        .unwrap();
    repository
        .mark_uploaded("inst", "upl", 42, DIGEST, "2026-08-10T10:01:00Z")
        .await
        .unwrap();
    repository
        .mark_ready("inst", "upl", None, "2026-08-10T10:02:00Z")
        .await
        .unwrap();
    repository
        .mark_processing("inst", "upl", "2026-08-10T10:03:00Z")
        .await
        .unwrap();

    let confirmed = confirmed_storage_archive_format(Protocol::Postgres, DumpArchiveFormat::Tar);
    assert!(
        repository
            .restore_ready(
                "inst",
                "upl",
                confirmed,
                None,
                Some("bounded catalog inspection"),
                "2026-08-10T10:04:00Z",
            )
            .await
            .unwrap()
    );
    let upload = repository.get("inst", "upl").await.unwrap().unwrap();
    assert_eq!(upload.state, ImportUploadState::Ready);
    assert_eq!(upload.archive_format, Some(ImportUploadArchiveFormat::Tar));
    assert_eq!(
        hardened_upload_archive_format(upload.protocol, upload.archive_format),
        Some("tar".to_string())
    );

    assert_eq!(
        confirmed_storage_archive_format(Protocol::Mongodb, DumpArchiveFormat::Gzip),
        None
    );
    assert_eq!(
        confirmed_storage_archive_format(Protocol::Redis, DumpArchiveFormat::TarGzip),
        None
    );
}

#[test]
fn upload_summaries_never_decode_or_serialize_the_catalog() {
    let upload = crate::storage::import_uploads::ImportUpload {
        upload_id: "upl_test".into(),
        instance_id: "tenant".into(),
        original_filename: "dump.sql".into(),
        stored_filename: "private.dump".into(),
        protocol: Protocol::Mysql,
        archive_format: Some(ImportUploadArchiveFormat::Plain),
        state: ImportUploadState::Ready,
        size_bytes: 1024,
        sha256: Some("a".repeat(64)),
        catalog_json: Some("deliberately invalid and large catalog".repeat(10_000)),
        last_error: None,
        claimed_job_id: None,
        created_at: "now".into(),
        updated_at: "now".into(),
        expires_at: "later".into(),
    };
    assert!(upload_catalog(&upload).is_err());
    let summary = serde_json::to_value(public_upload(upload.clone())).unwrap();
    assert_eq!(summary["catalog_available"], true);
    assert!(summary.get("catalog").is_none());
    assert!(summary.get("stored_filename").is_none());
    assert!(serde_json::to_vec(&summary).unwrap().len() < 1024);
    let mut missing = upload;
    missing.catalog_json = None;
    assert_eq!(
        upload_catalog(&missing).unwrap_err().status(),
        http::StatusCode::CONFLICT
    );
    assert!(!public_upload(missing).catalog_available);
}

#[tokio::test]
async fn catalog_routes_are_scoped_and_return_the_catalog_without_an_upload_wrapper() {
    use crate::{
        api::http::router::build_router,
        auth::api_token::ApiToken,
        instances::{manager::InstanceManager, state::InstanceStore},
        storage::repositories::InstanceRepository,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    let directory = tempfile::tempdir().unwrap();
    let db = crate::storage::sqlite::connect(directory.path())
        .await
        .unwrap();
    let instances = InstanceStore::default();
    for id in ["owner", "other"] {
        let mut metadata = crate::instances::test_support::metadata(id, Protocol::Mysql);
        metadata.database.username = format!("user_{id}");
        InstanceRepository::new(db.clone())
            .upsert(&metadata)
            .await
            .unwrap();
        instances.upsert(metadata).await;
    }
    let manager = InstanceManager::new(instances.clone(), InstanceRepository::new(db.clone()));
    let state = crate::api::test_support::state(
        crate::config::Config {
            remote: "https://panel.example.test".into(),
            ..Default::default()
        },
        directory.path().join("config.yml"),
        ApiToken::new("test-token"),
        instances,
        manager,
        db,
    );
    let id = format!("upl_{}", "a".repeat(32));
    let catalog = serde_json::json!({
        "protocol":"mysql","sha256":"a".repeat(64),"source_size_bytes":1024,
        "detected_archive_format":"plain","selection_kind":"tables",
        "selective_supported":true,"catalog_complete":true,"namespaces":[],
        "objects":[{"kind":"table","name":"users","selection_key":"users"}],
        "unselectable_object_count":0
    });
    state
        .import_uploads
        .repo()
        .insert(&ImportUpload {
            upload_id: id.clone(),
            instance_id: "owner".into(),
            original_filename: "dump.sql".into(),
            stored_filename: "dump.sql".into(),
            protocol: Protocol::Mysql,
            archive_format: Some(ImportUploadArchiveFormat::Plain),
            state: ImportUploadState::Ready,
            size_bytes: 1024,
            sha256: Some("a".repeat(64)),
            catalog_json: Some(catalog.to_string()),
            last_error: None,
            claimed_job_id: None,
            created_at: "2026-09-01T00:00:00Z".into(),
            updated_at: "2026-09-01T00:00:00Z".into(),
            expires_at: "2099-09-01T00:00:00Z".into(),
        })
        .await
        .unwrap();
    let app = build_router(state);
    for method in ["GET", "POST"] {
        for (instance, token, expected) in [
            ("owner", "test-token", StatusCode::OK),
            ("other", "test-token", StatusCode::NOT_FOUND),
            ("owner", "wrong-token", StatusCode::UNAUTHORIZED),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(format!(
                            "/api/instances/{instance}/import/uploads/{id}/catalog"
                        ))
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = to_bytes(response.into_body(), 4096).await.unwrap();
            assert_eq!(
                status,
                expected,
                "{method}/{instance}: {}",
                String::from_utf8_lossy(&body)
            );
            if expected == StatusCode::OK {
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                    catalog
                );
            }
        }
    }
}
