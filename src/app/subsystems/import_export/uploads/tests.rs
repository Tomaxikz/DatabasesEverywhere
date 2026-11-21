use super::*;
use super::{
    finalize::{spawn_owned_inspection, upload_catalog},
    ingest::{
        confirmed_storage_archive_format, hardened_upload_archive_format, receive_upload_body,
    },
    records::public_upload,
    worker::{UploadWorkerGuards, UploadWorkerOptions, UploadWorkerRecovery, spawn_upload_worker},
};
use std::{path::PathBuf, time::Duration};

use axum::{body::Body, http::StatusCode};

use crate::storage::{
    import_uploads::{ImportUpload, ImportUploadArchiveFormat, ImportUploadState, NewImportUpload},
    migrations, test_support,
};

use super::super::inspection::DumpArchiveFormat;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn configured_inspection_limit_is_shared_and_bounded_by_upload_workers() -> anyhow::Result<()>
{
    let pool = sqlx::sqlite::SqlitePoolOptions::new().connect_lazy("sqlite::memory:")?;
    let service =
        ImportUploadService::with_limits(ImportUploadRepository::new(pool.clone()), 8, 2, 3);
    let other = service.clone();
    let held = service
        .inspection_admission
        .clone()
        .try_acquire_many_owned(3)?;
    assert!(
        other
            .inspection_admission
            .clone()
            .try_acquire_owned()
            .is_err()
    );
    drop(held);
    assert!(
        other
            .inspection_admission
            .clone()
            .try_acquire_many_owned(3)
            .is_ok()
    );
    let service = ImportUploadService::with_limits(ImportUploadRepository::new(pool), 2, 2, 8);
    assert_eq!(service.inspection_admission.available_permits(), 2);

    Ok(())
}

#[tokio::test]
async fn output_reservations_share_capacity_without_consuming_staging_slots() -> anyhow::Result<()>
{
    let pool = sqlx::sqlite::SqlitePoolOptions::new().connect_lazy("sqlite::memory:")?;
    let service = ImportUploadService::new(ImportUploadRepository::new(pool), 1);
    let directory = tempfile::tempdir()?;
    let staging = service.staging_admission.clone().try_acquire_owned()?;

    let first = service
        .reserve_output_capacity(directory.path(), 1024)
        .await?;
    let second = service
        .reserve_output_capacity(directory.path(), 2048)
        .await?;
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

    Ok(())
}

#[tokio::test]
async fn output_roots_on_the_same_device_are_identified_as_one_filesystem() -> anyhow::Result<()> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new().connect_lazy("sqlite::memory:")?;
    let service = ImportUploadService::new(ImportUploadRepository::new(pool), 1);
    let directory = tempfile::tempdir()?;
    let staging = directory.path().join("staging");
    tokio::fs::create_dir(&staging).await?;

    assert!(
        service
            .output_roots_share_filesystem(directory.path(), &staging)
            .await?
    );

    Ok(())
}

fn reserved_total(service: &ImportUploadService) -> u64 {
    service.disk_capacity.reserved_bytes()
}

#[tokio::test]
async fn expensive_upload_work_has_separate_small_global_limits() -> anyhow::Result<()> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new().connect_lazy("sqlite::memory:")?;
    let service = ImportUploadService::new(ImportUploadRepository::new(pool), 32);
    let first = service.inspection_admission.clone().try_acquire_owned()?;
    let second = service.inspection_admission.clone().try_acquire_owned()?;
    assert!(
        service
            .inspection_admission
            .clone()
            .try_acquire_owned()
            .is_err()
    );
    assert!(service.admission.clone().try_acquire_owned().is_ok());
    drop((first, second));

    let first = service.staging_admission.clone().try_acquire_owned()?;
    let second = service.staging_admission.clone().try_acquire_owned()?;
    assert!(
        service
            .staging_admission
            .clone()
            .try_acquire_owned()
            .is_err()
    );
    drop((first, second));
    tokio::task::yield_now().await;

    Ok(())
}

#[tokio::test]
async fn cancelled_inspection_waiter_does_not_release_worker_guards() -> anyhow::Result<()> {
    let locks = crate::server::locks::InstanceLocks::default();
    let instance_operation = locks.lock("inst_inspection").await;
    let admission = Arc::new(Semaphore::new(1));
    let inspection_permit = admission.clone().try_acquire_owned()?;
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
    started_receiver.await?;
    caller.abort();
    assert!(
        caller
            .await
            .expect_err(
                "cancelled inspection waiter does not release worker guards should return an error"
            )
            .is_cancelled()
    );

    assert!(admission.clone().try_acquire_owned().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), locks.lock("inst_inspection"))
            .await
            .is_err()
    );

    release_sender
        .send(())
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    tokio::time::timeout(Duration::from_secs(1), async {
        while !completed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(permit) = admission.clone().try_acquire_owned() {
                drop(permit);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    tokio::time::timeout(Duration::from_secs(1), locks.lock("inst_inspection")).await?;

    Ok(())
}

#[tokio::test]
async fn upload_body_idle_timeout_returns_request_timeout() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let partial = dir.path().join("upload.partial");
    let body = Body::from_stream(futures::stream::pending::<
        Result<bytes::Bytes, std::io::Error>,
    >());

    let error = receive_upload_body(body, &partial, 1, None, Duration::from_millis(20))
        .await
        .expect_err("from millis should return an error");

    assert!(matches!(
        error,
        ApiError::RequestRejected { status, .. } if status == StatusCode::REQUEST_TIMEOUT
    ));

    Ok(())
}

#[tokio::test]
async fn upload_body_chunk_before_idle_deadline_succeeds() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
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
    .await?;

    assert_eq!(
        digest,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(tokio::fs::read(partial).await?, b"abc");

    Ok(())
}

#[tokio::test]
async fn cancelled_upload_waiter_keeps_guards_until_worker_commits() -> anyhow::Result<()> {
    let (repository, upload, directory, partial_path, final_path) = upload_worker_fixture().await;
    let admission = Arc::new(Semaphore::new(1));
    let admission_permit = admission.clone().try_acquire_owned()?;
    let locks = crate::server::locks::InstanceLocks::default();
    let instance_operation = locks.lock("inst").await;
    let disk_capacity = DiskCapacityService::default();
    let disk_reservation = disk_capacity.reserve(directory.path(), 3).await?;
    let guards = Arc::new(UploadWorkerGuards::new(
        admission_permit,
        instance_operation,
        disk_reservation,
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

    started_receiver.await?;
    caller.abort();
    assert!(
        caller
            .await
            .expect_err(
                "cancelled upload waiter keeps guards until worker commits should return an error"
            )
            .is_cancelled()
    );
    assert!(admission.clone().try_acquire_owned().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), locks.lock("inst"))
            .await
            .is_err()
    );
    assert_eq!(disk_capacity.reserved_bytes(), 3);

    release_sender
        .send(())
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let ready = repository
                .get("inst", "upl_worker")
                .await
                .expect("get should succeed")
                .is_some_and(|upload| upload.state == ImportUploadState::Ready);
            if ready && final_path.exists() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(tokio::fs::read(&final_path).await?, b"abc");
    assert!(!partial_path.exists());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if admission.clone().try_acquire_owned().is_ok() && disk_capacity.reserved_bytes() == 0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    tokio::time::timeout(Duration::from_secs(1), locks.lock("inst")).await?;
    drop(directory);

    Ok(())
}

#[tokio::test]
async fn panicking_upload_worker_durably_cleans_files_and_row() -> anyhow::Result<()> {
    let (repository, upload, directory, partial_path, final_path) = upload_worker_fixture().await;
    std::fs::write(&final_path, b"orphan")?;
    let admission = Arc::new(Semaphore::new(1));
    let locks = crate::server::locks::InstanceLocks::default();
    let disk_capacity = DiskCapacityService::default();
    let disk_reservation = disk_capacity.reserve(directory.path(), 3).await?;
    let guards = Arc::new(UploadWorkerGuards::new(
        admission.clone().try_acquire_owned()?,
        locks.lock("inst").await,
        disk_reservation,
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
    .await?
    .expect_err("from secs should return an error");

    assert!(matches!(error, ApiError::Runtime(_)));
    assert!(repository.get("inst", "upl_worker").await?.is_none());
    assert!(!partial_path.exists());
    assert!(!final_path.exists());
    assert!(admission.try_acquire_owned().is_ok());
    assert_eq!(disk_capacity.reserved_bytes(), 0);
    tokio::time::timeout(Duration::from_secs(1), locks.lock("inst")).await?;

    Ok(())
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
        .expect("connect should succeed");
    migrations::run(&pool).await.expect("run should succeed");
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
        .expect("to string should succeed");
    let directory = tempfile::tempdir().expect("tempdir should succeed");
    let partial_path = directory.path().join(".upl_worker.upload.partial");
    let final_path = directory.path().join("upl_worker.upload");
    (repository, upload, directory, partial_path, final_path)
}

#[tokio::test]
async fn retryable_inspection_retains_detected_wrapper_for_hardening() -> anyhow::Result<()> {
    use anyhow::Context as _;

    const CREATED: &str = "2026-08-10T10:00:00Z";
    const EXPIRES: &str = "2026-08-10T11:00:00Z";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    migrations::run(&pool).await?;
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
        .await?;
    repository
        .mark_uploaded("inst", "upl", 42, DIGEST, "2026-08-10T10:01:00Z")
        .await?;
    repository
        .mark_ready("inst", "upl", None, "2026-08-10T10:02:00Z")
        .await?;
    repository
        .mark_processing("inst", "upl", "2026-08-10T10:03:00Z")
        .await?;

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
            .await?
    );
    let upload = repository
        .get("inst", "upl")
        .await?
        .context("get should provide a value")?;
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

    Ok(())
}

#[test]
fn upload_summaries_never_decode_or_serialize_the_catalog() -> anyhow::Result<()> {
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
    let summary = serde_json::to_value(public_upload(upload.clone()))?;
    assert_eq!(summary["catalog_available"], true);
    assert!(summary.get("catalog").is_none());
    assert!(summary.get("stored_filename").is_none());
    assert!(serde_json::to_vec(&summary)?.len() < 1024);
    let mut missing = upload;
    missing.catalog_json = None;
    assert_eq!(
        upload_catalog(&missing)
            .expect_err("upload catalog should return an error")
            .status(),
        http::StatusCode::CONFLICT
    );
    assert!(!public_upload(missing).catalog_available);

    Ok(())
}

#[tokio::test]
async fn catalog_routes_are_scoped_and_return_the_catalog_without_an_upload_wrapper()
-> anyhow::Result<()> {
    use crate::{
        auth::api_token::ApiToken,
        routes::http::router::build_router,
        server::{manager::InstanceManager, state::InstanceStore},
        storage::repositories::InstanceRepository,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    let directory = tempfile::tempdir()?;
    let db = crate::storage::sqlite::connect(directory.path()).await?;
    let instances = InstanceStore::default();
    for id in ["owner", "other"] {
        let mut metadata = crate::server::test_support::metadata(id, Protocol::Mysql);
        metadata.database.username = format!("user_{id}");
        InstanceRepository::new(db.clone())
            .upsert(&metadata)
            .await?;
        instances.upsert(metadata).await;
    }
    let manager = InstanceManager::new(instances.clone(), InstanceRepository::new(db.clone()));
    let state = crate::subsystems::test_support::state(
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
        .await?;
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
                        .body(Body::empty())?,
                )
                .await
                .expect("expected a value from oneshot");
            let status = response.status();
            let body = to_bytes(response.into_body(), 4096).await?;
            assert_eq!(
                status,
                expected,
                "{method}/{instance}: {}",
                String::from_utf8_lossy(&body)
            );
            if expected == StatusCode::OK {
                assert_eq!(serde_json::from_slice::<serde_json::Value>(&body)?, catalog);
            }
        }
    }

    Ok(())
}
