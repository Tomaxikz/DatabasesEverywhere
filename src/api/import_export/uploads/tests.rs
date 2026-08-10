use super::*;

#[test]
fn disk_reservation_guard_releases_exactly_once() {
    let total = Arc::new(AtomicU64::new(4096));
    let guard = UploadDiskReservation {
        bytes: 4096,
        total: total.clone(),
    };
    drop(guard);
    assert_eq!(total.load(Ordering::Acquire), 0);
}

#[test]
fn disk_capacity_includes_other_in_flight_uploads_and_reserve() {
    assert_eq!(
        required_upload_capacity(1024, 2048).unwrap(),
        UPLOAD_DISK_RESERVE_BYTES + 3072
    );
    assert!(required_upload_capacity(u64::MAX, 1).is_err());
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
