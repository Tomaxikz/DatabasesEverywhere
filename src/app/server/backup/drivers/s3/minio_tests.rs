//! End-to-end run of the S3 driver against a real S3-compatible server.
//!
//! Ignored by default. Start MinIO, or SeaweedFS (`weed server -s3` with an
//! `-s3.config` identity so signatures are verified; endpoint port 8333), and
//! create the bucket, then run:
//! `cargo test --lib -- --ignored s3::minio_tests --test-threads=1`
//! Settings come from `DBEV_S3_E2E_ENDPOINT` (default
//! `http://127.0.0.1:9000`), `DBEV_S3_E2E_BUCKET` (`dbev-e2e`),
//! `DBEV_S3_E2E_ACCESS_KEY` (`dbevtest`) and `DBEV_S3_E2E_SECRET_KEY`
//! (`dbevtestsecret`).

use object_store::path::Path as ObjectPath;

use super::{
    tests::{RecordingJournal, bundle_with_archive},
    *,
};
use crate::config::{BackupS3Config, SensitiveString};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn minio_driver() -> S3BackupDriver {
    let secret = env_or("DBEV_S3_E2E_SECRET_KEY", "dbevtestsecret");
    S3BackupDriver::new(BackupS3Config {
        bucket: env_or("DBEV_S3_E2E_BUCKET", "dbev-e2e"),
        region: "us-east-1".to_string(),
        endpoint: env_or("DBEV_S3_E2E_ENDPOINT", "http://127.0.0.1:9000"),
        access_key_id: env_or("DBEV_S3_E2E_ACCESS_KEY", "dbevtest"),
        secret_access_key: serde_json::from_value::<SensitiveString>(secret.into()).unwrap(),
        path_style: true,
        allow_http: true,
        ..BackupS3Config::default()
    })
    .expect("build the MinIO driver")
}

/// A fresh instance id per run, so reruns never see earlier objects.
fn instance_id() -> String {
    format!("inst_e2e_{}", uuid::Uuid::new_v4().simple())
}

#[tokio::test]
#[ignore = "needs a running MinIO; see the module docs"]
async fn small_backup_round_trips_through_minio() {
    let driver = minio_driver();
    driver.preflight().await.expect("preflight");
    let instance = instance_id();
    let temp = tempfile::tempdir().unwrap();
    let (bundle, manifest) =
        bundle_with_archive(temp.path(), &instance, b"small archive body", true).await;
    let id = manifest.backup_id.clone();

    driver
        .commit(&bundle, &manifest, &RecordingJournal::default())
        .await
        .expect("commit a small backup");

    let listed = driver.inventory(&instance).await.expect("inventory");
    assert_eq!(listed.backups.len(), 1);
    assert!(listed.unsupported.is_empty());
    assert_eq!(listed.backups[0].backup_id, id);
    assert_eq!(listed.backups[0].sha256, manifest.sha256);
    assert_eq!(driver.find(&instance, &id).await.unwrap().size_bytes, 18);
    assert_eq!(
        driver.read_catalog(&instance, &id, 1024).await.unwrap(),
        Some(br#"{"objects":[]}"#.to_vec())
    );
    let restored = temp.path().join("restored");
    driver
        .materialize(&instance, &id, &restored)
        .await
        .expect("download");
    assert_eq!(
        tokio::fs::read(&restored).await.unwrap(),
        b"small archive body"
    );

    driver.delete(&instance, &id).await.expect("delete");
    assert!(matches!(
        driver.find(&instance, &id).await,
        Err(BackupStoreError::NotFound)
    ));
    assert!(
        driver
            .inventory(&instance)
            .await
            .unwrap()
            .backups
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs a running MinIO; see the module docs"]
async fn multipart_backup_round_trips_through_minio() {
    let driver = minio_driver();
    let instance = instance_id();
    let temp = tempfile::tempdir().unwrap();
    // Two full parts plus a tail, so completion stitches several parts.
    let size = MULTIPART_THRESHOLD_BYTES * 2 + 12_345;
    let archive: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
    let (bundle, manifest) = bundle_with_archive(temp.path(), &instance, &archive, false).await;
    let id = manifest.backup_id.clone();
    let journal = RecordingJournal::default();

    driver
        .commit(&bundle, &manifest, &journal)
        .await
        .expect("commit a multipart backup");

    let recorded = journal.0.lock().unwrap().clone();
    assert!(
        recorded
            .iter()
            .any(|resource| matches!(resource, PublicationResource::S3MultipartUpload { .. })),
        "the multipart upload must be journaled before parts are sent: {recorded:?}"
    );
    let restored = temp.path().join("restored");
    driver
        .materialize(&instance, &id, &restored)
        .await
        .expect("download the multipart backup");
    let downloaded = tokio::fs::read(&restored).await.unwrap();
    assert_eq!(downloaded.len(), archive.len());
    assert!(downloaded == archive, "downloaded bytes differ");

    driver.delete(&instance, &id).await.expect("delete");
    assert_eq!(driver.delete_instance(&instance).await.unwrap(), 0);
}

#[tokio::test]
#[ignore = "needs a running MinIO; see the module docs"]
async fn purge_aborts_journaled_and_unjournaled_uploads_on_minio() {
    let driver = minio_driver();
    let instance = instance_id();
    let temp = tempfile::tempdir().unwrap();
    let (bundle, manifest) = bundle_with_archive(temp.path(), &instance, b"a", false).await;
    let id = manifest.backup_id.clone();
    driver
        .commit(&bundle, &manifest, &RecordingJournal::default())
        .await
        .unwrap();
    let archive = driver.archive_key(&instance, &id).unwrap();
    let catalog = driver.catalog_key(&instance, &id).unwrap();
    let archive_path = ObjectPath::parse(&archive).unwrap();
    let catalog_path = ObjectPath::parse(&catalog).unwrap();
    // One upload the journal knows about, one it never recorded (a crash
    // between create and journal write), each with a part already sent.
    let journaled = driver
        .multipart
        .create_multipart(&archive_path)
        .await
        .unwrap();
    driver
        .multipart
        .put_part(&archive_path, &journaled, 0, vec![1_u8; 1024].into())
        .await
        .unwrap();
    let unjournaled = driver
        .multipart
        .create_multipart(&catalog_path)
        .await
        .unwrap();
    driver
        .multipart
        .put_part(&catalog_path, &unjournaled, 0, vec![2_u8; 1024].into())
        .await
        .unwrap();
    let resources = [PublicationResource::S3MultipartUpload {
        key: archive.clone(),
        upload_id: journaled.clone(),
    }];

    driver
        .purge_unpublished(&instance, &id, &resources)
        .await
        .expect("purge");

    assert!(matches!(
        driver.find(&instance, &id).await,
        Err(BackupStoreError::NotFound)
    ));
    for (path, upload) in [(&archive_path, &journaled), (&catalog_path, &unjournaled)] {
        assert!(
            driver
                .multipart
                .put_part(path, upload, 1, vec![3_u8; 1024].into())
                .await
                .is_err(),
            "upload {upload} on {path} must be aborted"
        );
    }
    // Nothing is left, so a repeated purge only confirms absence.
    driver
        .purge_unpublished(&instance, &id, &resources)
        .await
        .expect("repeat purge");
    assert_eq!(driver.delete_instance(&instance).await.unwrap(), 0);
}
