use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use object_store::{ObjectStoreExt, memory::InMemory, path::Path as ObjectPath};

use super::{
    client::{bucket_endpoint, endpoint_base},
    objects::{object_path, owned_key},
    *,
};
use crate::{
    config::{BackupS3Config, SensitiveString},
    databases::protocol::Protocol,
    server::backup::{
        BackupBundle, BackupLayout, build_manifest, drivers::DiscardJournal, new_backup_id,
        test_details,
    },
};

const PREFIX: &str = "dbev/instances/inst_one/backups/";

fn config() -> BackupS3Config {
    BackupS3Config {
        bucket: "bkt".to_string(),
        region: "eu-west-1".to_string(),
        access_key_id: "AKID".to_string(),
        secret_access_key: serde_json::from_str::<SensitiveString>("\"secret\"").unwrap(),
        ..BackupS3Config::default()
    }
}

#[derive(Default)]
pub(super) struct RecordingJournal(pub(super) Mutex<Vec<PublicationResource>>);

impl PublicationJournal for RecordingJournal {
    fn record<'a>(
        &'a self,
        resource: &'a PublicationResource,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        self.0.lock().unwrap().push(resource.clone());
        Box::pin(async { Ok(()) })
    }
}

pub(super) async fn bundle_with_archive(
    root: &std::path::Path,
    instance_id: &str,
    archive: &[u8],
    catalog: bool,
) -> (BackupBundle, StoredBackup) {
    let backup_id = new_backup_id(BackupLayout::Physical);
    let bundle = BackupBundle::create(root, instance_id, &backup_id)
        .await
        .unwrap();
    tokio::fs::write(&bundle.archive, archive).await.unwrap();
    if catalog {
        bundle.write_catalog(br#"{"objects":[]}"#).await.unwrap();
    }
    let manifest = build_manifest(
        backup_id,
        instance_id.to_string(),
        Protocol::Postgres,
        BackupLayout::Physical,
        &bundle.archive,
        catalog,
        test_details(BackupLayout::Physical),
    )
    .await
    .unwrap();
    (bundle, manifest)
}

async fn keys(store: &InMemory) -> Vec<String> {
    use futures::TryStreamExt;
    let mut keys: Vec<String> = store
        .list(None)
        .map_ok(|meta| meta.location.to_string())
        .try_collect()
        .await
        .unwrap();
    keys.sort();
    keys
}

#[tokio::test]
async fn round_trips_a_backup_with_its_catalog() {
    let temp = tempfile::tempdir().unwrap();
    let (driver, store) = S3BackupDriver::in_memory(config());
    let (bundle, manifest) = bundle_with_archive(temp.path(), "inst_one", b"archive", true).await;
    let id = manifest.backup_id.clone();

    driver
        .commit(&bundle, &manifest, &DiscardJournal)
        .await
        .unwrap();

    assert_eq!(
        keys(&store).await,
        vec![
            format!("{PREFIX}{id}"),
            format!("{PREFIX}{id}.catalog.json"),
            format!("{PREFIX}{id}.metadata.json"),
        ]
    );
    let listed = driver.list("inst_one").await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].sha256, manifest.sha256);
    assert_eq!(
        driver.read_catalog("inst_one", &id, 1024).await.unwrap(),
        Some(br#"{"objects":[]}"#.to_vec())
    );
    let destination = temp.path().join("restored");
    driver
        .materialize("inst_one", &id, &destination)
        .await
        .unwrap();
    assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"archive");

    driver.delete("inst_one", &id).await.unwrap();
    assert!(keys(&store).await.is_empty());
    assert!(matches!(
        driver.find("inst_one", &id).await,
        Err(BackupStoreError::NotFound)
    ));
}

#[tokio::test]
async fn commit_refuses_an_archive_that_does_not_match_its_manifest() {
    let temp = tempfile::tempdir().unwrap();
    let (driver, store) = S3BackupDriver::in_memory(config());
    let (bundle, mut manifest) =
        bundle_with_archive(temp.path(), "inst_one", b"archive", false).await;
    manifest.sha256 = "00".repeat(32);

    let error = driver
        .commit(&bundle, &manifest, &DiscardJournal)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("SHA-256"), "{error}");
    assert!(keys(&store).await.is_empty());
}

#[tokio::test]
async fn large_archives_use_a_journaled_verified_multipart_upload() {
    let temp = tempfile::tempdir().unwrap();
    let (driver, store) = S3BackupDriver::in_memory(config());
    let archive: Vec<u8> = (0..MULTIPART_THRESHOLD_BYTES + 1)
        .map(|index| (index % 251) as u8)
        .collect();
    let (bundle, manifest) = bundle_with_archive(temp.path(), "inst_one", &archive, false).await;
    let journal = RecordingJournal::default();

    driver.commit(&bundle, &manifest, &journal).await.unwrap();

    let archive_key = format!("{PREFIX}{}", manifest.backup_id);
    let recorded = journal.0.lock().unwrap().clone();
    assert!(matches!(
        recorded.as_slice(),
        [PublicationResource::S3MultipartUpload { key, upload_id }]
            if *key == archive_key && !upload_id.is_empty()
    ));
    let stored = store
        .get(&ObjectPath::parse(&archive_key).unwrap())
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(stored.as_ref(), archive.as_slice());

    // A changed source fails before the upload completes, and nothing stays.
    let (bundle, mut manifest) =
        bundle_with_archive(temp.path(), "inst_one", &archive, false).await;
    manifest.sha256 = "00".repeat(32);
    assert!(driver.commit(&bundle, &manifest, &journal).await.is_err());
    assert!(
        !keys(&store)
            .await
            .contains(&format!("{PREFIX}{}", manifest.backup_id))
    );
}

#[tokio::test]
async fn inventory_stays_inside_the_instance_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let (driver, store) = S3BackupDriver::in_memory(config());
    for instance in ["inst_one", "inst_one_b", "inst_two"] {
        let (bundle, manifest) = bundle_with_archive(temp.path(), instance, b"a", false).await;
        driver
            .commit(&bundle, &manifest, &DiscardJournal)
            .await
            .unwrap();
    }
    // Newer metadata is listed opaquely; a stray object is never a backup.
    let mut newer: serde_json::Value = serde_json::from_slice(
        &driver
            .get_bytes(&keys(&store).await[1], 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    newer["schema_version"] = 99.into();
    newer["backup_id"] = "zz-newer.physical.tar.gz".into();
    store
        .put(
            &ObjectPath::parse(format!("{PREFIX}zz-newer.physical.tar.gz.metadata.json")).unwrap(),
            serde_json::to_vec(&newer).unwrap().into(),
        )
        .await
        .unwrap();
    store
        .put(
            &ObjectPath::parse(format!("{PREFIX}orphan")).unwrap(),
            "x".into(),
        )
        .await
        .unwrap();

    let inventory = driver.inventory("inst_one").await.unwrap();

    assert_eq!(inventory.backups.len(), 1);
    assert_eq!(inventory.backups[0].instance_id, "inst_one");
    assert_eq!(inventory.unsupported.len(), 1);
    assert_eq!(
        inventory.unsupported[0].backup_id,
        "zz-newer.physical.tar.gz"
    );

    assert_eq!(driver.delete_instance("inst_one").await.unwrap(), 2);
    let remaining = keys(&store).await;
    assert!(remaining.iter().all(|key| !key.starts_with(PREFIX)));
    assert_eq!(remaining.len(), 4);
}

#[tokio::test]
async fn purge_aborts_journaled_uploads_and_removes_every_object() {
    let temp = tempfile::tempdir().unwrap();
    let (driver, store) = S3BackupDriver::in_memory(config());
    let (bundle, manifest) = bundle_with_archive(temp.path(), "inst_one", b"a", false).await;
    driver
        .commit(&bundle, &manifest, &DiscardJournal)
        .await
        .unwrap();
    let archive = format!("{PREFIX}{}", manifest.backup_id);
    let upload_id = store
        .create_multipart(&ObjectPath::parse(&archive).unwrap())
        .await
        .unwrap();
    let resources = [PublicationResource::S3MultipartUpload {
        key: archive.clone(),
        upload_id: upload_id.clone(),
    }];

    driver
        .purge_unpublished("inst_one", &manifest.backup_id, &resources)
        .await
        .unwrap();

    assert!(keys(&store).await.is_empty());
    let aborted = store
        .put_part(
            &ObjectPath::parse(&archive).unwrap(),
            &upload_id,
            0,
            "x".into(),
        )
        .await;
    assert!(aborted.is_err());
    // With no upload left, a repeated purge only confirms absence.
    driver
        .purge_unpublished("inst_one", &manifest.backup_id, &[])
        .await
        .unwrap();
}

#[tokio::test]
async fn bounded_reads_refuse_oversized_objects() {
    let (driver, store) = S3BackupDriver::in_memory(config());
    let key = format!("{PREFIX}big");
    store
        .put(&ObjectPath::parse(&key).unwrap(), vec![0_u8; 16].into())
        .await
        .unwrap();

    let error = driver.get_bytes(&key, 15).await.unwrap_err();

    assert!(error.to_string().contains("exceeded its safety limit"));
    assert_eq!(driver.get_bytes(&key, 16).await.unwrap().len(), 16);
}

#[test]
fn listed_s3_keys_must_remain_inside_the_requested_instance_prefix() {
    assert_eq!(
        owned_key("dbev/instances/a/backup", "dbev/instances/a/").unwrap(),
        "dbev/instances/a/backup"
    );
    let error = owned_key("dbev/instances/b/backup", "dbev/instances/a/").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("outside the requested backup prefix")
    );
}

#[test]
fn keys_must_be_normalized_object_paths() {
    assert_eq!(
        object_path(PREFIX).unwrap().as_ref(),
        PREFIX.trim_end_matches('/')
    );
    assert_eq!(object_path("a/b c+d").unwrap().as_ref(), "a/b c+d");
    for key in ["a//b", "a/../b", "/a", "a/\u{1}"] {
        assert!(object_path(key).is_err(), "{key}");
    }
}

#[test]
fn config_maps_onto_identity_and_bucket_endpoints() {
    let cases = [
        // (endpoint, path_style, identity base, bucket endpoint)
        (
            "",
            false,
            "https://bkt.s3.eu-west-1.amazonaws.com/",
            "https://bkt.s3.eu-west-1.amazonaws.com",
        ),
        (
            "",
            true,
            "https://s3.eu-west-1.amazonaws.com/",
            "https://s3.eu-west-1.amazonaws.com/bkt",
        ),
        (
            "http://minio:9000",
            true,
            "http://minio:9000/",
            "http://minio:9000/bkt",
        ),
        (
            "https://r2.example.com/",
            false,
            "https://bkt.r2.example.com/",
            "https://bkt.r2.example.com",
        ),
        (
            "https://gw.example.com/s3/",
            true,
            "https://gw.example.com/s3/",
            "https://gw.example.com/s3/bkt",
        ),
    ];
    for (endpoint, path_style, identity, bucket) in cases {
        let config = BackupS3Config {
            endpoint: endpoint.to_string(),
            path_style,
            ..config()
        };
        let base = endpoint_base(&config).unwrap();
        assert_eq!(base.as_str(), identity, "{endpoint}");
        assert_eq!(bucket_endpoint(&base, &config), bucket, "{endpoint}");
        let driver = S3BackupDriver::new(config).unwrap();
        assert_eq!(driver.identity(), format!("s3:{identity}|bkt|dbev"));
    }
}

#[test]
fn signed_requests_encode_keys_like_object_store() {
    let config = BackupS3Config {
        endpoint: "http://minio:9000".to_string(),
        path_style: true,
        allow_http: true,
        ..config()
    };
    let driver = S3BackupDriver::new(config).unwrap();
    let uploads = driver.uploads.as_deref().unwrap();
    assert_eq!(
        uploads
            .url("dbev/a b+c", &[("max-parts", "1"), ("uploadId", "x/y")])
            .unwrap()
            .as_str(),
        "http://minio:9000/bkt/dbev/a%20b%2Bc?max-parts=1&uploadId=x%2Fy"
    );
    assert_eq!(
        uploads.url("", &[("uploads", "")]).unwrap().as_str(),
        "http://minio:9000/bkt?uploads="
    );
}

/// A local stand-in for S3 that records each request and answers it with
/// `respond`.
struct MockS3 {
    endpoint: String,
    requests: Arc<Mutex<Vec<(String, String, HeaderMap)>>>,
}

async fn mock_s3(respond: fn(&str, &str) -> (StatusCode, Vec<u8>)) -> MockS3 {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    let app = Router::new().fallback(move |request: Request| {
        let seen = seen.clone();
        async move {
            let method = request.method().to_string();
            let uri = request.uri().to_string();
            seen.lock()
                .unwrap()
                .push((method.clone(), uri.clone(), request.headers().clone()));
            let (status, body) = respond(&method, &uri);
            Response::builder()
                .status(status)
                .body(Body::from(body))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    MockS3 {
        endpoint: format!("http://{address}"),
        requests,
    }
}

fn mock_driver(mock: &MockS3, max_retries: usize) -> S3BackupDriver {
    S3BackupDriver::new(BackupS3Config {
        endpoint: mock.endpoint.clone(),
        path_style: true,
        allow_http: true,
        max_retries,
        request_timeout_seconds: 5,
        ..config()
    })
    .unwrap()
}

fn list_page(key: &str) -> Vec<u8> {
    format!(
        "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>{key}</Key>\
         <LastModified>2026-10-18T00:00:00.000Z</LastModified><ETag>\"e\"</ETag>\
         <Size>1</Size></Contents></ListBucketResult>"
    )
    .into_bytes()
}

#[tokio::test]
async fn listings_are_signed_and_must_stay_inside_the_prefix() {
    let mock = mock_s3(|_, uri| {
        let key = if uri.contains("inst_one") {
            "dbev/instances/inst_two/backups/x"
        } else {
            "dbev/instances/inst_three/backups/x.metadata.json"
        };
        (StatusCode::OK, list_page(key))
    })
    .await;
    let driver = mock_driver(&mock, 0);

    let error = driver.list_keys(PREFIX).await.unwrap_err();

    assert!(
        error
            .to_string()
            .contains("outside the requested backup prefix"),
        "{error}"
    );
    let requests = mock.requests.lock().unwrap();
    let (method, uri, headers) = &requests[0];
    assert_eq!(method, "GET");
    assert!(uri.starts_with("/bkt?"), "{uri}");
    assert!(uri.contains("list-type=2"), "{uri}");
    assert!(
        uri.contains("prefix=dbev%2Finstances%2Finst_one%2Fbackups%2F"),
        "{uri}"
    );
    let authorization = headers["authorization"].to_str().unwrap();
    assert!(
        authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKID/"),
        "{authorization}"
    );
    assert!(authorization.contains("/eu-west-1/s3/aws4_request"));
}

#[tokio::test]
async fn api_responses_beyond_the_safety_limit_are_refused() {
    let mock = mock_s3(|_, _| {
        let padding = " ".repeat(MAX_RESPONSE_BYTES as usize + 1);
        let mut page = list_page("dbev/instances/inst_one/backups/x");
        page.extend_from_slice(padding.as_bytes());
        (StatusCode::OK, page)
    })
    .await;
    let driver = mock_driver(&mock, 0);

    assert!(driver.list_keys(PREFIX).await.is_err());
}

#[tokio::test]
async fn server_errors_are_retried_up_to_max_retries() {
    let mock = mock_s3(|_, _| (StatusCode::SERVICE_UNAVAILABLE, Vec::new())).await;
    let driver = mock_driver(&mock, 2);

    assert!(driver.get_bytes(&format!("{PREFIX}x"), 10).await.is_err());
    assert_eq!(mock.requests.lock().unwrap().len(), 3);

    mock.requests.lock().unwrap().clear();
    let uploads = driver.uploads.as_deref().unwrap();
    let (status, _) = uploads
        .send(reqwest::Method::GET, "", &[("uploads", "")], "list")
        .await
        .unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(mock.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn missing_objects_map_to_not_found() {
    let mock = mock_s3(|_, _| {
        (
            StatusCode::NOT_FOUND,
            b"<Error><Code>NoSuchKey</Code></Error>".to_vec(),
        )
    })
    .await;
    let driver = mock_driver(&mock, 0);

    assert!(matches!(
        driver.find("inst_one", "a.physical.tar.gz").await,
        Err(BackupStoreError::NotFound)
    ));
    driver
        .delete_object(&format!("{PREFIX}a"), true)
        .await
        .unwrap();
}

#[tokio::test]
async fn only_no_such_upload_confirms_an_abort() {
    let mock = mock_s3(|_, uri| {
        let code = if uri.contains("gone") {
            "NoSuchUpload"
        } else {
            "NoSuchBucket"
        };
        (
            StatusCode::NOT_FOUND,
            format!("<Error><Code>{code}</Code></Error>").into_bytes(),
        )
    })
    .await;
    let driver = mock_driver(&mock, 0);
    let uploads = driver.uploads.as_deref().unwrap();

    assert!(
        uploads
            .upload_gone(&format!("{PREFIX}a"), "gone")
            .await
            .unwrap()
    );
    assert!(
        uploads
            .upload_gone(&format!("{PREFIX}a"), "other")
            .await
            .is_err()
    );
}
