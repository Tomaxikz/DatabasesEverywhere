use std::collections::BTreeMap;

use axum::{
    body::{Bytes, to_bytes},
    response::IntoResponse,
};
use http::{Method, header};
use serde::Deserialize;

use super::*;

#[derive(Default)]
struct State {
    objects: BTreeMap<String, Bytes>,
    uploads: BTreeMap<(String, String), BTreeMap<u64, Bytes>>,
    next_id: u64,
    fail: Option<&'static str>,
    events: Vec<&'static str>,
}

#[derive(Clone, Default)]
pub(super) struct Fixture(Arc<Mutex<State>>);

impl Fixture {
    pub(super) async fn start() -> (S3BackupDriver, Self) {
        let fixture = Self::default();
        let server = fixture.clone();
        let app = Router::new().fallback(move |request: Request| {
            let server = server.clone();
            async move {
                let (head, body) = request.into_parts();
                let query = form_urlencoded::parse(head.uri.query().unwrap_or_default().as_bytes())
                    .collect::<BTreeMap<_, _>>();
                let body = to_bytes(body, 32 << 20)
                    .await
                    .expect("to bytes should succeed");
                let key = head
                    .uri
                    .path()
                    .strip_prefix("/bkt")
                    .expect("expected a value from strip_prefix")
                    .trim_start_matches('/');
                let key = crate::utils::percent::decode_strict(key)
                    .expect("decode strict should succeed");
                server.0.lock().expect("lock should succeed").respond(
                    head.method,
                    &key,
                    &query,
                    body,
                )
            }
        });
        let endpoint = super::wire::serve(app).await;
        let driver = S3BackupDriver::new(BackupS3Config {
            endpoint,
            path_style: true,
            allow_http: true,
            max_retries: 0,
            ..config()
        })
        .expect("config should succeed");
        (driver, fixture)
    }

    pub(super) fn keys(&self) -> Vec<String> {
        self.0
            .lock()
            .expect("lock should succeed")
            .objects
            .keys()
            .cloned()
            .collect()
    }
    pub(super) fn get(&self, key: &str) -> Bytes {
        self.0.lock().expect("lock should succeed").objects[key].clone()
    }
    pub(super) fn insert(&self, key: String, body: Bytes) {
        self.0
            .lock()
            .expect("lock should succeed")
            .objects
            .insert(key, body);
    }
}

impl State {
    fn respond(
        &mut self,
        method: Method,
        key: &str,
        query: &BTreeMap<std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>>,
        body: Bytes,
    ) -> Response {
        if let Some(id) = query.get("uploadId") {
            let handle = (key.to_string(), id.to_string());
            if method == Method::GET {
                self.events.push("confirm");
            }
            let Some(parts) = self.uploads.get_mut(&handle) else {
                return (
                    StatusCode::NOT_FOUND,
                    "<Error><Code>NoSuchUpload</Code></Error>",
                )
                    .into_response();
            };
            return match method {
                Method::PUT => {
                    self.events.push("part");
                    if self.fail == Some("part") {
                        return StatusCode::FORBIDDEN.into_response();
                    }
                    let number = query["partNumber"]
                        .parse::<u64>()
                        .expect("parse should succeed");
                    parts.insert(number, body);
                    ([(header::ETAG, format!("\"part&{number}\""))], "").into_response()
                }
                Method::POST => {
                    self.events.push("complete");
                    if self.fail == Some("complete") {
                        return "<Error><Code>InvalidPart</Code></Error>".into_response();
                    }
                    #[derive(Deserialize)]
                    struct Completed {
                        #[serde(rename = "Part")]
                        parts: Vec<CompletedPart>,
                    }
                    #[derive(Deserialize)]
                    struct CompletedPart {
                        #[serde(rename = "PartNumber")]
                        number: u64,
                        #[serde(rename = "ETag")]
                        etag: String,
                    }
                    let completed: Completed = quick_xml::de::from_reader(body.as_ref())
                        .expect("from reader should succeed");
                    let mut bytes = Vec::new();
                    for (i, part) in completed.parts.iter().enumerate() {
                        assert_eq!(part.number, i as u64 + 1);
                        assert_eq!(part.etag, format!("\"part&{}\"", part.number));
                        bytes.extend_from_slice(&parts[&part.number]);
                    }
                    self.objects.insert(key.to_string(), bytes.into());
                    self.uploads.remove(&handle);
                    "<CompleteMultipartUploadResult><ETag>done</ETag></CompleteMultipartUploadResult>".into_response()
                }
                Method::DELETE => {
                    self.events.push("abort");
                    self.uploads.remove(&handle);
                    StatusCode::NO_CONTENT.into_response()
                }
                Method::GET => "<ListPartsResult/>".into_response(),
                _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
            };
        }
        if query.contains_key("uploads") {
            if method == Method::POST {
                self.events.push("create");
                self.next_id += 1;
                let id = format!("up/{}+%", self.next_id);
                self.uploads
                    .insert((key.to_string(), id.clone()), BTreeMap::new());
                return format!("<InitiateMultipartUploadResult><UploadId>{id}</UploadId></InitiateMultipartUploadResult>").into_response();
            }
            self.events.push("discover");
            let mut xml =
                String::from("<ListMultipartUploadsResult><IsTruncated>false</IsTruncated>");
            for (key, id) in self
                .uploads
                .keys()
                .filter(|(key, _)| key.starts_with(query["prefix"].as_ref()))
            {
                let key = crate::utils::percent::encode_path(key.as_bytes());
                xml.push_str(&format!(
                    "<Upload><Key>{key}</Key><UploadId>{id}</UploadId></Upload>"
                ));
            }
            xml.push_str("</ListMultipartUploadsResult>");
            return xml.into_response();
        }
        if query.contains_key("list-type") {
            let mut xml = String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
            for key in self
                .objects
                .keys()
                .filter(|k| k.starts_with(query["prefix"].as_ref()))
            {
                xml.push_str(&format!(
                    "<Contents><Key>{}</Key></Contents>",
                    quick_xml::escape::escape(key)
                ));
            }
            xml.push_str("</ListBucketResult>");
            return xml.into_response();
        }
        match method {
            Method::PUT => {
                self.objects.insert(key.into(), body);
                ([(header::ETAG, "\"object\"")], "").into_response()
            }
            Method::GET => self
                .objects
                .get(key)
                .cloned()
                .map(IntoResponse::into_response)
                .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response()),
            Method::DELETE => {
                self.events.push("delete");
                self.objects.remove(key);
                StatusCode::NO_CONTENT.into_response()
            }
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        }
    }
}

impl PublicationJournal for Fixture {
    fn record<'a>(
        &'a self,
        resource: &'a PublicationResource,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(async move {
            let mut state = self.0.lock().expect("lock should succeed");
            let PublicationResource::S3MultipartUpload { key, upload_id } = resource else {
                panic!("unexpected journal entry")
            };
            assert!(
                state
                    .uploads
                    .contains_key(&(key.clone(), upload_id.clone()))
            );
            state.events.push("journal");
            if state.fail == Some("journal") {
                return Err(BackupStoreError::Runtime("injected journal failure".into()));
            }
            Ok(())
        })
    }
}

#[tokio::test]
async fn failed_publication_aborts_the_journaled_upload() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let (bundle, manifest) =
        bundle_with_archive(temp.path(), "inst_one", b"part body", false).await;
    for (failure, events) in [
        ("journal", vec!["create", "journal", "abort"]),
        ("part", vec!["create", "journal", "part", "abort", "delete"]),
        (
            "complete",
            vec!["create", "journal", "part", "complete", "abort", "delete"],
        ),
    ] {
        let (driver, fixture) = Fixture::start().await;
        fixture
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("test mutex was poisoned"))?
            .fail = Some(failure);
        let error = driver
            .multipart_upload(
                "archive",
                &bundle.archive,
                manifest.size_bytes,
                &manifest.sha256,
                &fixture,
            )
            .await
            .expect_err("multipart upload should return an error");
        if failure == "complete" {
            assert!(error.to_string().contains("InvalidPart"), "{error}");
        }
        let state = fixture
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("test mutex was poisoned"))?;
        assert_eq!(state.events, events);
        assert!(state.uploads.is_empty() && state.objects.is_empty());
    }

    Ok(())
}

#[tokio::test]
async fn instance_purge_confirms_and_relists_only_owned_uploads() -> anyhow::Result<()> {
    let (driver, fixture) = Fixture::start().await;
    let mut handles = Vec::new();
    for instance in ["inst_one", "inst_one_b"] {
        let key = format!("{}orphan", driver.instance_prefix(instance)?);
        let id = driver.client.create_multipart(&key).await?;
        driver.client.put_part(&key, &id, 1, "part".into()).await?;
        handles.push((key, id));
    }
    fixture
        .0
        .lock()
        .map_err(|_| anyhow::anyhow!("test mutex was poisoned"))?
        .events
        .clear();
    assert_eq!(driver.delete_instance("inst_one").await?, 0);
    let state = fixture
        .0
        .lock()
        .map_err(|_| anyhow::anyhow!("test mutex was poisoned"))?;
    assert_eq!(state.events, ["discover", "abort", "confirm", "discover"]);
    assert!(!state.uploads.contains_key(&handles[0]));
    assert_eq!(state.uploads[&handles[1]][&1], "part");

    Ok(())
}
