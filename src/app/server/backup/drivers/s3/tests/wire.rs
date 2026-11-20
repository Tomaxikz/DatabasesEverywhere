use std::{
    convert::Infallible,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, UNIX_EPOCH},
};

use aws_credential_types::Credentials;
use axum::body::{Bytes, to_bytes};
use futures::{StreamExt, stream};
use http::{Method, header};
use sha2::{Digest, Sha256};

use super::*;

pub(super) async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

pub(super) async fn driver(app: Router, retries: usize, timeout: u64) -> S3BackupDriver {
    S3BackupDriver::new(BackupS3Config {
        endpoint: format!("{}/gateway/", serve(app).await),
        path_style: true,
        allow_http: true,
        max_retries: retries,
        request_timeout_seconds: timeout,
        session_token: serde_json::from_str("\"session/token+\"").unwrap(),
        ..config()
    })
    .unwrap()
}

#[test]
fn aws_s3_ranged_get_signature_vector() {
    // AWS S3 SigV4 header authentication example, GET Object on 2013-05-24.
    let creds = Credentials::new(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        None,
        None,
        "test",
    );
    let request = http::Request::get("https://examplebucket.s3.amazonaws.com/test.txt")
        .header(header::RANGE, "bytes=0-9")
        .body(signing::ReplayBody::new(Bytes::new()))
        .unwrap();
    let midnight = UNIX_EPOCH + Duration::from_secs(1369353600);
    let signed = signing::sign_request(request, &creds, "us-east-1", midnight).unwrap();
    assert_eq!(
        signed.headers()[header::AUTHORIZATION],
        concat!(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, ",
            "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, ",
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        )
    );
    assert!(signed.headers()[header::AUTHORIZATION].is_sensitive());
}

#[tokio::test]
async fn part_put_signs_the_actual_payload_token_and_escaped_target() {
    let app = Router::new().fallback(|request: Request| async move {
        assert_eq!(request.method(), Method::PUT);
        assert_eq!(
            request.uri().to_string(),
            "/gateway/bkt/a%20b%2B%25/%C3%A9?partNumber=1&uploadId=x%20%2B%2F%25"
        );
        let (head, body) = request.into_parts();
        let body = to_bytes(body, 1024).await.unwrap();
        assert_eq!(body, "payload");
        assert_eq!(head.headers[header::CONTENT_LENGTH], "7");
        assert_eq!(
            head.headers["x-amz-content-sha256"],
            hex::encode(Sha256::digest(&body))
        );
        assert_eq!(head.headers["x-amz-security-token"], "session/token+");
        // Independently authenticate what actually arrived, including the ephemeral port.
        // The path and query above are already in S3's canonical order and encoding.
        let signed = "content-length;host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
        let digest = head.headers["x-amz-content-sha256"].to_str().unwrap();
        let host = head.headers[header::HOST].to_str().unwrap();
        let timestamp = head.headers["x-amz-date"].to_str().unwrap();
        let day = &timestamp[..8];
        let canonical = format!("PUT\n{}\n{}\ncontent-length:7\nhost:{host}\nx-amz-content-sha256:{digest}\nx-amz-date:{timestamp}\nx-amz-security-token:session/token+\n\n{signed}\n{digest}",
            head.uri.path(), head.uri.query().unwrap());
        let scope = format!("{day}/eu-west-1/s3/aws4_request");
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}", hex::encode(Sha256::digest(canonical)));
        let hmac = |key: &[u8], data: &str| {
            use aws_lc_rs::hmac::{Key, HMAC_SHA256, sign};
            sign(&Key::new(HMAC_SHA256, key), data.as_bytes()).as_ref().to_vec()
        };
        let key = scope.split('/').fold(b"AWS4secret".to_vec(), |key, field| hmac(&key, field));
        let signature = hex::encode(hmac(&key, &string_to_sign));
        assert_eq!(head.headers[header::AUTHORIZATION], format!("AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders={signed}, Signature={signature}"));
        [(header::ETAG, "\"part\"")]
    });
    driver(app, 0, 5)
        .await
        .client
        .put_part("a b+%/é", "x +/%", 1, "payload".into())
        .await
        .unwrap();
}

#[tokio::test]
async fn interrupted_download_requires_a_covering_range_of_the_same_object() {
    for (status, etag, range, body, valid) in [
        (206, "old", "bytes 3-7/8", "defgh", true),
        (206, "old", "bytes 1-7/8", "bcdefgh", true),
        (206, "new", "bytes 3-7/8", "defgh", false),
        (206, "old", "bytes 4-7/8", "efgh", false),
        (206, "old", "bytes 3-6/8", "defg", false),
        (206, "old", "bytes 3-7/9", "defgh", false),
        (200, "old", "bytes 0-7/8", "abcdefgh", false),
    ] {
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let app = Router::new().fallback(move |request: Request| {
            let n = count.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    return interrupted(&["\"old\""]);
                }
                assert_eq!(request.headers()[header::RANGE], "bytes=3-7");
                assert_eq!(request.headers()[header::IF_MATCH], "\"old\"");
                Response::builder()
                    .status(status)
                    .header(header::ETAG, format!("\"{etag}\""))
                    .header(header::CONTENT_RANGE, range)
                    .body(Body::from(body))
                    .unwrap()
            }
        });
        let result = driver(app, 1, 5).await.get_bytes("archive", 8).await;
        if valid {
            assert_eq!(result.unwrap(), b"abcdefgh");
        } else {
            assert!(result.is_err(), "{status} {range} {etag}");
        }
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn chunked_list_and_error_bodies_are_capped_before_parsing() {
    for status in [
        StatusCode::OK,
        StatusCode::FORBIDDEN,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let app = Router::new().fallback(move || async move {
            let chunk = Bytes::from(vec![b' '; 64 * 1024]);
            let chunks = (0..=MAX_RESPONSE_BYTES / chunk.len() as u64)
                .map(move |_| Ok::<_, Infallible>(chunk.clone()));
            Response::builder()
                .status(status)
                .body(Body::from_stream(stream::iter(chunks)))
                .unwrap()
        });
        let driver = driver(app, 0, 5).await;
        let error = if status == StatusCode::OK {
            driver.list_keys(PREFIX).await.unwrap_err()
        } else {
            driver.get_bytes("object", 100).await.unwrap_err()
        };
        assert!(
            error.to_string().contains("exceeded its safety limit"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn truncated_list_requires_a_fresh_opaque_token() {
    for token in [
        "",
        "<NextContinuationToken></NextContinuationToken>",
        "<NextContinuationToken>+/%2F</NextContinuationToken>",
    ] {
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let app = Router::new().fallback(move |request: Request| {
            let n = count.fetch_add(1, Ordering::SeqCst);
            async move {
                if n > 0 {
                    assert!(
                        request
                            .uri()
                            .query()
                            .unwrap()
                            .contains("continuation-token=%2B%2F%252F")
                    );
                }
                format!(
                    "<ListBucketResult><IsTruncated>true</IsTruncated>{token}</ListBucketResult>"
                )
            }
        });
        let error = driver(app, 0, 5).await.list_keys(PREFIX).await.unwrap_err();
        assert!(error.to_string().contains("continuation token"), "{error}");
        assert_eq!(
            requests.load(Ordering::SeqCst),
            if token.contains('%') { 2 } else { 1 }
        );
    }
}

#[tokio::test]
async fn all_list_pages_share_one_deadline() {
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let app = Router::new().fallback(move || {
        let n = count.fetch_add(1, Ordering::SeqCst);
        async move {
            tokio::time::sleep(Duration::from_millis(600)).await;
            format!("<ListBucketResult><IsTruncated>{}</IsTruncated><NextContinuationToken>next</NextContinuationToken></ListBucketResult>", n == 0)
        }
    });
    let error = driver(app, 0, 1).await.list_keys(PREFIX).await.unwrap_err();
    assert!(
        error.to_string().contains("overall request deadline"),
        "{error}"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 2);
}

fn interrupted(tags: &[&str]) -> Response {
    let chunks =
        stream::once(async { Ok(Bytes::from_static(b"abc")) }).chain(stream::once(async {
            tokio::time::sleep(Duration::from_millis(25)).await;
            Err(std::io::Error::other("injected body interruption"))
        }));
    let mut response = Response::builder().header(header::CONTENT_LENGTH, 8);
    for tag in tags {
        response = response.header(header::ETAG, *tag);
    }
    response.body(Body::from_stream(chunks)).unwrap()
}

#[tokio::test]
async fn chunked_resume_enforces_the_range_length_including_overlap() {
    for (tail, valid) in [("gh", true), ("g", false), ("ghi", false)] {
        let app = Router::new().fallback(move |req: Request| async move {
            if !req.headers().contains_key(header::RANGE) {
                return interrupted(&["\"old\""]);
            }
            let chunks = stream::iter(["bc", "def", tail].map(Ok::<_, Infallible>));
            Response::builder()
                .status(206)
                .header(header::ETAG, "\"old\"")
                .header(header::CONTENT_RANGE, "bytes 1-7/8")
                .body(Body::from_stream(chunks))
                .unwrap()
        });
        let result = driver(app, 1, 5).await.get_bytes("archive", 8).await;
        if valid {
            assert_eq!(result.unwrap(), b"abcdefgh");
        } else {
            assert!(result.is_err());
        }
    }
}

#[tokio::test]
async fn resume_requires_one_strong_quoted_etag() {
    for tags in [
        &["W/\"v1\""][..],
        &["*"],
        &["v1"],
        &["\"a\", \"b\""],
        &["\"a b\""],
        &["\"a\"", "\"b\""],
    ] {
        let requests = Arc::new(AtomicUsize::new(0));
        let seen = requests.clone();
        let app = Router::new().fallback(move || {
            seen.fetch_add(1, Ordering::Relaxed);
            async move { interrupted(tags) }
        });
        assert!(
            driver(app, 1, 5)
                .await
                .get_bytes("archive", 8)
                .await
                .is_err()
        );
        assert_eq!(requests.load(Ordering::Relaxed), 1, "{tags:?}");
    }
    let app = Router::new().fallback(|| async { ([(header::ETAG, "W/\"v1\"")], "intact") });
    assert_eq!(
        driver(app, 1, 5)
            .await
            .get_bytes("archive", 8)
            .await
            .unwrap(),
        b"intact"
    );
}

#[test]
fn signer_trace_contains_only_the_payload_digest() {
    let trace = tempfile::NamedTempFile::new().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(trace.reopen().unwrap())
        .finish();
    let body = Bytes::from_static(b"private backup payload");
    let digest = hex::encode(Sha256::digest(&body));
    let request = http::Request::put("https://bkt.example/archive")
        .body(signing::ReplayBody::new(body))
        .unwrap();
    tracing::subscriber::with_default(subscriber, || {
        signing::sign_request(
            request,
            &client::credentials(&config()).unwrap(),
            "us-east-1",
            UNIX_EPOCH,
        )
        .unwrap()
    });
    let log = std::fs::read_to_string(trace.path()).unwrap();
    assert!(log.contains(&format!("Precomputed(\"{digest}\")")));
    assert!(!log.contains("private backup payload"));
}
