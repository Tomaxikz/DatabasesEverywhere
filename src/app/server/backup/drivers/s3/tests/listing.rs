use http::Method;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[tokio::test]
async fn purge_rejects_invalid_or_foreign_upload_pages_before_aborting() {
    for page in [
        "<Error><Code>NoSuchBucket</Code><IsTruncated>false</IsTruncated></Error>".to_owned(),
        "<ListMultipartUploadsResult/>".into(),
        format!(
            "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated><Upload><Key>{PREFIX}ours</Key><UploadId>1</UploadId></Upload><Upload><Key>dbev/instances/inst_one_b/backups/foreign</Key><UploadId>2</UploadId></Upload></ListMultipartUploadsResult>"
        ),
    ] {
        let app = Router::new().fallback(move |req: Request| {
            let page = page.clone();
            async move {
                assert_eq!(req.method(), Method::GET);
                // Objects are still listed afterwards; nothing may be aborted or deleted.
                let query = req.uri().query().unwrap();
                assert!(query.contains("uploads=") || query.contains("list-type=2"));
                page
            }
        });
        let err = wire::driver(app, 0, 5)
            .await
            .delete_instance("inst_one")
            .await
            .unwrap_err();
        assert!(matches!(err, BackupStoreError::Corrupt(_)), "{err}");
    }
}

#[tokio::test]
async fn object_listing_counts_utf8_bytes() {
    for size in [1024, 1025] {
        let suffix = "é".repeat((size - PREFIX.len()) / 2);
        let key = format!("{PREFIX}{suffix}{}", "x".repeat((size - PREFIX.len()) % 2));
        let page = list_page(&key);
        let app = Router::new().fallback(move || {
            let page = page.clone();
            async move { page }
        });
        let result = wire::driver(app, 0, 5).await.list_keys(PREFIX).await;
        if size == 1024 {
            assert_eq!(result.unwrap(), [key]);
        } else {
            assert!(result.unwrap_err().to_string().contains("1024 bytes"));
        }
    }
}

#[tokio::test]
async fn empty_object_pages_with_distinct_tokens_hit_the_page_limit() {
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    let app = Router::new().fallback(move || {
        let n = count.fetch_add(1, Ordering::Relaxed);
        async move {
            if n == MAX_LIST_PAGES {
                return "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>".into();
            }
            format!("<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>{n}</NextContinuationToken></ListBucketResult>")
        }
    });
    let err = wire::driver(app, 0, 60)
        .await
        .list_keys(PREFIX)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("page safety limit"), "{err}");
    assert_eq!(seen.load(Ordering::Relaxed), MAX_LIST_PAGES);
}

#[tokio::test]
async fn multipart_byte_limit_accumulates_ids_and_markers_across_pages() {
    // IDs plus keys fit exactly. Retaining the first continuation markers exceeds the budget.
    let key = format!("{PREFIX}archive");
    let id = "x".repeat(MAX_RESPONSE_BYTES as usize / 2 - key.len());
    let app = Router::new().fallback(move |req: Request| {
        let first = !req.uri().query().unwrap().contains("key-marker=");
        let marker = if first { "<NextKeyMarker>next</NextKeyMarker><NextUploadIdMarker>id</NextUploadIdMarker>" } else { "" };
        let page = format!("<ListMultipartUploadsResult><IsTruncated>{first}</IsTruncated>{marker}<Upload><Key>{key}</Key><UploadId>{id}</UploadId></Upload></ListMultipartUploadsResult>");
        async move { page }
    });
    let error = wire::driver(app, 0, 10)
        .await
        .delete_instance("inst_one")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("byte limit"), "{error}");
}

#[tokio::test]
async fn final_object_page_must_not_advertise_a_continuation() {
    let mock = mock_s3(|_, _| (StatusCode::OK, b"<ListBucketResult><IsTruncated>false</IsTruncated><NextContinuationToken>more</NextContinuationToken></ListBucketResult>".to_vec())).await;
    assert!(mock_driver(&mock, 0).inventory("inst_one").await.is_err());
}

#[tokio::test]
async fn interleaved_contents_are_all_listed() {
    let mock = mock_s3(|_, _| (StatusCode::OK, format!("<ListBucketResult><Contents><Key>{PREFIX}a</Key></Contents><IsTruncated>false</IsTruncated><Contents><Key>{PREFIX}b</Key></Contents></ListBucketResult>").into_bytes())).await;
    assert_eq!(
        mock_driver(&mock, 0).list_keys(PREFIX).await.unwrap(),
        [format!("{PREFIX}a"), format!("{PREFIX}b")]
    );
}

#[tokio::test]
async fn diagnostics_omit_reflected_codes_element_names_and_invalid_keys() {
    const SECRET: &str = "reflected-session-token";
    let app = Router::new().fallback(|req: Request| async move {
        let uri = req.uri().to_string();
        let (status, body) = if uri.contains("list-type=") && uri.contains("invalid-key") {
            (
                StatusCode::OK,
                list_page(&format!("invalid-key/{SECRET}/../x")),
            )
        } else if uri.contains("list-type=") || uri.contains("uploads=") {
            (StatusCode::OK, format!("<{SECRET}/>").into_bytes())
        } else {
            let status = if req.method() == Method::POST {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            };
            (
                status,
                format!("<Error><Code>{SECRET}</Code></Error>").into_bytes(),
            )
        };
        (status, body)
    });
    let driver = wire::driver(app, 0, 5).await;
    for error in [
        driver.get_bytes("key", 1).await.unwrap_err(),
        driver
            .client
            .complete_multipart("key", "id", vec![])
            .await
            .unwrap_err(),
    ] {
        assert!(error.to_string().contains("returned HTTP"), "{error}");
        assert!(!error.to_string().contains(SECRET), "{error}");
    }
    for error in [
        driver.list_keys("invalid-key/").await.unwrap_err(),
        driver.list_keys(PREFIX).await.unwrap_err(),
        driver.client.create_multipart("key").await.unwrap_err(),
        driver.delete_instance("inst_one").await.unwrap_err(),
    ] {
        assert!(!error.to_string().contains(SECRET), "{error}");
    }
}

#[tokio::test]
async fn refused_upload_listing_still_removes_the_instance_objects_and_is_reported() {
    let mock = mock_s3(|method, uri| match (method, uri) {
        ("GET", uri) if uri.contains("uploads=") => (StatusCode::FORBIDDEN, Vec::new()),
        ("GET", _) => (
            StatusCode::OK,
            format!(
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>{PREFIX}b1.metadata.json</Key></Contents></ListBucketResult>"
            )
            .into_bytes(),
        ),
        _ => (StatusCode::NO_CONTENT, Vec::new()),
    })
    .await;
    let error = mock_driver(&mock, 0)
        .delete_instance("inst_one")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("HTTP 403"), "{error}");
    let requests = mock.requests.lock().unwrap();
    let deleted: Vec<_> = requests.iter().filter(|r| r.0 == "DELETE").collect();
    assert_eq!(deleted.len(), 1);
    assert!(deleted[0].1.ends_with("b1.metadata.json"));
}
