use super::*;

#[test]
fn filename_percent_decoding_is_strict() {
    assert_eq!(
        percent_decode_utf8("dump%20one.postgres.sql").unwrap(),
        "dump one.postgres.sql"
    );
    assert!(percent_decode_utf8("dump%2.sql").is_err());
    assert!(percent_decode_utf8("dump%GG.sql").is_err());
    assert!(percent_decode_utf8("%FF.sql").is_err());
}

#[test]
fn sha256_header_is_lowercase_hex() {
    let mut headers = HeaderMap::new();
    headers.insert(SHA256_HEADER, "a".repeat(64).parse().unwrap());
    assert_eq!(expected_sha256(&headers).unwrap().unwrap().len(), 64);
    headers.insert(SHA256_HEADER, "A".repeat(64).parse().unwrap());
    assert!(expected_sha256(&headers).is_err());
}

#[tokio::test]
async fn partial_cleanup_is_durable_missing_safe_and_does_not_follow_links() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let victim = directory.path().join("victim");
    let partial = directory.path().join(".upload.partial");
    std::fs::write(&victim, b"keep").unwrap();
    symlink(&victim, &partial).unwrap();

    worker::remove_worker_file(&partial).await.unwrap();
    assert!(!partial.exists());
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    worker::remove_worker_file(&partial).await.unwrap();

    let missing_parent = directory.path().join("missing").join("partial");
    assert!(worker::remove_worker_file(&missing_parent).await.is_err());
}
