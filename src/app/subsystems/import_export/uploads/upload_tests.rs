use super::*;
use axum::http::HeaderMap;

use super::ingest::{expected_sha256, percent_decode_utf8};

#[test]
fn filename_percent_decoding_is_strict() -> anyhow::Result<()> {
    assert_eq!(
        percent_decode_utf8("dump%20one.postgres.sql")?,
        "dump one.postgres.sql"
    );
    assert!(percent_decode_utf8("dump%2.sql").is_err());
    assert!(percent_decode_utf8("dump%GG.sql").is_err());
    assert!(percent_decode_utf8("%FF.sql").is_err());

    Ok(())
}

#[test]
fn sha256_header_is_lowercase_hex() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut headers = HeaderMap::new();
    headers.insert(SHA256_HEADER, "a".repeat(64).parse()?);
    assert_eq!(
        expected_sha256(&headers)?
            .context("expected sha256 should provide a value")?
            .len(),
        64
    );
    headers.insert(SHA256_HEADER, "A".repeat(64).parse()?);
    assert!(expected_sha256(&headers).is_err());

    Ok(())
}

#[tokio::test]
async fn partial_cleanup_is_durable_missing_safe_and_does_not_follow_links() -> anyhow::Result<()> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let victim = directory.path().join("victim");
    let partial = directory.path().join(".upload.partial");
    std::fs::write(&victim, b"keep")?;
    symlink(&victim, &partial)?;

    worker::remove_worker_file(&partial).await?;
    assert!(!partial.exists());
    assert_eq!(std::fs::read(&victim)?, b"keep");
    worker::remove_worker_file(&partial).await?;

    let missing_parent = directory.path().join("missing").join("partial");
    assert!(worker::remove_worker_file(&missing_parent).await.is_err());

    Ok(())
}
