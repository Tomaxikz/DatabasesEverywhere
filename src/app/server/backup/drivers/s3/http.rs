use std::time::Duration;

use reqwest::StatusCode;

use super::{MAX_RETRY_BACKOFF_EXPONENT, RETRY_BASE_DELAY_MILLIS};
use crate::server::backup::BackupStoreError;

pub(super) fn s3_status_error(operation: &str, response: &reqwest::Response) -> BackupStoreError {
    let request_id = response
        .headers()
        .get("x-amz-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unavailable");
    BackupStoreError::Remote(format!(
        "S3 {operation} returned HTTP {} (request id {request_id})",
        response.status()
    ))
}

pub(super) fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

pub(super) fn retryable_error(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout() || error.is_body()
}

pub(super) async fn retry_delay(attempt: usize) {
    let factor = 1_u64 << attempt.min(MAX_RETRY_BACKOFF_EXPONENT);
    tokio::time::sleep(Duration::from_millis(RETRY_BASE_DELAY_MILLIS * factor)).await;
}
