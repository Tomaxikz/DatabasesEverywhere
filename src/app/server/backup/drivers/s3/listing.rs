use std::{collections::HashSet, time::Duration};

use reqwest::{Method, StatusCode};

use super::{
    EMPTY_SHA256, LIST_PAGE_MAX_KEYS, MAX_LIST_BYTES, MAX_LIST_PAGES, MAX_LISTED_OBJECT_KEYS,
    S3BackupDriver,
    download::response_bytes_bounded,
    http::{retry_delay, retryable_error, retryable_status, s3_status_error},
    xml::{percent_decode, xml_unescape, xml_value, xml_values},
};
use crate::server::backup::BackupStoreError;

impl S3BackupDriver {
    pub(super) async fn delete_object(
        &self,
        key: &str,
        missing_ok: bool,
    ) -> Result<(), BackupStoreError> {
        for attempt in 0..=self.config.max_retries {
            let response = self
                .signed_request(Method::DELETE, key, &[], EMPTY_SHA256)?
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) if response.status() == StatusCode::NOT_FOUND && missing_ok => {
                    return Ok(());
                }
                Ok(response)
                    if retryable_status(response.status()) && attempt < self.config.max_retries =>
                {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(s3_status_error("delete object", &response)),
                Err(error) if attempt < self.config.max_retries && retryable_error(&error) => {
                    retry_delay(attempt).await;
                }
                Err(error) => {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 delete request failed: {error}"
                    )));
                }
            }
        }
        Err(BackupStoreError::Remote(
            "S3 delete exhausted its retry budget".to_string(),
        ))
    }

    pub(super) async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, BackupStoreError> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        let mut seen_continuations = HashSet::new();
        let mut pages = 0_usize;
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.config.request_timeout_seconds);
        let deadline_exceeded = |_| {
            BackupStoreError::Remote(
                "S3 list objects exceeded its overall request deadline".to_string(),
            )
        };
        loop {
            pages += 1;
            if pages > MAX_LIST_PAGES {
                return Err(BackupStoreError::Remote(format!(
                    "S3 list objects exceeded its {MAX_LIST_PAGES}-page safety limit"
                )));
            }
            let query = list_objects_query(prefix, continuation.as_deref());
            let response = tokio::time::timeout_at(deadline, self.list_with_retry(&query))
                .await
                .map_err(deadline_exceeded)??;
            let body = tokio::time::timeout_at(
                deadline,
                response_bytes_bounded(response, MAX_LIST_BYTES, "list objects"),
            )
            .await
            .map_err(deadline_exceeded)??;
            let xml = std::str::from_utf8(&body).map_err(|_| {
                BackupStoreError::Corrupt("S3 list response was not UTF-8 XML".to_string())
            })?;
            let keys_before_page = keys.len();
            for value in xml_values(xml, "Key") {
                keys.push(decode_listed_key(&value, prefix)?);
                if keys.len() > MAX_LISTED_OBJECT_KEYS {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 backup prefix contains more than {MAX_LISTED_OBJECT_KEYS} objects"
                    )));
                }
            }
            let truncated = xml_value(xml, "IsTruncated").is_some_and(|value| value == "true");
            if !truncated {
                break;
            }
            if keys.len() == keys_before_page {
                return Err(BackupStoreError::Corrupt(
                    "S3 list response made no progress on a truncated page".to_string(),
                ));
            }
            let Some(next_continuation) = xml_value(xml, "NextContinuationToken")
                .map(|value| xml_unescape(&value))
                .filter(|token| !token.is_empty())
            else {
                return Err(BackupStoreError::Corrupt(
                    "S3 list response omitted its continuation token".to_string(),
                ));
            };
            if !seen_continuations.insert(next_continuation.clone()) {
                return Err(BackupStoreError::Corrupt(
                    "S3 list response repeated its continuation token".to_string(),
                ));
            }
            continuation = Some(next_continuation);
        }
        Ok(keys)
    }

    async fn list_with_retry(
        &self,
        query: &[(String, String)],
    ) -> Result<reqwest::Response, BackupStoreError> {
        for attempt in 0..=self.config.max_retries {
            match self
                .signed_request(Method::GET, "", query, EMPTY_SHA256)?
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response)
                    if retryable_status(response.status()) && attempt < self.config.max_retries =>
                {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(s3_status_error("list objects", &response)),
                Err(error) if attempt < self.config.max_retries && retryable_error(&error) => {
                    retry_delay(attempt).await;
                }
                Err(error) => {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 list request failed: {error}"
                    )));
                }
            }
        }
        Err(BackupStoreError::Remote(
            "S3 list request exhausted its retry budget".to_string(),
        ))
    }
}

fn list_objects_query(prefix: &str, continuation: Option<&str>) -> Vec<(String, String)> {
    let mut query = vec![
        ("encoding-type".to_string(), "url".to_string()),
        ("list-type".to_string(), "2".to_string()),
        ("max-keys".to_string(), LIST_PAGE_MAX_KEYS.to_string()),
        ("prefix".to_string(), prefix.to_string()),
    ];
    if let Some(token) = continuation {
        query.push(("continuation-token".to_string(), token.to_string()));
    }
    query
}

pub(super) fn decode_listed_key(
    encoded_key: &str,
    requested_prefix: &str,
) -> Result<String, BackupStoreError> {
    let key = percent_decode(&xml_unescape(encoded_key))?;
    if !key.starts_with(requested_prefix) {
        return Err(BackupStoreError::Corrupt(
            "S3 list response returned an object outside the requested backup prefix".to_string(),
        ));
    }
    Ok(key)
}
