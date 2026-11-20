use std::{collections::HashSet, time::Duration};

use bytes::Bytes;
use http::Method;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{MAX_LIST_PAGES, MAX_LISTED_OBJECT_KEYS, S3BackupDriver, objects::object_path};
use crate::server::backup::BackupStoreError;

#[derive(Deserialize)]
enum ListResponse {
    ListBucketResult(Page),
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Page {
    is_truncated: bool,
    next_continuation_token: Option<String>,
    #[serde(default)]
    contents: Vec<Object>,
}

#[derive(Deserialize)]
struct Object {
    #[serde(rename = "Key")]
    key: String,
}

impl S3BackupDriver {
    pub(super) async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, BackupStoreError> {
        object_path(prefix)?;
        tokio::time::timeout(
            Duration::from_secs(self.config.request_timeout_seconds),
            self.list_pages(prefix),
        )
        .await
        .map_err(|_| {
            BackupStoreError::Remote("S3 list objects exceeded its overall request deadline".into())
        })?
    }

    async fn list_pages(&self, prefix: &str) -> Result<Vec<String>, BackupStoreError> {
        let mut keys = Vec::new();
        let mut seen = HashSet::new();
        let mut token = None;
        for _ in 0..MAX_LIST_PAGES {
            let mut query = vec![("list-type", "2"), ("prefix", prefix)];
            if let Some(token) = token.as_deref() {
                query.push(("continuation-token", token));
            }
            let response = self
                .client
                .send(Method::GET, "", &query, Bytes::new(), "list objects")
                .await?
                .success("list objects")?;
            let ListResponse::ListBucketResult(page) =
                quick_xml::de::from_reader(response.body.as_slice()).map_err(|_| {
                    BackupStoreError::Corrupt("invalid S3 list objects response".into())
                })?;
            for object in page.contents {
                if !object.key.starts_with(prefix) {
                    return Err(BackupStoreError::Corrupt(
                        "S3 list response returned an object outside the requested backup prefix"
                            .into(),
                    ));
                }
                object_path(&object.key)?;
                keys.push(object.key);
                if keys.len() > MAX_LISTED_OBJECT_KEYS {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 backup prefix contains more than {MAX_LISTED_OBJECT_KEYS} objects"
                    )));
                }
            }
            let next = page
                .next_continuation_token
                .filter(|token| !token.is_empty());
            if !page.is_truncated {
                if next.is_some() {
                    return Err(BackupStoreError::Corrupt(
                        "S3 final listing page supplied a continuation token".into(),
                    ));
                }
                return Ok(keys);
            }
            let next = next.ok_or_else(|| {
                BackupStoreError::Corrupt("S3 truncated listing missing continuation token".into())
            })?;
            // Keep fixed-size fingerprints even if a server sends large opaque tokens.
            if !seen.insert(Sha256::digest(next.as_bytes())) {
                return Err(BackupStoreError::Corrupt(
                    "S3 listing repeated a continuation token".into(),
                ));
            }
            token = Some(next);
        }
        Err(BackupStoreError::Remote(format!(
            "S3 object list exceeded its {MAX_LIST_PAGES}-page safety limit"
        )))
    }
}
