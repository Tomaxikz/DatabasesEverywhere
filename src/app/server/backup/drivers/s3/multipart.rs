//! Removal of multipart uploads whose publication did not settle.
//!
//! An upload id is journaled as soon as CreateMultipartUpload returns it, but
//! an initiation whose response was lost, or a crash before the journal
//! write, is found only by listing the in-progress uploads of the exact owned
//! key. Every found upload is aborted and its removal confirmed with ListParts
//! (`NoSuchUpload`) and a final relisting. AWS documents that a part upload in
//! flight during an abort can still succeed, so an upload that is listed
//! again is aborted again.

use std::collections::{BTreeSet, HashSet};

use reqwest::{Method, StatusCode};

use super::{
    EMPTY_SHA256, MAX_LIST_BYTES, MAX_LIST_PAGES, S3BackupDriver,
    download::response_bytes_bounded,
    http::{retry_delay, retryable_error, retryable_status, s3_status_error},
    xml::{percent_decode, xml_unescape, xml_value, xml_values},
};
use crate::server::backup::{BackupStoreError, MAX_METADATA_BYTES};

/// Abort and confirm rounds before cleanup is left to a later recovery pass.
const MAX_ABORT_ROUNDS: usize = 3;
const MAX_LISTED_UPLOADS: usize = 10_000;
const NO_SUCH_UPLOAD: &str = "NoSuchUpload";

impl S3BackupDriver {
    /// Aborts every in-progress upload of `key`, journaled or listed, and
    /// succeeds only once none remains.
    pub(super) async fn purge_multipart_uploads(
        &self,
        key: &str,
        journaled: &[&str],
    ) -> Result<(), BackupStoreError> {
        let mut known: BTreeSet<String> = journaled.iter().map(|id| (*id).to_string()).collect();
        for _ in 0..MAX_ABORT_ROUNDS {
            known.extend(self.list_multipart_uploads(key).await?);
            if known.is_empty() {
                return Ok(());
            }
            let mut remaining = BTreeSet::new();
            for upload_id in known {
                self.abort_upload(key, &upload_id).await?;
                if !self.upload_gone(key, &upload_id).await? {
                    remaining.insert(upload_id);
                }
            }
            known = remaining;
        }
        Err(BackupStoreError::Remote(format!(
            "S3 multipart uploads of {key} remain after {MAX_ABORT_ROUNDS} abort rounds"
        )))
    }

    /// Upload ids of in-progress multipart uploads of exactly `key`.
    async fn list_multipart_uploads(&self, key: &str) -> Result<Vec<String>, BackupStoreError> {
        let mut upload_ids = Vec::new();
        let mut marker: Option<(String, String)> = None;
        let mut seen_markers = HashSet::new();
        for _ in 0..MAX_LIST_PAGES {
            let query = list_uploads_query(key, marker.as_ref());
            let response = self
                .request_with_retry(Method::GET, "", &query, "list multipart uploads")
                .await?;
            if !response.status().is_success() {
                return Err(s3_status_error("list multipart uploads", &response));
            }
            let body =
                response_bytes_bounded(response, MAX_LIST_BYTES, "list multipart uploads").await?;
            let xml = std::str::from_utf8(&body).map_err(|_| {
                BackupStoreError::Corrupt("S3 multipart upload list was not UTF-8 XML".to_string())
            })?;
            let page = parse_upload_page(xml, key)?;
            upload_ids.extend(page.upload_ids);
            if upload_ids.len() > MAX_LISTED_UPLOADS {
                return Err(BackupStoreError::Remote(format!(
                    "S3 lists more than {MAX_LISTED_UPLOADS} multipart uploads of {key}"
                )));
            }
            let Some(next) = page.next else {
                return Ok(upload_ids);
            };
            if !seen_markers.insert(next.clone()) {
                return Err(BackupStoreError::Corrupt(
                    "S3 multipart upload list repeated its continuation markers".to_string(),
                ));
            }
            marker = Some(next);
        }
        Err(BackupStoreError::Remote(format!(
            "S3 multipart upload list exceeded its {MAX_LIST_PAGES}-page safety limit"
        )))
    }

    /// Aborts one upload. One that no longer exists is already aborted.
    async fn abort_upload(&self, key: &str, upload_id: &str) -> Result<(), BackupStoreError> {
        let query = vec![("uploadId".to_string(), upload_id.to_string())];
        let response = self
            .request_with_retry(Method::DELETE, key, &query, "abort multipart upload")
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        let error = s3_status_error("abort multipart upload", &response);
        if is_no_such_upload(response).await? {
            Ok(())
        } else {
            Err(error)
        }
    }

    /// ListParts reports `NoSuchUpload` once an upload and its parts are gone.
    async fn upload_gone(&self, key: &str, upload_id: &str) -> Result<bool, BackupStoreError> {
        let query = vec![
            ("max-parts".to_string(), "1".to_string()),
            ("uploadId".to_string(), upload_id.to_string()),
        ];
        let response = self
            .request_with_retry(Method::GET, key, &query, "list multipart parts")
            .await?;
        if response.status().is_success() {
            return Ok(false);
        }
        let error = s3_status_error("list multipart parts", &response);
        if is_no_such_upload(response).await? {
            Ok(true)
        } else {
            Err(error)
        }
    }

    async fn request_with_retry(
        &self,
        method: Method,
        key: &str,
        query: &[(String, String)],
        operation: &str,
    ) -> Result<reqwest::Response, BackupStoreError> {
        for attempt in 0..=self.config.max_retries {
            match self
                .signed_request(method.clone(), key, query, EMPTY_SHA256)?
                .send()
                .await
            {
                Ok(response)
                    if retryable_status(response.status()) && attempt < self.config.max_retries =>
                {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Ok(response),
                Err(error) if attempt < self.config.max_retries && retryable_error(&error) => {
                    retry_delay(attempt).await;
                }
                Err(error) => {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 {operation} request failed: {error}"
                    )));
                }
            }
        }
        Err(BackupStoreError::Remote(format!(
            "S3 {operation} exhausted its retry budget"
        )))
    }
}

/// A 404 means the upload is gone only when S3 names it `NoSuchUpload`; a
/// missing bucket must not pass for a confirmed abort.
async fn is_no_such_upload(response: reqwest::Response) -> Result<bool, BackupStoreError> {
    if response.status() != StatusCode::NOT_FOUND {
        return Ok(false);
    }
    let body = response_bytes_bounded(response, MAX_METADATA_BYTES, "multipart error").await?;
    Ok(std::str::from_utf8(&body)
        .ok()
        .and_then(|xml| xml_value(xml, "Code"))
        .is_some_and(|code| code == NO_SUCH_UPLOAD))
}

fn list_uploads_query(key: &str, marker: Option<&(String, String)>) -> Vec<(String, String)> {
    let mut query = vec![
        ("encoding-type".to_string(), "url".to_string()),
        ("prefix".to_string(), key.to_string()),
        ("uploads".to_string(), String::new()),
    ];
    if let Some((key_marker, upload_id_marker)) = marker {
        query.push(("key-marker".to_string(), key_marker.clone()));
        query.push(("upload-id-marker".to_string(), upload_id_marker.clone()));
    }
    query
}

#[derive(Debug, PartialEq, Eq)]
struct UploadPage {
    /// Uploads of exactly the requested key; the prefix also matches longer keys.
    upload_ids: Vec<String>,
    /// `(key-marker, upload-id-marker)` of the next page.
    next: Option<(String, String)>,
}

/// Parses one ListMultipartUploads page requested with `encoding-type=url`,
/// under which `Key` and `NextKeyMarker` are percent-encoded.
fn parse_upload_page(xml: &str, key: &str) -> Result<UploadPage, BackupStoreError> {
    let mut upload_ids = Vec::new();
    for upload in xml_values(xml, "Upload") {
        let listed_key = xml_value(&upload, "Key")
            .ok_or_else(|| corrupt_listing("an upload without a key"))
            .and_then(|value| percent_decode(&xml_unescape(&value)))?;
        if !listed_key.starts_with(key) {
            return Err(corrupt_listing("an upload outside the requested key"));
        }
        if listed_key != key {
            continue;
        }
        let upload_id = xml_value(&upload, "UploadId")
            .map(|value| xml_unescape(&value))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| corrupt_listing("an upload without an id"))?;
        upload_ids.push(upload_id);
    }
    let truncated = xml_value(xml, "IsTruncated").is_some_and(|value| value == "true");
    let next = if truncated {
        let key_marker = xml_value(xml, "NextKeyMarker")
            .map(|value| percent_decode(&xml_unescape(&value)))
            .transpose()?
            .filter(|value| !value.is_empty())
            .ok_or_else(|| corrupt_listing("a truncated page without NextKeyMarker"))?;
        let upload_id_marker = xml_value(xml, "NextUploadIdMarker")
            .map(|value| xml_unescape(&value))
            .unwrap_or_default();
        Some((key_marker, upload_id_marker))
    } else {
        None
    };
    Ok(UploadPage { upload_ids, next })
}

fn corrupt_listing(what: &str) -> BackupStoreError {
    BackupStoreError::Corrupt(format!("S3 multipart upload list returned {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "dbev/instances/inst_one/backups/a b.physical.tar.gz";

    #[test]
    fn upload_pages_keep_only_the_exact_owned_key() {
        // Shape of AWS's documented response, with `encoding-type=url`.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>bucket</Bucket>
  <KeyMarker></KeyMarker>
  <UploadIdMarker></UploadIdMarker>
  <NextKeyMarker>dbev/instances/inst_one/backups/a%20b.physical.tar.gz.catalog.json</NextKeyMarker>
  <NextUploadIdMarker>WVc1NUlHbGtaV0U</NextUploadIdMarker>
  <Prefix>dbev/instances/inst_one/backups/a%20b.physical.tar.gz</Prefix>
  <MaxUploads>1000</MaxUploads>
  <IsTruncated>true</IsTruncated>
  <Upload>
    <Key>dbev/instances/inst_one/backups/a%20b.physical.tar.gz</Key>
    <UploadId>VXBsb2FkIElE&amp;1</UploadId>
    <Initiator><ID>arn:aws:iam::111122223333:user/dbev</ID></Initiator>
    <Owner><ID>75aa57f09aa0c8caeab4f8c24e99d10f</ID></Owner>
    <StorageClass>STANDARD</StorageClass>
    <Initiated>2026-10-11T10:00:00.000Z</Initiated>
  </Upload>
  <Upload>
    <Key>dbev/instances/inst_one/backups/a%20b.physical.tar.gz.catalog.json</Key>
    <UploadId>T3RoZXI</UploadId>
    <StorageClass>STANDARD</StorageClass>
    <Initiated>2026-10-11T10:00:01.000Z</Initiated>
  </Upload>
  <EncodingType>url</EncodingType>
</ListMultipartUploadsResult>"#;
        let page = parse_upload_page(xml, KEY).unwrap();
        assert_eq!(page.upload_ids, vec!["VXBsb2FkIElE&1".to_string()]);
        assert_eq!(
            page.next,
            Some((
                "dbev/instances/inst_one/backups/a b.physical.tar.gz.catalog.json".to_string(),
                "WVc1NUlHbGtaV0U".to_string()
            ))
        );

        let last = "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>";
        assert_eq!(
            parse_upload_page(last, KEY).unwrap(),
            UploadPage {
                upload_ids: Vec::new(),
                next: None
            }
        );
    }

    #[test]
    fn upload_pages_reject_foreign_keys_and_missing_markers() {
        let foreign = "<ListMultipartUploadsResult><Upload><Key>other/key</Key><UploadId>x</UploadId></Upload></ListMultipartUploadsResult>";
        assert!(parse_upload_page(foreign, KEY).is_err());
        let no_marker = "<ListMultipartUploadsResult><IsTruncated>true</IsTruncated></ListMultipartUploadsResult>";
        assert!(parse_upload_page(no_marker, KEY).is_err());
        let no_id = format!(
            "<ListMultipartUploadsResult><Upload><Key>{}</Key></Upload></ListMultipartUploadsResult>",
            KEY.replace(' ', "%20")
        );
        assert!(parse_upload_page(&no_id, KEY).is_err());
    }

    #[test]
    fn upload_list_requests_are_scoped_to_the_key() {
        let first = list_uploads_query(KEY, None);
        assert!(first.contains(&("prefix".to_string(), KEY.to_string())));
        assert!(first.contains(&("uploads".to_string(), String::new())));
        assert!(first.contains(&("encoding-type".to_string(), "url".to_string())));
        let next = list_uploads_query(KEY, Some(&("k".to_string(), "u".to_string())));
        assert!(next.contains(&("key-marker".to_string(), "k".to_string())));
        assert!(next.contains(&("upload-id-marker".to_string(), "u".to_string())));
    }
}
