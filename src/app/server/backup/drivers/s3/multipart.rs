//! Multipart uploads, and removal of those whose publication did not settle.
//!
//! An upload id is journaled as soon as CreateMultipartUpload returns it, but
//! an initiation whose response was lost, or a crash before the journal
//! write, is found only by listing the in-progress uploads of the exact owned
//! key. Every found upload is aborted and its removal confirmed with ListParts
//! (`NoSuchUpload`) and a final relisting. AWS documents that a part upload in
//! flight during an abort can still succeed, so an upload that is listed
//! again is aborted again. `object_store` has no API for either listing, so
//! those two requests are signed with its [`AwsAuthorizer`] here.
//!
//! [`AwsAuthorizer`]: object_store::aws::AwsAuthorizer

use std::{
    collections::{BTreeSet, HashSet},
    path::Path,
};

use bytes::Bytes;
use object_store::{PutPayload, path::Path as ObjectPath};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use super::{
    DEFAULT_MULTIPART_PART_BYTES, MAX_LIST_PAGES, MAX_MULTIPART_PARTS, MAX_S3_OBJECT_BYTES,
    S3BackupDriver,
    client::{UploadAdmin, remote_error},
    objects::{object_path, verify_sha256},
};
use crate::server::backup::{
    BackupStoreError,
    drivers::{PublicationJournal, PublicationResource},
    io_error,
};

/// Abort and confirm rounds before cleanup is left to a later recovery pass.
const MAX_ABORT_ROUNDS: usize = 3;
const MAX_LISTED_UPLOADS: usize = 10_000;
const NO_SUCH_UPLOAD: &str = "NoSuchUpload";

impl S3BackupDriver {
    pub(super) async fn multipart_upload(
        &self,
        key: &str,
        path: &Path,
        size: u64,
        sha256: &str,
        journal: &dyn PublicationJournal,
    ) -> Result<(), BackupStoreError> {
        if size > MAX_S3_OBJECT_BYTES {
            return Err(BackupStoreError::InvalidConfiguration(
                "S3 backup exceeds the 5 TiB object limit".to_string(),
            ));
        }
        let location = object_path(key)?;
        let upload_id = self
            .multipart
            .create_multipart(&location)
            .await
            .map_err(|error| remote_error("initiate multipart upload", error))?;
        // Parts are billable until aborted. Journal the id before any part
        // exists so recovery can abort it after a crash; an initiation whose
        // id never reached the journal is found by listing the key.
        let resource = PublicationResource::S3MultipartUpload {
            key: key.to_string(),
            upload_id: upload_id.clone(),
        };
        if let Err(error) = journal.record(&resource).await {
            self.abort_after_failure(&location, &upload_id).await;
            return Err(error);
        }
        let result = match self
            .upload_parts(&location, &upload_id, path, size, sha256)
            .await
        {
            Ok(parts) => self
                .multipart
                .complete_multipart(&location, &upload_id, parts)
                .await
                .map(drop)
                .map_err(|error| remote_error("complete multipart upload", error)),
            Err(error) => Err(error),
        };
        if result.is_err() {
            self.abort_after_failure(&location, &upload_id).await;
            if let Err(error) = self.delete_object(key, true).await {
                tracing::warn!(object_key = key, %error, "failed to clean up S3 multipart object");
            }
        }
        result
    }

    /// Uploads the file part by part, hashing it on the way, and refuses to
    /// hand back the parts unless the bytes match the recorded SHA-256.
    async fn upload_parts(
        &self,
        location: &ObjectPath,
        upload_id: &str,
        path: &Path,
        size: u64,
        sha256: &str,
    ) -> Result<Vec<object_store::multipart::PartId>, BackupStoreError> {
        let part_size = multipart_part_size(size);
        let part_count = size.div_ceil(part_size);
        if part_count == 0 || part_count > MAX_MULTIPART_PARTS {
            return Err(BackupStoreError::InvalidConfiguration(format!(
                "S3 backup requires an unsupported {part_count}-part upload"
            )));
        }
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|source| io_error("open S3 multipart upload source", source))?;
        let mut digest = Sha256::new();
        let mut parts = Vec::new();
        let mut remaining = size;
        for part_index in 0..part_count {
            let length = usize::try_from(remaining.min(part_size)).map_err(|_| {
                BackupStoreError::Runtime("S3 multipart chunk exceeded usize".to_string())
            })?;
            let mut bytes = vec![0_u8; length];
            file.read_exact(&mut bytes)
                .await
                .map_err(|source| io_error("read S3 multipart upload source", source))?;
            digest.update(&bytes);
            let part_index = usize::try_from(part_index).map_err(|_| {
                BackupStoreError::Runtime("S3 multipart part number overflowed".to_string())
            })?;
            let part = self
                .multipart
                .put_part(
                    location,
                    &upload_id.to_string(),
                    part_index,
                    PutPayload::from(Bytes::from(bytes)),
                )
                .await
                .map_err(|error| {
                    remote_error(&format!("upload multipart part {}", part_index + 1), error)
                })?;
            parts.push(part);
            remaining -= length as u64;
        }
        let mut probe = [0_u8; 1];
        let trailing = file
            .read(&mut probe)
            .await
            .map_err(|source| io_error("read S3 multipart upload source", source))?;
        if remaining != 0 || trailing != 0 {
            return Err(BackupStoreError::Corrupt(
                "S3 upload source changed before upload".to_string(),
            ));
        }
        verify_sha256(digest.finalize().as_slice(), sha256)?;
        Ok(parts)
    }

    async fn abort_after_failure(&self, location: &ObjectPath, upload_id: &str) {
        if let Err(error) = self
            .multipart
            .abort_multipart(location, &upload_id.to_string())
            .await
        {
            tracing::warn!(object_key = %location, %error, "failed to abort incomplete S3 upload");
        }
    }

    /// Aborts every in-progress upload of `key`, journaled or listed, and
    /// succeeds only once none remains.
    pub(super) async fn purge_multipart_uploads(
        &self,
        key: &str,
        journaled: &[&str],
    ) -> Result<(), BackupStoreError> {
        let location = object_path(key)?;
        let mut known: BTreeSet<String> = journaled.iter().map(|id| (*id).to_string()).collect();
        let Some(uploads) = self.uploads.as_deref() else {
            // A store without the S3 API offers neither listing; abort what
            // the journal names.
            for upload_id in known {
                self.abort_upload(&location, &upload_id).await?;
            }
            return Ok(());
        };
        for _ in 0..MAX_ABORT_ROUNDS {
            known.extend(uploads.list_multipart_uploads(key).await?);
            if known.is_empty() {
                return Ok(());
            }
            let mut remaining = BTreeSet::new();
            for upload_id in known {
                self.abort_upload(&location, &upload_id).await?;
                if !uploads.upload_gone(key, &upload_id).await? {
                    remaining.insert(upload_id);
                }
            }
            known = remaining;
        }
        Err(BackupStoreError::Remote(format!(
            "S3 multipart uploads of {key} remain after {MAX_ABORT_ROUNDS} abort rounds"
        )))
    }

    /// Aborts one upload. A 404 may mean it is already gone; ListParts then
    /// tells `NoSuchUpload` apart from a missing bucket.
    async fn abort_upload(
        &self,
        location: &ObjectPath,
        upload_id: &str,
    ) -> Result<(), BackupStoreError> {
        match self
            .multipart
            .abort_multipart(location, &upload_id.to_string())
            .await
        {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(remote_error("abort multipart upload", error)),
        }
    }
}

impl UploadAdmin {
    /// Upload ids of in-progress multipart uploads of exactly `key`.
    async fn list_multipart_uploads(&self, key: &str) -> Result<Vec<String>, BackupStoreError> {
        let mut upload_ids = Vec::new();
        let mut marker: Option<(String, String)> = None;
        let mut seen_markers = HashSet::new();
        for _ in 0..MAX_LIST_PAGES {
            let mut query = vec![("encoding-type", "url"), ("prefix", key), ("uploads", "")];
            if let Some((key_marker, upload_id_marker)) = &marker {
                query.push(("key-marker", key_marker));
                query.push(("upload-id-marker", upload_id_marker));
            }
            let (status, body) = self
                .send(Method::GET, "", &query, "list multipart uploads")
                .await?;
            if !status.is_success() {
                return Err(status_error("list multipart uploads", status, &body));
            }
            let page = parse_upload_page(&body, key)?;
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

    /// ListParts reports `NoSuchUpload` once an upload and its parts are gone.
    pub(super) async fn upload_gone(
        &self,
        key: &str,
        upload_id: &str,
    ) -> Result<bool, BackupStoreError> {
        let query = [("max-parts", "1"), ("uploadId", upload_id)];
        let (status, body) = self
            .send(Method::GET, key, &query, "list multipart parts")
            .await?;
        if status.is_success() {
            return Ok(false);
        }
        // A 404 means the upload is gone only when S3 names it
        // `NoSuchUpload`; a missing bucket must not pass for a confirmed abort.
        if status == StatusCode::NOT_FOUND && error_code(&body).as_deref() == Some(NO_SUCH_UPLOAD) {
            return Ok(true);
        }
        Err(status_error("list multipart parts", status, &body))
    }
}

fn status_error(operation: &str, status: StatusCode, body: &[u8]) -> BackupStoreError {
    let code = error_code(body).unwrap_or_else(|| "unknown".to_string());
    BackupStoreError::Remote(format!("S3 {operation} returned HTTP {status} ({code})"))
}

#[derive(Deserialize)]
struct ErrorDocument {
    #[serde(rename = "Code")]
    code: String,
}

fn error_code(body: &[u8]) -> Option<String> {
    quick_xml::de::from_reader::<_, ErrorDocument>(body)
        .ok()
        .map(|document| document.code)
}

/// One ListMultipartUploads page requested with `encoding-type=url`, under
/// which `Key` and `NextKeyMarker` are percent-encoded.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListUploadsDocument {
    #[serde(default)]
    is_truncated: bool,
    next_key_marker: Option<String>,
    next_upload_id_marker: Option<String>,
    #[serde(default, rename = "Upload")]
    uploads: Vec<ListedUpload>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListedUpload {
    key: Option<String>,
    upload_id: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct UploadPage {
    /// Uploads of exactly the requested key; the prefix also matches longer keys.
    upload_ids: Vec<String>,
    /// `(key-marker, upload-id-marker)` of the next page.
    next: Option<(String, String)>,
}

fn parse_upload_page(xml: &[u8], key: &str) -> Result<UploadPage, BackupStoreError> {
    let document: ListUploadsDocument = quick_xml::de::from_reader(xml)
        .map_err(|error| corrupt_listing(&format!("an unparsable page ({error})")))?;
    let mut upload_ids = Vec::new();
    for upload in document.uploads {
        let listed_key = upload
            .key
            .ok_or_else(|| corrupt_listing("an upload without a key"))
            .and_then(|value| url_decode(&value))?;
        if !listed_key.starts_with(key) {
            return Err(corrupt_listing("an upload outside the requested key"));
        }
        if listed_key != key {
            continue;
        }
        let upload_id = upload
            .upload_id
            .filter(|value| !value.is_empty())
            .ok_or_else(|| corrupt_listing("an upload without an id"))?;
        upload_ids.push(upload_id);
    }
    let next = if document.is_truncated {
        let key_marker = document
            .next_key_marker
            .map(|value| url_decode(&value))
            .transpose()?
            .filter(|value| !value.is_empty())
            .ok_or_else(|| corrupt_listing("a truncated page without NextKeyMarker"))?;
        Some((
            key_marker,
            document.next_upload_id_marker.unwrap_or_default(),
        ))
    } else {
        None
    };
    Ok(UploadPage { upload_ids, next })
}

/// Decodes an `encoding-type=url` value; `+` is a literal plus, not a space.
fn url_decode(value: &str) -> Result<String, BackupStoreError> {
    crate::utils::percent::decode_strict(value)
        .map_err(|_| corrupt_listing("an invalid percent-encoded key"))
}

fn corrupt_listing(what: &str) -> BackupStoreError {
    BackupStoreError::Corrupt(format!("S3 multipart upload list returned {what}"))
}

pub(super) fn multipart_part_size(size: u64) -> u64 {
    const MIB: u64 = 1024 * 1024;
    let minimum_for_part_limit = size.div_ceil(MAX_MULTIPART_PARTS);
    DEFAULT_MULTIPART_PART_BYTES
        .max(minimum_for_part_limit)
        .div_ceil(MIB)
        * MIB
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
        let page = parse_upload_page(xml.as_bytes(), KEY).unwrap();
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
            parse_upload_page(last.as_bytes(), KEY).unwrap(),
            UploadPage {
                upload_ids: Vec::new(),
                next: None
            }
        );
    }

    #[test]
    fn upload_pages_reject_foreign_keys_and_missing_markers() {
        let foreign = "<ListMultipartUploadsResult><Upload><Key>other/key</Key><UploadId>x</UploadId></Upload></ListMultipartUploadsResult>";
        assert!(parse_upload_page(foreign.as_bytes(), KEY).is_err());
        let no_marker = "<ListMultipartUploadsResult><IsTruncated>true</IsTruncated></ListMultipartUploadsResult>";
        assert!(parse_upload_page(no_marker.as_bytes(), KEY).is_err());
        let no_id = format!(
            "<ListMultipartUploadsResult><Upload><Key>{}</Key></Upload></ListMultipartUploadsResult>",
            KEY.replace(' ', "%20")
        );
        assert!(parse_upload_page(no_id.as_bytes(), KEY).is_err());
    }

    #[test]
    fn encoded_keys_keep_plus_literal() {
        assert_eq!(url_decode("dbev/a%20b%2Bc+d").unwrap(), "dbev/a b+c+d");
        assert!(url_decode("dbev/a%2").is_err());
    }

    #[test]
    fn only_no_such_upload_confirms_an_abort() {
        let gone = b"<Error><Code>NoSuchUpload</Code><Message>x</Message></Error>";
        let no_bucket = b"<Error><Code>NoSuchBucket</Code></Error>";
        assert_eq!(error_code(gone).as_deref(), Some(NO_SUCH_UPLOAD));
        assert_eq!(error_code(no_bucket).as_deref(), Some("NoSuchBucket"));
        assert_eq!(error_code(b"not xml"), None);
    }

    #[test]
    fn multipart_size_stays_within_the_s3_part_limit() {
        assert_eq!(multipart_part_size(64 * 1024 * 1024), 16 * 1024 * 1024);
        let eight_tib = 8 * 1024_u64.pow(4);
        assert!(eight_tib.div_ceil(multipart_part_size(eight_tib)) <= MAX_MULTIPART_PARTS);
    }
}
