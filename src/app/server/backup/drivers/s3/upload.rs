use std::path::Path;
use tokio::io::AsyncReadExt;

use bytes::Bytes;
use reqwest::{Method, StatusCode, header};
use tokio_util::io::ReaderStream;

use super::{
    DEFAULT_MULTIPART_PART_BYTES, EMPTY_SHA256, MAX_MULTIPART_PARTS, MAX_S3_OBJECT_BYTES,
    MULTIPART_THRESHOLD_BYTES, MultipartPart, S3BackupDriver,
    download::response_bytes_bounded,
    http::{retry_delay, retryable_error, retryable_status, s3_status_error},
    signing::hex_sha256,
    xml::{xml_unescape, xml_value},
};
use crate::{
    databases::protocol::xml_escape,
    server::backup::{BackupStoreError, MAX_METADATA_BYTES, io_error},
};

impl S3BackupDriver {
    pub(super) async fn put_file(
        &self,
        key: &str,
        path: &Path,
        size: u64,
        sha256: &str,
    ) -> Result<(), BackupStoreError> {
        let metadata = tokio::fs::symlink_metadata(path)
            .await
            .map_err(|source| io_error("inspect S3 upload source", source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != size {
            return Err(BackupStoreError::Corrupt(
                "S3 upload source changed before upload".to_string(),
            ));
        }
        if size >= MULTIPART_THRESHOLD_BYTES {
            return self.multipart_upload(key, path, size).await;
        }

        for attempt in 0..=self.config.max_retries {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|source| io_error("open S3 upload source", source))?;
            let body = reqwest::Body::wrap_stream(ReaderStream::new(file));
            let response = self
                .signed_request(Method::PUT, key, &[], sha256)?
                .header(header::CONTENT_LENGTH, size)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(body)
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response)
                    if retryable_status(response.status()) && attempt < self.config.max_retries =>
                {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(s3_status_error("upload object", &response)),
                Err(error) if attempt < self.config.max_retries && retryable_error(&error) => {
                    retry_delay(attempt).await;
                }
                Err(error) => {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 upload request failed: {error}"
                    )));
                }
            }
        }
        Err(BackupStoreError::Remote(
            "S3 upload exhausted its retry budget".to_string(),
        ))
    }

    async fn multipart_upload(
        &self,
        key: &str,
        path: &Path,
        size: u64,
    ) -> Result<(), BackupStoreError> {
        if size > MAX_S3_OBJECT_BYTES {
            return Err(BackupStoreError::InvalidConfiguration(
                "S3 backup exceeds the 5 TiB object limit".to_string(),
            ));
        }
        let upload_id = self.initiate_multipart_upload(key).await?;
        let result = match self
            .upload_multipart_parts(key, path, size, &upload_id)
            .await
        {
            Ok(parts) => {
                self.complete_multipart_upload(key, &upload_id, &parts)
                    .await
            }
            Err(error) => Err(error),
        };
        if result.is_err() {
            self.abort_multipart_upload(key, &upload_id).await;
            if let Err(error) = self.delete_object(key, true).await {
                tracing::warn!(object_key = key, %error, "failed to clean up S3 multipart object");
            }
        }
        result
    }

    async fn initiate_multipart_upload(&self, key: &str) -> Result<String, BackupStoreError> {
        let query = vec![("uploads".to_string(), String::new())];
        let response = self
            .signed_request(Method::POST, key, &query, EMPTY_SHA256)?
            .header(header::CONTENT_LENGTH, 0)
            .send()
            .await
            .map_err(|error| {
                BackupStoreError::Remote(format!("S3 multipart initiation request failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(s3_status_error("initiate multipart upload", &response));
        }
        let body =
            response_bytes_bounded(response, MAX_METADATA_BYTES, "multipart initiation").await?;
        let xml = std::str::from_utf8(&body).map_err(|_| {
            BackupStoreError::Corrupt(
                "S3 multipart initiation response was not UTF-8 XML".to_string(),
            )
        })?;
        xml_value(xml, "UploadId")
            .map(|value| xml_unescape(&value))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                BackupStoreError::Corrupt(
                    "S3 multipart initiation response omitted UploadId".to_string(),
                )
            })
    }

    async fn upload_multipart_parts(
        &self,
        key: &str,
        path: &Path,
        size: u64,
        upload_id: &str,
    ) -> Result<Vec<MultipartPart>, BackupStoreError> {
        let part_size = multipart_part_size(size);
        let part_count = size.div_ceil(part_size);
        if part_count == 0 || part_count > MAX_MULTIPART_PARTS {
            return Err(BackupStoreError::InvalidConfiguration(format!(
                "S3 backup requires an unsupported {part_count}-part upload"
            )));
        }
        let capacity = usize::try_from(part_count).map_err(|_| {
            BackupStoreError::Runtime("S3 multipart count exceeded usize".to_string())
        })?;
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|source| io_error("open S3 multipart upload source", source))?;
        let mut parts = Vec::with_capacity(capacity);
        let mut remaining = size;
        for part_number in 1..=part_count {
            let length = remaining.min(part_size);
            let length = usize::try_from(length).map_err(|_| {
                BackupStoreError::Runtime("S3 multipart chunk exceeded usize".to_string())
            })?;
            let mut bytes = vec![0_u8; length];
            file.read_exact(&mut bytes)
                .await
                .map_err(|source| io_error("read S3 multipart upload source", source))?;
            let part_number = u16::try_from(part_number).map_err(|_| {
                BackupStoreError::Runtime("S3 multipart part number overflowed".to_string())
            })?;
            let etag = self
                .upload_multipart_part(key, upload_id, part_number, Bytes::from(bytes))
                .await?;
            parts.push(MultipartPart { part_number, etag });
            remaining = remaining.saturating_sub(length as u64);
        }
        if remaining != 0 {
            return Err(BackupStoreError::Corrupt(
                "S3 multipart upload did not consume the complete archive".to_string(),
            ));
        }
        Ok(parts)
    }

    async fn upload_multipart_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u16,
        bytes: Bytes,
    ) -> Result<String, BackupStoreError> {
        let query = vec![
            ("partNumber".to_string(), part_number.to_string()),
            ("uploadId".to_string(), upload_id.to_string()),
        ];
        let payload_hash = hex_sha256(&bytes);
        for attempt in 0..=self.config.max_retries {
            let response = self
                .signed_request(Method::PUT, key, &query, &payload_hash)?
                .header(header::CONTENT_LENGTH, bytes.len())
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(bytes.clone())
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => {
                    return response
                        .headers()
                        .get(header::ETAG)
                        .and_then(|value| value.to_str().ok())
                        .filter(|value| valid_multipart_etag(value))
                        .map(str::to_string)
                        .ok_or_else(|| {
                            BackupStoreError::Corrupt(format!(
                                "S3 multipart part {part_number} response omitted ETag"
                            ))
                        });
                }
                Ok(response)
                    if retryable_status(response.status()) && attempt < self.config.max_retries =>
                {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(s3_status_error("upload multipart part", &response)),
                Err(error) if attempt < self.config.max_retries && retryable_error(&error) => {
                    retry_delay(attempt).await;
                }
                Err(error) => {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 multipart part {part_number} request failed: {error}"
                    )));
                }
            }
        }
        Err(BackupStoreError::Remote(format!(
            "S3 multipart part {part_number} exhausted its retry budget"
        )))
    }

    async fn complete_multipart_upload(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[MultipartPart],
    ) -> Result<(), BackupStoreError> {
        let body = complete_multipart_body(parts).into_bytes();
        let query = vec![("uploadId".to_string(), upload_id.to_string())];
        let payload_hash = hex_sha256(&body);
        let response = self
            .signed_request(Method::POST, key, &query, &payload_hash)?
            .header(header::CONTENT_LENGTH, body.len())
            .header(header::CONTENT_TYPE, "application/xml")
            .body(body)
            .send()
            .await
            .map_err(|error| {
                BackupStoreError::Remote(format!("S3 multipart completion request failed: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(s3_status_error("complete multipart upload", &response));
        }
        let body =
            response_bytes_bounded(response, MAX_METADATA_BYTES, "multipart completion").await?;
        let xml = std::str::from_utf8(&body).map_err(|_| {
            BackupStoreError::Corrupt(
                "S3 multipart completion response was not UTF-8 XML".to_string(),
            )
        })?;
        if xml.contains("<Error>") {
            return Err(BackupStoreError::Remote(format!(
                "S3 multipart completion returned error {}",
                xml_value(xml, "Code").unwrap_or_else(|| "unknown".to_string())
            )));
        }
        Ok(())
    }

    async fn abort_multipart_upload(&self, key: &str, upload_id: &str) {
        let query = vec![("uploadId".to_string(), upload_id.to_string())];
        let result = async {
            let response = self
                .signed_request(Method::DELETE, key, &query, EMPTY_SHA256)?
                .send()
                .await
                .map_err(|error| {
                    BackupStoreError::Remote(format!("S3 multipart abort request failed: {error}"))
                })?;
            if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
                Ok(())
            } else {
                Err(s3_status_error("abort multipart upload", &response))
            }
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(object_key = key, %error, "failed to abort incomplete S3 upload");
        }
    }

    pub(super) async fn put_bytes(
        &self,
        key: &str,
        bytes: Vec<u8>,
    ) -> Result<(), BackupStoreError> {
        let payload_hash = hex_sha256(&bytes);
        for attempt in 0..=self.config.max_retries {
            let response = self
                .signed_request(Method::PUT, key, &[], &payload_hash)?
                .header(header::CONTENT_LENGTH, bytes.len())
                .header(header::CONTENT_TYPE, "application/json")
                .body(bytes.clone())
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response)
                    if retryable_status(response.status()) && attempt < self.config.max_retries =>
                {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(s3_status_error("upload metadata", &response)),
                Err(error) if attempt < self.config.max_retries && retryable_error(&error) => {
                    retry_delay(attempt).await;
                }
                Err(error) => {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 metadata upload request failed: {error}"
                    )));
                }
            }
        }
        Err(BackupStoreError::Remote(
            "S3 metadata upload exhausted its retry budget".to_string(),
        ))
    }
}

fn complete_multipart_body(parts: &[MultipartPart]) -> String {
    let mut body = String::from("<CompleteMultipartUpload>");
    for part in parts {
        body.push_str("<Part><PartNumber>");
        body.push_str(&part.part_number.to_string());
        body.push_str("</PartNumber><ETag>");
        body.push_str(&xml_escape(&part.etag));
        body.push_str("</ETag></Part>");
    }
    body.push_str("</CompleteMultipartUpload>");
    body
}

pub(super) fn multipart_part_size(size: u64) -> u64 {
    const MIB: u64 = 1024 * 1024;
    let minimum_for_part_limit = size.div_ceil(MAX_MULTIPART_PARTS);
    DEFAULT_MULTIPART_PART_BYTES
        .max(minimum_for_part_limit)
        .div_ceil(MIB)
        * MIB
}

fn valid_multipart_etag(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'<' | b'>'))
}
