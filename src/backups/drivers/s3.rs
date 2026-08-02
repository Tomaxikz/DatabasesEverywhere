use std::{fmt, path::Path, time::Duration};

use bytes::Bytes;
use futures::StreamExt;
use reqwest::{Method, StatusCode, Url, header};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;

use crate::{
    backups::{
        BackupBundle, BackupStoreError, StoredBackup, catalog_file_name, io_error,
        metadata_file_name, remove_file_if_exists, sha256_file, validate_backup_id,
    },
    config::BackupS3Config,
    shared::ids::validate_instance_id,
};

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const MAX_METADATA_BYTES: u64 = 64 * 1024;
const MAX_LIST_BYTES: u64 = 8 * 1024 * 1024;
const MULTIPART_THRESHOLD_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MULTIPART_PART_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MULTIPART_PARTS: u64 = 10_000;
const MAX_S3_OBJECT_BYTES: u64 = 5 * 1024_u64.pow(4);
const MAX_LISTED_OBJECT_KEYS: usize = 100_000;

#[derive(Clone)]
pub struct S3BackupDriver {
    config: BackupS3Config,
    endpoint: S3Endpoint,
    credentials: S3Credentials,
    client: reqwest::Client,
}

impl fmt::Debug for S3BackupDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3BackupDriver")
            .field("bucket", &self.config.bucket)
            .field("region", &self.config.region)
            .field("endpoint", &self.endpoint.base)
            .field("prefix", &self.config.prefix)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct S3Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

#[derive(Debug)]
struct MultipartPart {
    part_number: u16,
    etag: String,
}

#[derive(Debug, Clone)]
struct S3Endpoint {
    base: Url,
    authority: String,
    base_path: String,
    bucket_in_path: bool,
}

impl S3BackupDriver {
    pub fn new(config: BackupS3Config) -> Result<Self, BackupStoreError> {
        let credentials = credentials(&config)?;
        let endpoint = S3Endpoint::new(&config)?;
        let timeout = Duration::from_secs(config.request_timeout_seconds);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(timeout.as_secs().min(30)))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        Ok(Self {
            config,
            endpoint,
            credentials,
            client,
        })
    }

    pub async fn preflight(&self) -> Result<(), BackupStoreError> {
        if self.credentials.access_key_id.is_empty()
            || self.credentials.secret_access_key.is_empty()
        {
            return Err(BackupStoreError::InvalidConfiguration(
                "S3 credentials are empty".to_string(),
            ));
        }
        Ok(())
    }

    pub async fn commit(
        &self,
        bundle: &BackupBundle,
        manifest: &StoredBackup,
    ) -> Result<(), BackupStoreError> {
        manifest.validate(&manifest.instance_id)?;
        let archive_key = self.archive_key(&manifest.instance_id, &manifest.backup_id)?;
        let catalog_key = self.catalog_key(&manifest.instance_id, &manifest.backup_id)?;
        let metadata_key = self.metadata_key(&manifest.instance_id, &manifest.backup_id)?;

        if let Err(error) = self
            .put_file(
                &archive_key,
                &bundle.archive,
                manifest.size_bytes,
                &manifest.sha256,
            )
            .await
        {
            // A timed-out PUT can have reached S3 even when the client never
            // received its response. Keep such an object out of the inventory.
            self.cleanup_incomplete(&archive_key, None, None).await;
            return Err(error);
        }
        if manifest.catalog_available {
            let catalog_metadata = tokio::fs::metadata(&bundle.catalog)
                .await
                .map_err(|source| io_error("inspect backup catalog", source))?;
            let catalog_sha = sha256_file(&bundle.catalog).await?;
            if let Err(error) = self
                .put_file(
                    &catalog_key,
                    &bundle.catalog,
                    catalog_metadata.len(),
                    &catalog_sha,
                )
                .await
            {
                // Include the catalog key because its PUT may have committed
                // remotely before a transport error reached this process.
                self.cleanup_incomplete(&archive_key, Some(&catalog_key), None)
                    .await;
                return Err(error);
            }
        }
        let metadata = serde_json::to_vec_pretty(manifest)
            .map_err(|error| BackupStoreError::Corrupt(error.to_string()))?;
        if let Err(error) = self.put_bytes(&metadata_key, metadata).await {
            self.cleanup_incomplete(
                &archive_key,
                manifest.catalog_available.then_some(catalog_key.as_str()),
                Some(&metadata_key),
            )
            .await;
            return Err(error);
        }
        Ok(())
    }

    pub async fn list(&self, instance_id: &str) -> Result<Vec<StoredBackup>, BackupStoreError> {
        let prefix = self.instance_prefix(instance_id)?;
        let keys = self.list_keys(&prefix).await?;
        let mut backups = Vec::new();
        for key in keys {
            if !key.ends_with(".metadata.json") {
                continue;
            }
            match self.get_manifest_by_key(instance_id, &key).await {
                Ok(manifest) => backups.push(manifest),
                Err(BackupStoreError::NotFound) => {}
                Err(error @ (BackupStoreError::InvalidBackupId | BackupStoreError::Corrupt(_))) => {
                    tracing::warn!(
                        object_key = %key,
                        %error,
                        "ignored invalid S3 backup metadata"
                    )
                }
                Err(error) => return Err(error),
            }
        }
        Ok(backups)
    }

    pub async fn find(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<StoredBackup, BackupStoreError> {
        let key = self.metadata_key(instance_id, backup_id)?;
        self.get_manifest_by_key(instance_id, &key).await
    }

    pub async fn delete(&self, instance_id: &str, backup_id: &str) -> Result<(), BackupStoreError> {
        let manifest = self.find(instance_id, backup_id).await?;
        let archive = self.archive_key(instance_id, backup_id)?;
        let catalog = self.catalog_key(instance_id, backup_id)?;
        let metadata = self.metadata_key(instance_id, backup_id)?;
        self.delete_object(&archive, true).await?;
        if manifest.catalog_available {
            self.delete_object(&catalog, true).await?;
        }
        self.delete_object(&metadata, false).await
    }

    pub async fn materialize(
        &self,
        instance_id: &str,
        backup_id: &str,
        destination: &Path,
    ) -> Result<(), BackupStoreError> {
        let manifest = self.find(instance_id, backup_id).await?;
        let key = self.archive_key(instance_id, backup_id)?;
        self.download_file(&key, destination, &manifest).await
    }

    pub async fn read_catalog(
        &self,
        instance_id: &str,
        backup_id: &str,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, BackupStoreError> {
        let manifest = self.find(instance_id, backup_id).await?;
        if !manifest.catalog_available {
            return Ok(None);
        }
        let key = self.catalog_key(instance_id, backup_id)?;
        self.get_bytes(&key, max_bytes).await.map(Some)
    }

    pub async fn delete_instance(&self, instance_id: &str) -> Result<usize, BackupStoreError> {
        let prefix = self.instance_prefix(instance_id)?;
        let mut keys = self.list_keys(&prefix).await?;
        let published = keys
            .iter()
            .filter(|key| key.ends_with(".metadata.json"))
            .count();
        // Hide published entries first, then remove archives, catalogs, and
        // any crash-orphaned objects that never received metadata.
        keys.sort_by_key(|key| !key.ends_with(".metadata.json"));
        for key in keys {
            self.delete_object(&key, true).await?;
        }
        Ok(published)
    }

    async fn get_manifest_by_key(
        &self,
        instance_id: &str,
        key: &str,
    ) -> Result<StoredBackup, BackupStoreError> {
        let bytes = self.get_bytes(key, MAX_METADATA_BYTES).await?;
        let manifest: StoredBackup = serde_json::from_slice(&bytes).map_err(|error| {
            BackupStoreError::Corrupt(format!("invalid S3 backup metadata: {error}"))
        })?;
        manifest.validate(instance_id)?;
        if self.metadata_key(instance_id, &manifest.backup_id)? != key {
            return Err(BackupStoreError::Corrupt(
                "S3 backup metadata key does not match its backup id".to_string(),
            ));
        }
        Ok(manifest)
    }

    async fn put_file(
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
        let mut body = String::from("<CompleteMultipartUpload>");
        for part in parts {
            body.push_str("<Part><PartNumber>");
            body.push_str(&part.part_number.to_string());
            body.push_str("</PartNumber><ETag>");
            body.push_str(&xml_escape(&part.etag));
            body.push_str("</ETag></Part>");
        }
        body.push_str("</CompleteMultipartUpload>");
        let body = body.into_bytes();
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

    async fn put_bytes(&self, key: &str, bytes: Vec<u8>) -> Result<(), BackupStoreError> {
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

    async fn get_bytes(&self, key: &str, max_bytes: u64) -> Result<Vec<u8>, BackupStoreError> {
        for attempt in 0..=self.config.max_retries {
            let response = self
                .signed_request(Method::GET, key, &[], EMPTY_SHA256)?
                .send()
                .await;
            let mut response = match response {
                Ok(response) if response.status() == StatusCode::NOT_FOUND => {
                    return Err(BackupStoreError::NotFound);
                }
                Ok(response) if response.status().is_success() => response,
                Ok(response)
                    if retryable_status(response.status()) && attempt < self.config.max_retries =>
                {
                    retry_delay(attempt).await;
                    continue;
                }
                Ok(response) => return Err(s3_status_error("download object", &response)),
                Err(error) if attempt < self.config.max_retries && retryable_error(&error) => {
                    retry_delay(attempt).await;
                    continue;
                }
                Err(error) => {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 download request failed: {error}"
                    )));
                }
            };
            if response
                .content_length()
                .is_some_and(|length| length > max_bytes)
            {
                return Err(BackupStoreError::Corrupt(format!(
                    "S3 object exceeds the configured {max_bytes}-byte limit"
                )));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|error| {
                BackupStoreError::Remote(format!("failed while reading S3 object: {error}"))
            })? {
                if u64::try_from(bytes.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(chunk.len() as u64)
                    > max_bytes
                {
                    return Err(BackupStoreError::Corrupt(format!(
                        "S3 object exceeds the configured {max_bytes}-byte limit"
                    )));
                }
                bytes.extend_from_slice(&chunk);
            }
            return Ok(bytes);
        }
        Err(BackupStoreError::Remote(
            "S3 download exhausted its retry budget".to_string(),
        ))
    }

    async fn download_file(
        &self,
        key: &str,
        destination: &Path,
        manifest: &StoredBackup,
    ) -> Result<(), BackupStoreError> {
        let response = self
            .get_response_with_retry(key, "download backup archive")
            .await?;
        if response
            .content_length()
            .is_some_and(|length| length != manifest.size_bytes)
        {
            return Err(BackupStoreError::Corrupt(
                "S3 backup size does not match its metadata".to_string(),
            ));
        }

        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = options
            .open(destination)
            .await
            .map_err(|source| io_error("create materialized S3 backup", source))?;
        let mut stream = response.bytes_stream();
        let mut written = 0_u64;
        let result = async {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| {
                    BackupStoreError::Remote(format!("failed while reading S3 backup: {error}"))
                })?;
                written = written.saturating_add(chunk.len() as u64);
                if written > manifest.size_bytes {
                    return Err(BackupStoreError::Corrupt(
                        "S3 backup exceeds the size recorded in its metadata".to_string(),
                    ));
                }
                file.write_all(&chunk)
                    .await
                    .map_err(|source| io_error("write materialized S3 backup", source))?;
            }
            file.flush()
                .await
                .map_err(|source| io_error("flush materialized S3 backup", source))?;
            file.sync_all()
                .await
                .map_err(|source| io_error("sync materialized S3 backup", source))?;
            if written != manifest.size_bytes {
                return Err(BackupStoreError::Corrupt(
                    "S3 backup ended before its recorded size".to_string(),
                ));
            }
            let actual = sha256_file(destination).await?;
            if actual != manifest.sha256 {
                return Err(BackupStoreError::Corrupt(
                    "S3 backup SHA-256 does not match its metadata".to_string(),
                ));
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            drop(file);
            remove_file_if_exists(destination).await;
        }
        result
    }

    async fn get_response_with_retry(
        &self,
        key: &str,
        operation: &str,
    ) -> Result<reqwest::Response, BackupStoreError> {
        for attempt in 0..=self.config.max_retries {
            match self
                .signed_request(Method::GET, key, &[], EMPTY_SHA256)?
                .send()
                .await
            {
                Ok(response) if response.status() == StatusCode::NOT_FOUND => {
                    return Err(BackupStoreError::NotFound);
                }
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response)
                    if retryable_status(response.status()) && attempt < self.config.max_retries =>
                {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(s3_status_error(operation, &response)),
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

    async fn delete_object(&self, key: &str, missing_ok: bool) -> Result<(), BackupStoreError> {
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

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, BackupStoreError> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut query = vec![
                ("encoding-type".to_string(), "url".to_string()),
                ("list-type".to_string(), "2".to_string()),
                ("max-keys".to_string(), "1000".to_string()),
                ("prefix".to_string(), prefix.to_string()),
            ];
            if let Some(token) = continuation.as_ref() {
                query.push(("continuation-token".to_string(), token.clone()));
            }
            let response = self.list_response_with_retry(&query).await?;
            let body = response_bytes_bounded(response, MAX_LIST_BYTES, "list objects").await?;
            let xml = std::str::from_utf8(&body).map_err(|_| {
                BackupStoreError::Corrupt("S3 list response was not UTF-8 XML".to_string())
            })?;
            for value in xml_values(xml, "Key") {
                keys.push(percent_decode(&xml_unescape(&value))?);
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
            continuation =
                xml_value(xml, "NextContinuationToken").map(|value| xml_unescape(&value));
            if continuation.as_deref().is_none_or(str::is_empty) {
                return Err(BackupStoreError::Corrupt(
                    "S3 list response omitted its continuation token".to_string(),
                ));
            }
        }
        Ok(keys)
    }

    async fn list_response_with_retry(
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

    fn signed_request(
        &self,
        method: Method,
        key: &str,
        query: &[(String, String)],
        payload_hash: &str,
    ) -> Result<reqwest::RequestBuilder, BackupStoreError> {
        let now = time::OffsetDateTime::now_utc();
        let date = format!(
            "{:04}{:02}{:02}",
            now.year(),
            u8::from(now.month()),
            now.day()
        );
        let timestamp = format!(
            "{date}T{:02}{:02}{:02}Z",
            now.hour(),
            now.minute(),
            now.second()
        );
        let canonical_query = canonical_query(query);
        let (url, canonical_uri) = self
            .endpoint
            .url(&self.config.bucket, key, &canonical_query)?;
        let mut canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            self.endpoint.authority, payload_hash, timestamp
        );
        let mut signed_headers = "host;x-amz-content-sha256;x-amz-date".to_string();
        if let Some(token) = self.credentials.session_token.as_deref() {
            canonical_headers.push_str(&format!("x-amz-security-token:{}\n", token.trim()));
            signed_headers.push_str(";x-amz-security-token");
        }
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.config.region.trim());
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            timestamp,
            scope,
            hex_sha256(canonical_request.as_bytes())
        );
        let signing_key = signing_key(
            &self.credentials.secret_access_key,
            &date,
            self.config.region.trim(),
        );
        let signature = hex_bytes(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
            self.credentials.access_key_id, scope, signed_headers, signature
        );
        let mut request = self
            .client
            .request(method, url)
            .header(header::HOST, &self.endpoint.authority)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", timestamp)
            .header(header::AUTHORIZATION, authorization);
        if let Some(token) = self.credentials.session_token.as_deref() {
            request = request.header("x-amz-security-token", token);
        }
        Ok(request)
    }

    fn instance_prefix(&self, instance_id: &str) -> Result<String, BackupStoreError> {
        validate_instance_id(instance_id)
            .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        let prefix = self.config.prefix.trim_matches('/');
        let relative = format!("instances/{instance_id}/backups/");
        Ok(if prefix.is_empty() {
            relative
        } else {
            format!("{prefix}/{relative}")
        })
    }

    fn archive_key(&self, instance_id: &str, backup_id: &str) -> Result<String, BackupStoreError> {
        validate_backup_id(backup_id)?;
        Ok(format!("{}{backup_id}", self.instance_prefix(instance_id)?))
    }

    fn catalog_key(&self, instance_id: &str, backup_id: &str) -> Result<String, BackupStoreError> {
        validate_backup_id(backup_id)?;
        Ok(format!(
            "{}{}",
            self.instance_prefix(instance_id)?,
            catalog_file_name(backup_id)
        ))
    }

    fn metadata_key(&self, instance_id: &str, backup_id: &str) -> Result<String, BackupStoreError> {
        validate_backup_id(backup_id)?;
        Ok(format!(
            "{}{}",
            self.instance_prefix(instance_id)?,
            metadata_file_name(backup_id)
        ))
    }

    async fn cleanup_incomplete(
        &self,
        archive: &str,
        catalog: Option<&str>,
        metadata: Option<&str>,
    ) {
        if let Some(metadata) = metadata {
            self.cleanup_object(metadata).await;
        }
        if let Some(catalog) = catalog {
            self.cleanup_object(catalog).await;
        }
        self.cleanup_object(archive).await;
    }

    async fn cleanup_object(&self, key: &str) {
        if let Err(error) = self.delete_object(key, true).await {
            tracing::warn!(
                object_key = key,
                %error,
                "failed to remove an incomplete S3 backup object"
            );
        }
    }
}

impl S3Endpoint {
    fn new(config: &BackupS3Config) -> Result<Self, BackupStoreError> {
        let mut base = if config.endpoint.trim().is_empty() {
            if config.path_style {
                Url::parse(&format!(
                    "https://s3.{}.amazonaws.com/",
                    config.region.trim()
                ))
            } else {
                Url::parse(&format!(
                    "https://{}.s3.{}.amazonaws.com/",
                    config.bucket.trim(),
                    config.region.trim()
                ))
            }
        } else {
            Url::parse(config.endpoint.trim())
        }
        .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        if !config.path_style && !config.endpoint.trim().is_empty() {
            let host = base.host_str().ok_or_else(|| {
                BackupStoreError::InvalidConfiguration("S3 endpoint has no host".to_string())
            })?;
            let virtual_host = format!("{}.{}", config.bucket.trim(), host);
            base.set_host(Some(&virtual_host)).map_err(|_| {
                BackupStoreError::InvalidConfiguration(
                    "failed to construct virtual-hosted S3 endpoint".to_string(),
                )
            })?;
        }
        let host = base.host().ok_or_else(|| {
            BackupStoreError::InvalidConfiguration("S3 endpoint has no host".to_string())
        })?;
        let authority = match base.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        let base_path = base.path().trim_end_matches('/').to_string();
        base.set_query(None);
        base.set_fragment(None);
        Ok(Self {
            base,
            authority,
            base_path,
            bucket_in_path: config.path_style,
        })
    }

    fn url(
        &self,
        bucket: &str,
        key: &str,
        canonical_query: &str,
    ) -> Result<(Url, String), BackupStoreError> {
        let mut canonical_uri = self.base_path.clone();
        if self.bucket_in_path {
            canonical_uri.push('/');
            canonical_uri.push_str(&aws_uri_encode(bucket.as_bytes(), false));
        }
        if !key.is_empty() {
            canonical_uri.push('/');
            canonical_uri.push_str(&aws_uri_encode(key.as_bytes(), true));
        } else if canonical_uri.is_empty() {
            canonical_uri.push('/');
        }
        if !canonical_uri.starts_with('/') {
            canonical_uri.insert(0, '/');
        }
        let mut url = format!(
            "{}://{}{}",
            self.base.scheme(),
            self.authority,
            canonical_uri
        );
        if !canonical_query.is_empty() {
            url.push('?');
            url.push_str(canonical_query);
        }
        let url = Url::parse(&url)
            .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        Ok((url, canonical_uri))
    }
}

fn credentials(config: &BackupS3Config) -> Result<S3Credentials, BackupStoreError> {
    let configured_access = config.access_key_id.trim();
    let configured_secret = config.secret_access_key.expose().trim();
    let access_key_id = if configured_access.is_empty() {
        std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default()
    } else {
        configured_access.to_string()
    };
    let secret_access_key = if configured_secret.is_empty() {
        std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default()
    } else {
        configured_secret.to_string()
    };
    let access_key_id = access_key_id.trim().to_string();
    let secret_access_key = secret_access_key.trim().to_string();
    if access_key_id.is_empty() || secret_access_key.is_empty() {
        return Err(BackupStoreError::InvalidConfiguration(
            "S3 requires access_key_id/secret_access_key or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY"
                .to_string(),
        ));
    }
    let configured_token = config.session_token.expose().trim();
    let session_token = if configured_token.is_empty() {
        std::env::var("AWS_SESSION_TOKEN").ok()
    } else {
        Some(configured_token.to_string())
    }
    .map(|token| token.trim().to_string())
    .filter(|token| !token.is_empty());
    Ok(S3Credentials {
        access_key_id,
        secret_access_key,
        session_token,
    })
}

fn canonical_query(query: &[(String, String)]) -> String {
    let mut encoded = query
        .iter()
        .map(|(name, value)| {
            (
                aws_uri_encode(name.as_bytes(), false),
                aws_uri_encode(value.as_bytes(), false),
            )
        })
        .collect::<Vec<_>>();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn aws_uri_encode(bytes: &[u8], preserve_slashes: bool) -> String {
    let mut encoded = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (preserve_slashes && byte == b'/')
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

fn signing_key(secret: &str, date: &str, region: &str) -> [u8; 32] {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, b"s3");
    hmac_sha256(&service_key, b"aws4_request")
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut normalized = [0_u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn xml_values(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut values = Vec::new();
    let mut remainder = xml;
    while let Some(start) = remainder.find(&open) {
        let value = &remainder[start + open.len()..];
        let Some(end) = value.find(&close) else {
            break;
        };
        values.push(value[..end].to_string());
        remainder = &value[end + close.len()..];
    }
    values
}

fn xml_value(xml: &str, tag: &str) -> Option<String> {
    xml_values(xml, tag).into_iter().next()
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn percent_decode(value: &str) -> Result<String, BackupStoreError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(BackupStoreError::Corrupt(
                    "S3 returned an invalid percent-encoded object key".to_string(),
                ));
            }
            let high = hex_digit(bytes[index + 1])?;
            let low = hex_digit(bytes[index + 2])?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| BackupStoreError::Corrupt("S3 returned a non-UTF-8 object key".to_string()))
}

fn hex_digit(byte: u8) -> Result<u8, BackupStoreError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(BackupStoreError::Corrupt(
            "S3 returned an invalid percent-encoded object key".to_string(),
        )),
    }
}

fn s3_status_error(operation: &str, response: &reqwest::Response) -> BackupStoreError {
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

fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn retryable_error(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout() || error.is_body()
}

async fn retry_delay(attempt: usize) {
    let factor = 1_u64 << u32::try_from(attempt.min(4)).unwrap_or(4);
    tokio::time::sleep(Duration::from_millis(200 * factor)).await;
}

fn multipart_part_size(size: u64) -> u64 {
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

async fn response_bytes_bounded(
    response: reqwest::Response,
    max_bytes: u64,
    operation: &str,
) -> Result<Bytes, BackupStoreError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes)
    {
        return Err(BackupStoreError::Corrupt(format!(
            "S3 {operation} response exceeded its safety limit"
        )));
    }
    let bytes = response.bytes().await.map_err(|error| {
        BackupStoreError::Remote(format!("failed to read S3 {operation} response: {error}"))
    })?;
    if bytes.len() as u64 > max_bytes {
        return Err(BackupStoreError::Corrupt(format!(
            "S3 {operation} response exceeded its safety limit"
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_encoding_preserves_only_unreserved_bytes_and_key_slashes() {
        assert_eq!(aws_uri_encode(b"a b/c+$", true), "a%20b/c%2B%24");
        assert_eq!(aws_uri_encode(b"a/b", false), "a%2Fb");
    }

    #[test]
    fn hmac_matches_the_rfc_4231_sha256_vector() {
        let key = [0x0b_u8; 20];
        assert_eq!(
            hex_bytes(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn parses_encoded_s3_keys_without_treating_plus_as_space() {
        let xml =
            "<ListBucketResult><Contents><Key>dbev/a%20b%2Bc</Key></Contents></ListBucketResult>";
        let key = percent_decode(&xml_values(xml, "Key")[0]).unwrap();
        assert_eq!(key, "dbev/a b+c");
    }

    #[test]
    fn multipart_size_stays_within_the_s3_part_limit() {
        assert_eq!(multipart_part_size(64 * 1024 * 1024), 16 * 1024 * 1024);
        let eight_tib = 8 * 1024_u64.pow(4);
        assert!(eight_tib.div_ceil(multipart_part_size(eight_tib)) <= MAX_MULTIPART_PARTS);
    }

    #[test]
    fn multipart_etags_are_xml_escaped() {
        assert_eq!(xml_escape("\"a&b\""), "&quot;a&amp;b&quot;");
    }
}
