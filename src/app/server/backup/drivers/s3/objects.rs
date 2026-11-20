use std::path::Path;

use bytes::Bytes;
use http::{Method, StatusCode};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{MULTIPART_THRESHOLD_BYTES, S3BackupDriver, download::Download};
use crate::server::backup::{
    BackupStoreError, StoredBackup, drivers::PublicationJournal, io_error, remove_file_if_exists,
};

impl S3BackupDriver {
    pub(super) async fn put_file(
        &self,
        key: &str,
        path: &Path,
        size: u64,
        sha256: &str,
        journal: &dyn PublicationJournal,
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
            return self
                .multipart_upload(key, path, size, sha256, journal)
                .await;
        }
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|source| io_error("open S3 upload source", source))?;
        let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or_default());
        file.take(size.saturating_add(1))
            .read_to_end(&mut bytes)
            .await
            .map_err(|source| io_error("read S3 upload source", source))?;
        if bytes.len() as u64 != size {
            return Err(BackupStoreError::Corrupt(
                "S3 upload source changed before upload".to_string(),
            ));
        }
        verify_sha256(Sha256::digest(&bytes).as_slice(), sha256)?;
        self.put_bytes(key, bytes).await
    }

    pub(super) async fn put_bytes(
        &self,
        key: &str,
        bytes: Vec<u8>,
    ) -> Result<(), BackupStoreError> {
        self.client
            .send(Method::PUT, key, &[], bytes.into(), "upload object")
            .await?
            .success("upload object")?
            .etag("upload object")?;
        Ok(())
    }

    pub(super) async fn get_bytes(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, BackupStoreError> {
        let mut download = Download::open(&self.client, key).await?;
        if download.size > max_bytes {
            return Err(BackupStoreError::Corrupt(
                "S3 object download response exceeded its safety limit".into(),
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = download.chunk().await? {
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    pub(super) async fn download_file(
        &self,
        key: &str,
        destination: &Path,
        manifest: &StoredBackup,
    ) -> Result<(), BackupStoreError> {
        let mut download = Download::open(&self.client, key).await?;
        if download.size != manifest.size_bytes {
            return Err(BackupStoreError::Corrupt(
                "S3 backup size does not match its metadata".to_string(),
            ));
        }

        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options
            .open(destination)
            .await
            .map_err(|source| io_error("create materialized S3 backup", source))?;
        let result = async {
            while let Some(chunk) = download.chunk().await? {
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
            manifest.verify_archive(destination, "S3 backup").await
        }
        .await;
        if result.is_err() {
            drop(file);
            remove_file_if_exists(destination).await;
        }
        result
    }

    pub(super) async fn delete_object(
        &self,
        key: &str,
        missing_ok: bool,
    ) -> Result<(), BackupStoreError> {
        let response = self
            .client
            .send(Method::DELETE, key, &[], Bytes::new(), "delete object")
            .await?;
        if missing_ok && response.status == StatusCode::NOT_FOUND {
            return Ok(());
        }
        response.success("delete object").map(drop)
    }
}

pub(super) fn object_path(key: &str) -> Result<&str, BackupStoreError> {
    let trimmed = key.strip_suffix('/').unwrap_or(key);
    if key.len() > 1024 {
        return Err(BackupStoreError::InvalidConfiguration(
            "S3 key exceeds 1024 bytes".into(),
        ));
    }
    if trimmed
        .split('/')
        .any(|part| matches!(part, "" | "." | "..") || part.bytes().any(|b| b.is_ascii_control()))
    {
        return Err(BackupStoreError::InvalidConfiguration(
            "S3 key is not a normalized object path".into(),
        ));
    }
    Ok(trimmed)
}

pub(super) fn verify_sha256(actual: &[u8], expected: &str) -> Result<(), BackupStoreError> {
    if !hex::encode(actual).eq_ignore_ascii_case(expected.trim()) {
        return Err(BackupStoreError::Corrupt(
            "S3 upload source does not match its recorded SHA-256".to_string(),
        ));
    }
    Ok(())
}
