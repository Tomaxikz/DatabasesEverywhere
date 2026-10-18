use std::{path::Path, time::Duration};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use object_store::{ObjectStoreExt, PutPayload, path::Path as ObjectPath};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    MAX_LISTED_OBJECT_KEYS, MULTIPART_THRESHOLD_BYTES, S3BackupDriver, client::remote_error,
};
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
        self.store
            .put(&object_path(key)?, PutPayload::from(bytes))
            .await
            .map_err(|error| remote_error("upload object", error))?;
        Ok(())
    }

    pub(super) async fn put_bytes(
        &self,
        key: &str,
        bytes: Vec<u8>,
    ) -> Result<(), BackupStoreError> {
        self.store
            .put(&object_path(key)?, PutPayload::from(bytes))
            .await
            .map_err(|error| remote_error("upload metadata", error))?;
        Ok(())
    }

    pub(super) async fn get_bytes(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, BackupStoreError> {
        let result = match self.store.get(&object_path(key)?).await {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => return Err(BackupStoreError::NotFound),
            Err(error) => return Err(remote_error("download object", error)),
        };
        if result.meta.size > max_bytes {
            return Err(response_too_large("object download"));
        }
        collect_bounded(result.into_stream(), max_bytes, "object download").await
    }

    pub(super) async fn download_file(
        &self,
        key: &str,
        destination: &Path,
        manifest: &StoredBackup,
    ) -> Result<(), BackupStoreError> {
        let result = match self.store.get(&object_path(key)?).await {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => return Err(BackupStoreError::NotFound),
            Err(error) => return Err(remote_error("download backup archive", error)),
        };
        if result.meta.size != manifest.size_bytes {
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
        let mut stream = result.into_stream();
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
        match self.store.delete(&object_path(key)?).await {
            Ok(()) => Ok(()),
            Err(object_store::Error::NotFound { .. }) if missing_ok => Ok(()),
            Err(error) => Err(remote_error("delete object", error)),
        }
    }

    /// Every key under `prefix`, which must end with `/`. The whole listing
    /// shares one request deadline.
    pub(super) async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, BackupStoreError> {
        let listing = async {
            let mut objects = self.store.list(Some(&object_path(prefix)?));
            let mut keys = Vec::new();
            while let Some(object) = objects.next().await {
                let object = object.map_err(|error| remote_error("list objects", error))?;
                keys.push(owned_key(object.location.as_ref(), prefix)?);
                if keys.len() > MAX_LISTED_OBJECT_KEYS {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 backup prefix contains more than {MAX_LISTED_OBJECT_KEYS} objects"
                    )));
                }
            }
            Ok(keys)
        };
        tokio::time::timeout(
            Duration::from_secs(self.config.request_timeout_seconds),
            listing,
        )
        .await
        .map_err(|_| {
            BackupStoreError::Remote(
                "S3 list objects exceeded its overall request deadline".to_string(),
            )
        })?
    }
}

/// The `object_store` path of an S3 key. Backup keys are always valid paths;
/// one that is not would be stored under a different, re-encoded key.
pub(super) fn object_path(key: &str) -> Result<ObjectPath, BackupStoreError> {
    let trimmed = key.strip_suffix('/').unwrap_or(key);
    match ObjectPath::parse(trimmed) {
        Ok(path) if path.as_ref() == trimmed => Ok(path),
        _ => Err(BackupStoreError::InvalidConfiguration(format!(
            "S3 key {key:?} is not a normalized object path"
        ))),
    }
}

/// S3 decides what a listing returns; anything outside the requested
/// instance prefix must never be acted on as one of its backups.
pub(super) fn owned_key(key: &str, requested_prefix: &str) -> Result<String, BackupStoreError> {
    if !key.starts_with(requested_prefix) {
        return Err(BackupStoreError::Corrupt(
            "S3 list response returned an object outside the requested backup prefix".to_string(),
        ));
    }
    Ok(key.to_string())
}

pub(super) fn verify_sha256(actual: &[u8], expected: &str) -> Result<(), BackupStoreError> {
    if !hex::encode(actual).eq_ignore_ascii_case(expected.trim()) {
        return Err(BackupStoreError::Corrupt(
            "S3 upload source does not match its recorded SHA-256".to_string(),
        ));
    }
    Ok(())
}

pub(super) async fn collect_bounded(
    mut stream: impl Stream<Item = object_store::Result<Bytes>> + Unpin,
    max_bytes: u64,
    operation: &str,
) -> Result<Vec<u8>, BackupStoreError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            BackupStoreError::Remote(format!("failed to read S3 {operation} response: {error}"))
        })?;
        let prospective_size = (bytes.len() as u64).saturating_add(chunk.len() as u64);
        if prospective_size > max_bytes {
            return Err(response_too_large(operation));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn response_too_large(operation: &str) -> BackupStoreError {
    BackupStoreError::Corrupt(format!("S3 {operation} response exceeded its safety limit"))
}
