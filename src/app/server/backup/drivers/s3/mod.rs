use std::{collections::HashSet, fmt, path::Path, time::Duration};

use bytes::Bytes;
use futures::{StreamExt, future::BoxFuture};
use reqwest::{Method, StatusCode, Url, header};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;

use crate::{
    config::BackupS3Config,
    databases::protocol::xml_escape,
    server::backup::{
        BackupBundle, BackupStoreError, MAX_METADATA_BYTES, StoredBackup, catalog_file_name,
        check_instance_id, io_error, metadata_file_name, remove_file_if_exists, sha256_file,
        validate_backup_id,
    },
    utils::hex::{encode_lower, nibble},
};

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const MAX_LIST_BYTES: u64 = 8 * 1024 * 1024;
const MULTIPART_THRESHOLD_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MULTIPART_PART_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MULTIPART_PARTS: u64 = 10_000;
const MAX_S3_OBJECT_BYTES: u64 = 5 * 1024_u64.pow(4);
const MAX_LISTED_OBJECT_KEYS: usize = 100_000;
const MAX_LIST_PAGES: usize = 1_024;
const LIST_PAGE_MAX_KEYS: &str = "1000";
const MAX_CONNECT_TIMEOUT_SECONDS: u64 = 30;
const RETRY_BASE_DELAY_MILLIS: u64 = 200;
const MAX_RETRY_BACKOFF_EXPONENT: usize = 4;
const METADATA_KEY_SUFFIX: &str = ".metadata.json";

mod download;
mod endpoint;
mod http;
mod keys;
mod listing;
mod operations;
mod signing;
#[cfg(test)]
mod tests;
mod upload;
mod xml;

use self::download::*;
use self::endpoint::*;
use self::http::*;
use self::signing::*;
use self::xml::*;

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

impl super::BackupPreflight for S3BackupDriver {
    fn preflight(&self) -> BoxFuture<'_, Result<(), BackupStoreError>> {
        Box::pin(Self::preflight(self))
    }
}

impl super::BackupCommit for S3BackupDriver {
    fn commit<'a>(
        &'a self,
        bundle: &'a BackupBundle,
        manifest: &'a StoredBackup,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(Self::commit(self, bundle, manifest))
    }
}

impl super::BackupInventory for S3BackupDriver {
    fn list<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<StoredBackup>, BackupStoreError>> {
        Box::pin(Self::list(self, instance_id))
    }

    fn find<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
    ) -> BoxFuture<'a, Result<StoredBackup, BackupStoreError>> {
        Box::pin(Self::find(self, instance_id, backup_id))
    }
}

impl super::BackupDelete for S3BackupDriver {
    fn delete<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(Self::delete(self, instance_id, backup_id))
    }
}

impl S3BackupDriver {
    pub fn new(config: BackupS3Config) -> Result<Self, BackupStoreError> {
        let credentials = credentials(&config)?;
        let endpoint = S3Endpoint::new(&config)?;
        let timeout = Duration::from_secs(config.request_timeout_seconds);
        let client = reqwest::Client::builder()
            .tls_certs_only(crate::utils::tls::mozilla_root_certificates())
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(
                timeout.as_secs().min(MAX_CONNECT_TIMEOUT_SECONDS),
            ))
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
}
