//! S3 backup storage on top of `object_store`'s `AmazonS3`.
//!
//! Object reads, writes, listing, deletes, multipart uploads, SigV4 and
//! retries come from `object_store`. This module keeps the backup layout,
//! the security checks on what S3 returns, and the discovery of in-progress
//! multipart uploads (ListMultipartUploads/ListParts), which `object_store`
//! does not expose.

use std::{fmt, sync::Arc};

use futures::future::BoxFuture;
use object_store::{ObjectStore, multipart::MultipartStore};
use reqwest::Url;

use crate::{
    config::BackupS3Config,
    server::backup::{
        BackupBundle, BackupInventory, BackupStoreError, StoredBackup,
        drivers::{PublicationJournal, PublicationResource},
    },
};

/// Bound on every S3 API response body other than an object download.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
/// Files at or above this size are uploaded in parts; smaller ones are
/// buffered and sent in one PUT.
const MULTIPART_THRESHOLD_BYTES: u64 = DEFAULT_MULTIPART_PART_BYTES;
const DEFAULT_MULTIPART_PART_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MULTIPART_PARTS: u64 = 10_000;
const MAX_S3_OBJECT_BYTES: u64 = 5 * 1024_u64.pow(4);
const MAX_LISTED_OBJECT_KEYS: usize = 100_000;
const MAX_LIST_PAGES: usize = 1_024;
const MAX_CONNECT_TIMEOUT_SECONDS: u64 = 30;
const RETRY_BASE_DELAY_MILLIS: u64 = 200;
const MAX_RETRY_BACKOFF_EXPONENT: u32 = 4;
const METADATA_KEY_SUFFIX: &str = ".metadata.json";

mod client;
mod keys;
#[cfg(test)]
mod minio_tests;
mod multipart;
mod objects;
mod operations;
#[cfg(test)]
mod tests;

use self::client::{S3Credentials, UploadAdmin};

#[derive(Clone)]
pub struct S3BackupDriver {
    config: BackupS3Config,
    /// Endpoint as configured, kept for [`S3BackupDriver::identity`].
    base: Url,
    credentials: S3Credentials,
    store: Arc<dyn ObjectStore>,
    multipart: Arc<dyn MultipartStore>,
    /// Absent only for stores without an S3 API (tests on `InMemory`).
    uploads: Option<Arc<UploadAdmin>>,
}

impl fmt::Debug for S3BackupDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3BackupDriver")
            .field("bucket", &self.config.bucket)
            .field("region", &self.config.region)
            .field("endpoint", &self.base)
            .field("prefix", &self.config.prefix)
            .finish_non_exhaustive()
    }
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
        journal: &'a dyn PublicationJournal,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(Self::commit(self, bundle, manifest, journal))
    }
}

impl super::BackupListing for S3BackupDriver {
    fn inventory<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<BackupInventory, BackupStoreError>> {
        Box::pin(Self::inventory(self, instance_id))
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

    fn purge_unpublished<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
        resources: &'a [PublicationResource],
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(Self::purge_unpublished(
            self,
            instance_id,
            backup_id,
            resources,
        ))
    }
}

impl S3BackupDriver {
    pub fn new(config: BackupS3Config) -> Result<Self, BackupStoreError> {
        let credentials = client::credentials(&config)?;
        let base = client::endpoint_base(&config)?;
        let bucket_endpoint = client::bucket_endpoint(&base, &config);
        let http = client::http_client(&config)?;
        let store = Arc::new(client::amazon_s3(
            &config,
            &credentials,
            &bucket_endpoint,
            http.clone(),
        )?);
        let uploads = UploadAdmin::new(&config, &credentials, &bucket_endpoint, http);
        Ok(Self {
            config,
            base,
            credentials,
            store: store.clone(),
            multipart: store,
            uploads: Some(Arc::new(uploads)),
        })
    }
}

#[cfg(test)]
impl S3BackupDriver {
    /// A driver over `object_store`'s in-memory store, which has neither
    /// network nor the multipart listing API.
    fn in_memory(config: BackupS3Config) -> (Self, Arc<object_store::memory::InMemory>) {
        let store = Arc::new(object_store::memory::InMemory::new());
        let driver = Self {
            base: client::endpoint_base(&config).unwrap(),
            credentials: S3Credentials {
                access_key_id: "AKID".to_string(),
                secret_access_key: "secret".to_string(),
                session_token: None,
            },
            config,
            store: store.clone(),
            multipart: store.clone(),
            uploads: None,
        };
        (driver, store)
    }
}
