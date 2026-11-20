//! S3 backup storage with signed requests and journaled multipart uploads.

use std::{fmt, sync::Arc};

use futures::future::BoxFuture;
use reqwest::Url;

use crate::{
    config::BackupS3Config,
    server::backup::{
        BackupBundle, BackupInventory, BackupStoreError, StoredBackup,
        drivers::{PublicationJournal, PublicationResource},
    },
};

const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
/// Files at or above this size use multipart upload.
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
mod download;
mod keys;
mod listing;
#[cfg(test)]
mod minio_tests;
mod multipart;
mod multipart_api;
mod objects;
mod operations;
mod signing;
#[cfg(test)]
mod tests;

use self::client::S3Client;

#[derive(Clone)]
pub struct S3BackupDriver {
    config: BackupS3Config,
    base: Url,
    client: Arc<S3Client>,
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
        let client = Arc::new(S3Client::new(&config, credentials, bucket_endpoint)?);
        Ok(Self {
            config,
            base,
            client,
        })
    }
}
