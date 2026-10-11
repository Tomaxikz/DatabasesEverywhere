pub mod kopia;
pub mod local;
pub mod s3;

use futures::future::BoxFuture;

use super::{BackupBundle, BackupInventory, BackupStoreError, StoredBackup};

/// A remote resource a provider creates while publishing that cannot be
/// found again from the backup id alone. It is journaled before it exists,
/// or immediately after the provider assigns its identity, so recovery can
/// remove it and confirm removal before settling the publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationResource {
    /// Absolute source path of a Kopia snapshot, unique to one bundle. The
    /// CLI tags only the final manifest; checkpoint snapshots are found by
    /// this path label, independent of the client's user@host identity.
    KopiaSourcePath(String),
    /// An S3 multipart upload of one owned object key.
    S3MultipartUpload { key: String, upload_id: String },
}

const KOPIA_SOURCE_KIND: &str = "kopia_source_path";
const S3_MULTIPART_KIND: &str = "s3_multipart_upload";

impl PublicationResource {
    /// `(kind, locator, detail)` as stored in the publication journal.
    pub fn journal_parts(&self) -> (&'static str, &str, &str) {
        match self {
            Self::KopiaSourcePath(source) => (KOPIA_SOURCE_KIND, source, ""),
            Self::S3MultipartUpload { key, upload_id } => (S3_MULTIPART_KIND, key, upload_id),
        }
    }

    pub fn from_journal(kind: &str, locator: &str, detail: &str) -> Result<Self, BackupStoreError> {
        match kind {
            KOPIA_SOURCE_KIND if !locator.is_empty() && detail.is_empty() => {
                Ok(Self::KopiaSourcePath(locator.to_string()))
            }
            S3_MULTIPART_KIND if !locator.is_empty() && !detail.is_empty() => {
                Ok(Self::S3MultipartUpload {
                    key: locator.to_string(),
                    upload_id: detail.to_string(),
                })
            }
            _ => Err(BackupStoreError::Corrupt(format!(
                "publication journal holds an unreadable {kind} resource"
            ))),
        }
    }
}

/// Durable record of the resources of one publication.
pub trait PublicationJournal: Send + Sync {
    fn record<'a>(
        &'a self,
        resource: &'a PublicationResource,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>>;
}

pub(crate) trait BackupPreflight: Send + Sync {
    fn preflight(&self) -> BoxFuture<'_, Result<(), BackupStoreError>>;
}

pub(crate) trait BackupCommit: Send + Sync {
    fn commit<'a>(
        &'a self,
        bundle: &'a BackupBundle,
        manifest: &'a StoredBackup,
        journal: &'a dyn PublicationJournal,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>>;
}

pub(crate) trait BackupListing: Send + Sync {
    /// Readable backups plus opaque entries in formats this daemon cannot
    /// interpret.
    fn inventory<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<BackupInventory, BackupStoreError>>;

    fn find<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
    ) -> BoxFuture<'a, Result<StoredBackup, BackupStoreError>>;
}

pub(crate) trait BackupDelete: Send + Sync {
    /// Deletes one listed backup, including one in an unsupported format.
    fn delete<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>>;

    /// Idempotently removes every object of a backup id whose publication
    /// did not settle, whether or not its metadata exists or parses, plus
    /// the journaled `resources`. Succeeds only once removal is confirmed.
    fn purge_unpublished<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
        resources: &'a [PublicationResource],
    ) -> BoxFuture<'a, Result<(), BackupStoreError>>;
}
/// Common provider operations behind the storage facade.
///
/// Providers retain their validation and publication rules. The facade owns
/// inventory ordering; materialization and instance purging remain separate
/// because their resource ownership and cleanup semantics differ by provider.
pub(crate) trait BackupDriver:
    BackupPreflight + BackupCommit + BackupListing + BackupDelete
{
}

impl<T> BackupDriver for T where T: BackupPreflight + BackupCommit + BackupListing + BackupDelete {}

/// Journal for callers that publish outside the publication coordinator.
#[cfg(test)]
pub(crate) struct DiscardJournal;

#[cfg(test)]
impl PublicationJournal for DiscardJournal {
    fn record<'a>(
        &'a self,
        _resource: &'a PublicationResource,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_resources_round_trip_through_the_journal() {
        for resource in [
            PublicationResource::KopiaSourcePath("/b/.staging/i/.x.bundle".to_string()),
            PublicationResource::S3MultipartUpload {
                key: "dbev/instances/i/backups/a".to_string(),
                upload_id: "VXBsb2FkIElE".to_string(),
            },
        ] {
            let (kind, locator, detail) = resource.journal_parts();
            assert_eq!(
                PublicationResource::from_journal(kind, locator, detail).unwrap(),
                resource
            );
        }
        for (kind, locator, detail) in [
            ("kopia_source_path", "", ""),
            ("kopia_source_path", "/x", "extra"),
            ("s3_multipart_upload", "key", ""),
            ("surprise", "a", "b"),
        ] {
            assert!(PublicationResource::from_journal(kind, locator, detail).is_err());
        }
    }
}
