pub mod kopia;
pub mod local;
pub mod s3;

use futures::future::BoxFuture;

use super::{BackupBundle, BackupStoreError, StoredBackup};

/// Common provider operations behind the storage facade.
///
/// Providers retain their validation and publication rules. The facade owns
/// inventory ordering; materialization and instance purging remain separate
/// because their resource ownership and cleanup semantics differ by provider.
pub(crate) trait BackupDriver: Send + Sync {
    fn preflight(&self) -> BoxFuture<'_, Result<(), BackupStoreError>>;

    fn commit<'a>(
        &'a self,
        bundle: &'a BackupBundle,
        manifest: &'a StoredBackup,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>>;

    fn list<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<StoredBackup>, BackupStoreError>>;

    fn find<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
    ) -> BoxFuture<'a, Result<StoredBackup, BackupStoreError>>;

    fn delete<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>>;
}
