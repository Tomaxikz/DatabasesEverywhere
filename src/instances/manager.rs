use super::{metadata::InstanceMetadata, state::InstanceStore};
use crate::storage::repositories::{InstanceRepository, RepositoryError};

#[derive(Debug, Clone)]
pub struct InstanceManager {
    store: InstanceStore,
    repository: InstanceRepository,
}

impl InstanceManager {
    pub fn new(store: InstanceStore, repository: InstanceRepository) -> Self {
        Self { store, repository }
    }

    pub fn store(&self) -> InstanceStore {
        self.store.clone()
    }

    pub async fn load_from_storage(&self) -> Result<(), RepositoryError> {
        let loaded = self.repository.load_for_daemon().await?;
        for incident in &loaded.protected_secret_incidents {
            let fields = incident
                .fields
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            tracing::error!(
                event = "audit protected_secret_recovery_required",
                instance_id = %incident.instance_id,
                %fields,
                "quarantined an instance with invalid or ambiguous protected metadata; use the offline repair-protected-secret command with the known original value"
            );
        }
        let metadata = loaded.metadata;
        let encrypted_rows = self
            .repository
            .rewrite_protected_route_auth(&metadata)
            .await?;
        if encrypted_rows > 0 {
            tracing::info!(
                encrypted_rows,
                "encrypted protected route authentication metadata"
            );
        }
        self.store.replace_all(metadata).await;
        Ok(())
    }

    pub async fn upsert(&self, metadata: InstanceMetadata) -> Result<(), RepositoryError> {
        self.repository.upsert(&metadata).await?;
        self.store.upsert(metadata).await;
        Ok(())
    }

    /// Read the durable metadata directly instead of consulting the in-memory
    /// route store. Mutation recovery uses this after an SQLite commit returns
    /// an error: the transaction may have committed even though its
    /// acknowledgement was lost, while the store is updated only on `Ok`.
    pub async fn get_persisted(
        &self,
        instance_id: &str,
    ) -> Result<Option<InstanceMetadata>, RepositoryError> {
        self.repository.get(instance_id).await
    }

    pub async fn delete(&self, instance_id: &str) -> Result<bool, RepositoryError> {
        let deleted = self.repository.delete(instance_id).await?;
        if deleted {
            self.store.remove(instance_id).await;
        }
        Ok(deleted)
    }
}
