use super::{metadata::InstanceMetadata, state::InstanceStore};
use crate::runtime::docker::ManagedContainerIdentity;
use crate::storage::repositories::{CompatibilityAttestation, InstanceRepository, RepositoryError};

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

    /// Commits live-verified replacement credentials and clears any protected
    /// secret recovery marker in the same durable transaction.
    pub(crate) async fn upsert_recovered_protected_secrets(
        &self,
        metadata: InstanceMetadata,
    ) -> Result<(), RepositoryError> {
        self.repository
            .upsert_recovered_protected_secrets(&metadata)
            .await?;
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

    pub(crate) async fn auth_hardening_attestation_is_current(
        &self,
        metadata: &InstanceMetadata,
        identity: &ManagedContainerIdentity,
        hardening_revision: u32,
    ) -> Result<bool, RepositoryError> {
        self.repository
            .auth_hardening_attestation_is_current(
                metadata,
                &identity.id,
                &identity.started_at,
                hardening_revision,
            )
            .await
    }

    pub(crate) async fn record_auth_hardening_attestation(
        &self,
        metadata: &InstanceMetadata,
        identity: &ManagedContainerIdentity,
        hardening_revision: u32,
    ) -> Result<(), RepositoryError> {
        self.repository
            .record_auth_hardening_attestation(
                metadata,
                &identity.id,
                &identity.started_at,
                hardening_revision,
            )
            .await
    }

    pub(crate) async fn compatibility_attestation(
        &self,
        instance_id: &str,
    ) -> Result<Option<CompatibilityAttestation>, RepositoryError> {
        self.repository.compatibility_attestation(instance_id).await
    }

    pub(crate) async fn delete_compatibility_attestation(
        &self,
        instance_id: &str,
    ) -> Result<(), RepositoryError> {
        self.repository
            .delete_compatibility_attestation(instance_id)
            .await
    }

    pub(crate) async fn record_compatibility_attestation(
        &self,
        attestation: &CompatibilityAttestation,
    ) -> Result<(), RepositoryError> {
        self.repository
            .record_compatibility_attestation(attestation)
            .await
    }

    pub async fn delete(&self, instance_id: &str) -> Result<bool, RepositoryError> {
        let deleted = self.repository.delete(instance_id).await?;
        if deleted {
            self.store.remove(instance_id).await;
        }
        Ok(deleted)
    }
}
