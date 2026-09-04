use super::{metadata::InstanceMetadata, state::InstanceStore};
use crate::runtime::docker::ManagedContainerIdentity;
use crate::storage::repositories::{CompatibilityAttestation, InstanceRepository, RepositoryError};

#[derive(Clone)]
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
        let encrypted_rows = self.repository.rewrite_route_auth(&metadata).await?;
        if encrypted_rows > 0 {
            tracing::info!(
                encrypted_rows,
                "encrypted protected route authentication metadata"
            );
        }
        self.store.replace_all(metadata).await;
        Ok(())
    }

    pub async fn upsert(&self, mut metadata: InstanceMetadata) -> Result<(), RepositoryError> {
        fill_runtime_id(&mut metadata);
        self.repository.upsert(&metadata).await?;
        self.store.upsert(metadata).await;
        Ok(())
    }

    /// Persists an intermediate mutation state without republishing its
    /// gateway routes. Callers must use [`Self::upsert`] only after engine
    /// access and credentials have been verified.
    pub(crate) async fn upsert_fenced(
        &self,
        mut metadata: InstanceMetadata,
    ) -> Result<(), RepositoryError> {
        fill_runtime_id(&mut metadata);
        self.repository.upsert(&metadata).await?;
        self.store.upsert_fenced(metadata).await;
        Ok(())
    }

    /// Persists pool-derived metadata while preserving the route's current
    /// open/fenced state. This prevents a runtime status transition from
    /// bypassing the tenant-specific quota and credential replay that owns
    /// route publication.
    pub(crate) async fn upsert_preserving_fence(
        &self,
        mut metadata: InstanceMetadata,
    ) -> Result<(), RepositoryError> {
        fill_runtime_id(&mut metadata);
        self.repository.upsert(&metadata).await?;
        self.store.upsert_preserving_fence(metadata).await;
        Ok(())
    }

    /// Commits live-verified replacement credentials and clears any protected
    /// secret recovery marker in the same durable transaction.
    pub(crate) async fn upsert_recovered_secrets(
        &self,
        mut metadata: InstanceMetadata,
    ) -> Result<(), RepositoryError> {
        fill_runtime_id(&mut metadata);
        self.repository.upsert_recovered_secrets(&metadata).await?;
        self.store.upsert(metadata).await;
        Ok(())
    }

    pub(crate) async fn stage_dedicated_admin_secrets(
        &self,
        target: &InstanceMetadata,
    ) -> Result<(), RepositoryError> {
        self.repository.stage_dedicated_admin_secrets(target).await
    }

    pub(crate) async fn clear_staged_admin_secrets(
        &self,
        instance_id: &str,
    ) -> Result<(), RepositoryError> {
        self.repository
            .clear_staged_admin_secrets(instance_id)
            .await
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

    pub(crate) async fn hardening_is_current(
        &self,
        metadata: &InstanceMetadata,
        identity: &ManagedContainerIdentity,
        hardening_revision: u32,
    ) -> Result<bool, RepositoryError> {
        self.repository
            .hardening_is_current(
                metadata,
                &identity.id,
                &identity.started_at,
                hardening_revision,
            )
            .await
    }

    pub(crate) async fn record_hardening_attestation(
        &self,
        metadata: &InstanceMetadata,
        identity: &ManagedContainerIdentity,
        hardening_revision: u32,
    ) -> Result<(), RepositoryError> {
        self.repository
            .record_hardening_attestation(
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

    pub(crate) async fn delete_compatibility(
        &self,
        instance_id: &str,
    ) -> Result<(), RepositoryError> {
        self.repository.delete_compatibility(instance_id).await
    }

    pub(crate) async fn record_compatibility(
        &self,
        attestation: &CompatibilityAttestation,
    ) -> Result<(), RepositoryError> {
        self.repository.record_compatibility(attestation).await
    }

    pub async fn delete(&self, instance_id: &str) -> Result<bool, RepositoryError> {
        let deleted = self.repository.delete(instance_id).await?;
        if deleted {
            self.store.remove(instance_id).await;
        }
        Ok(deleted)
    }
}

fn fill_runtime_id(metadata: &mut InstanceMetadata) {
    if metadata.deployment_mode == crate::placement::DeploymentMode::Dedicated
        && metadata.runtime_id.is_empty()
    {
        metadata.runtime_id.clone_from(&metadata.instance_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        instances::metadata::InstanceMetadata, shared::limits::InstanceLimits, storage::sqlite,
    };

    #[tokio::test]
    async fn upsert_fills_legacy_dedicated_runtime_id_in_memory() {
        let directory = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(directory.path()).await.unwrap();
        let store = InstanceStore::default();
        let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool));
        let metadata: InstanceMetadata = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "instance_id": "dedicated-one",
            "protocol": "postgres",
            "status": "running",
            "public": {"host": "db.example.com", "port": 5432},
            "backend": {"kind": "unix_socket", "socket_path": "/run/postgres.sock"},
            "runtime": {"kind": "docker", "container_name": "dedicated-one", "network_mode": "none"},
            "database": {"name": "app", "username": "app"},
            "limits": InstanceLimits::default(),
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        }))
        .unwrap();

        manager.upsert(metadata).await.unwrap();

        let stored = store.get("dedicated-one").await.unwrap();
        assert_eq!(stored.runtime_id, "dedicated-one");
        assert_eq!(
            serde_json::to_value(stored).unwrap()["runtime_id"],
            "dedicated-one"
        );
    }
}
