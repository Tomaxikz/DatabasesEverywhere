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
        let metadata = self.repository.list().await?;
        self.store.replace_all(metadata).await;
        Ok(())
    }

    pub async fn upsert(&self, metadata: InstanceMetadata) -> Result<(), RepositoryError> {
        self.repository.upsert(&metadata).await?;
        self.store.upsert(metadata).await;
        Ok(())
    }

    pub async fn delete(&self, instance_id: &str) -> Result<bool, RepositoryError> {
        let deleted = self.repository.delete(instance_id).await?;
        if deleted {
            self.store.remove(instance_id).await;
        }
        Ok(deleted)
    }
}
