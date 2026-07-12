use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;

use super::metadata::{InstanceMetadata, InstanceStatus};
use crate::shared::{backend::BackendEndpoint, protocol::Protocol};

#[derive(Debug, Clone)]
pub struct MariadbRouteTarget {
    pub endpoint: BackendEndpoint,
    pub native_password_sha1_stage2: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct InstanceStore {
    inner: Arc<RwLock<InstanceState>>,
}

impl InstanceStore {
    pub async fn replace_all(&self, instances: Vec<InstanceMetadata>) {
        let mut state = self.inner.write().await;
        *state = InstanceState::from_instances(instances);
    }

    pub async fn upsert(&self, metadata: InstanceMetadata) {
        let mut state = self.inner.write().await;
        state.upsert(metadata);
    }

    pub async fn remove(&self, instance_id: &str) -> Option<InstanceMetadata> {
        let mut state = self.inner.write().await;
        state.remove(instance_id)
    }

    pub async fn list(&self) -> Vec<InstanceMetadata> {
        self.inner
            .read()
            .await
            .instances
            .values()
            .cloned()
            .collect()
    }

    pub async fn get(&self, instance_id: &str) -> Option<InstanceMetadata> {
        self.inner.read().await.instances.get(instance_id).cloned()
    }

    pub async fn resolve_postgres(
        &self,
        username: &str,
        database: &str,
    ) -> Option<BackendEndpoint> {
        let state = self.inner.read().await;
        let instance_id = state
            .postgres_routes
            .get(&(username.to_string(), database.to_string()))?;
        state
            .instances
            .get(instance_id)
            .map(|metadata| metadata.backend.clone())
    }

    pub async fn resolve_redis(&self, username: &str) -> Option<BackendEndpoint> {
        let state = self.inner.read().await;
        let instance_id = state.redis_routes.get(username)?;
        state
            .instances
            .get(instance_id)
            .map(|metadata| metadata.backend.clone())
    }

    pub async fn resolve_mariadb(
        &self,
        username: &str,
        database: &str,
    ) -> Option<MariadbRouteTarget> {
        let state = self.inner.read().await;
        let instance_id = state
            .mariadb_routes
            .get(&(username.to_string(), database.to_string()))?;
        let metadata = state.instances.get(instance_id)?;
        Some(MariadbRouteTarget {
            endpoint: metadata.backend.clone(),
            native_password_sha1_stage2: metadata.mariadb_native_password_sha1_stage2.clone(),
        })
    }

    pub async fn resolve_mysql(
        &self,
        username: &str,
        database: &str,
    ) -> Option<MariadbRouteTarget> {
        let state = self.inner.read().await;
        let instance_id = state
            .mysql_routes
            .get(&(username.to_string(), database.to_string()))?;
        let metadata = state.instances.get(instance_id)?;
        Some(MariadbRouteTarget {
            endpoint: metadata.backend.clone(),
            native_password_sha1_stage2: metadata.mysql_native_password_sha1_stage2.clone(),
        })
    }

    pub async fn resolve_mongodb(&self, username: &str, database: &str) -> Option<BackendEndpoint> {
        let state = self.inner.read().await;
        let instance_id = state
            .mongodb_routes
            .get(&(username.to_string(), database.to_string()))?;
        state
            .instances
            .get(instance_id)
            .map(|metadata| metadata.backend.clone())
    }

    pub async fn resolve_clickhouse(
        &self,
        username: &str,
        database: &str,
    ) -> Option<BackendEndpoint> {
        let state = self.inner.read().await;
        let instance_id = state
            .clickhouse_routes
            .get(&(username.to_string(), database.to_string()))?;
        state
            .instances
            .get(instance_id)
            .map(|metadata| metadata.backend.clone())
    }

    pub async fn resolve_qdrant(&self, route_key_sha256: &str) -> Option<BackendEndpoint> {
        let state = self.inner.read().await;
        let instance_id = state.qdrant_routes.get(route_key_sha256)?;
        state
            .instances
            .get(instance_id)
            .map(|metadata| metadata.backend.clone())
    }
}

#[derive(Debug, Default)]
struct InstanceState {
    instances: HashMap<String, InstanceMetadata>,
    postgres_routes: HashMap<(String, String), String>,
    mariadb_routes: HashMap<(String, String), String>,
    mysql_routes: HashMap<(String, String), String>,
    mongodb_routes: HashMap<(String, String), String>,
    clickhouse_routes: HashMap<(String, String), String>,
    qdrant_routes: HashMap<String, String>,
    redis_routes: HashMap<String, String>,
}

impl InstanceState {
    fn from_instances(instances: Vec<InstanceMetadata>) -> Self {
        let mut state = Self::default();
        for metadata in instances {
            state.upsert(metadata);
        }
        state
    }

    fn upsert(&mut self, metadata: InstanceMetadata) {
        self.remove_routes_for(&metadata.instance_id);
        if metadata.status != InstanceStatus::Running {
            self.instances
                .insert(metadata.instance_id.clone(), metadata);
            return;
        }
        match metadata.protocol {
            Protocol::Postgres => {
                self.postgres_routes.insert(
                    (
                        metadata.database.username.clone(),
                        metadata.database.name.clone(),
                    ),
                    metadata.instance_id.clone(),
                );
            }
            Protocol::Redis => {
                self.redis_routes.insert(
                    metadata.database.username.clone(),
                    metadata.instance_id.clone(),
                );
            }
            Protocol::Mariadb => {
                self.mariadb_routes.insert(
                    (
                        metadata.database.username.clone(),
                        metadata.database.name.clone(),
                    ),
                    metadata.instance_id.clone(),
                );
            }
            Protocol::Mysql => {
                self.mysql_routes.insert(
                    (
                        metadata.database.username.clone(),
                        metadata.database.name.clone(),
                    ),
                    metadata.instance_id.clone(),
                );
            }
            Protocol::Mongodb => {
                self.mongodb_routes.insert(
                    (
                        metadata.database.username.clone(),
                        metadata.database.name.clone(),
                    ),
                    metadata.instance_id.clone(),
                );
            }
            Protocol::Clickhouse => {
                self.clickhouse_routes.insert(
                    (
                        metadata.database.username.clone(),
                        metadata.database.name.clone(),
                    ),
                    metadata.instance_id.clone(),
                );
            }
            Protocol::Qdrant => {
                if let Some(route_key_sha256) = &metadata.route_key_sha256 {
                    self.qdrant_routes
                        .insert(route_key_sha256.clone(), metadata.instance_id.clone());
                }
            }
        }
        self.instances
            .insert(metadata.instance_id.clone(), metadata);
    }

    fn remove_routes_for(&mut self, instance_id: &str) {
        self.postgres_routes
            .retain(|_, routed_instance_id| routed_instance_id != instance_id);
        self.mariadb_routes
            .retain(|_, routed_instance_id| routed_instance_id != instance_id);
        self.mysql_routes
            .retain(|_, routed_instance_id| routed_instance_id != instance_id);
        self.mongodb_routes
            .retain(|_, routed_instance_id| routed_instance_id != instance_id);
        self.clickhouse_routes
            .retain(|_, routed_instance_id| routed_instance_id != instance_id);
        self.qdrant_routes
            .retain(|_, routed_instance_id| routed_instance_id != instance_id);
        self.redis_routes
            .retain(|_, routed_instance_id| routed_instance_id != instance_id);
    }

    fn remove(&mut self, instance_id: &str) -> Option<InstanceMetadata> {
        self.remove_routes_for(instance_id);
        self.instances.remove(instance_id)
    }
}
