use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use secrecy::SecretString;
use tokio::sync::RwLock;

use super::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus};
use crate::shared::{backend::BackendEndpoint, protocol::Protocol};

#[derive(Debug, Clone)]
pub struct RouteTarget {
    pub instance_id: String,
    pub endpoint: BackendEndpoint,
}

#[derive(Debug, Clone)]
pub struct MariadbRouteTarget {
    pub instance_id: String,
    pub endpoint: BackendEndpoint,
    pub native_password_sha1_stage2: Option<String>,
    pub tenant_password: Option<SecretString>,
}

#[derive(Debug, Clone)]
pub enum DatabaseRouteResolution<T> {
    Found { database: String, target: T },
    NotFound,
    Ambiguous,
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

    /// Temporarily removes every gateway lookup for an instance while keeping
    /// its metadata available to lifecycle and recovery code. The caller must
    /// hold the per-instance operation lock and republish through `upsert`
    /// only after the runtime is ready and its durable state is settled.
    pub(crate) async fn fence_routes(&self, instance_id: &str) -> bool {
        let mut state = self.inner.write().await;
        if !state.instances.contains_key(instance_id) {
            return false;
        }
        state.remove_routes_for(instance_id);
        state.fenced_instances.insert(instance_id.to_string());
        true
    }

    pub(crate) async fn routes_fenced(&self, instance_id: &str) -> bool {
        self.inner
            .read()
            .await
            .fenced_instances
            .contains(instance_id)
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
        database: Option<&str>,
    ) -> DatabaseRouteResolution<RouteTarget> {
        let state = self.inner.read().await;
        resolve_plain_database_route(&state, &state.postgres_routes, username, database)
    }

    pub async fn resolve_redis(&self, username: &str) -> Option<RouteTarget> {
        let state = self.inner.read().await;
        let instance_id = state.redis_routes.get(username)?;
        state
            .instances
            .get(instance_id)
            .map(|metadata| RouteTarget {
                instance_id: metadata.instance_id.clone(),
                endpoint: metadata.backend.clone(),
            })
    }

    pub async fn resolve_redis_password(
        &self,
        password_sha256: &str,
    ) -> Option<(String, RouteTarget)> {
        let state = self.inner.read().await;
        resolve_password_route(&state, &state.redis_password_routes, password_sha256)
    }

    pub async fn resolve_valkey(&self, username: &str) -> Option<RouteTarget> {
        let state = self.inner.read().await;
        let instance_id = state.valkey_routes.get(username)?;
        state
            .instances
            .get(instance_id)
            .map(|metadata| RouteTarget {
                instance_id: metadata.instance_id.clone(),
                endpoint: metadata.backend.clone(),
            })
    }

    pub async fn resolve_valkey_password(
        &self,
        password_sha256: &str,
    ) -> Option<(String, RouteTarget)> {
        let state = self.inner.read().await;
        resolve_password_route(&state, &state.valkey_password_routes, password_sha256)
    }

    pub async fn resolve_mariadb(
        &self,
        username: &str,
        database: Option<&str>,
    ) -> DatabaseRouteResolution<MariadbRouteTarget> {
        let state = self.inner.read().await;
        resolve_mariadb_route(
            &state,
            &state.mariadb_routes,
            username,
            database,
            |metadata| metadata.mariadb_native_password_sha1_stage2.clone(),
        )
    }

    pub async fn resolve_mysql(
        &self,
        username: &str,
        database: Option<&str>,
    ) -> DatabaseRouteResolution<MariadbRouteTarget> {
        let state = self.inner.read().await;
        resolve_mariadb_route(
            &state,
            &state.mysql_routes,
            username,
            database,
            |metadata| metadata.mysql_native_password_sha1_stage2.clone(),
        )
    }

    pub async fn resolve_mongodb(&self, username: &str, database: &str) -> Option<RouteTarget> {
        let state = self.inner.read().await;
        let instance_id = state
            .mongodb_routes
            .get(&(username.to_string(), database.to_string()))?;
        state
            .instances
            .get(instance_id)
            .map(|metadata| RouteTarget {
                instance_id: metadata.instance_id.clone(),
                endpoint: metadata.backend.clone(),
            })
    }

    pub async fn resolve_clickhouse(
        &self,
        username: &str,
        database: Option<&str>,
    ) -> DatabaseRouteResolution<RouteTarget> {
        let state = self.inner.read().await;
        resolve_plain_database_route(&state, &state.clickhouse_routes, username, database)
    }

    pub async fn resolve_qdrant(&self, route_key_sha256: &str) -> Option<RouteTarget> {
        let state = self.inner.read().await;
        let instance_id = state.qdrant_routes.get(route_key_sha256)?;
        state
            .instances
            .get(instance_id)
            .map(|metadata| RouteTarget {
                instance_id: metadata.instance_id.clone(),
                endpoint: metadata.backend.clone(),
            })
    }
}

enum RouteKeyResolution<'a> {
    Found {
        database: &'a String,
        instance_id: &'a String,
    },
    NotFound,
    Ambiguous,
}

fn resolve_database_route<'a>(
    routes: &'a HashMap<(String, String), String>,
    username: &str,
    database: Option<&str>,
) -> RouteKeyResolution<'a> {
    if let Some(database) = database.filter(|database| !database.is_empty()) {
        let lookup = (username.to_string(), database.to_string());
        return routes.get_key_value(&lookup).map_or(
            RouteKeyResolution::NotFound,
            |((_, database), instance_id)| RouteKeyResolution::Found {
                database,
                instance_id,
            },
        );
    }

    let mut matches = routes
        .iter()
        .filter(|((route_username, _), _)| route_username == username);
    let Some(((_, database), instance_id)) = matches.next() else {
        return RouteKeyResolution::NotFound;
    };
    if matches.next().is_some() {
        return RouteKeyResolution::Ambiguous;
    }
    RouteKeyResolution::Found {
        database,
        instance_id,
    }
}

fn resolve_mariadb_route(
    state: &InstanceState,
    routes: &HashMap<(String, String), String>,
    username: &str,
    database: Option<&str>,
    verifier: impl FnOnce(&InstanceMetadata) -> Option<String>,
) -> DatabaseRouteResolution<MariadbRouteTarget> {
    match resolve_database_route(routes, username, database) {
        RouteKeyResolution::Found {
            database,
            instance_id,
        } => {
            state
                .instances
                .get(instance_id)
                .map_or(DatabaseRouteResolution::NotFound, |metadata| {
                    DatabaseRouteResolution::Found {
                        database: database.clone(),
                        target: MariadbRouteTarget {
                            instance_id: metadata.instance_id.clone(),
                            endpoint: metadata.backend.clone(),
                            native_password_sha1_stage2: verifier(metadata),
                            tenant_password: metadata
                                .tenant_password
                                .as_ref()
                                .map(|password| SecretString::from(password.clone())),
                        },
                    }
                })
        }
        RouteKeyResolution::NotFound => DatabaseRouteResolution::NotFound,
        RouteKeyResolution::Ambiguous => DatabaseRouteResolution::Ambiguous,
    }
}

fn resolve_plain_database_route(
    state: &InstanceState,
    routes: &HashMap<(String, String), String>,
    username: &str,
    database: Option<&str>,
) -> DatabaseRouteResolution<RouteTarget> {
    match resolve_database_route(routes, username, database) {
        RouteKeyResolution::Found {
            database,
            instance_id,
        } => {
            state
                .instances
                .get(instance_id)
                .map_or(DatabaseRouteResolution::NotFound, |metadata| {
                    DatabaseRouteResolution::Found {
                        database: database.clone(),
                        target: RouteTarget {
                            instance_id: metadata.instance_id.clone(),
                            endpoint: metadata.backend.clone(),
                        },
                    }
                })
        }
        RouteKeyResolution::NotFound => DatabaseRouteResolution::NotFound,
        RouteKeyResolution::Ambiguous => DatabaseRouteResolution::Ambiguous,
    }
}

#[derive(Debug, Default)]
struct InstanceState {
    instances: HashMap<String, InstanceMetadata>,
    fenced_instances: HashSet<String>,
    postgres_routes: HashMap<(String, String), String>,
    mariadb_routes: HashMap<(String, String), String>,
    mysql_routes: HashMap<(String, String), String>,
    mongodb_routes: HashMap<(String, String), String>,
    clickhouse_routes: HashMap<(String, String), String>,
    qdrant_routes: HashMap<String, String>,
    redis_routes: HashMap<String, String>,
    valkey_routes: HashMap<String, String>,
    redis_password_routes: HashMap<String, HashSet<String>>,
    valkey_password_routes: HashMap<String, HashSet<String>>,
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
        self.fenced_instances.remove(&metadata.instance_id);
        if metadata.status != InstanceStatus::Running
            || metadata.desired_state != DesiredInstanceState::Running
        {
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
                if let Some(password) = metadata.tenant_password.as_deref() {
                    self.redis_password_routes
                        .entry(crate::protocols::redis::password_route_sha256(
                            password.as_bytes(),
                        ))
                        .or_default()
                        .insert(metadata.instance_id.clone());
                }
            }
            Protocol::Valkey => {
                self.valkey_routes.insert(
                    metadata.database.username.clone(),
                    metadata.instance_id.clone(),
                );
                if let Some(password) = metadata.tenant_password.as_deref() {
                    self.valkey_password_routes
                        .entry(crate::protocols::redis::password_route_sha256(
                            password.as_bytes(),
                        ))
                        .or_default()
                        .insert(metadata.instance_id.clone());
                }
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
        self.valkey_routes
            .retain(|_, routed_instance_id| routed_instance_id != instance_id);
        remove_password_route(&mut self.redis_password_routes, instance_id);
        remove_password_route(&mut self.valkey_password_routes, instance_id);
    }

    fn remove(&mut self, instance_id: &str) -> Option<InstanceMetadata> {
        self.remove_routes_for(instance_id);
        self.fenced_instances.remove(instance_id);
        self.instances.remove(instance_id)
    }
}

fn resolve_password_route(
    state: &InstanceState,
    routes: &HashMap<String, HashSet<String>>,
    password_sha256: &str,
) -> Option<(String, RouteTarget)> {
    let instance_ids = routes.get(password_sha256)?;
    if instance_ids.len() != 1 {
        return None;
    }
    let instance_id = instance_ids.iter().next()?;
    state.instances.get(instance_id).map(|metadata| {
        (
            metadata.database.username.clone(),
            RouteTarget {
                instance_id: metadata.instance_id.clone(),
                endpoint: metadata.backend.clone(),
            },
        )
    })
}

fn remove_password_route(routes: &mut HashMap<String, HashSet<String>>, instance_id: &str) {
    routes.retain(|_, instance_ids| {
        instance_ids.remove(instance_id);
        !instance_ids.is_empty()
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        instances::metadata::{
            DatabaseIdentity, PublicEndpoint, RuntimeKind, RuntimeMetadata, SCHEMA_VERSION,
        },
        shared::limits::InstanceLimits,
    };

    #[test]
    fn database_route_prefers_exact_names_and_infers_only_unique_usernames() {
        let mut routes = HashMap::new();
        routes.insert(
            ("app".to_string(), "primary".to_string()),
            "instance-primary".to_string(),
        );

        assert!(matches!(
            resolve_database_route(&routes, "app", Some("primary")),
            RouteKeyResolution::Found { database, .. } if database == "primary"
        ));
        assert!(matches!(
            resolve_database_route(&routes, "app", None),
            RouteKeyResolution::Found { database, .. } if database == "primary"
        ));

        routes.insert(
            ("app".to_string(), "secondary".to_string()),
            "instance-secondary".to_string(),
        );
        assert!(matches!(
            resolve_database_route(&routes, "app", None),
            RouteKeyResolution::Ambiguous
        ));
        assert!(matches!(
            resolve_database_route(&routes, "app", Some("primary")),
            RouteKeyResolution::Found { database, .. } if database == "primary"
        ));
        assert!(matches!(
            resolve_database_route(&routes, "unknown", None),
            RouteKeyResolution::NotFound
        ));
    }

    #[tokio::test]
    async fn password_only_resp_routing_is_unique_and_updates_after_rotation_or_removal() {
        let store = InstanceStore::default();
        let first = resp_metadata("inst_first", "first", "shared-secret");
        let second = resp_metadata("inst_second", "second", "shared-secret");
        store.upsert(first.clone()).await;
        let hash = crate::protocols::redis::password_route_sha256(b"shared-secret");
        assert_eq!(
            store.resolve_redis_password(&hash).await.unwrap().0,
            "first"
        );

        store.upsert(second).await;
        assert!(store.resolve_redis_password(&hash).await.is_none());

        store.remove("inst_second").await;
        assert_eq!(
            store.resolve_redis_password(&hash).await.unwrap().0,
            "first"
        );

        let mut rotated = first;
        rotated.tenant_password = Some("rotated-secret".to_string());
        store.upsert(rotated).await;
        assert!(store.resolve_redis_password(&hash).await.is_none());
        let rotated_hash = crate::protocols::redis::password_route_sha256(b"rotated-secret");
        assert_eq!(
            store.resolve_redis_password(&rotated_hash).await.unwrap().0,
            "first"
        );
    }

    #[tokio::test]
    async fn route_fence_keeps_metadata_but_blocks_connections_until_republished() {
        let store = InstanceStore::default();
        let metadata = resp_metadata("inst_fenced", "tenant", "secret");
        let password_hash = crate::protocols::redis::password_route_sha256(b"secret");
        store.upsert(metadata.clone()).await;
        assert!(store.resolve_redis("tenant").await.is_some());
        assert!(store.resolve_redis_password(&password_hash).await.is_some());

        assert!(store.fence_routes("inst_fenced").await);
        assert!(store.routes_fenced("inst_fenced").await);
        assert!(store.get("inst_fenced").await.is_some());
        assert!(store.resolve_redis("tenant").await.is_none());
        assert!(store.resolve_redis_password(&password_hash).await.is_none());

        store.upsert(metadata).await;
        assert!(!store.routes_fenced("inst_fenced").await);
        assert!(store.resolve_redis("tenant").await.is_some());
        assert!(store.resolve_redis_password(&password_hash).await.is_some());
        assert!(!store.fence_routes("missing").await);
    }

    fn resp_metadata(instance_id: &str, username: &str, password: &str) -> InstanceMetadata {
        InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: instance_id.to_string(),
            protocol: Protocol::Redis,
            status: InstanceStatus::Running,
            desired_state: DesiredInstanceState::Running,
            disk_limit_blocked: false,
            public: PublicEndpoint {
                host: "db.example.test".to_string(),
                port: 6379,
            },
            backend: BackendEndpoint::UnixSocket {
                socket_path: format!("/run/dbev/{instance_id}.sock"),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: format!("dbe-redis-{instance_id}"),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: "0".to_string(),
                username: username.to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mysql_native_password_sha1_stage2: None,
            mysql_root_password: None,
            mongodb_root_password: None,
            postgres_admin_password: None,
            tenant_password: Some(password.to_string()),
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-08-19T00:00:00Z".to_string(),
            updated_at: "2026-08-19T00:00:00Z".to_string(),
        }
    }
}
