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
    pub instance_generation: String,
    pub endpoint: BackendEndpoint,
    pub connection_limit: Option<usize>,
    pub(crate) route_revision: u64,
}

#[derive(Clone)]
pub struct MariadbRouteTarget {
    pub instance_id: String,
    pub instance_generation: String,
    pub endpoint: BackendEndpoint,
    pub shared: bool,
    pub native_password_sha1_stage2: Option<String>,
    pub tenant_password: Option<SecretString>,
    pub connection_limit: Option<usize>,
    pub(crate) route_revision: u64,
}

fn connection_limit(metadata: &InstanceMetadata) -> Option<usize> {
    (metadata.deployment_mode == crate::placement::DeploymentMode::Shared)
        .then(|| crate::placement::policy::max_connections(&metadata.limits) as usize)
}

#[derive(Debug, Clone)]
pub enum DatabaseRouteResolution<T> {
    Found { database: String, target: T },
    NotFound,
    Ambiguous,
}

#[derive(Clone, Default)]
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

    /// Replaces cached metadata while keeping every gateway route fenced.
    /// Mutation code uses this after durable intermediate commits and calls
    /// [`Self::upsert`] only after engine access and credentials are verified.
    pub(crate) async fn upsert_fenced(&self, metadata: InstanceMetadata) {
        let mut state = self.inner.write().await;
        state.upsert_fenced(metadata);
    }

    /// Replaces cached metadata without changing whether the tenant is
    /// currently reachable through a gateway route. Runtime reconciliation
    /// uses this while propagating pool status: an already-open tenant may
    /// stay open, while a stopped or explicitly fenced tenant cannot become
    /// reachable merely because its container changed to `Running`.
    pub(crate) async fn upsert_preserving_fence(&self, metadata: InstanceMetadata) {
        let mut state = self.inner.write().await;
        state.upsert_preserving_fence(metadata);
    }

    /// Publishes metadata after the durable operation that owned a pinned
    /// recovery fence has reached a terminal state. Callers must verify the
    /// runtime and its credential before opening the route.
    pub(crate) async fn open_routes(&self, metadata: InstanceMetadata) {
        let mut state = self.inner.write().await;
        state.pinned_fences.remove(&metadata.instance_id);
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
        state.bump_route_revision(instance_id);
        state.remove_routes_for(instance_id);
        state.fenced_instances.insert(instance_id.to_string());
        true
    }

    /// Fences a route until the instance is removed or the daemon rebuilds
    /// its store from durable state. Ordinary metadata upserts cannot clear a
    /// pinned recovery fence.
    pub(crate) async fn pin_routes_fenced(&self, instance_id: &str) -> bool {
        let mut state = self.inner.write().await;
        if !state.instances.contains_key(instance_id) {
            return false;
        }
        state.bump_route_revision(instance_id);
        state.remove_routes_for(instance_id);
        state.fenced_instances.insert(instance_id.to_string());
        state.pinned_fences.insert(instance_id.to_string());
        true
    }

    /// Confirms that a route resolved before an async boundary still refers to
    /// the currently published tenant identity. Lifecycle fencing and every
    /// metadata republish advance this revision before changing route maps.
    pub(crate) async fn route_is_current(&self, instance_id: &str, revision: u64) -> bool {
        let state = self.inner.read().await;
        !state.fenced_instances.contains(instance_id)
            && state.route_revisions.get(instance_id) == Some(&revision)
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
        resolve_plain_route(&state, &state.postgres_routes, username, database)
    }

    pub async fn resolve_redis(&self, username: &str) -> Option<RouteTarget> {
        let state = self.inner.read().await;
        let instance_id = state.redis_routes.get(username)?;
        state
            .instances
            .get(instance_id)
            .map(|metadata| RouteTarget {
                instance_id: metadata.instance_id.clone(),
                instance_generation: metadata.created_at.clone(),
                endpoint: metadata.backend.clone(),
                connection_limit: connection_limit(metadata),
                route_revision: state.route_revision(instance_id),
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
                instance_generation: metadata.created_at.clone(),
                endpoint: metadata.backend.clone(),
                connection_limit: connection_limit(metadata),
                route_revision: state.route_revision(instance_id),
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
                instance_generation: metadata.created_at.clone(),
                endpoint: metadata.backend.clone(),
                connection_limit: connection_limit(metadata),
                route_revision: state.route_revision(instance_id),
            })
    }

    pub async fn resolve_clickhouse(
        &self,
        username: &str,
        database: Option<&str>,
    ) -> DatabaseRouteResolution<RouteTarget> {
        let state = self.inner.read().await;
        resolve_plain_route(&state, &state.clickhouse_routes, username, database)
    }

    pub async fn resolve_qdrant(&self, route_key_sha256: &str) -> Option<RouteTarget> {
        let state = self.inner.read().await;
        let instance_id = state.qdrant_routes.get(route_key_sha256)?;
        state
            .instances
            .get(instance_id)
            .map(|metadata| RouteTarget {
                instance_id: metadata.instance_id.clone(),
                instance_generation: metadata.created_at.clone(),
                endpoint: metadata.backend.clone(),
                connection_limit: connection_limit(metadata),
                route_revision: state.route_revision(instance_id),
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
                            instance_generation: metadata.created_at.clone(),
                            endpoint: metadata.backend.clone(),
                            shared: metadata.deployment_mode
                                == crate::placement::DeploymentMode::Shared,
                            native_password_sha1_stage2: verifier(metadata),
                            tenant_password: metadata
                                .tenant_password
                                .as_ref()
                                .map(|password| SecretString::from(password.clone())),
                            connection_limit: connection_limit(metadata),
                            route_revision: state.route_revision(instance_id),
                        },
                    }
                })
        }
        RouteKeyResolution::NotFound => DatabaseRouteResolution::NotFound,
        RouteKeyResolution::Ambiguous => DatabaseRouteResolution::Ambiguous,
    }
}

fn resolve_plain_route(
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
                            instance_generation: metadata.created_at.clone(),
                            endpoint: metadata.backend.clone(),
                            connection_limit: connection_limit(metadata),
                            route_revision: state.route_revision(instance_id),
                        },
                    }
                })
        }
        RouteKeyResolution::NotFound => DatabaseRouteResolution::NotFound,
        RouteKeyResolution::Ambiguous => DatabaseRouteResolution::Ambiguous,
    }
}

#[derive(Default)]
struct InstanceState {
    instances: HashMap<String, InstanceMetadata>,
    fenced_instances: HashSet<String>,
    pinned_fences: HashSet<String>,
    route_revisions: HashMap<String, u64>,
    next_route_revision: u64,
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

fn route_eligible(metadata: &InstanceMetadata) -> bool {
    metadata.status == InstanceStatus::Running
        && metadata.desired_state == DesiredInstanceState::Running
        && !metadata.disk_limit_blocked
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
        self.bump_route_revision(&metadata.instance_id);
        self.remove_routes_for(&metadata.instance_id);
        if self.pinned_fences.contains(&metadata.instance_id) {
            self.fenced_instances.insert(metadata.instance_id.clone());
            self.instances
                .insert(metadata.instance_id.clone(), metadata);
            return;
        }
        self.fenced_instances.remove(&metadata.instance_id);
        if !route_eligible(&metadata) {
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

    fn upsert_fenced(&mut self, metadata: InstanceMetadata) {
        self.bump_route_revision(&metadata.instance_id);
        self.remove_routes_for(&metadata.instance_id);
        self.fenced_instances.insert(metadata.instance_id.clone());
        self.instances
            .insert(metadata.instance_id.clone(), metadata);
    }

    fn upsert_preserving_fence(&mut self, metadata: InstanceMetadata) {
        let was_open = self
            .instances
            .get(&metadata.instance_id)
            .is_some_and(route_eligible)
            && !self.fenced_instances.contains(&metadata.instance_id);
        if was_open {
            self.upsert(metadata);
        } else {
            self.upsert_fenced(metadata);
        }
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
        self.bump_route_revision(instance_id);
        self.remove_routes_for(instance_id);
        self.fenced_instances.remove(instance_id);
        self.pinned_fences.remove(instance_id);
        self.route_revisions.remove(instance_id);
        self.instances.remove(instance_id)
    }

    fn bump_route_revision(&mut self, instance_id: &str) {
        self.next_route_revision = self.next_route_revision.wrapping_add(1).max(1);
        self.route_revisions
            .insert(instance_id.to_string(), self.next_route_revision);
    }

    fn route_revision(&self, instance_id: &str) -> u64 {
        self.route_revisions
            .get(instance_id)
            .copied()
            .unwrap_or_default()
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
                instance_generation: metadata.created_at.clone(),
                endpoint: metadata.backend.clone(),
                connection_limit: connection_limit(metadata),
                route_revision: state.route_revision(instance_id),
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
    use crate::{instances::test_support, shared::backend::BackendEndpoint};

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

    #[tokio::test]
    async fn fenced_upsert_never_publishes_running_metadata() {
        let store = InstanceStore::default();
        let mut metadata = resp_metadata("inst_mutating", "tenant", "secret");
        store.upsert(metadata.clone()).await;
        assert!(store.resolve_redis("tenant").await.is_some());

        metadata.updated_at = "2026-08-19T00:01:00Z".to_string();
        store.upsert_fenced(metadata.clone()).await;

        assert!(store.routes_fenced("inst_mutating").await);
        assert!(store.resolve_redis("tenant").await.is_none());
        assert_eq!(
            store.get("inst_mutating").await.unwrap().updated_at,
            metadata.updated_at
        );

        store.upsert(metadata).await;
        assert!(!store.routes_fenced("inst_mutating").await);
        assert!(store.resolve_redis("tenant").await.is_some());
    }

    #[tokio::test]
    async fn pinned_recovery_fence_survives_ordinary_metadata_upserts() {
        let store = InstanceStore::default();
        let metadata = resp_metadata("inst_pinned", "pinned", "secret");
        store.upsert(metadata.clone()).await;
        assert!(store.resolve_redis("pinned").await.is_some());

        assert!(store.pin_routes_fenced("inst_pinned").await);
        store.upsert(metadata.clone()).await;
        assert!(store.routes_fenced("inst_pinned").await);
        assert!(store.resolve_redis("pinned").await.is_none());

        store.open_routes(metadata).await;
        assert!(!store.routes_fenced("inst_pinned").await);
        assert!(store.resolve_redis("pinned").await.is_some());
    }

    #[tokio::test]
    async fn runtime_metadata_updates_preserve_existing_route_state() {
        let store = InstanceStore::default();
        let mut open = resp_metadata("inst_open", "open", "secret");
        store.upsert(open.clone()).await;
        open.updated_at = "2026-08-19T00:01:00Z".to_string();
        store.upsert_preserving_fence(open).await;
        assert!(store.resolve_redis("open").await.is_some());

        let mut stopped = resp_metadata("inst_stopped", "stopped", "secret");
        stopped.status = InstanceStatus::Stopped;
        store.upsert(stopped.clone()).await;
        stopped.status = InstanceStatus::Running;
        store.upsert_preserving_fence(stopped).await;
        assert!(store.routes_fenced("inst_stopped").await);
        assert!(store.resolve_redis("stopped").await.is_none());

        let mut fenced = resp_metadata("inst_fenced_update", "fenced", "secret");
        store.upsert(fenced.clone()).await;
        store.fence_routes("inst_fenced_update").await;
        fenced.updated_at = "2026-08-19T00:02:00Z".to_string();
        store.upsert_preserving_fence(fenced).await;
        assert!(store.routes_fenced("inst_fenced_update").await);
        assert!(store.resolve_redis("fenced").await.is_none());
    }

    #[tokio::test]
    async fn resolved_route_revision_expires_on_fence_and_republish() {
        let store = InstanceStore::default();
        let metadata = resp_metadata("inst_revision", "tenant", "secret");
        store.upsert(metadata.clone()).await;
        let original = store.resolve_redis("tenant").await.unwrap();
        assert_eq!(
            original.connection_limit, None,
            "dedicated routes must keep their existing gateway connection behavior"
        );
        assert!(
            store
                .route_is_current("inst_revision", original.route_revision)
                .await
        );

        store.fence_routes("inst_revision").await;
        assert!(
            !store
                .route_is_current("inst_revision", original.route_revision)
                .await
        );

        store.upsert(metadata).await;
        let replacement = store.resolve_redis("tenant").await.unwrap();
        assert_ne!(original.route_revision, replacement.route_revision);
        assert!(
            !store
                .route_is_current("inst_revision", original.route_revision)
                .await
        );
        assert!(
            store
                .route_is_current("inst_revision", replacement.route_revision)
                .await
        );
    }

    #[tokio::test]
    async fn durable_disk_block_never_republishes_a_gateway_route() {
        let store = InstanceStore::default();
        let mut metadata = resp_metadata("inst_full", "tenant", "secret");
        metadata.disk_limit_blocked = true;

        store.upsert(metadata.clone()).await;
        assert!(store.get("inst_full").await.is_some());
        assert!(store.resolve_redis("tenant").await.is_none());

        metadata.disk_limit_blocked = false;
        store.upsert(metadata).await;
        assert!(store.resolve_redis("tenant").await.is_some());
    }

    fn resp_metadata(instance_id: &str, username: &str, password: &str) -> InstanceMetadata {
        let mut metadata = test_support::metadata(instance_id, Protocol::Redis);
        metadata.backend = BackendEndpoint::UnixSocket {
            socket_path: format!("/run/dbev/{instance_id}.sock"),
        };
        metadata.database.name = "0".to_string();
        metadata.database.username = username.to_string();
        metadata.tenant_password = Some(password.to_string());
        metadata
    }
}
