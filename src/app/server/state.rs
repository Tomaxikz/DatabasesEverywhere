use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use secrecy::SecretString;
use tokio::sync::RwLock;

use super::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus};
use super::placement::DeploymentMode;
use crate::{databases::protocol::Protocol, utils::backend::BackendEndpoint};

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
    (metadata.deployment_mode == crate::server::placement::DeploymentMode::Shared)
        .then(|| crate::server::placement::policy::max_connections(&metadata.limits) as usize)
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

    /// Replaces cached metadata keeping every route fenced; call `upsert` only after access is verified.
    pub(crate) async fn upsert_fenced(&self, metadata: InstanceMetadata) {
        let mut state = self.inner.write().await;
        state.upsert_fenced(metadata);
    }

    /// Replaces cached metadata without changing route reachability: open stays open, fenced doesn't open just because the container is `Running`.
    pub(crate) async fn upsert_preserving_fence(&self, metadata: InstanceMetadata) {
        let mut state = self.inner.write().await;
        state.upsert_preserving_fence(metadata);
    }

    /// Publishes metadata once the operation owning a pinned recovery fence is terminal; verify runtime and credential first.
    pub(crate) async fn open_routes(&self, metadata: InstanceMetadata) {
        let mut state = self.inner.write().await;
        state.pinned_fences.remove(&metadata.instance_id);
        state.upsert(metadata);
    }

    pub async fn remove(&self, instance_id: &str) -> Option<InstanceMetadata> {
        let mut state = self.inner.write().await;
        state.remove(instance_id)
    }

    /// Temporarily removes gateway lookups but keeps metadata; caller holds the operation lock and republishes via `upsert` once settled.
    pub(crate) async fn fence_routes(&self, instance_id: &str) -> bool {
        let mut state = self.inner.write().await;
        state.fence_existing(instance_id)
    }

    /// Fences a route until removal or store rebuild; ordinary upserts can't clear a pinned fence.
    pub(crate) async fn pin_routes_fenced(&self, instance_id: &str) -> bool {
        let mut state = self.inner.write().await;
        if !state.fence_existing(instance_id) {
            return false;
        }
        state.pinned_fences.insert(instance_id.to_string());
        true
    }

    /// Confirms a route resolved before an await still matches the published tenant identity; fencing and republish advance the revision.
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
            .map(|metadata| metadata.as_ref().clone())
            .collect()
    }

    pub async fn get(&self, instance_id: &str) -> Option<InstanceMetadata> {
        self.snapshot(instance_id).await.map(Arc::unwrap_or_clone)
    }

    pub(crate) async fn snapshot(&self, instance_id: &str) -> Option<Arc<InstanceMetadata>> {
        self.inner.read().await.instances.get(instance_id).cloned()
    }

    pub(crate) async fn snapshots_matching(
        &self,
        matches: impl Fn(&InstanceMetadata) -> bool,
    ) -> Vec<Arc<InstanceMetadata>> {
        self.inner
            .read()
            .await
            .instances
            .values()
            .filter(|metadata| matches(metadata))
            .cloned()
            .collect()
    }

    pub(crate) async fn shared_runtime_members(
        &self,
        runtime_id: &str,
    ) -> Vec<Arc<InstanceMetadata>> {
        let state = self.inner.read().await;
        state
            .shared_members
            .get(runtime_id)
            .into_iter()
            .flatten()
            .map(|id| Arc::clone(&state.instances[id]))
            .collect()
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
        state.route_target_for(state.redis_routes.get(username)?)
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
        state.route_target_for(state.valkey_routes.get(username)?)
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
            .by_username
            .get(username)?
            .get(database)?;
        state.route_target_for(instance_id)
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
        state.route_target_for(state.qdrant_routes.get(route_key_sha256)?)
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

#[derive(Default)]
struct DatabaseRoutes {
    by_username: HashMap<String, BTreeMap<String, String>>,
}

impl DatabaseRoutes {
    fn insert(&mut self, metadata: &InstanceMetadata) {
        self.by_username
            .entry(metadata.database.username.clone())
            .or_default()
            .insert(metadata.database.name.clone(), metadata.instance_id.clone());
    }

    fn remove(&mut self, metadata: &InstanceMetadata) {
        let username = &metadata.database.username;
        let Some(databases) = self.by_username.get_mut(username) else {
            return;
        };
        let database = &metadata.database.name;
        if databases.get(database) == Some(&metadata.instance_id) {
            databases.remove(database);
            if databases.is_empty() {
                self.by_username.remove(username);
            }
        }
    }

    fn resolve(&self, username: &str, database: Option<&str>) -> RouteKeyResolution<'_> {
        let Some(databases) = self.by_username.get(username) else {
            return RouteKeyResolution::NotFound;
        };
        let route = match database.filter(|name| !name.is_empty()) {
            Some(name) => databases.get_key_value(name),
            None if databases.len() > 1 => return RouteKeyResolution::Ambiguous,
            None => databases.first_key_value(),
        };
        match route {
            Some((database, instance_id)) => RouteKeyResolution::Found {
                database,
                instance_id,
            },
            None => RouteKeyResolution::NotFound,
        }
    }
}

fn resolve_mariadb_route(
    state: &InstanceState,
    routes: &DatabaseRoutes,
    username: &str,
    database: Option<&str>,
    verifier: impl FnOnce(&InstanceMetadata) -> Option<String>,
) -> DatabaseRouteResolution<MariadbRouteTarget> {
    resolve_database_target(
        state,
        routes,
        username,
        database,
        |instance_id, metadata| MariadbRouteTarget {
            instance_id: metadata.instance_id.clone(),
            instance_generation: metadata.created_at.clone(),
            endpoint: metadata.backend.clone(),
            shared: metadata.deployment_mode == crate::server::placement::DeploymentMode::Shared,
            native_password_sha1_stage2: verifier(metadata),
            tenant_password: metadata
                .tenant_password
                .as_ref()
                .map(|password| SecretString::from(password.clone())),
            connection_limit: connection_limit(metadata),
            route_revision: state.route_revision(instance_id),
        },
    )
}

fn resolve_plain_route(
    state: &InstanceState,
    routes: &DatabaseRoutes,
    username: &str,
    database: Option<&str>,
) -> DatabaseRouteResolution<RouteTarget> {
    resolve_database_target(
        state,
        routes,
        username,
        database,
        |instance_id, metadata| state.route_target(instance_id, metadata),
    )
}

fn resolve_database_target<T>(
    state: &InstanceState,
    routes: &DatabaseRoutes,
    username: &str,
    database: Option<&str>,
    build_target: impl FnOnce(&str, &InstanceMetadata) -> T,
) -> DatabaseRouteResolution<T> {
    match routes.resolve(username, database) {
        RouteKeyResolution::Found {
            database,
            instance_id,
        } => match state.instances.get(instance_id) {
            Some(metadata) => DatabaseRouteResolution::Found {
                database: database.clone(),
                target: build_target(instance_id, metadata),
            },
            None => DatabaseRouteResolution::NotFound,
        },
        RouteKeyResolution::NotFound => DatabaseRouteResolution::NotFound,
        RouteKeyResolution::Ambiguous => DatabaseRouteResolution::Ambiguous,
    }
}

#[derive(Default)]
struct InstanceState {
    instances: HashMap<String, Arc<InstanceMetadata>>,
    shared_members: HashMap<String, HashSet<String>>,
    fenced_instances: HashSet<String>,
    pinned_fences: HashSet<String>,
    route_revisions: HashMap<String, u64>,
    next_route_revision: u64,
    postgres_routes: DatabaseRoutes,
    mariadb_routes: DatabaseRoutes,
    mysql_routes: DatabaseRoutes,
    mongodb_routes: DatabaseRoutes,
    clickhouse_routes: DatabaseRoutes,
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
            self.store_metadata(metadata);
            return;
        }
        self.fenced_instances.remove(&metadata.instance_id);
        if route_eligible(&metadata) {
            self.publish_routes(&metadata);
        }
        self.store_metadata(metadata);
    }

    fn store_metadata(&mut self, metadata: InstanceMetadata) {
        let metadata = Arc::new(metadata);
        let previous = self
            .instances
            .insert(metadata.instance_id.clone(), Arc::clone(&metadata));
        if let Some(previous) = previous {
            if previous.deployment_mode == metadata.deployment_mode
                && previous.runtime_id() == metadata.runtime_id()
            {
                return;
            }
            self.remove_shared_member(&previous);
        }
        if metadata.deployment_mode == DeploymentMode::Shared {
            self.shared_members
                .entry(metadata.runtime_id().to_owned())
                .or_default()
                .insert(metadata.instance_id.clone());
        }
    }

    fn remove_shared_member(&mut self, metadata: &InstanceMetadata) {
        if metadata.deployment_mode == DeploymentMode::Shared
            && let Some(members) = self.shared_members.get_mut(metadata.runtime_id())
        {
            members.remove(&metadata.instance_id);
            if members.is_empty() {
                self.shared_members.remove(metadata.runtime_id());
            }
        }
    }

    fn publish_routes(&mut self, metadata: &InstanceMetadata) {
        match metadata.protocol {
            Protocol::Postgres => {
                self.postgres_routes.insert(metadata);
            }
            Protocol::Redis => {
                self.redis_routes.insert(
                    metadata.database.username.clone(),
                    metadata.instance_id.clone(),
                );
                add_password_route(
                    &mut self.redis_password_routes,
                    metadata.tenant_password.as_deref(),
                    metadata.instance_id.clone(),
                );
            }
            Protocol::Valkey => {
                self.valkey_routes.insert(
                    metadata.database.username.clone(),
                    metadata.instance_id.clone(),
                );
                add_password_route(
                    &mut self.valkey_password_routes,
                    metadata.tenant_password.as_deref(),
                    metadata.instance_id.clone(),
                );
            }
            Protocol::Mariadb => {
                self.mariadb_routes.insert(metadata);
            }
            Protocol::Mysql => {
                self.mysql_routes.insert(metadata);
            }
            Protocol::Mongodb => {
                self.mongodb_routes.insert(metadata);
            }
            Protocol::Clickhouse => {
                self.clickhouse_routes.insert(metadata);
            }
            Protocol::Qdrant => {
                if let Some(route_key_sha256) = &metadata.route_key_sha256 {
                    self.qdrant_routes
                        .insert(route_key_sha256.clone(), metadata.instance_id.clone());
                }
            }
        }
    }

    fn fence_existing(&mut self, instance_id: &str) -> bool {
        if !self.instances.contains_key(instance_id) {
            return false;
        }
        self.bump_route_revision(instance_id);
        self.remove_routes_for(instance_id);
        self.fenced_instances.insert(instance_id.to_string());
        true
    }

    fn route_target(&self, instance_id: &str, metadata: &InstanceMetadata) -> RouteTarget {
        RouteTarget {
            instance_id: metadata.instance_id.clone(),
            instance_generation: metadata.created_at.clone(),
            endpoint: metadata.backend.clone(),
            connection_limit: connection_limit(metadata),
            route_revision: self.route_revision(instance_id),
        }
    }

    fn route_target_for(&self, instance_id: &str) -> Option<RouteTarget> {
        self.instances
            .get(instance_id)
            .map(|metadata| self.route_target(instance_id, metadata))
    }

    fn upsert_fenced(&mut self, metadata: InstanceMetadata) {
        self.bump_route_revision(&metadata.instance_id);
        self.remove_routes_for(&metadata.instance_id);
        self.fenced_instances.insert(metadata.instance_id.clone());
        self.store_metadata(metadata);
    }

    fn upsert_preserving_fence(&mut self, metadata: InstanceMetadata) {
        let was_open = self
            .instances
            .get(&metadata.instance_id)
            .is_some_and(|metadata| route_eligible(metadata))
            && !self.fenced_instances.contains(&metadata.instance_id);
        if was_open {
            self.upsert(metadata);
        } else {
            self.upsert_fenced(metadata);
        }
    }

    fn remove_routes_for(&mut self, instance_id: &str) {
        let Some(old) = self.instances.get(instance_id) else {
            return;
        };
        // Another instance can have replaced this one at the same route key.
        match old.protocol {
            Protocol::Postgres => self.postgres_routes.remove(old),
            Protocol::Mariadb => self.mariadb_routes.remove(old),
            Protocol::Mysql => self.mysql_routes.remove(old),
            Protocol::Mongodb => self.mongodb_routes.remove(old),
            Protocol::Clickhouse => self.clickhouse_routes.remove(old),
            Protocol::Redis => {
                remove_owned_route(&mut self.redis_routes, &old.database.username, instance_id);
                remove_password_route(&mut self.redis_password_routes, old);
            }
            Protocol::Valkey => {
                remove_owned_route(&mut self.valkey_routes, &old.database.username, instance_id);
                remove_password_route(&mut self.valkey_password_routes, old);
            }
            Protocol::Qdrant => {
                if let Some(key) = &old.route_key_sha256 {
                    remove_owned_route(&mut self.qdrant_routes, key, instance_id);
                }
            }
        }
    }

    fn remove(&mut self, instance_id: &str) -> Option<InstanceMetadata> {
        self.bump_route_revision(instance_id);
        self.remove_routes_for(instance_id);
        self.fenced_instances.remove(instance_id);
        self.pinned_fences.remove(instance_id);
        self.route_revisions.remove(instance_id);
        let previous = self.instances.remove(instance_id)?;
        self.remove_shared_member(&previous);
        Some(Arc::unwrap_or_clone(previous))
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
            state.route_target(instance_id, metadata),
        )
    })
}

fn add_password_route(
    routes: &mut HashMap<String, HashSet<String>>,
    password: Option<&str>,
    instance_id: String,
) {
    let Some(password) = password else {
        return;
    };
    routes
        .entry(crate::gateway::protocols::redis::password_route_sha256(
            password.as_bytes(),
        ))
        .or_default()
        .insert(instance_id);
}

fn remove_owned_route(routes: &mut HashMap<String, String>, key: &str, instance_id: &str) {
    if routes.get(key).is_some_and(|owner| owner == instance_id) {
        routes.remove(key);
    }
}

fn remove_password_route(routes: &mut HashMap<String, HashSet<String>>, old: &InstanceMetadata) {
    let Some(password) = &old.tenant_password else {
        return;
    };
    let hash = crate::gateway::protocols::redis::password_route_sha256(password.as_bytes());
    if let Some(owners) = routes.get_mut(&hash) {
        owners.remove(&old.instance_id);
        if owners.is_empty() {
            routes.remove(&hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{server::test_support, utils::backend::BackendEndpoint};

    #[tokio::test]
    async fn shared_members_follow_inventory_replacement_migration_and_removal() {
        let store = InstanceStore::default();
        let mut tenant = test_support::shared_metadata();
        store.replace_all(vec![tenant.clone()]).await;
        let original = store.shared_runtime_members("pool-a").await.pop().unwrap();
        assert!(Arc::ptr_eq(
            &original,
            &store.snapshot(&tenant.instance_id).await.unwrap()
        ));

        tenant.runtime_id = "pool-b".to_owned();
        store.upsert_fenced(tenant.clone()).await;
        assert!(store.shared_runtime_members("pool-a").await.is_empty());
        assert_eq!(store.shared_runtime_members("pool-b").await.len(), 1);
        assert_eq!(original.runtime_id(), "pool-a");

        tenant.deployment_mode = DeploymentMode::Dedicated;
        store.upsert_preserving_fence(tenant.clone()).await;
        assert!(store.shared_runtime_members("pool-b").await.is_empty());

        tenant.deployment_mode = DeploymentMode::Shared;
        tenant.runtime_id.clear();
        store.open_routes(tenant.clone()).await;
        assert_eq!(
            store
                .shared_runtime_members(&tenant.instance_id)
                .await
                .len(),
            1
        );
        store.remove(&tenant.instance_id).await.unwrap();
        assert!(
            store
                .shared_runtime_members(&tenant.instance_id)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn database_inference_tracks_current_owners_across_route_changes() {
        use DatabaseRouteResolution::{Ambiguous, Found, NotFound};

        let store = InstanceStore::default();
        let first = test_support::metadata("first", Protocol::Postgres);
        let mut replacement = test_support::metadata("replacement", Protocol::Postgres);
        let mut second = test_support::metadata("second", Protocol::Postgres);
        second.database.name = "second_db".into();
        store
            .replace_all(vec![first, replacement.clone(), second.clone()])
            .await;

        store.remove("first").await;
        for database in [None, Some("")] {
            assert!(matches!(
                store.resolve_postgres("user", database).await,
                Ambiguous
            ));
        }
        assert!(
            matches!(store.resolve_postgres("user", Some("database")).await,
            Found { database, target } if database == "database" && target.instance_id == "replacement")
        );
        assert!(matches!(
            store.resolve_postgres("user", Some("missing")).await,
            NotFound
        ));

        store.pin_routes_fenced("second").await;
        store.upsert(second.clone()).await;
        assert!(matches!(store.resolve_postgres("user", Some("")).await,
            Found { database, target } if database == "database" && target.instance_id == "replacement"));
        store.open_routes(second).await;
        assert!(matches!(
            store.resolve_postgres("user", None).await,
            Ambiguous
        ));

        replacement.protocol = Protocol::Clickhouse;
        replacement.database.username = "renamed".into();
        store.upsert(replacement).await;
        assert!(matches!(
            store.resolve_postgres("user", Some("database")).await,
            NotFound
        ));
        assert!(matches!(store.resolve_postgres("user", None).await,
            Found { database, target } if database == "second_db" && target.instance_id == "second"));
        assert!(matches!(store.resolve_clickhouse("renamed", None).await,
            Found { target, .. } if target.instance_id == "replacement"));
        store.remove("second").await;
        assert!(matches!(
            store.resolve_postgres("user", None).await,
            NotFound
        ));
    }

    #[tokio::test]
    async fn mysql_and_mariadb_infer_only_their_own_published_identity() {
        use DatabaseRouteResolution::{Found, NotFound};

        let store = InstanceStore::default();
        let first = test_support::metadata("first", Protocol::Mysql);
        let replacement = test_support::metadata("replacement", Protocol::Mysql);
        let mut mariadb = test_support::metadata("maria", Protocol::Mariadb);
        mariadb.database.name = "other_db".into();
        store.replace_all(vec![first, replacement, mariadb]).await;

        assert!(matches!(store.resolve_mysql("user", None).await,
            Found { database, target } if database == "database" && target.instance_id == "replacement"));
        store.remove("replacement").await;
        assert!(matches!(store.resolve_mysql("user", None).await, NotFound));
        assert!(matches!(
            store.resolve_mysql("user", Some("database")).await,
            NotFound
        ));
        assert!(matches!(store.resolve_mariadb("user", None).await,
            Found { database, target } if database == "other_db" && target.instance_id == "maria"));
    }

    #[tokio::test]
    async fn removing_displaced_owners_preserves_resp_password_sets_and_qdrant_keys() {
        let store = InstanceStore::default();
        let hash = crate::gateway::protocols::redis::password_route_sha256(b"secret");
        for protocol in [Protocol::Redis, Protocol::Valkey, Protocol::Qdrant] {
            let mut first = resp_metadata("first", "user", "secret");
            first.protocol = protocol;
            first.route_key_sha256 = Some("fingerprint".into());
            let mut last = first.clone();
            last.instance_id = "last".into();
            store.replace_all(vec![first, last]).await;
            assert!(store.resolve_redis_password(&hash).await.is_none());
            assert!(store.resolve_valkey_password(&hash).await.is_none());
            store.fence_routes("first").await;
            store.remove("first").await;
            let target = match protocol {
                Protocol::Redis => {
                    assert_eq!(
                        store
                            .resolve_redis_password(&hash)
                            .await
                            .unwrap()
                            .1
                            .instance_id,
                        "last"
                    );
                    store.resolve_redis("user").await
                }
                Protocol::Valkey => {
                    assert_eq!(
                        store
                            .resolve_valkey_password(&hash)
                            .await
                            .unwrap()
                            .1
                            .instance_id,
                        "last"
                    );
                    store.resolve_valkey("user").await
                }
                Protocol::Qdrant => store.resolve_qdrant("fingerprint").await,
                _ => unreachable!(),
            };
            assert_eq!(target.unwrap().instance_id, "last");
            store.remove("last").await;
            assert!(store.resolve_redis_password(&hash).await.is_none());
            assert!(store.resolve_valkey_password(&hash).await.is_none());
            assert!(store.resolve_qdrant("fingerprint").await.is_none());
        }
    }

    #[tokio::test]
    async fn mongodb_uses_the_exact_database_even_when_it_is_empty() {
        let store = InstanceStore::default();
        let mut metadata = test_support::metadata("mongo", Protocol::Mongodb);
        store.upsert(metadata.clone()).await;
        assert!(store.resolve_mongodb("user", "").await.is_none());
        metadata.database.name.clear();
        store.upsert(metadata).await;
        assert!(store.resolve_mongodb("user", "database").await.is_none());
        assert_eq!(
            store.resolve_mongodb("user", "").await.unwrap().instance_id,
            "mongo"
        );
    }

    #[tokio::test]
    async fn password_only_resp_routing_is_unique_and_updates_after_rotation_or_removal() {
        let store = InstanceStore::default();
        let first = resp_metadata("inst_first", "first", "shared-secret");
        let second = resp_metadata("inst_second", "second", "shared-secret");
        store.upsert(first.clone()).await;
        let hash = crate::gateway::protocols::redis::password_route_sha256(b"shared-secret");
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
        let rotated_hash =
            crate::gateway::protocols::redis::password_route_sha256(b"rotated-secret");
        assert_eq!(
            store.resolve_redis_password(&rotated_hash).await.unwrap().0,
            "first"
        );
    }

    #[tokio::test]
    async fn route_fence_keeps_metadata_but_blocks_connections_until_republished() {
        let store = InstanceStore::default();
        let metadata = resp_metadata("inst_fenced", "tenant", "secret");
        let password_hash = crate::gateway::protocols::redis::password_route_sha256(b"secret");
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
