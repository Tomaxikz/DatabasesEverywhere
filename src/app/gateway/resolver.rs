use crate::protocols::qdrant::QdrantRouteKey;
use crate::{
    api::monitoring::resources::{NetworkCounter, ResourceCache},
    instances::state::{DatabaseRouteResolution, InstanceStore, MariadbRouteTarget, RouteTarget},
    monitoring::ActivityCounter,
    shared::backend::BackendEndpoint,
};
use secrecy::SecretString;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct ResolvedRoute {
    pub instance_id: String,
    pub endpoint: BackendEndpoint,
    pub network: NetworkCounter,
    pub activity: Arc<ActivityCounter>,
    pub session: crate::gateway::sessions::TenantSession,
}

pub(crate) struct PendingPostgresRoute {
    pub target: ResolvedRoute,
    pub connection_limit: Option<usize>,
    pub route_revision: u64,
}

pub(crate) struct ResolvedMariadbRoute {
    pub instance_id: String,
    pub endpoint: BackendEndpoint,
    pub shared: bool,
    pub native_password_sha1_stage2: Option<String>,
    pub tenant_password: Option<SecretString>,
    pub network: NetworkCounter,
    pub activity: Arc<ActivityCounter>,
    pub session: crate::gateway::sessions::TenantSession,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingMongodbRoute {
    pub instance_id: String,
    instance_generation: String,
    pub endpoint: BackendEndpoint,
    username: String,
    database: String,
    connection_limit: Option<usize>,
    route_revision: u64,
}

#[derive(Clone)]
pub struct RouteResolver {
    store: InstanceStore,
    resources: ResourceCache,
    qdrant_route_key: QdrantRouteKey,
    sessions: crate::gateway::sessions::TenantSessions,
}

impl RouteResolver {
    pub(crate) fn new(
        store: InstanceStore,
        resources: ResourceCache,
        qdrant_route_key: QdrantRouteKey,
        sessions: crate::gateway::sessions::TenantSessions,
    ) -> Self {
        Self {
            store,
            resources,
            qdrant_route_key,
            sessions,
        }
    }

    pub(crate) async fn resolve_postgres(
        &self,
        username: &str,
        database: Option<&str>,
    ) -> DatabaseRouteResolution<PendingPostgresRoute> {
        let mut resolution = self.store.resolve_postgres(username, database).await;
        if matches!(resolution, DatabaseRouteResolution::NotFound)
            && should_retry_without_database(
                crate::shared::protocol::Protocol::Postgres,
                username,
                database,
            )
        {
            resolution = self.store.resolve_postgres(username, None).await;
        }
        match resolution {
            DatabaseRouteResolution::Found { database, target } => {
                let connection_limit = target.connection_limit;
                let route_revision = target.route_revision;
                let session = self.sessions.open_pending(&target.instance_id);
                self.finish_route(
                    target.instance_id,
                    target.instance_generation,
                    target.endpoint,
                    route_revision,
                    session,
                )
                .await
                .map_or(DatabaseRouteResolution::NotFound, |target| {
                    DatabaseRouteResolution::Found {
                        database,
                        target: PendingPostgresRoute {
                            target,
                            connection_limit,
                            route_revision,
                        },
                    }
                })
            }
            DatabaseRouteResolution::NotFound => DatabaseRouteResolution::NotFound,
            DatabaseRouteResolution::Ambiguous => DatabaseRouteResolution::Ambiguous,
        }
    }

    pub(crate) async fn route_is_current(&self, instance_id: &str, revision: u64) -> bool {
        self.store.route_is_current(instance_id, revision).await
    }

    pub(crate) async fn resolve_redis(&self, username: &str) -> Option<ResolvedRoute> {
        let target = self.store.resolve_redis(username).await?;
        self.resolve_target(
            target.instance_id,
            target.instance_generation,
            target.endpoint,
            target.connection_limit,
            target.route_revision,
        )
        .await
    }

    pub(crate) async fn resolve_redis_password(
        &self,
        password_sha256: &str,
    ) -> Option<(String, ResolvedRoute)> {
        let (username, target) = self.store.resolve_redis_password(password_sha256).await?;
        Some((
            username,
            self.resolve_target(
                target.instance_id,
                target.instance_generation,
                target.endpoint,
                target.connection_limit,
                target.route_revision,
            )
            .await?,
        ))
    }

    pub(crate) async fn resolve_valkey(&self, username: &str) -> Option<ResolvedRoute> {
        let target = self.store.resolve_valkey(username).await?;
        self.resolve_target(
            target.instance_id,
            target.instance_generation,
            target.endpoint,
            target.connection_limit,
            target.route_revision,
        )
        .await
    }

    pub(crate) async fn resolve_valkey_password(
        &self,
        password_sha256: &str,
    ) -> Option<(String, ResolvedRoute)> {
        let (username, target) = self.store.resolve_valkey_password(password_sha256).await?;
        Some((
            username,
            self.resolve_target(
                target.instance_id,
                target.instance_generation,
                target.endpoint,
                target.connection_limit,
                target.route_revision,
            )
            .await?,
        ))
    }

    pub(crate) async fn resolve_mariadb(
        &self,
        username: &str,
        database: Option<&str>,
    ) -> DatabaseRouteResolution<ResolvedMariadbRoute> {
        self.resolve_mariadb_route(self.store.resolve_mariadb(username, database).await)
            .await
    }

    pub(crate) async fn resolve_mysql(
        &self,
        username: &str,
        database: Option<&str>,
    ) -> DatabaseRouteResolution<ResolvedMariadbRoute> {
        self.resolve_mariadb_route(self.store.resolve_mysql(username, database).await)
            .await
    }

    /// Resolves MongoDB ownership without opening a tenant session or network
    /// meter. The listener must authenticate this exact identity against the
    /// backend before calling `activate_mongodb`.
    pub(crate) async fn resolve_mongodb_pending(
        &self,
        username: &str,
        database: &str,
    ) -> Option<PendingMongodbRoute> {
        let target = self.store.resolve_mongodb(username, database).await?;
        Some(PendingMongodbRoute {
            instance_id: target.instance_id,
            instance_generation: target.instance_generation,
            endpoint: target.endpoint,
            username: username.to_string(),
            database: database.to_string(),
            connection_limit: target.connection_limit,
            route_revision: target.route_revision,
        })
    }

    /// Re-resolves the authenticated MongoDB identity and acquires accounting
    /// only if no lifecycle fence or route replacement occurred during SCRAM.
    pub(crate) async fn activate_mongodb(
        &self,
        pending: PendingMongodbRoute,
    ) -> Option<ResolvedRoute> {
        let current = self
            .store
            .resolve_mongodb(&pending.username, &pending.database)
            .await?;
        if current.instance_id != pending.instance_id
            || current.instance_generation != pending.instance_generation
            || current.endpoint != pending.endpoint
            || current.connection_limit != pending.connection_limit
            || current.route_revision != pending.route_revision
        {
            return None;
        }
        self.resolve_target(
            current.instance_id,
            current.instance_generation,
            current.endpoint,
            current.connection_limit,
            current.route_revision,
        )
        .await
    }

    pub(crate) async fn resolve_clickhouse(
        &self,
        username: &str,
        database: Option<&str>,
    ) -> DatabaseRouteResolution<ResolvedRoute> {
        let mut resolution = self.store.resolve_clickhouse(username, database).await;
        if matches!(resolution, DatabaseRouteResolution::NotFound)
            && should_retry_without_database(
                crate::shared::protocol::Protocol::Clickhouse,
                username,
                database,
            )
        {
            resolution = self.store.resolve_clickhouse(username, None).await;
        }
        self.resolve_database_target(resolution).await
    }

    pub(crate) async fn resolve_qdrant(&self, route_key_sha256: &str) -> Option<ResolvedRoute> {
        let target = self.store.resolve_qdrant(route_key_sha256).await?;
        self.resolve_target(
            target.instance_id,
            target.instance_generation,
            target.endpoint,
            target.connection_limit,
            target.route_revision,
        )
        .await
    }

    pub(crate) fn qdrant_route_fingerprint(&self, api_key: &str) -> String {
        self.qdrant_route_key.fingerprint(api_key)
    }

    async fn resolve_target(
        &self,
        instance_id: String,
        instance_generation: String,
        endpoint: BackendEndpoint,
        connection_limit: Option<usize>,
        route_revision: u64,
    ) -> Option<ResolvedRoute> {
        let session = self
            .sessions
            .try_open(&instance_id, connection_limit)
            .ok()?;
        self.finish_route(
            instance_id,
            instance_generation,
            endpoint,
            route_revision,
            session,
        )
        .await
    }

    async fn finish_route(
        &self,
        instance_id: String,
        instance_generation: String,
        endpoint: BackendEndpoint,
        route_revision: u64,
        session: crate::gateway::sessions::TenantSession,
    ) -> Option<ResolvedRoute> {
        if !self
            .store
            .route_is_current(&instance_id, route_revision)
            .await
        {
            return None;
        }
        let network = self.resources.network_counter(&instance_id).await;
        let activity = self
            .resources
            .activity_counter(&instance_id, &instance_generation)
            .await;
        if !self
            .store
            .route_is_current(&instance_id, route_revision)
            .await
        {
            return None;
        }
        Some(ResolvedRoute {
            instance_id,
            endpoint,
            network,
            activity,
            session,
        })
    }

    async fn resolve_database_target(
        &self,
        resolution: DatabaseRouteResolution<RouteTarget>,
    ) -> DatabaseRouteResolution<ResolvedRoute> {
        match resolution {
            DatabaseRouteResolution::Found { database, target } => self
                .resolve_target(
                    target.instance_id,
                    target.instance_generation,
                    target.endpoint,
                    target.connection_limit,
                    target.route_revision,
                )
                .await
                .map_or(DatabaseRouteResolution::NotFound, |target| {
                    DatabaseRouteResolution::Found { database, target }
                }),
            DatabaseRouteResolution::NotFound => DatabaseRouteResolution::NotFound,
            DatabaseRouteResolution::Ambiguous => DatabaseRouteResolution::Ambiguous,
        }
    }

    async fn resolve_mariadb_route(
        &self,
        resolution: DatabaseRouteResolution<MariadbRouteTarget>,
    ) -> DatabaseRouteResolution<ResolvedMariadbRoute> {
        match resolution {
            DatabaseRouteResolution::Found { database, target } => self
                .resolve_mariadb_target(target)
                .await
                .map_or(DatabaseRouteResolution::NotFound, |target| {
                    DatabaseRouteResolution::Found { database, target }
                }),
            DatabaseRouteResolution::NotFound => DatabaseRouteResolution::NotFound,
            DatabaseRouteResolution::Ambiguous => DatabaseRouteResolution::Ambiguous,
        }
    }

    async fn resolve_mariadb_target(
        &self,
        target: MariadbRouteTarget,
    ) -> Option<ResolvedMariadbRoute> {
        let instance_id = target.instance_id;
        let instance_generation = target.instance_generation;
        let session = self
            .sessions
            .try_open(&instance_id, target.connection_limit)
            .ok()?;
        if !self
            .store
            .route_is_current(&instance_id, target.route_revision)
            .await
        {
            return None;
        }
        let network = self.resources.network_counter(&instance_id).await;
        let activity = self
            .resources
            .activity_counter(&instance_id, &instance_generation)
            .await;
        if !self
            .store
            .route_is_current(&instance_id, target.route_revision)
            .await
        {
            return None;
        }
        Some(ResolvedMariadbRoute {
            instance_id,
            endpoint: target.endpoint,
            shared: target.shared,
            native_password_sha1_stage2: target.native_password_sha1_stage2,
            tenant_password: target.tenant_password,
            network,
            activity,
            session,
        })
    }
}

/// Some drivers insert a protocol-defined catalog placeholder before the
/// application selects its real catalog. Keep those aliases in one resolver
/// policy so native, HTTP, pooled, and future listener paths cannot diverge.
fn should_retry_without_database(
    protocol: crate::shared::protocol::Protocol,
    username: &str,
    database: Option<&str>,
) -> bool {
    match protocol {
        crate::shared::protocol::Protocol::Postgres => database == Some(username),
        crate::shared::protocol::Protocol::Clickhouse => database == Some("default"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        instances::{metadata::InstanceMetadata, test_support},
        placement::DeploymentMode,
        shared::protocol::Protocol,
    };

    #[test]
    fn default_catalog_alias_policy_is_protocol_specific() {
        assert!(should_retry_without_database(
            Protocol::Postgres,
            "tenant",
            Some("tenant")
        ));
        assert!(should_retry_without_database(
            Protocol::Clickhouse,
            "tenant",
            Some("default")
        ));
        assert!(!should_retry_without_database(
            Protocol::Postgres,
            "tenant",
            Some("other")
        ));
        assert!(!should_retry_without_database(
            Protocol::Mysql,
            "tenant",
            Some("tenant")
        ));
    }

    #[tokio::test]
    async fn mongodb_accounting_opens_only_after_current_route_activation() {
        let store = InstanceStore::default();
        let resources = ResourceCache::default();
        let sessions = crate::gateway::sessions::TenantSessions::default();
        let metadata = mongodb_metadata();
        store.upsert(metadata.clone()).await;
        let resolver = RouteResolver::new(
            store.clone(),
            resources,
            crate::protocols::qdrant::QdrantRouteKey::new(b"test-key"),
            sessions.clone(),
        );

        let pending = resolver
            .resolve_mongodb_pending("tenant_user", "tenant_db")
            .await
            .unwrap();
        assert_eq!(sessions.active("tenant-mongo"), 0);
        assert!(store.fence_routes("tenant-mongo").await);
        assert!(resolver.activate_mongodb(pending).await.is_none());
        assert_eq!(sessions.active("tenant-mongo"), 0);

        store.upsert(metadata).await;
        let pending = resolver
            .resolve_mongodb_pending("tenant_user", "tenant_db")
            .await
            .unwrap();
        let active = resolver.activate_mongodb(pending).await.unwrap();
        assert_eq!(sessions.active("tenant-mongo"), 1);
        drop(active);
        assert_eq!(sessions.active("tenant-mongo"), 0);
    }

    fn mongodb_metadata() -> InstanceMetadata {
        let mut metadata = test_support::metadata("tenant-mongo", Protocol::Mongodb);
        metadata.deployment_mode = DeploymentMode::Shared;
        metadata.runtime_id = "pool-mongo".to_string();
        metadata.backend = BackendEndpoint::UnixSocket {
            socket_path: "/run/dbev/pool-mongo.sock".to_string(),
        };
        metadata.runtime.container_name = "pool-mongo".to_string();
        metadata.database.name = "tenant_db".to_string();
        metadata.database.username = "tenant_user".to_string();
        metadata.image = Some(crate::instances::metadata::InstanceImageStatus {
            current: Some("mongo:8".to_string()),
            configured: "mongo:8".to_string(),
            update_available: false,
        });
        metadata
    }
}
