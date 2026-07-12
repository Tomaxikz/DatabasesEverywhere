use crate::{
    api::resources::{NetworkCounter, ResourceCache},
    instances::state::{InstanceStore, MariadbRouteTarget},
    shared::backend::BackendEndpoint,
};

#[derive(Debug, Clone)]
pub(crate) struct ResolvedRoute {
    pub endpoint: BackendEndpoint,
    pub network: NetworkCounter,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedMariadbRoute {
    pub endpoint: BackendEndpoint,
    pub native_password_sha1_stage2: Option<String>,
    pub network: NetworkCounter,
}

#[derive(Debug, Clone)]
pub struct RouteResolver {
    store: InstanceStore,
    resources: ResourceCache,
}

impl RouteResolver {
    pub(crate) fn new(store: InstanceStore, resources: ResourceCache) -> Self {
        Self { store, resources }
    }

    pub(crate) async fn resolve_postgres(
        &self,
        username: &str,
        database: &str,
    ) -> Option<ResolvedRoute> {
        let target = self.store.resolve_postgres(username, database).await?;
        Some(
            self.resolve_target(target.instance_id, target.endpoint)
                .await,
        )
    }

    pub(crate) async fn resolve_redis(&self, username: &str) -> Option<ResolvedRoute> {
        let target = self.store.resolve_redis(username).await?;
        Some(
            self.resolve_target(target.instance_id, target.endpoint)
                .await,
        )
    }

    pub(crate) async fn resolve_mariadb(
        &self,
        username: &str,
        database: &str,
    ) -> Option<ResolvedMariadbRoute> {
        let target = self.store.resolve_mariadb(username, database).await?;
        Some(self.resolve_mariadb_target(target).await)
    }

    pub(crate) async fn resolve_mysql(
        &self,
        username: &str,
        database: &str,
    ) -> Option<ResolvedMariadbRoute> {
        let target = self.store.resolve_mysql(username, database).await?;
        Some(self.resolve_mariadb_target(target).await)
    }

    pub(crate) async fn resolve_mongodb(
        &self,
        username: &str,
        database: &str,
    ) -> Option<ResolvedRoute> {
        let target = self.store.resolve_mongodb(username, database).await?;
        Some(
            self.resolve_target(target.instance_id, target.endpoint)
                .await,
        )
    }

    pub(crate) async fn resolve_clickhouse(
        &self,
        username: &str,
        database: &str,
    ) -> Option<ResolvedRoute> {
        let target = self.store.resolve_clickhouse(username, database).await?;
        Some(
            self.resolve_target(target.instance_id, target.endpoint)
                .await,
        )
    }

    pub(crate) async fn resolve_qdrant(&self, route_key_sha256: &str) -> Option<ResolvedRoute> {
        let target = self.store.resolve_qdrant(route_key_sha256).await?;
        Some(
            self.resolve_target(target.instance_id, target.endpoint)
                .await,
        )
    }

    async fn resolve_target(
        &self,
        instance_id: String,
        endpoint: BackendEndpoint,
    ) -> ResolvedRoute {
        ResolvedRoute {
            endpoint,
            network: self.resources.network_counter(&instance_id).await,
        }
    }

    async fn resolve_mariadb_target(&self, target: MariadbRouteTarget) -> ResolvedMariadbRoute {
        ResolvedMariadbRoute {
            endpoint: target.endpoint,
            native_password_sha1_stage2: target.native_password_sha1_stage2,
            network: self.resources.network_counter(&target.instance_id).await,
        }
    }
}
