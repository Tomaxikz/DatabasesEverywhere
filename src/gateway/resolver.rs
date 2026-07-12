use crate::{
    instances::state::{InstanceStore, MariadbRouteTarget},
    shared::backend::BackendEndpoint,
};

#[derive(Debug, Clone)]
pub struct RouteResolver {
    store: InstanceStore,
}

impl RouteResolver {
    pub fn new(store: InstanceStore) -> Self {
        Self { store }
    }

    pub async fn resolve_postgres(
        &self,
        username: &str,
        database: &str,
    ) -> Option<BackendEndpoint> {
        self.store.resolve_postgres(username, database).await
    }

    pub async fn resolve_redis(&self, username: &str) -> Option<BackendEndpoint> {
        self.store.resolve_redis(username).await
    }

    pub async fn resolve_mariadb(
        &self,
        username: &str,
        database: &str,
    ) -> Option<MariadbRouteTarget> {
        self.store.resolve_mariadb(username, database).await
    }

    pub async fn resolve_mysql(
        &self,
        username: &str,
        database: &str,
    ) -> Option<MariadbRouteTarget> {
        self.store.resolve_mysql(username, database).await
    }

    pub async fn resolve_mongodb(&self, username: &str, database: &str) -> Option<BackendEndpoint> {
        self.store.resolve_mongodb(username, database).await
    }

    pub async fn resolve_clickhouse(
        &self,
        username: &str,
        database: &str,
    ) -> Option<BackendEndpoint> {
        self.store.resolve_clickhouse(username, database).await
    }

    pub async fn resolve_qdrant(&self, route_key_sha256: &str) -> Option<BackendEndpoint> {
        self.store.resolve_qdrant(route_key_sha256).await
    }
}
