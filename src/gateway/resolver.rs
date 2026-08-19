use crate::{
    api::resources::{NetworkCounter, ResourceCache},
    instances::state::{DatabaseRouteResolution, InstanceStore, MariadbRouteTarget, RouteTarget},
    shared::backend::BackendEndpoint,
};
use secrecy::SecretString;

#[derive(Debug, Clone)]
pub(crate) struct ResolvedRoute {
    pub instance_id: String,
    pub endpoint: BackendEndpoint,
    pub network: NetworkCounter,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedMariadbRoute {
    pub instance_id: String,
    pub endpoint: BackendEndpoint,
    pub native_password_sha1_stage2: Option<String>,
    pub tenant_password: Option<SecretString>,
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
        database: Option<&str>,
    ) -> DatabaseRouteResolution<ResolvedRoute> {
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
        self.resolve_database_target(resolution).await
    }

    pub(crate) async fn resolve_redis(&self, username: &str) -> Option<ResolvedRoute> {
        let target = self.store.resolve_redis(username).await?;
        Some(
            self.resolve_target(target.instance_id, target.endpoint)
                .await,
        )
    }

    pub(crate) async fn resolve_redis_password(
        &self,
        password_sha256: &str,
    ) -> Option<(String, ResolvedRoute)> {
        let (username, target) = self.store.resolve_redis_password(password_sha256).await?;
        Some((
            username,
            self.resolve_target(target.instance_id, target.endpoint)
                .await,
        ))
    }

    pub(crate) async fn resolve_valkey(&self, username: &str) -> Option<ResolvedRoute> {
        let target = self.store.resolve_valkey(username).await?;
        Some(
            self.resolve_target(target.instance_id, target.endpoint)
                .await,
        )
    }

    pub(crate) async fn resolve_valkey_password(
        &self,
        password_sha256: &str,
    ) -> Option<(String, ResolvedRoute)> {
        let (username, target) = self.store.resolve_valkey_password(password_sha256).await?;
        Some((
            username,
            self.resolve_target(target.instance_id, target.endpoint)
                .await,
        ))
    }

    pub(crate) async fn resolve_mariadb(
        &self,
        username: &str,
        database: Option<&str>,
    ) -> DatabaseRouteResolution<ResolvedMariadbRoute> {
        self.resolve_mariadb_database_target(self.store.resolve_mariadb(username, database).await)
            .await
    }

    pub(crate) async fn resolve_mysql(
        &self,
        username: &str,
        database: Option<&str>,
    ) -> DatabaseRouteResolution<ResolvedMariadbRoute> {
        self.resolve_mariadb_database_target(self.store.resolve_mysql(username, database).await)
            .await
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
        let network = self.resources.network_counter(&instance_id).await;
        ResolvedRoute {
            instance_id,
            endpoint,
            network,
        }
    }

    async fn resolve_database_target(
        &self,
        resolution: DatabaseRouteResolution<RouteTarget>,
    ) -> DatabaseRouteResolution<ResolvedRoute> {
        match resolution {
            DatabaseRouteResolution::Found { database, target } => DatabaseRouteResolution::Found {
                database,
                target: self
                    .resolve_target(target.instance_id, target.endpoint)
                    .await,
            },
            DatabaseRouteResolution::NotFound => DatabaseRouteResolution::NotFound,
            DatabaseRouteResolution::Ambiguous => DatabaseRouteResolution::Ambiguous,
        }
    }

    async fn resolve_mariadb_database_target(
        &self,
        resolution: DatabaseRouteResolution<MariadbRouteTarget>,
    ) -> DatabaseRouteResolution<ResolvedMariadbRoute> {
        match resolution {
            DatabaseRouteResolution::Found { database, target } => DatabaseRouteResolution::Found {
                database,
                target: self.resolve_mariadb_target(target).await,
            },
            DatabaseRouteResolution::NotFound => DatabaseRouteResolution::NotFound,
            DatabaseRouteResolution::Ambiguous => DatabaseRouteResolution::Ambiguous,
        }
    }

    async fn resolve_mariadb_target(&self, target: MariadbRouteTarget) -> ResolvedMariadbRoute {
        let network = self.resources.network_counter(&target.instance_id).await;
        ResolvedMariadbRoute {
            instance_id: target.instance_id,
            endpoint: target.endpoint,
            native_password_sha1_stage2: target.native_password_sha1_stage2,
            tenant_password: target.tenant_password,
            network,
        }
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
    use crate::shared::protocol::Protocol;

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
}
