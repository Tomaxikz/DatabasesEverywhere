//! Shared-engine tenant operations. Capabilities used by only one engine family
//! (telemetry, catalog lockdown, rollback inspection) remain explicit at the facade.

use futures::future::BoxFuture;
use secrecy::SecretString;

use super::{TenantEngineError, TenantTarget};
use crate::{
    databases::protocol::Protocol,
    runtime::docker::{CommandOutput, DockerRuntime},
    server::placement::EngineRuntime,
    utils::limits::InstanceLimits,
};

mod clickhouse;
mod mongodb;
mod mysql;
mod postgres;

pub(crate) use clickhouse::Clickhouse as ClickhouseTenantBackend;
#[cfg(test)]
pub(super) use clickhouse::clickhouse_telemetry_script;
pub(crate) use mongodb::Mongodb as MongodbTenantBackend;
pub(crate) use mysql::MysqlFlavor;
pub(crate) use postgres::Postgres as PostgresTenantBackend;
pub(super) use postgres::postgres_sql;

/// Every supported backend implements the complete shared-tenant lifecycle.
/// No default operation can silently accept an unsupported engine capability.
pub(crate) trait TenantBackend: Sync {
    fn apply<'a>(
        &'a self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        target: TenantTarget<'a>,
        operation: TenantOperation<'a>,
    ) -> BoxFuture<'a, Result<(), TenantEngineError>>;

    fn verify_command(&self, target: TenantTarget<'_>) -> String;

    fn measure_storage<'a>(
        &'a self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        database_names: &'a [&'a str],
    ) -> BoxFuture<'a, Result<CommandOutput, TenantEngineError>>;

    fn admin_sql<'a>(
        &'a self,
        _docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        _sql: &'a str,
    ) -> BoxFuture<'a, Result<CommandOutput, TenantEngineError>> {
        Box::pin(async move { Err(TenantEngineError::Unsupported(runtime.protocol)) })
    }

    fn telemetry_sql<'a>(
        &'a self,
        _docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        _sql: &'a str,
    ) -> BoxFuture<'a, Result<CommandOutput, TenantEngineError>> {
        Box::pin(async move { Err(TenantEngineError::Unsupported(runtime.protocol)) })
    }

    fn telemetry_window<'a>(
        &'a self,
        _docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        _prior_cutoff_micros: Option<u64>,
        _sql: &'a str,
    ) -> BoxFuture<'a, Result<CommandOutput, TenantEngineError>> {
        Box::pin(async move { Err(TenantEngineError::Unsupported(runtime.protocol)) })
    }

    fn secure_pool<'a>(
        &'a self,
        _docker: &'a DockerRuntime,
        _runtime: &'a EngineRuntime,
    ) -> BoxFuture<'a, Result<(), TenantEngineError>> {
        Box::pin(async { Ok(()) })
    }
}

pub(crate) enum TenantOperation<'a> {
    Create {
        password: &'a str,
        limits: &'a InstanceLimits,
        admin: SecretString,
    },
    Fence,
    Unfence,
    Drop,
    SetQuota {
        limits: &'a InstanceLimits,
    },
    RotatePassword {
        password: &'a str,
    },
}

pub(super) fn for_protocol(
    protocol: Protocol,
) -> Result<&'static dyn TenantBackend, TenantEngineError> {
    protocol
        .engine()
        .tenant_backend()
        .ok_or(TenantEngineError::Unsupported(protocol))
}
