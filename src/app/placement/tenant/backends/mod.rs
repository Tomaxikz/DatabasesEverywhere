//! Shared-engine tenant operations. Capabilities used by only one engine family
//! (telemetry, catalog lockdown, rollback inspection) remain explicit at the facade.

use futures::future::BoxFuture;
use secrecy::SecretString;

use super::{TenantEngineError, TenantTarget};
use crate::{
    placement::EngineRuntime,
    runtime::docker::{CommandOutput, DockerRuntime},
    shared::{limits::InstanceLimits, protocol::Protocol},
};

mod clickhouse;
mod mongodb;
mod mysql;
mod postgres;

pub(super) use clickhouse::clickhouse_telemetry_command;
#[cfg(test)]
pub(super) use clickhouse::clickhouse_telemetry_script;
pub(super) use mysql::MysqlFlavor;
pub(super) use postgres::postgres_sql;

/// Every supported backend implements the complete shared-tenant lifecycle.
/// No default operation can silently accept an unsupported engine capability.
pub(super) trait TenantBackend: Sync {
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
}

pub(super) enum TenantOperation<'a> {
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
    match protocol {
        Protocol::Postgres => Ok(&postgres::Postgres),
        Protocol::Mysql => Ok(&MysqlFlavor::Mysql),
        Protocol::Mariadb => Ok(&MysqlFlavor::Mariadb),
        Protocol::Mongodb => Ok(&mongodb::Mongodb),
        Protocol::Clickhouse => Ok(&clickhouse::Clickhouse),
        protocol => Err(TenantEngineError::Unsupported(protocol)),
    }
}
