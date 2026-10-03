use crate::{
    databases::engine::{EngineTenancy, TenantDiskBoundary},
    instance::placement::tenant::backends::{MongodbTenantBackend, TenantBackend},
    utils::shell::sh_quote,
};

use super::engine::Mongodb;

impl EngineTenancy for Mongodb {
    fn tenant_backend(&self) -> Option<&'static dyn TenantBackend> {
        Some(&MongodbTenantBackend)
    }

    fn tenant_disk_boundary(&self) -> Option<TenantDiskBoundary> {
        Some(TenantDiskBoundary::SoftScanner)
    }

    fn manifest_query_command(
        &self,
        statement: &str,
        username: &str,
        database: &str,
    ) -> Option<String> {
        Some(format!(
            "mongosh --quiet --host 127.0.0.1 --username {} --password \"$DBE_TENANT_PASSWORD\" --authenticationDatabase {} {} --eval {}",
            sh_quote(username),
            sh_quote(database),
            sh_quote(database),
            sh_quote(statement),
        ))
    }
}
