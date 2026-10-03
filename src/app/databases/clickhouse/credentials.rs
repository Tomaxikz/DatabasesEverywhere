use crate::{
    databases::engine::{CredentialRollback, EngineCredentials},
    utils::shell::sh_quote,
};

use super::engine::Clickhouse;

impl EngineCredentials for Clickhouse {
    fn credential_rollback(&self) -> CredentialRollback {
        CredentialRollback::RecreateContainer
    }

    fn tenant_password_env_keys(&self) -> &'static [&'static str] {
        &["CLICKHOUSE_PASSWORD"]
    }

    fn tenant_auth_probe(&self, username: &str, database: &str) -> Option<String> {
        Some(format!(
            "clickhouse-client --host 127.0.0.1 --user {} --password \"$DBE_ROTATED_PASSWORD\" --database {} --query 'SELECT 1' >/dev/null",
            sh_quote(username),
            sh_quote(database),
        ))
    }
}
