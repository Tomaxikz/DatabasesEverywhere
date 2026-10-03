use crate::{
    databases::engine::{CredentialRollback, EngineCredentials},
    utils::shell::sh_quote,
};

use super::engine::{Redis, Valkey};

impl EngineCredentials for Redis {
    fn credential_rollback(&self) -> CredentialRollback {
        CredentialRollback::RespAcl
    }

    fn tenant_auth_probe(&self, username: &str, _database: &str) -> Option<String> {
        Some(format!(
            "test \"$(redis-cli -s /run/dbev/redis.sock --user {} -a \"$DBE_ROTATED_PASSWORD\" --no-auth-warning --raw ping)\" = PONG",
            sh_quote(username),
        ))
    }

    fn acl_reload_command(&self) -> Option<&'static str> {
        Some(
            "redis-cli -s /run/dbev/redis.sock --user \"$DBE_TENANT_USER\" -a \"$DBE_CURRENT_PASSWORD\" --no-auth-warning ACL LOAD >/dev/null",
        )
    }
}

impl EngineCredentials for Valkey {
    fn credential_rollback(&self) -> CredentialRollback {
        CredentialRollback::RespAcl
    }

    fn tenant_auth_probe(&self, username: &str, _database: &str) -> Option<String> {
        Some(format!(
            "test \"$(valkey-cli -s /run/dbev/valkey.sock --user {} -a \"$DBE_ROTATED_PASSWORD\" --no-auth-warning --raw ping)\" = PONG",
            sh_quote(username),
        ))
    }

    fn acl_reload_command(&self) -> Option<&'static str> {
        Some(
            "valkey-cli -s /run/dbev/valkey.sock --user \"$DBE_TENANT_USER\" -a \"$DBE_CURRENT_PASSWORD\" --no-auth-warning ACL LOAD >/dev/null",
        )
    }
}
