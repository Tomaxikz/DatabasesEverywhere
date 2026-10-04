use crate::server::metadata::InstanceMetadata;

use super::EngineInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialRollback {
    PostgresVerifier,
    MysqlAuthString,
    MariadbNativeVerifier,
    Plaintext,
    RespAcl,
    RecreateContainer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TenantAuthHardening {
    None,
    Postgres,
    Mysql,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoverySecret<'a> {
    pub field: &'static str,
    pub value: Option<&'a str>,
    pub hex_len: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MaintenanceCredential {
    PostgresInternalAdmin,
    Stored {
        container_keys: &'static [&'static str],
        username: &'static str,
    },
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MaintenanceAuthCheck {
    PostgresScram,
    MysqlRoot,
    Probe(&'static str),
    Unsupported,
}

pub(crate) struct LiveRotation<'a> {
    pub username: &'a str,
    pub database: &'a str,
    pub rotating: bool,
    pub native_password_verifier: Option<&'a str>,
    pub previous_mysql_auth_plugin: Option<&'a str>,
}

pub(crate) struct LiveRotationScript {
    pub script: String,
    pub passes_password_as_base64: bool,
    pub passes_postgres_admin_password: bool,
}

impl LiveRotationScript {
    pub(crate) fn plain(script: String) -> Self {
        Self {
            script,
            passes_password_as_base64: false,
            passes_postgres_admin_password: false,
        }
    }
}

pub(crate) struct RotatedSecrets<'a> {
    pub plaintext: &'a str,
    pub maintenance: Option<String>,
    pub qdrant_route_secret: &'a [u8],
}

pub(crate) trait EngineCredentials: EngineInfo {
    fn credential_rollback(&self) -> CredentialRollback;

    fn live_rotation_script(
        &self,
        _rotation: &LiveRotation<'_>,
    ) -> Result<LiveRotationScript, String> {
        Err(format!(
            "{} credentials are managed through recreated startup configuration, not live SQL",
            self.protocol()
        ))
    }

    fn is_password_rejection(&self, _lowercase_failure_output: &str) -> bool {
        false
    }

    fn acl_reload_command(&self) -> Option<&'static str> {
        None
    }

    fn store_rotated_secrets(
        &self,
        _metadata: &mut InstanceMetadata,
        _rotated: &RotatedSecrets<'_>,
    ) {
    }

    fn tenant_password_env_keys(&self) -> &'static [&'static str] {
        &[]
    }

    fn tenant_auth_probe(&self, _username: &str, _database: &str) -> Option<String> {
        None
    }

    fn tenant_auth_hardening(&self) -> TenantAuthHardening {
        TenantAuthHardening::None
    }

    fn store_tenant_native_verifier(&self, _metadata: &mut InstanceMetadata, _password: &str) {}

    fn stored_native_password_verifier<'a>(
        &self,
        _metadata: &'a InstanceMetadata,
    ) -> Option<&'a str> {
        None
    }

    fn tenant_route_fingerprint(&self, _daemon_secret: &[u8], _secret: &str) -> Option<String> {
        None
    }

    fn maintenance_credential(&self) -> MaintenanceCredential {
        MaintenanceCredential::None
    }

    fn maintenance_auth_check(&self) -> MaintenanceAuthCheck {
        MaintenanceAuthCheck::Unsupported
    }

    fn stored_maintenance_password<'a>(&self, _metadata: &'a InstanceMetadata) -> Option<&'a str> {
        None
    }

    fn root_environment_secret<'a>(
        &self,
        _metadata: &'a InstanceMetadata,
    ) -> (Option<&'a str>, &'static str) {
        (None, "maintenance password")
    }

    fn required_recovery_secrets<'a>(
        &self,
        _metadata: &'a InstanceMetadata,
    ) -> Vec<RecoverySecret<'a>> {
        Vec::new()
    }

    fn hardening_binding_secrets<'a>(
        &self,
        _metadata: &'a InstanceMetadata,
    ) -> Result<Vec<&'a str>, &'static str> {
        Err("supported_protocol")
    }

    fn legacy_recovery_env_keys(&self) -> &'static [&'static str] {
        &[]
    }

    fn legacy_recovery_username_env_key(&self) -> Option<&'static str> {
        None
    }

    fn matches_legacy_verifier(
        &self,
        _metadata: &InstanceMetadata,
        _secret: &str,
        _daemon_secret: &[u8],
    ) -> bool {
        false
    }
}
