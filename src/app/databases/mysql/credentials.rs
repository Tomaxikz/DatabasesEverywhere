use crate::{
    databases::engine::{
        CredentialRollback, EngineCredentials, LiveRotation, LiveRotationScript,
        MaintenanceAuthCheck, MaintenanceCredential, RecoverySecret, RotatedSecrets,
        TenantAuthHardening,
    },
    gateway::protocols::mariadb::native_password_sha1_stage2_hex,
    server::metadata::InstanceMetadata,
    utils::shell::sh_quote,
};

use super::{engine::Mysql, provision};

impl EngineCredentials for Mysql {
    fn credential_rollback(&self) -> CredentialRollback {
        CredentialRollback::MysqlAuthString
    }

    fn maintenance_credential(&self) -> MaintenanceCredential {
        MaintenanceCredential::Stored {
            container_keys: &["MYSQL_ROOT_PASSWORD"],
            username: "root",
        }
    }

    fn stored_maintenance_password<'a>(&self, metadata: &'a InstanceMetadata) -> Option<&'a str> {
        metadata.mysql_root_password.as_deref()
    }

    fn stored_native_password_verifier<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> Option<&'a str> {
        metadata.mysql_native_password_sha1_stage2.as_deref()
    }

    fn maintenance_auth_check(&self) -> MaintenanceAuthCheck {
        MaintenanceAuthCheck::MysqlRoot
    }

    fn tenant_auth_probe(&self, username: &str, database: &str) -> Option<String> {
        Some(format!(
            "MYSQL_PWD=\"$DBE_ROTATED_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u {} {} -e 'SELECT 1' >/dev/null",
            sh_quote(username),
            sh_quote(database),
        ))
    }

    fn live_rotation_script(
        &self,
        rotation: &LiveRotation<'_>,
    ) -> Result<LiveRotationScript, String> {
        let script = if rotation.rotating {
            rotation_script(rotation.username)?
        } else {
            let plugin = rotation.previous_mysql_auth_plugin.ok_or_else(|| {
                "the previous MySQL authentication plugin was not captured".to_string()
            })?;
            auth_restore_script(rotation.username, plugin)?
        };
        Ok(LiveRotationScript {
            script,
            passes_password_as_base64: true,
            passes_postgres_admin_password: false,
        })
    }

    fn root_environment_secret<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> (Option<&'a str>, &'static str) {
        (
            metadata.mysql_root_password.as_deref(),
            "MySQL maintenance password",
        )
    }

    fn required_recovery_secrets<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> Vec<RecoverySecret<'a>> {
        vec![
            RecoverySecret {
                field: "mysql_root_password",
                value: metadata.mysql_root_password.as_deref(),
                hex_len: None,
            },
            RecoverySecret {
                field: "mysql_native_password_sha1_stage2",
                value: metadata.mysql_native_password_sha1_stage2.as_deref(),
                hex_len: Some(40),
            },
        ]
    }

    fn hardening_binding_secrets<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> Result<Vec<&'a str>, &'static str> {
        Ok(vec![
            metadata
                .mysql_root_password
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or("mysql_root_password")?,
            metadata
                .mysql_native_password_sha1_stage2
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or("mysql_native_password_sha1_stage2")?,
        ])
    }

    fn tenant_auth_hardening(&self) -> TenantAuthHardening {
        TenantAuthHardening::Mysql
    }

    fn store_tenant_native_verifier(&self, metadata: &mut InstanceMetadata, password: &str) {
        metadata.mysql_native_password_sha1_stage2 =
            Some(native_password_sha1_stage2_hex(password));
    }

    fn store_rotated_secrets(&self, metadata: &mut InstanceMetadata, rotated: &RotatedSecrets<'_>) {
        metadata.mysql_root_password = rotated.maintenance.clone();
        metadata.mysql_native_password_sha1_stage2 =
            Some(native_password_sha1_stage2_hex(rotated.plaintext));
    }
}

pub(crate) fn rotation_script(username: &str) -> Result<String, String> {
    let sql = provision::reset_tenant_password_sql(username);
    let (before_password, after_password) =
        provision::password_sql_fragments(&sql).map_err(|error| error.to_string())?;
    Ok(format!(
        "set -eu\n{{ printf %s {}; printf %s \"$DBE_ROTATED_PASSWORD_B64\"; printf %s {}; }} | MYSQL_PWD=\"$DBE_ROTATION_ADMIN_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -uroot\n",
        sh_quote(before_password),
        sh_quote(after_password),
    ))
}

pub(crate) fn auth_restore_script(username: &str, plugin: &str) -> Result<String, String> {
    let sql =
        provision::restore_tenant_auth_sql(username, plugin).map_err(|error| error.to_string())?;
    let (before_auth, after_auth) =
        provision::auth_string_sql_fragments(&sql).map_err(|error| error.to_string())?;
    Ok(format!(
        "set -eu\n{{ printf %s {}; printf %s \"$DBE_PREVIOUS_MYSQL_AUTH_B64\"; printf %s {}; }} | MYSQL_PWD=\"$DBE_ROTATION_ADMIN_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -uroot\n",
        sh_quote(before_auth),
        sh_quote(after_auth),
    ))
}
