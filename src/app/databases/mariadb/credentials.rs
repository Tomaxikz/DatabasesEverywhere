use crate::{
    databases::engine::{
        CredentialRollback, EngineCredentials, LiveRotation, LiveRotationScript,
        MaintenanceAuthCheck, MaintenanceCredential, RecoverySecret, RotatedSecrets,
    },
    gateway::protocols::mariadb::native_password_sha1_stage2_hex,
    instance::metadata::InstanceMetadata,
    utils::shell::sh_quote,
};

use super::{engine::Mariadb, provision};

impl EngineCredentials for Mariadb {
    fn credential_rollback(&self) -> CredentialRollback {
        CredentialRollback::MariadbNativeVerifier
    }

    fn maintenance_credential(&self) -> MaintenanceCredential {
        MaintenanceCredential::Stored {
            container_keys: &["DBE_MARIADB_ROOT_PASSWORD", "MARIADB_ROOT_PASSWORD"],
            username: "root",
        }
    }

    fn stored_maintenance_password<'a>(&self, metadata: &'a InstanceMetadata) -> Option<&'a str> {
        metadata.mariadb_root_password.as_deref()
    }

    fn stored_native_password_verifier<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> Option<&'a str> {
        metadata.mariadb_native_password_sha1_stage2.as_deref()
    }

    fn maintenance_auth_check(&self) -> MaintenanceAuthCheck {
        MaintenanceAuthCheck::Probe(
            "MYSQL_PWD=\"$DBE_ROTATION_ADMIN_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -u root -N -B -e 'SELECT 1' >/dev/null",
        )
    }

    fn is_password_rejection(&self, lowercase_failure_output: &str) -> bool {
        lowercase_failure_output.contains("access denied for user")
            && lowercase_failure_output.contains("using password: yes")
    }

    fn tenant_auth_probe(&self, username: &str, database: &str) -> Option<String> {
        Some(format!(
            "MYSQL_PWD=\"$DBE_ROTATED_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u {} {} -N -B -e 'SELECT 1' >/dev/null",
            sh_quote(username),
            sh_quote(database),
        ))
    }

    fn live_rotation_script(
        &self,
        rotation: &LiveRotation<'_>,
    ) -> Result<LiveRotationScript, String> {
        let verifier = rotation
            .native_password_verifier
            .ok_or_else(|| "mariadb replacement verifier is missing".to_string())?;
        let sql = provision::tenant_user_sql(rotation.database, rotation.username, verifier)
            .map_err(|error| error.to_string())?;
        Ok(LiveRotationScript::plain(format!(
            "set -eu\nprintf %s {} | MYSQL_PWD=\"$DBE_ROTATION_ADMIN_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -u root\n",
            sh_quote(&sql)
        )))
    }

    fn root_environment_secret<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> (Option<&'a str>, &'static str) {
        (
            metadata.mariadb_root_password.as_deref(),
            "MariaDB maintenance password",
        )
    }

    fn required_recovery_secrets<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> Vec<RecoverySecret<'a>> {
        vec![
            RecoverySecret {
                field: "mariadb_root_password",
                value: metadata.mariadb_root_password.as_deref(),
                hex_len: None,
            },
            RecoverySecret {
                field: "mariadb_native_password_sha1_stage2",
                value: metadata.mariadb_native_password_sha1_stage2.as_deref(),
                hex_len: Some(40),
            },
        ]
    }

    fn store_tenant_native_verifier(&self, metadata: &mut InstanceMetadata, password: &str) {
        metadata.mariadb_native_password_sha1_stage2 =
            Some(native_password_sha1_stage2_hex(password));
    }

    fn legacy_recovery_env_keys(&self) -> &'static [&'static str] {
        &["DBE_MARIADB_PASSWORD", "MARIADB_PASSWORD"]
    }

    fn legacy_recovery_username_env_key(&self) -> Option<&'static str> {
        Some("MARIADB_USER")
    }

    fn matches_legacy_verifier(
        &self,
        metadata: &InstanceMetadata,
        secret: &str,
        _daemon_secret: &[u8],
    ) -> bool {
        metadata
            .mariadb_native_password_sha1_stage2
            .as_ref()
            .is_some_and(|saved| {
                saved.eq_ignore_ascii_case(&native_password_sha1_stage2_hex(secret))
            })
    }

    fn store_rotated_secrets(&self, metadata: &mut InstanceMetadata, rotated: &RotatedSecrets<'_>) {
        metadata.mariadb_root_password = rotated.maintenance.clone();
        metadata.mariadb_native_password_sha1_stage2 =
            Some(native_password_sha1_stage2_hex(rotated.plaintext));
    }
}
