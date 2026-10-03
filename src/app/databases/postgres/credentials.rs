use crate::{
    databases::engine::{
        CredentialRollback, EngineCredentials, LiveRotation, LiveRotationScript,
        MaintenanceAuthCheck, MaintenanceCredential, RecoverySecret, RotatedSecrets,
        TenantAuthHardening,
    },
    instance::metadata::InstanceMetadata,
    utils::shell::sh_quote,
};

use super::{docker::INTERNAL_ADMIN_USERNAME, engine::Postgres, provision};

impl EngineCredentials for Postgres {
    fn credential_rollback(&self) -> CredentialRollback {
        CredentialRollback::PostgresVerifier
    }

    fn tenant_password_env_keys(&self) -> &'static [&'static str] {
        &["DBE_POSTGRES_PASSWORD"]
    }

    fn maintenance_credential(&self) -> MaintenanceCredential {
        MaintenanceCredential::PostgresInternalAdmin
    }

    fn stored_maintenance_password<'a>(&self, metadata: &'a InstanceMetadata) -> Option<&'a str> {
        metadata.postgres_admin_password.as_deref()
    }

    fn maintenance_auth_check(&self) -> MaintenanceAuthCheck {
        MaintenanceAuthCheck::PostgresScram
    }

    fn is_password_rejection(&self, lowercase_failure_output: &str) -> bool {
        lowercase_failure_output.contains("password authentication failed")
    }

    fn tenant_auth_probe(&self, username: &str, database: &str) -> Option<String> {
        Some(format!(
            "PGPASSWORD=\"$DBE_ROTATED_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -Atqc 'SELECT 1' >/dev/null",
            sh_quote(username),
            sh_quote(database),
        ))
    }

    fn live_rotation_script(
        &self,
        rotation: &LiveRotation<'_>,
    ) -> Result<LiveRotationScript, String> {
        let script = if rotation.rotating {
            rotation_script(rotation.username, rotation.database)
        } else {
            verifier_restore_script(rotation.username, rotation.database)
        };
        Ok(LiveRotationScript {
            script,
            passes_password_as_base64: false,
            passes_postgres_admin_password: true,
        })
    }

    fn hardens_auth_after_rotation(&self) -> bool {
        true
    }

    fn required_recovery_secrets<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> Vec<RecoverySecret<'a>> {
        vec![RecoverySecret {
            field: "postgres_admin_password",
            value: metadata.postgres_admin_password.as_deref(),
            hex_len: None,
        }]
    }

    fn hardening_binding_secrets<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> Result<Vec<&'a str>, &'static str> {
        Ok(vec![
            metadata
                .postgres_admin_password
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or("postgres_admin_password")?,
        ])
    }

    fn tenant_auth_hardening(&self) -> TenantAuthHardening {
        TenantAuthHardening::Postgres
    }

    fn store_rotated_secrets(&self, metadata: &mut InstanceMetadata, rotated: &RotatedSecrets<'_>) {
        metadata.postgres_admin_password = rotated.maintenance.clone();
    }
}

pub(crate) fn rotation_script(username: &str, database: &str) -> String {
    let sql = provision::reset_tenant_password_sql(username);
    format!(
        "set -eu\n{{ printf '%s\\n' '\\getenv tenant_password DBE_ROTATED_PASSWORD'; printf '%s\\n' {}; }} | PGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -v ON_ERROR_STOP=1\n",
        sh_quote(&sql),
        sh_quote(INTERNAL_ADMIN_USERNAME),
        sh_quote(database),
    )
}

fn verifier_restore_script(username: &str, database: &str) -> String {
    let sql = provision::restore_verifier_sql(username);
    format!(
        "set -eu\n{{ printf '%s\\n' '\\getenv tenant_password_verifier DBE_PREVIOUS_PASSWORD_VERIFIER'; printf '%s\\n' {}; }} | PGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -v ON_ERROR_STOP=1\n",
        sh_quote(&sql),
        sh_quote(INTERNAL_ADMIN_USERNAME),
        sh_quote(database),
    )
}
