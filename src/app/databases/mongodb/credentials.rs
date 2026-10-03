use crate::{
    databases::engine::{
        CredentialRollback, EngineCredentials, LiveRotation, LiveRotationScript,
        MaintenanceAuthCheck, MaintenanceCredential, RecoverySecret, RotatedSecrets,
    },
    server::metadata::InstanceMetadata,
    utils::shell::sh_quote,
};

use super::{engine::Mongodb, provision};

impl EngineCredentials for Mongodb {
    fn credential_rollback(&self) -> CredentialRollback {
        CredentialRollback::Plaintext
    }

    fn tenant_password_env_keys(&self) -> &'static [&'static str] {
        &["DBE_MONGO_PASSWORD"]
    }

    fn maintenance_credential(&self) -> MaintenanceCredential {
        MaintenanceCredential::Stored {
            container_keys: &["DBE_MONGO_ROOT_PASSWORD"],
            username: "dbe_root",
        }
    }

    fn stored_maintenance_password<'a>(&self, metadata: &'a InstanceMetadata) -> Option<&'a str> {
        metadata.mongodb_root_password.as_deref()
    }

    fn maintenance_auth_check(&self) -> MaintenanceAuthCheck {
        MaintenanceAuthCheck::Probe(
            "mongosh --quiet --host 127.0.0.1 --username dbe_root --password \"$DBE_ROTATION_ADMIN_PASSWORD\" --authenticationDatabase admin admin --eval 'db.adminCommand({ ping: 1 }).ok' >/dev/null",
        )
    }

    fn is_password_rejection(&self, lowercase_failure_output: &str) -> bool {
        lowercase_failure_output.contains("authentication failed")
            || lowercase_failure_output.contains("code: 18")
    }

    fn tenant_auth_probe(&self, username: &str, database: &str) -> Option<String> {
        Some(format!(
            "mongosh --quiet --host 127.0.0.1 --username {} --password \"$DBE_ROTATED_PASSWORD\" --authenticationDatabase {} {} --eval 'db.runCommand({{ ping: 1 }}).ok' >/dev/null",
            sh_quote(username),
            sh_quote(database),
            sh_quote(database),
        ))
    }

    fn live_rotation_script(
        &self,
        rotation: &LiveRotation<'_>,
    ) -> Result<LiveRotationScript, String> {
        if !rotation.rotating {
            return Err(
                "the previous MongoDB tenant credential is unavailable for rollback".to_string(),
            );
        }
        let javascript = provision::password_update_script(rotation.database, rotation.username)
            .map_err(|error| error.to_string())?;
        Ok(LiveRotationScript::plain(format!(
            "set -eu\nmongosh --quiet --host 127.0.0.1 --username dbe_root --password \"$DBE_ROTATION_ADMIN_PASSWORD\" --authenticationDatabase admin admin --eval {}\n",
            sh_quote(&javascript)
        )))
    }

    fn root_environment_secret<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> (Option<&'a str>, &'static str) {
        (
            metadata.mongodb_root_password.as_deref(),
            "MongoDB maintenance password",
        )
    }

    fn required_recovery_secrets<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> Vec<RecoverySecret<'a>> {
        vec![RecoverySecret {
            field: "mongodb_root_password",
            value: metadata.mongodb_root_password.as_deref(),
            hex_len: None,
        }]
    }

    fn store_rotated_secrets(&self, metadata: &mut InstanceMetadata, rotated: &RotatedSecrets<'_>) {
        metadata.mongodb_root_password = rotated.maintenance.clone();
    }
}
