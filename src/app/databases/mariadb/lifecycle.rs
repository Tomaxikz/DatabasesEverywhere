use crate::{
    databases::engine::{
        CredentialKind, DedicatedSpecInput, EngineInfo, EngineLifecycle, LifecycleFlow,
        LifecycleRejection, SharedSpecInput, TenantAuthPlan, TenantAuthStep,
    },
    runtime::docker::DockerInstanceSpec,
    server::metadata::InstanceMetadata,
};

use super::{
    docker::{instance_spec, shared_spec},
    engine::Mariadb,
};

impl EngineLifecycle for Mariadb {
    fn generate_maintenance_password(&self) -> Option<String> {
        Some(format!("dbe-root-{}", uuid::Uuid::new_v4()))
    }

    fn store_maintenance_password(
        &self,
        metadata: &mut InstanceMetadata,
        password: Option<String>,
    ) {
        metadata.mariadb_root_password = password;
    }

    fn runtime_admin_secret<'a>(&self, metadata: &'a InstanceMetadata) -> Option<&'a str> {
        metadata.mariadb_root_password.as_deref()
    }

    fn maintenance_secret_label(&self) -> Option<&'static str> {
        Some("MariaDB root")
    }

    fn refresh_native_password_verifier(&self, metadata: &mut InstanceMetadata, password: &str) {
        metadata.mariadb_native_password_sha1_stage2 =
            Some(crate::gateway::protocols::mariadb::native_password_sha1_stage2_hex(password));
    }

    fn dedicated_spec(&self, input: DedicatedSpecInput<'_>) -> DockerInstanceSpec {
        instance_spec(
            input.instance_id,
            input.image,
            input.database,
            input.username,
            input.password,
            input.maintenance_password,
            input.data_path,
            input.sockets,
        )
    }

    fn shared_spec(&self, input: SharedSpecInput<'_>) -> Option<DockerInstanceSpec> {
        Some(shared_spec(
            input.runtime_id,
            input.image,
            input.admin_password,
            input.data_path,
            input.sockets,
        ))
    }

    fn tenant_auth_plan(&self, flow: LifecycleFlow) -> Option<TenantAuthPlan> {
        match flow {
            LifecycleFlow::Create => Some(TenantAuthPlan {
                step: TenantAuthStep::MariadbProvisionUser,
                stage: Some("creating or updating MariaDB tenant user"),
            }),
            LifecycleFlow::ImageUpdateReprovision => Some(TenantAuthPlan {
                step: TenantAuthStep::MariadbProvisionUser,
                stage: Some("re-provisioning MariaDB user"),
            }),
            _ => None,
        }
    }

    fn missing_credential(&self, flow: LifecycleFlow, kind: CredentialKind) -> LifecycleRejection {
        match (flow, kind) {
            (LifecycleFlow::ImageUpdateReprovision, CredentialKind::Tenant) => {
                LifecycleRejection::BadRequest(
                    "password is required when recreating mariadb database containers".to_string(),
                )
            }
            (
                LifecycleFlow::ImageUpdateSpec | LifecycleFlow::ImageUpdateReprovision,
                CredentialKind::Maintenance,
            ) => LifecycleRejection::BadRequest(
                "mariadb internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
            ),
            _ => LifecycleRejection::Conflict(format!("{} credential is missing", self.protocol())),
        }
    }

    fn replacement_check_command(&self, _username: &str, _database: &str) -> Option<String> {
        Some("MYSQL_PWD=\"$DBE_UPGRADE_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" \"$MARIADB_DATABASE\" -N -B -e 'select 1' >/dev/null".to_string())
    }
}
