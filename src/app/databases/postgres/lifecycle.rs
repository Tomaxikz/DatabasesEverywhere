use crate::{
    databases::engine::{
        CredentialKind, DedicatedSpecInput, EngineInfo, EngineLifecycle, LifecycleFlow,
        LifecycleRejection, SharedSpecInput, TenantAuthPlan, TenantAuthStep,
    },
    runtime::docker::DockerInstanceSpec,
    server::metadata::InstanceMetadata,
    utils::shell::sh_quote,
};

use super::{
    docker::{instance_spec, shared_spec},
    engine::Postgres,
};

impl EngineLifecycle for Postgres {
    fn generate_maintenance_password(&self) -> Option<String> {
        Some(format!("dbe-admin-{}", uuid::Uuid::new_v4().simple()))
    }

    fn store_maintenance_password(
        &self,
        metadata: &mut InstanceMetadata,
        password: Option<String>,
    ) {
        metadata.postgres_admin_password = password;
    }

    fn runtime_admin_secret<'a>(&self, metadata: &'a InstanceMetadata) -> Option<&'a str> {
        metadata.postgres_admin_password.as_deref()
    }

    fn maintenance_secret_label(&self) -> Option<&'static str> {
        Some("PostgreSQL administrator")
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
                step: TenantAuthStep::PostgresProvisionRole,
                stage: Some("restricting PostgreSQL tenant role"),
            }),
            LifecycleFlow::MajorUpgradeLaunch => Some(TenantAuthPlan {
                step: TenantAuthStep::PostgresProvisionRole,
                stage: None,
            }),
            LifecycleFlow::ImageUpdateReprovision
            | LifecycleFlow::UpgradeHarden(_)
            | LifecycleFlow::StartHarden => Some(TenantAuthPlan {
                step: TenantAuthStep::PostgresHarden,
                stage: None,
            }),
            _ => None,
        }
    }

    fn missing_credential(&self, flow: LifecycleFlow, kind: CredentialKind) -> LifecycleRejection {
        match (flow, kind) {
            (LifecycleFlow::ImageUpdateSpec, CredentialKind::Maintenance) => {
                LifecycleRejection::BadRequest(
                    "PostgreSQL administrator credential is missing; restart the daemon to migrate this legacy instance before recreation".to_string(),
                )
            }
            (LifecycleFlow::ImageUpdateReprovision, CredentialKind::Tenant) => {
                LifecycleRejection::Conflict(
                    "the encrypted PostgreSQL tenant credential is missing; reset or recreate this legacy instance before replacing its image".to_string(),
                )
            }
            (LifecycleFlow::ImageUpdateReprovision, CredentialKind::Maintenance) => {
                LifecycleRejection::Conflict(
                    "the encrypted PostgreSQL administrator credential is missing; restart the daemon to migrate this legacy instance before replacing its image".to_string(),
                )
            }
            (LifecycleFlow::MajorUpgradeLaunch, _) => LifecycleRejection::Conflict(
                "the encrypted PostgreSQL administrator credential is missing; restart the daemon to migrate this legacy instance before a major upgrade".to_string(),
            ),
            (LifecycleFlow::UpgradeHarden(phase), _) => LifecycleRejection::Conflict(format!(
                "the encrypted PostgreSQL administrator credential is missing {phase}"
            )),
            (LifecycleFlow::StartHarden, CredentialKind::Tenant) => LifecycleRejection::Conflict(
                "the encrypted PostgreSQL tenant credential is missing; reset or recreate this legacy instance before starting it".to_string(),
            ),
            (LifecycleFlow::StartHarden, CredentialKind::Maintenance) => {
                LifecycleRejection::Conflict(
                    "the encrypted PostgreSQL administrator credential is missing; restart the daemon to migrate this legacy instance before starting it".to_string(),
                )
            }
            _ => LifecycleRejection::Conflict(format!("{} credential is missing", self.protocol())),
        }
    }

    fn replacement_check_command(&self, username: &str, database: &str) -> Option<String> {
        Some(format!(
            "PGPASSWORD=\"$DBE_UPGRADE_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -v ON_ERROR_STOP=1 -c 'select 1' >/dev/null",
            sh_quote(username),
            sh_quote(database),
        ))
    }
}
