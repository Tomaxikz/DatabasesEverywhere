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
    engine::Mysql,
};

impl EngineLifecycle for Mysql {
    fn generate_maintenance_password(&self) -> Option<String> {
        Some(format!("dbe-root-{}", uuid::Uuid::new_v4()))
    }

    fn store_maintenance_password(
        &self,
        metadata: &mut InstanceMetadata,
        password: Option<String>,
    ) {
        metadata.mysql_root_password = password;
    }

    fn runtime_admin_secret<'a>(&self, metadata: &'a InstanceMetadata) -> Option<&'a str> {
        metadata.mysql_root_password.as_deref()
    }

    fn maintenance_secret_label(&self) -> Option<&'static str> {
        Some("MySQL root")
    }

    fn refresh_native_password_verifier(&self, metadata: &mut InstanceMetadata, password: &str) {
        metadata.mysql_native_password_sha1_stage2 =
            Some(crate::gateway::protocols::mariadb::native_password_sha1_stage2_hex(password));
    }

    fn dedicated_spec(&self, input: DedicatedSpecInput<'_>) -> DockerInstanceSpec {
        instance_spec(
            input.instance_id,
            input.image,
            input.database,
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
                step: TenantAuthStep::MysqlProvisionUser,
                stage: Some("creating or updating MySQL tenant user"),
            }),
            LifecycleFlow::ImageUpdateReprovision => Some(TenantAuthPlan {
                step: TenantAuthStep::MysqlProvisionUser,
                stage: Some("re-provisioning MySQL user"),
            }),
            LifecycleFlow::MajorUpgradeLaunch | LifecycleFlow::MajorUpgradeRecreate => {
                Some(TenantAuthPlan {
                    step: TenantAuthStep::MysqlProvisionUser,
                    stage: None,
                })
            }
            LifecycleFlow::UpgradeHarden(_) | LifecycleFlow::StartHarden => Some(TenantAuthPlan {
                step: TenantAuthStep::MysqlHarden,
                stage: None,
            }),
            _ => None,
        }
    }

    fn missing_credential(&self, flow: LifecycleFlow, kind: CredentialKind) -> LifecycleRejection {
        match (flow, kind) {
            (LifecycleFlow::ImageUpdateReprovision, CredentialKind::Tenant) => {
                LifecycleRejection::BadRequest(
                    "password is required when recreating mysql database containers".to_string(),
                )
            }
            (
                LifecycleFlow::ImageUpdateSpec | LifecycleFlow::ImageUpdateReprovision,
                CredentialKind::Maintenance,
            ) => LifecycleRejection::BadRequest(
                "mysql internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
            ),
            (LifecycleFlow::MajorUpgradeLaunch, _) => LifecycleRejection::BadRequest(
                "mysql internal root password is missing; automatic major upgrades require an instance created with MySQL maintenance credentials".to_string(),
            ),
            (LifecycleFlow::MajorUpgradeRecreate, _) => LifecycleRejection::BadRequest(
                "mysql internal root password is missing; container recreation requires maintenance credentials".to_string(),
            ),
            (LifecycleFlow::UpgradeHarden(phase), _) => LifecycleRejection::Conflict(format!(
                "the encrypted MySQL maintenance credential is missing {phase}"
            )),
            (LifecycleFlow::StartHarden, CredentialKind::Tenant) => LifecycleRejection::Conflict(
                "the encrypted MySQL tenant credential is missing; reset or recreate this legacy instance before starting it".to_string(),
            ),
            (LifecycleFlow::StartHarden, CredentialKind::Maintenance) => {
                LifecycleRejection::Conflict(
                    "the encrypted MySQL maintenance credential is missing; recreate this legacy instance before starting it".to_string(),
                )
            }
            _ => LifecycleRejection::Conflict(format!("{} credential is missing", self.protocol())),
        }
    }

    fn replacement_check_command(&self, username: &str, database: &str) -> Option<String> {
        Some(format!(
            "MYSQL_PWD=\"$DBE_UPGRADE_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u {} {} -e 'select 1' >/dev/null",
            sh_quote(username),
            sh_quote(database),
        ))
    }
}
