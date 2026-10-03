use crate::{
    databases::engine::{
        CredentialKind, DedicatedSpecInput, EngineInfo, EngineLifecycle, LifecycleFlow,
        LifecycleRejection, PostLaunchPlan, PostLaunchStep, SharedSpecInput, UpgradePrecheck,
    },
    instance::metadata::InstanceMetadata,
    runtime::docker::DockerInstanceSpec,
    utils::shell::sh_quote,
};

use super::{
    docker::{MongodbAuth, instance_spec, shared_spec},
    engine::Mongodb,
};

impl EngineLifecycle for Mongodb {
    fn generate_maintenance_password(&self) -> Option<String> {
        Some(format!("dbe-root-{}", uuid::Uuid::new_v4()))
    }

    fn store_maintenance_password(
        &self,
        metadata: &mut InstanceMetadata,
        password: Option<String>,
    ) {
        metadata.mongodb_root_password = password;
    }

    fn runtime_admin_secret<'a>(&self, metadata: &'a InstanceMetadata) -> Option<&'a str> {
        metadata.mongodb_root_password.as_deref()
    }

    fn maintenance_secret_label(&self) -> Option<&'static str> {
        Some("MongoDB root")
    }

    fn dedicated_spec(&self, input: DedicatedSpecInput<'_>) -> DockerInstanceSpec {
        instance_spec(
            input.instance_id,
            input.image,
            input.database,
            MongodbAuth {
                username: input.username.to_string(),
                password: input.password,
                root_password: input.maintenance_password,
            },
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

    fn post_launch_plan(&self, flow: LifecycleFlow) -> Option<PostLaunchPlan> {
        match flow {
            LifecycleFlow::Create => Some(PostLaunchPlan {
                step: PostLaunchStep::ProvisionTenantUser,
                stage: Some("creating MongoDB tenant user"),
            }),
            LifecycleFlow::MajorUpgradeLaunch => Some(PostLaunchPlan {
                step: PostLaunchStep::ProvisionTenantUser,
                stage: None,
            }),
            LifecycleFlow::PoolCreate => Some(PostLaunchPlan {
                step: PostLaunchStep::BootstrapRoot,
                stage: None,
            }),
            _ => None,
        }
    }

    fn missing_credential(&self, flow: LifecycleFlow, _kind: CredentialKind) -> LifecycleRejection {
        match flow {
            LifecycleFlow::ImageUpdateSpec => LifecycleRejection::BadRequest(
                "mongodb internal root password is missing; old MongoDB instances must be recreated or restored from a manual admin dump before image replacement".to_string(),
            ),
            LifecycleFlow::MajorUpgradePrecheck => LifecycleRejection::BadRequest(
                "mongodb internal root password is missing; this instance was created before DBE stored MongoDB maintenance credentials, so automatic major upgrades cannot safely dump protected internal collections. Recreate the instance or restore from a manual admin dump.".to_string(),
            ),
            LifecycleFlow::MajorUpgradeLaunch => LifecycleRejection::BadRequest(
                "mongodb internal root password is missing; this instance was created before DBE stored MongoDB maintenance credentials, so automatic major upgrades cannot dump protected internal collections. Recreate the instance or restore from a manually created admin dump.".to_string(),
            ),
            _ => LifecycleRejection::Conflict(format!("{} credential is missing", self.protocol())),
        }
    }

    fn major_upgrade_precheck(&self) -> UpgradePrecheck {
        UpgradePrecheck::FeatureCompatibilityVersion
    }

    fn replacement_check_command(&self, username: &str, database: &str) -> Option<String> {
        Some(format!(
            "mongosh --quiet --host 127.0.0.1 --username {} --password \"$DBE_UPGRADE_PASSWORD\" --authenticationDatabase {} {} --eval 'db.runCommand({{ ping: 1 }}).ok' >/dev/null",
            sh_quote(username),
            sh_quote(database),
            sh_quote(database),
        ))
    }
}
