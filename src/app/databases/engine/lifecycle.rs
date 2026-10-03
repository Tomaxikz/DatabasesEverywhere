use std::path::{Path, PathBuf};

use futures::future::{BoxFuture, FutureExt};
use secrecy::SecretString;

use crate::{runtime::docker::DockerInstanceSpec, server::metadata::InstanceMetadata};

use super::EngineInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LifecycleFlow {
    Create,
    PoolCreate,
    ImageUpdateSpec,
    ImageUpdateReprovision,
    MajorUpgradePrecheck,
    MajorUpgradeLaunch,
    MajorUpgradeRecreate,
    UpgradeHarden(&'static str),
    StartHarden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialKind {
    Tenant,
    Maintenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleRejection {
    BadRequest(String),
    Conflict(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TenantAuthStep {
    PostgresProvisionRole,
    PostgresHarden,
    MariadbProvisionUser,
    MysqlProvisionUser,
    MysqlHarden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TenantAuthPlan {
    pub step: TenantAuthStep,
    pub stage: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PostLaunchStep {
    BootstrapRoot,
    ProvisionTenantUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PostLaunchPlan {
    pub step: PostLaunchStep,
    pub stage: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteIdentity {
    UsernameAndDatabase,
    RouteKey,
    Username,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpgradePrecheck {
    LogicalImport,
    FeatureCompatibilityVersion,
}

pub(crate) struct DedicatedSpecInput<'a> {
    pub instance_id: &'a str,
    pub image: &'a str,
    pub database: &'a str,
    pub username: &'a str,
    pub password: SecretString,
    pub maintenance_password: SecretString,
    pub data_path: PathBuf,
    pub sockets: PathBuf,
    pub hosted_config: Option<PathBuf>,
    pub socket_bridge_binary: PathBuf,
}

pub(crate) struct SharedSpecInput<'a> {
    pub runtime_id: &'a str,
    pub image: &'a str,
    pub admin_password: SecretString,
    pub data_path: PathBuf,
    pub sockets: PathBuf,
    pub hosted_config: Option<PathBuf>,
    pub socket_bridge_binary: PathBuf,
}

pub(crate) trait EngineLifecycle: EngineInfo {
    fn generate_maintenance_password(&self) -> Option<String> {
        None
    }

    fn store_maintenance_password(
        &self,
        _metadata: &mut InstanceMetadata,
        _password: Option<String>,
    ) {
    }

    fn runtime_admin_secret<'a>(&self, _metadata: &'a InstanceMetadata) -> Option<&'a str> {
        None
    }

    fn maintenance_secret_label(&self) -> Option<&'static str> {
        None
    }

    fn route_key_fingerprint(&self, _daemon_secret: &[u8], _password: &str) -> Option<String> {
        None
    }

    fn route_identity(&self) -> RouteIdentity {
        RouteIdentity::UsernameAndDatabase
    }

    fn refresh_native_password_verifier(&self, _metadata: &mut InstanceMetadata, _password: &str) {}

    fn acl_file_stage(&self) -> Option<&'static str> {
        None
    }

    fn write_hosted_config<'a>(
        &self,
        _runtime_config: &'a Path,
        _shared: bool,
    ) -> BoxFuture<'a, Result<Option<PathBuf>, String>> {
        async { Ok(None) }.boxed()
    }

    fn dedicated_spec(&self, input: DedicatedSpecInput<'_>) -> DockerInstanceSpec;

    fn shared_spec(&self, _input: SharedSpecInput<'_>) -> Option<DockerInstanceSpec> {
        None
    }

    fn tenant_auth_plan(&self, _flow: LifecycleFlow) -> Option<TenantAuthPlan> {
        None
    }

    fn post_launch_plan(&self, _flow: LifecycleFlow) -> Option<PostLaunchPlan> {
        None
    }

    fn missing_credential(
        &self,
        _flow: LifecycleFlow,
        _kind: CredentialKind,
    ) -> LifecycleRejection {
        LifecycleRejection::Conflict(format!("{} credential is missing", self.protocol()))
    }

    fn major_upgrade_block(&self) -> Option<&'static str> {
        None
    }

    fn major_upgrade_precheck(&self) -> UpgradePrecheck {
        UpgradePrecheck::LogicalImport
    }

    fn replacement_check_command(&self, _username: &str, _database: &str) -> Option<String> {
        None
    }
}
