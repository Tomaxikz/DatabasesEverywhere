use serde::{Deserialize, Serialize};

use crate::{
    api::public_diagnostic::PublicDiagnostic,
    config::DaemonEngine,
    shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceMetadata {
    pub schema_version: u32,
    pub instance_id: String,
    pub protocol: Protocol,
    pub status: InstanceStatus,
    pub public: PublicEndpoint,
    pub backend: BackendEndpoint,
    pub runtime: RuntimeMetadata,
    pub database: DatabaseIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_key_sha256: Option<String>,
    #[serde(default, skip_serializing)]
    pub mariadb_native_password_sha1_stage2: Option<String>,
    #[serde(default, skip_serializing)]
    pub mariadb_root_password: Option<String>,
    #[serde(default, skip_serializing)]
    pub mongodb_root_password: Option<String>,
    pub limits: InstanceLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<InstanceImageStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_version: Option<InstanceDatabaseVersion>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceImageStatus {
    pub current: Option<String>,
    pub configured: String,
    pub update_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceDatabaseVersion {
    pub current: Option<String>,
    pub error: Option<PublicDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceStatus {
    Creating,
    Running,
    Stopped,
    Failed,
    Quarantined,
    Deleting,
}

impl InstanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
            Self::Deleting => "deleting",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeMetadata {
    pub kind: RuntimeKind,
    pub container_name: String,
    #[serde(alias = "network")]
    pub network_mode: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeKind {
    Docker,
    Podman,
}

impl RuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_metadata_reads_legacy_network_field_as_network_mode() {
        let runtime: RuntimeMetadata = serde_json::from_value(serde_json::json!({
            "kind": "docker",
            "container_name": "dbe-postgres-inst_1",
            "network": "databases-everywhere"
        }))
        .unwrap();

        assert_eq!(runtime.network_mode, "databases-everywhere");
        assert!(
            serde_json::to_value(runtime)
                .unwrap()
                .get("network_mode")
                .is_some()
        );
    }
}

impl From<DaemonEngine> for RuntimeKind {
    fn from(engine: DaemonEngine) -> Self {
        match engine {
            DaemonEngine::Docker => Self::Docker,
            DaemonEngine::Podman => Self::Podman,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseIdentity {
    pub name: String,
    pub username: String,
}
