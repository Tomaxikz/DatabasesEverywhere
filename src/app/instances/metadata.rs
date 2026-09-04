use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    api::http::diagnostics::PublicDiagnostic,
    config::DaemonEngine,
    placement::DeploymentMode,
    shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Serialize, Deserialize)]
pub struct InstanceMetadata {
    pub schema_version: u32,
    pub instance_id: String,
    #[serde(default)]
    pub deployment_mode: DeploymentMode,
    /// Runtime ownership is normalized in SQLite. Empty values only occur
    /// while reading metadata JSON written before placement was introduced.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runtime_id: String,
    pub protocol: Protocol,
    pub status: InstanceStatus,
    /// Durable operator intent, kept separate from the observed runtime status.
    ///
    /// This is loaded from the normalized SQLite column by `InstanceRepository`
    /// and deliberately omitted from API JSON to preserve the public response
    /// shape. Runtime reconciliation may change `status`, but must never infer or
    /// overwrite this value from a transient container state.
    #[serde(skip)]
    pub(crate) desired_state: DesiredInstanceState,
    /// Durable restart hysteresis owned exclusively by the predictive disk
    /// limiter. It lives in a normalized SQLite column and is omitted from
    /// public instance JSON to preserve the API shape.
    #[serde(skip)]
    pub(crate) disk_limit_blocked: bool,
    pub public: PublicEndpoint,
    pub backend: BackendEndpoint,
    pub runtime: RuntimeMetadata,
    pub database: DatabaseIdentity,
    /// Keyed HMAC-SHA256 used only as the Qdrant gateway route index. The
    /// legacy field name is retained for durable/API compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_key_sha256: Option<String>,
    #[serde(default, skip_serializing)]
    pub mariadb_native_password_sha1_stage2: Option<String>,
    #[serde(default, skip_serializing)]
    pub mariadb_root_password: Option<String>,
    #[serde(default, skip_serializing)]
    pub mysql_native_password_sha1_stage2: Option<String>,
    #[serde(default, skip_serializing)]
    pub mysql_root_password: Option<String>,
    #[serde(default, skip_serializing)]
    pub mongodb_root_password: Option<String>,
    #[serde(default, skip_serializing)]
    pub postgres_admin_password: Option<String>,
    /// Current tenant credential used only for daemon-managed maintenance and
    /// rollback. The repository encrypts it separately from public metadata,
    /// and API serialization always omits it.
    #[serde(default, skip_serializing)]
    pub tenant_password: Option<String>,
    pub limits: InstanceLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<InstanceImageStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_version: Option<InstanceDatabaseVersion>,
    pub created_at: String,
    pub updated_at: String,
}

impl fmt::Debug for InstanceMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstanceMetadata")
            .field("schema_version", &self.schema_version)
            .field("instance_id", &self.instance_id)
            .field("deployment_mode", &self.deployment_mode)
            .field("runtime_id", &self.runtime_id)
            .field("protocol", &self.protocol)
            .field("status", &self.status)
            .field("desired_state", &self.desired_state)
            .field("disk_limit_blocked", &self.disk_limit_blocked)
            .field("public", &self.public)
            .field("backend", &self.backend)
            .field("runtime", &self.runtime)
            .field("database", &self.database)
            .field(
                "route_key_sha256",
                &self.route_key_sha256.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "mariadb_native_password_sha1_stage2",
                &self
                    .mariadb_native_password_sha1_stage2
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field(
                "mariadb_root_password",
                &self.mariadb_root_password.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "mysql_native_password_sha1_stage2",
                &self
                    .mysql_native_password_sha1_stage2
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field(
                "mysql_root_password",
                &self.mysql_root_password.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "mongodb_root_password",
                &self.mongodb_root_password.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "postgres_admin_password",
                &self.postgres_admin_password.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "tenant_password",
                &self.tenant_password.as_ref().map(|_| "<redacted>"),
            )
            .field("limits", &self.limits)
            .field("image", &self.image)
            .field("database_version", &self.database_version)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl InstanceMetadata {
    /// Returns the runtime that owns the engine process. Historical metadata
    /// omitted the field because every instance owned its container.
    pub fn runtime_id(&self) -> &str {
        if self.runtime_id.is_empty() {
            &self.instance_id
        } else {
            &self.runtime_id
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DesiredInstanceState {
    #[default]
    Running,
    Stopped,
}

impl DesiredInstanceState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "running" => Some(Self::Running),
            "stopped" => Some(Self::Stopped),
            _ => None,
        }
    }
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
    Booting,
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
            Self::Booting => "booting",
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
    fn legacy_instance_placement_is_dedicated_to_its_instance_id() {
        let value = serde_json::json!({
            "schema_version": 1,
            "instance_id": "legacy-instance",
            "protocol": "postgres",
            "status": "running",
            "public": {"host": "db.example.com", "port": 5432},
            "backend": {"kind": "unix_socket", "socket_path": "/run/postgres.sock"},
            "runtime": {"kind": "docker", "container_name": "legacy", "network_mode": "none"},
            "database": {"name": "app", "username": "app"},
            "limits": InstanceLimits::default(),
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        });
        let metadata: InstanceMetadata = serde_json::from_value(value).unwrap();

        assert_eq!(metadata.deployment_mode, DeploymentMode::Dedicated);
        assert_eq!(metadata.runtime_id(), "legacy-instance");
    }

    #[test]
    fn debug_redacts_credentials_and_route_keys() {
        let value = serde_json::json!({
            "schema_version": 1,
            "instance_id": "shared-tenant",
            "deployment_mode": "shared",
            "runtime_id": "shared-pool",
            "protocol": "mysql",
            "status": "running",
            "public": {"host": "db.example.com", "port": 3306},
            "backend": {"kind": "unix_socket", "socket_path": "/run/mysql.sock"},
            "runtime": {"kind": "docker", "container_name": "pool", "network_mode": "none"},
            "database": {"name": "app", "username": "tenant"},
            "route_key_sha256": "route-secret",
            "mariadb_root_password": "mariadb-secret",
            "mysql_root_password": "mysql-secret",
            "mongodb_root_password": "mongo-secret",
            "postgres_admin_password": "postgres-secret",
            "tenant_password": "tenant-secret",
            "limits": InstanceLimits::default(),
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        });
        let metadata: InstanceMetadata = serde_json::from_value(value).unwrap();
        let debug = format!("{metadata:?}");

        for secret in [
            "route-secret",
            "mariadb-secret",
            "mysql-secret",
            "mongo-secret",
            "postgres-secret",
            "tenant-secret",
        ] {
            assert!(!debug.contains(secret), "debug output leaked {secret}");
        }
        assert!(debug.contains("<redacted>"));
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
