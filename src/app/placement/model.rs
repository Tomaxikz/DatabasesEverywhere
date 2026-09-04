use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    instances::metadata::{InstanceMetadata, RuntimeKind, RuntimeMetadata},
    shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
};

pub const ENGINE_RUNTIME_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    #[default]
    Dedicated,
    Shared,
}

impl DeploymentMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dedicated => "dedicated",
            Self::Shared => "shared",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "dedicated" => Some(Self::Dedicated),
            "shared" => Some(Self::Shared),
            _ => None,
        }
    }

    pub const fn supports(self, protocol: Protocol) -> bool {
        match self {
            Self::Dedicated => true,
            Self::Shared => matches!(
                protocol,
                Protocol::Postgres
                    | Protocol::Mariadb
                    | Protocol::Mysql
                    | Protocol::Mongodb
                    | Protocol::Clickhouse
            ),
        }
    }

    pub fn check(self, protocol: Protocol) -> Result<(), PlacementError> {
        if self.supports(protocol) {
            Ok(())
        } else {
            Err(PlacementError::UnsupportedSharedProtocol(protocol))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineRuntimeStatus {
    Creating,
    Booting,
    Running,
    Stopped,
    Failed,
    Quarantined,
    Deleting,
}

impl EngineRuntimeStatus {
    pub const fn as_str(self) -> &'static str {
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

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RuntimeReservation {
    pub tenants: u32,
    pub cpu_cores: f64,
    pub memory_mib: u64,
    pub disk_mib: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantReservationState {
    Reserved,
    Provisioned,
}

impl TenantReservationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Provisioned => "provisioned",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "reserved" => Some(Self::Reserved),
            "provisioned" => Some(Self::Provisioned),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TenantReservation {
    pub instance_id: String,
    pub runtime_id: String,
    pub database: String,
    pub username: String,
    pub state: TenantReservationState,
    pub limits: InstanceLimits,
}

#[derive(Debug, Clone, Copy)]
pub struct ReserveTenant<'a> {
    pub instance_id: &'a str,
    pub runtime_id: &'a str,
    pub database: &'a str,
    pub username: &'a str,
    pub limits: &'a InstanceLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCompatibility {
    pub container_id: String,
    pub image_id: String,
    pub probe_revision: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EngineRuntime {
    pub schema_version: u32,
    pub runtime_id: String,
    pub protocol: Protocol,
    pub deployment_mode: DeploymentMode,
    pub status: EngineRuntimeStatus,
    pub backend: BackendEndpoint,
    pub runtime: RuntimeMetadata,
    pub limits: InstanceLimits,
    pub image: String,
    /// Canonical engine version produced by the compatibility probe. Raw
    /// command output belongs in diagnostics, never in placement identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility: Option<RuntimeCompatibility>,
    pub compatibility_key: String,
    pub max_tenants: u32,
    pub reserved: RuntimeReservation,
    #[serde(default, skip_serializing)]
    pub admin_secret: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl fmt::Debug for EngineRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineRuntime")
            .field("schema_version", &self.schema_version)
            .field("runtime_id", &self.runtime_id)
            .field("protocol", &self.protocol)
            .field("deployment_mode", &self.deployment_mode)
            .field("status", &self.status)
            .field("backend", &self.backend)
            .field("runtime", &self.runtime)
            .field("limits", &self.limits)
            .field("image", &self.image)
            .field("database_version", &self.database_version)
            .field("compatibility", &self.compatibility)
            .field("compatibility_key", &self.compatibility_key)
            .field("max_tenants", &self.max_tenants)
            .field("reserved", &self.reserved)
            .field(
                "admin_secret",
                &self.admin_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl EngineRuntime {
    pub fn check(&self) -> Result<(), PlacementError> {
        if self.schema_version != ENGINE_RUNTIME_SCHEMA_VERSION {
            return Err(PlacementError::UnsupportedSchema(self.schema_version));
        }
        if self.runtime_id.trim().is_empty() {
            return Err(PlacementError::EmptyRuntimeId);
        }
        self.deployment_mode.check(self.protocol)?;
        crate::shared::limits::validate_runtime_limits(
            self.limits.cpu_cores,
            self.limits.memory_mib,
        )
        .map_err(|error| PlacementError::InvalidLimits(error.to_string()))?;
        if self.limits.disk_mib == 0 {
            return Err(PlacementError::InvalidLimits(
                "disk_mib must be greater than zero".to_string(),
            ));
        }
        if self.max_tenants == 0 {
            return Err(PlacementError::ZeroTenantLimit);
        }
        if self.deployment_mode == DeploymentMode::Dedicated && self.max_tenants != 1 {
            return Err(PlacementError::DedicatedTenantLimit(self.max_tenants));
        }
        if let Some(version) = &self.database_version {
            let normalized =
                crate::compatibility::normalize_database_version(self.protocol, version);
            if normalized.as_deref() != Some(version.as_str()) {
                return Err(PlacementError::InvalidDatabaseVersion(version.clone()));
            }
        }
        if let Some(compatibility) = &self.compatibility
            && (compatibility.container_id.trim().is_empty()
                || compatibility.image_id.trim().is_empty()
                || compatibility.probe_revision == 0)
        {
            return Err(PlacementError::InvalidCompatibility);
        }
        if self.deployment_mode == DeploymentMode::Shared
            && self.database_version.is_some() != self.compatibility.is_some()
        {
            return Err(PlacementError::IncompleteSharedCompatibility);
        }
        if !self.reserved.cpu_cores.is_finite()
            || self.reserved.cpu_cores < 0.0
            || self.reserved.tenants > self.max_tenants
            || self.reserved.cpu_cores > self.limits.cpu_cores
            || self.reserved.memory_mib > self.limits.memory_mib
            || self.reserved.disk_mib > self.limits.disk_mib
        {
            return Err(PlacementError::ReservationExceedsLimits);
        }
        Ok(())
    }

    pub fn legacy_dedicated(
        instance: &InstanceMetadata,
        status: EngineRuntimeStatus,
        image: String,
    ) -> Self {
        let runtime_id = instance.instance_id.clone();
        let protocol = instance.protocol;
        Self {
            schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
            compatibility_key: format!("dedicated:{protocol}:{runtime_id}"),
            runtime_id,
            protocol,
            deployment_mode: DeploymentMode::Dedicated,
            status,
            backend: instance.backend.clone(),
            runtime: instance.runtime.clone(),
            limits: instance.limits.clone(),
            image,
            database_version: None,
            compatibility: None,
            max_tenants: 1,
            reserved: RuntimeReservation::default(),
            admin_secret: None,
            created_at: instance.created_at.clone(),
            updated_at: instance.updated_at.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PlacementError {
    #[error("{0} cannot use shared deployment")]
    UnsupportedSharedProtocol(Protocol),
    #[error("engine runtime schema version {0} is not supported")]
    UnsupportedSchema(u32),
    #[error("runtime_id must not be empty")]
    EmptyRuntimeId,
    #[error("max_tenants must be greater than zero")]
    ZeroTenantLimit,
    #[error("a dedicated runtime must have max_tenants=1, got {0}")]
    DedicatedTenantLimit(u32),
    #[error("database version {0:?} is not normalized")]
    InvalidDatabaseVersion(String),
    #[error("runtime compatibility identity and probe revision must be non-empty")]
    InvalidCompatibility,
    #[error("shared runtime version and compatibility identity must be stored together")]
    IncompleteSharedCompatibility,
    #[error("runtime reservations exceed its hard limits")]
    ReservationExceedsLimits,
    #[error("invalid runtime limits: {0}")]
    InvalidLimits(String),
}

pub(crate) fn parse_mode(value: &str) -> Option<DeploymentMode> {
    DeploymentMode::parse(value)
}

pub(crate) fn parse_status(value: &str) -> Option<EngineRuntimeStatus> {
    match value {
        "creating" => Some(EngineRuntimeStatus::Creating),
        "booting" => Some(EngineRuntimeStatus::Booting),
        "running" => Some(EngineRuntimeStatus::Running),
        "stopped" => Some(EngineRuntimeStatus::Stopped),
        "failed" => Some(EngineRuntimeStatus::Failed),
        "quarantined" => Some(EngineRuntimeStatus::Quarantined),
        "deleting" => Some(EngineRuntimeStatus::Deleting),
        _ => None,
    }
}

pub(crate) fn parse_runtime_kind(value: &str) -> Option<RuntimeKind> {
    match value {
        "docker" => Some(RuntimeKind::Docker),
        "podman" => Some(RuntimeKind::Podman),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_mode_support_is_explicit() {
        for protocol in Protocol::ALL {
            let supported = matches!(
                protocol,
                Protocol::Postgres
                    | Protocol::Mariadb
                    | Protocol::Mysql
                    | Protocol::Mongodb
                    | Protocol::Clickhouse
            );
            assert_eq!(DeploymentMode::Shared.supports(protocol), supported);
            assert!(DeploymentMode::Dedicated.supports(protocol));
        }
    }

    #[test]
    fn missing_mode_defaults_to_dedicated() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            mode: DeploymentMode,
        }

        let parsed: Wrapper = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.mode, DeploymentMode::Dedicated);
    }

    #[test]
    fn runtime_debug_redacts_the_admin_secret() {
        let mut runtime = EngineRuntime {
            schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
            runtime_id: "runtime-1".to_string(),
            protocol: Protocol::Postgres,
            deployment_mode: DeploymentMode::Dedicated,
            status: EngineRuntimeStatus::Running,
            backend: BackendEndpoint::UnixSocket {
                socket_path: "/run/dbev/postgres.sock".to_string(),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: "pool".to_string(),
                network_mode: "none".to_string(),
            },
            limits: InstanceLimits::default(),
            image: "postgres:18".to_string(),
            database_version: None,
            compatibility: None,
            compatibility_key: "dedicated:postgres:runtime-1".to_string(),
            max_tenants: 1,
            reserved: RuntimeReservation::default(),
            admin_secret: None,
            created_at: "now".to_string(),
            updated_at: "now".to_string(),
        };
        runtime.admin_secret = Some("pool-admin-secret".to_string());

        let debug = format!("{runtime:?}");
        assert!(!debug.contains("pool-admin-secret"));
        assert!(debug.contains("<redacted>"));
    }
}
