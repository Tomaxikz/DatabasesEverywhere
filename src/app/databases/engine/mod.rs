mod config;
mod credentials;
mod family;
mod inspection;
mod lifecycle;
mod tenancy;
mod transfer;

pub(crate) use config::{EngineConfig, ImageSettings, ListenerSettings};
pub(crate) use credentials::{
    CredentialRollback, EngineCredentials, LiveRotation, LiveRotationScript, MaintenanceAuthCheck,
    MaintenanceCredential, RecoverySecret, RotatedSecrets, TenantAuthHardening,
};
pub(crate) use family::EngineFamily;
pub(crate) use inspection::EngineInspection;
pub(crate) use lifecycle::{
    CredentialKind, DedicatedSpecInput, EngineLifecycle, LifecycleFlow, LifecycleRejection,
    PostLaunchPlan, PostLaunchStep, RouteIdentity, SharedSpecInput, TenantAuthPlan, TenantAuthStep,
    UpgradePrecheck,
};
pub(crate) use tenancy::{EngineTenancy, TenantDiskBoundary};
#[cfg(test)]
pub(crate) use transfer::validate_line_safe_secret;
pub(crate) use transfer::{
    EngineTransfer, ImportConnection, LogicalCredential, LogicalImportRequest, RemoteDumpFlow,
    SelectionUse, TransferError, validate_header_safe_secret,
};

use crate::{
    instance::compatibility::{EngineVersion, ProtocolCapabilities},
    utils::protocol::Protocol,
};

use super::{
    clickhouse::engine::Clickhouse,
    mariadb::engine::Mariadb,
    mongodb::engine::Mongodb,
    mysql::engine::Mysql,
    postgres::engine::Postgres,
    qdrant::engine::Qdrant,
    resp::engine::{Redis, Valkey},
};

pub(crate) trait Engine:
    EngineInfo
    + EngineCompatibility
    + EngineConfig
    + EngineCredentials
    + EngineTransfer
    + EngineInspection
    + EngineLifecycle
    + EngineTenancy
    + Send
    + Sync
{
}

impl<
    T: EngineInfo
        + EngineCompatibility
        + EngineConfig
        + EngineCredentials
        + EngineTransfer
        + EngineInspection
        + EngineLifecycle
        + EngineTenancy
        + Send
        + Sync,
> Engine for T
{
}

impl Protocol {
    pub(crate) fn engine(self) -> &'static dyn Engine {
        match self {
            Self::Postgres => &Postgres,
            Self::Redis => &Redis,
            Self::Valkey => &Valkey,
            Self::Mariadb => &Mariadb,
            Self::Mysql => &Mysql,
            Self::Mongodb => &Mongodb,
            Self::Clickhouse => &Clickhouse,
            Self::Qdrant => &Qdrant,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SharedPoolProfile {
    pub disk_overhead_mib: u64,
    pub max_database_name_bytes: usize,
    pub reserved_databases: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JobCostProfile {
    pub base_memory_mib: u64,
    pub io_multiplier: u64,
    pub base_cpu_units: usize,
    pub stream_memory_divisor: u64,
    pub stream_memory_cap_mib: u64,
}

pub(crate) const SQL_JOB_COST: JobCostProfile = JobCostProfile {
    base_memory_mib: 96,
    io_multiplier: 4,
    base_cpu_units: 1,
    stream_memory_divisor: 32,
    stream_memory_cap_mib: 256,
};

pub(crate) const PHYSICAL_JOB_COST: JobCostProfile = JobCostProfile {
    base_memory_mib: 128,
    io_multiplier: 2,
    base_cpu_units: 1,
    stream_memory_divisor: 32,
    stream_memory_cap_mib: 256,
};

pub(crate) trait EngineInfo {
    fn protocol(&self) -> Protocol;

    fn family(&self) -> EngineFamily;

    fn is_physical(&self) -> bool {
        self.family().is_physical()
    }

    fn default_container_port(&self) -> u16;

    fn container_data_target(&self) -> &'static str;

    fn container_socket_directory(&self) -> &'static str;

    fn socket_filename(&self) -> &'static str;

    fn rootless_podman_identity(&self) -> (&'static str, &'static str);

    fn startup_readiness_script(&self) -> &'static str;

    fn allows_socket_bridges(&self) -> bool {
        false
    }

    fn database_env_key(&self) -> Option<&'static str> {
        None
    }

    fn requires_heavy_memory(&self) -> bool {
        false
    }

    fn mmap_writes_bypass_inotify(&self) -> bool {
        false
    }

    fn fuse_quota_unsupported(&self) -> bool {
        false
    }

    fn shared_pool(&self) -> Option<SharedPoolProfile> {
        None
    }

    fn job_cost(&self) -> JobCostProfile;

    fn export_expansion_factor(&self) -> u64;

    fn gateway_counts_operations(&self) -> bool {
        false
    }

    fn dump_extension(&self) -> &'static str;

    fn dump_candidate_suffixes(&self) -> &'static [&'static str];

    fn logical_dump_extension(&self) -> Option<&'static str> {
        (!self.is_physical()).then(|| self.dump_extension())
    }

    fn native_export_compression(&self) -> bool {
        self.is_physical()
    }

    fn remote_import_recovery_kind(&self) -> &'static str {
        "logical_remote_import"
    }

    fn default_remote_port(&self, tls: bool) -> u16;

    fn sql_backslash_strings(&self) -> bool {
        false
    }

    fn is_driver_placeholder_database(&self, _username: &str, _database: Option<&str>) -> bool {
        false
    }

    fn auth_hardening_revision(&self) -> Option<u32> {
        None
    }

    fn release_line_components(&self) -> usize {
        2
    }
}

pub(crate) trait EngineCompatibility {
    fn is_supported_version(&self, version: EngineVersion) -> bool;

    fn supported_versions(&self) -> &'static str;

    fn capabilities(&self, _version: EngineVersion) -> ProtocolCapabilities {
        ProtocolCapabilities::default()
    }

    fn version_script(&self) -> &'static str;

    fn normalize_version<'a>(&self, line: &'a str) -> &'a str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_groupings_match_the_legacy_protocol_lists() {
        for protocol in Protocol::ALL {
            let engine = protocol.engine();
            assert_eq!(
                engine.is_physical(),
                matches!(
                    protocol,
                    Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
                ),
            );
            assert_eq!(
                engine.family().is_resp(),
                matches!(protocol, Protocol::Redis | Protocol::Valkey),
            );
            assert_eq!(
                engine.family().is_mysql(),
                matches!(protocol, Protocol::Mysql | Protocol::Mariadb),
            );
            assert_eq!(
                engine.shared_pool().is_some(),
                matches!(
                    protocol,
                    Protocol::Postgres
                        | Protocol::Mariadb
                        | Protocol::Mysql
                        | Protocol::Mongodb
                        | Protocol::Clickhouse
                ),
            );
            assert_eq!(
                engine.native_export_compression(),
                matches!(
                    protocol,
                    Protocol::Mongodb | Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
                ),
            );
        }
    }
}
