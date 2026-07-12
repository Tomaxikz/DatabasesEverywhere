pub mod load;
pub mod path_policy;
pub mod validate;

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::constants::{defaults, ports};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub debug: bool,
    pub uuid: String,
    pub token_id: String,
    pub token: String,
    pub jwt_signing_key: String,
    pub remote: String,
    pub tls: TlsConfig,
    pub postgres: ListenerConfig,
    pub mariadb: ListenerConfig,
    pub mysql: ListenerConfig,
    pub redis: ListenerConfig,
    pub mongodb: ListenerConfig,
    pub clickhouse: ClickhouseConfig,
    pub qdrant: ListenerConfig,
    pub api: ApiConfig,
    pub security: SecurityConfig,
    pub artifacts: ArtifactConfig,
    pub backups: BackupConfig,
    pub allocation: AllocationConfig,
    pub disk: DiskConfig,
    pub daemon: DaemonConfig,
    pub images: ImageConfig,
    pub paths: PathConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            debug: false,
            uuid: String::new(),
            token_id: String::new(),
            token: String::new(),
            jwt_signing_key: String::new(),
            remote: String::new(),
            tls: TlsConfig::default(),
            postgres: ListenerConfig::enabled(format!("127.0.0.1:{}", ports::POSTGRES)),
            mariadb: ListenerConfig::enabled(format!("127.0.0.1:{}", ports::MARIADB)),
            mysql: ListenerConfig::disabled(format!("127.0.0.1:{}", ports::MYSQL)),
            redis: ListenerConfig::enabled(format!("127.0.0.1:{}", ports::REDIS)),
            mongodb: ListenerConfig::disabled(format!("127.0.0.1:{}", ports::MONGODB)),
            clickhouse: ClickhouseConfig::disabled(
                format!("127.0.0.1:{}", ports::CLICKHOUSE),
                format!("127.0.0.1:{}", ports::CLICKHOUSE_HTTP),
            ),
            qdrant: ListenerConfig::disabled(format!("127.0.0.1:{}", ports::QDRANT)),
            api: ApiConfig::default(),
            security: SecurityConfig::default(),
            artifacts: ArtifactConfig::default(),
            backups: BackupConfig::default(),
            allocation: AllocationConfig::default(),
            disk: DiskConfig::default(),
            daemon: DaemonConfig::default(),
            images: ImageConfig::default(),
            paths: PathConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
}

impl TlsConfig {
    pub fn configured(&self) -> bool {
        !self.cert.trim().is_empty() || !self.key.trim().is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerConfig {
    pub enabled: bool,
    pub bind: String,
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClickhouseConfig {
    pub enabled: bool,
    pub bind: String,
    pub http_bind: String,
    pub tls: bool,
}

impl ClickhouseConfig {
    pub fn enabled(bind: String, http_bind: String) -> Self {
        Self {
            enabled: true,
            bind,
            http_bind,
            tls: false,
        }
    }

    pub fn disabled(bind: String, http_bind: String) -> Self {
        Self {
            enabled: false,
            bind,
            http_bind,
            tls: false,
        }
    }
}

impl Default for ClickhouseConfig {
    fn default() -> Self {
        Self::disabled(
            format!("127.0.0.1:{}", ports::CLICKHOUSE),
            format!("127.0.0.1:{}", ports::CLICKHOUSE_HTTP),
        )
    }
}

impl ListenerConfig {
    pub fn enabled(bind: String) -> Self {
        Self {
            enabled: true,
            bind,
            tls: false,
        }
    }

    pub fn disabled(bind: String) -> Self {
        Self {
            enabled: false,
            bind,
            tls: false,
        }
    }
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self::disabled("127.0.0.1:0".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
    pub trusted_hosts: Vec<String>,
    pub ssl: ApiSslConfig,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: ports::API,
            trusted_hosts: Vec::new(),
            ssl: ApiSslConfig::default(),
        }
    }
}

impl Config {
    pub fn cors_allowed_hosts(&self) -> Vec<String> {
        let mut hosts = Vec::new();
        push_url_host(&mut hosts, &self.remote);
        hosts
    }

    pub fn request_allowed_hosts(&self) -> Vec<String> {
        let mut hosts = self.cors_allowed_hosts();
        for host in &self.api.trusted_hosts {
            push_unique(&mut hosts, host.trim());
        }
        if !matches!(self.api.host.trim(), "0.0.0.0" | "::" | "[::]") {
            push_unique(&mut hosts, self.api.host.trim());
        }
        hosts
    }

    pub fn websocket_jwt_secret(&self) -> &[u8] {
        self.jwt_signing_key.as_bytes()
    }
}

impl ApiConfig {
    pub fn bind_addr(&self) -> String {
        let host = self.host.trim();
        host.parse::<IpAddr>().map_or_else(
            |_| format!("{host}:{}", self.port),
            |address| SocketAddr::new(address, self.port).to_string(),
        )
    }
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    let normalized = value.to_ascii_lowercase();
    if !values
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&normalized))
    {
        values.push(normalized);
    }
}

fn push_url_host(hosts: &mut Vec<String>, value: &str) {
    if let Some(host) = url_host(value) {
        push_unique(hosts, &host);
    }
}

pub(crate) fn url_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let rest = trimmed.split_once("://")?.1;
    let host = rest.split('/').next().unwrap_or(rest).trim();
    if host.is_empty() {
        None
    } else {
        Some(host.trim_end_matches('/').to_ascii_lowercase())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiSslConfig {
    pub enabled: bool,
    pub cert: String,
    pub key: String,
    pub require_client_cert: bool,
    pub client_ca: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    pub api_body_limit_bytes: usize,
    pub api_rate_limit_per_minute: u32,
    pub db_connection_limit_per_minute: u32,
    pub self_upgrade_enabled: bool,
    pub pids_limit: i64,
    pub pids_limits: PidsLimitConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            api_body_limit_bytes: 1024 * 1024,
            api_rate_limit_per_minute: 600,
            db_connection_limit_per_minute: 240,
            self_upgrade_enabled: false,
            pids_limit: 512,
            pids_limits: PidsLimitConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PidsLimitConfig {
    pub postgres: Option<i64>,
    pub redis: Option<i64>,
    pub mariadb: Option<i64>,
    pub mysql: Option<i64>,
    pub mongodb: Option<i64>,
    pub clickhouse: Option<i64>,
    pub qdrant: Option<i64>,
}

impl Default for PidsLimitConfig {
    fn default() -> Self {
        Self {
            postgres: None,
            redis: None,
            mariadb: None,
            mysql: None,
            mongodb: None,
            clickhouse: Some(4096),
            qdrant: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArtifactConfig {
    pub retention_keep_latest: usize,
    pub retention_max_age_days: u64,
}

impl Default for ArtifactConfig {
    fn default() -> Self {
        Self {
            retention_keep_latest: 20,
            retention_max_age_days: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupConfig {
    pub enabled: bool,
    pub interval_minutes: u64,
    pub run_on_startup: bool,
    pub retention_keep_latest_per_instance: usize,
    pub retention_max_age_days: u64,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: 1440,
            run_on_startup: false,
            retention_keep_latest_per_instance: 7,
            retention_max_age_days: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub engine: DaemonEngine,
    pub socket_path: String,
    pub container_read_only_rootfs: bool,
    pub container_userns_mode: String,
    pub container_seccomp_profile: String,
    pub container_apparmor_profile: String,
    pub container_security_opts: Vec<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            engine: DaemonEngine::Docker,
            socket_path: String::new(),
            container_read_only_rootfs: false,
            container_userns_mode: String::new(),
            container_seccomp_profile: String::new(),
            container_apparmor_profile: String::new(),
            container_security_opts: Vec::new(),
        }
    }
}

impl DaemonConfig {
    pub fn configured_socket_path(&self) -> Option<&str> {
        let socket_path = self.socket_path.trim();
        if socket_path.is_empty() {
            None
        } else {
            Some(socket_path)
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonEngine {
    #[default]
    Docker,
    Podman,
}

impl DaemonEngine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskConfig {
    #[serde(skip)]
    pub mode: DiskLimitMode,
    pub project_id_base: u32,
    pub fuse_quota_binary: String,
    pub fuse_quota_binary_sha256: String,
    pub fuse_quota_rescan_interval_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DiskFileConfig {
    project_id_base: u32,
    fuse_quota_binary: String,
    fuse_quota_binary_sha256: String,
    fuse_quota_rescan_interval_seconds: u64,
}

impl Default for DiskFileConfig {
    fn default() -> Self {
        let defaults = DiskConfig::default();
        Self {
            project_id_base: defaults.project_id_base,
            fuse_quota_binary: defaults.fuse_quota_binary,
            fuse_quota_binary_sha256: defaults.fuse_quota_binary_sha256,
            fuse_quota_rescan_interval_seconds: defaults.fuse_quota_rescan_interval_seconds,
        }
    }
}

impl<'de> Deserialize<'de> for DiskConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let file = DiskFileConfig::deserialize(deserializer)?;
        Ok(Self {
            mode: DiskLimitMode::default(),
            project_id_base: file.project_id_base,
            fuse_quota_binary: file.fuse_quota_binary,
            fuse_quota_binary_sha256: file.fuse_quota_binary_sha256,
            fuse_quota_rescan_interval_seconds: file.fuse_quota_rescan_interval_seconds,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllocationConfig {
    /// Optional hard reservation ceiling. When omitted, physical memory minus
    /// `reserved_memory_mib` is used.
    pub max_memory_mib: Option<u64>,
    /// Optional hard reservation ceiling. When omitted, the capacity of the
    /// filesystem backing `paths.volumes` minus `reserved_disk_mib` is used.
    pub max_disk_mib: Option<u64>,
    /// Memory kept outside the database allocation pool for the OS and other
    /// services. This reserve is also required to remain currently available
    /// before an allocation increase is admitted.
    pub reserved_memory_mib: u64,
    /// Disk kept outside the database allocation pool. This reserve is also
    /// required to remain currently available before an allocation increase.
    pub reserved_disk_mib: u64,
}

impl Default for AllocationConfig {
    fn default() -> Self {
        Self {
            max_memory_mib: None,
            max_disk_mib: None,
            reserved_memory_mib: 512,
            reserved_disk_mib: 2048,
        }
    }
}

impl AllocationConfig {
    pub fn effective_memory_limit_bytes(&self, physical_total_bytes: u64) -> u64 {
        effective_allocation_limit_bytes(
            physical_total_bytes,
            self.max_memory_mib,
            self.reserved_memory_mib,
        )
    }

    pub fn effective_disk_limit_bytes(&self, physical_total_bytes: u64) -> u64 {
        effective_allocation_limit_bytes(
            physical_total_bytes,
            self.max_disk_mib,
            self.reserved_disk_mib,
        )
    }

    pub fn reserved_memory_bytes(&self) -> u64 {
        mib_to_bytes_saturating(self.reserved_memory_mib)
    }

    pub fn reserved_disk_bytes(&self) -> u64 {
        mib_to_bytes_saturating(self.reserved_disk_mib)
    }
}

fn effective_allocation_limit_bytes(
    physical_total_bytes: u64,
    configured_max_mib: Option<u64>,
    reserved_mib: u64,
) -> u64 {
    let after_reserve = physical_total_bytes.saturating_sub(mib_to_bytes_saturating(reserved_mib));
    configured_max_mib
        .map(mib_to_bytes_saturating)
        .unwrap_or(after_reserve)
        .min(after_reserve)
}

fn mib_to_bytes_saturating(mib: u64) -> u64 {
    mib.saturating_mul(1024 * 1024)
}

#[cfg(test)]
mod allocation_config_tests {
    use super::*;

    #[test]
    fn automatic_pool_keeps_the_reserve_outside_allocations() {
        let allocation = AllocationConfig {
            reserved_memory_mib: 512,
            ..AllocationConfig::default()
        };

        assert_eq!(
            allocation.effective_memory_limit_bytes(8 * 1024 * 1024 * 1024),
            7_680 * 1024 * 1024
        );
    }

    #[test]
    fn explicit_pool_can_only_reduce_the_safe_physical_pool() {
        let allocation = AllocationConfig {
            max_disk_mib: Some(20_000),
            reserved_disk_mib: 2_048,
            ..AllocationConfig::default()
        };

        assert_eq!(
            allocation.effective_disk_limit_bytes(16_000 * 1024 * 1024),
            13_952 * 1024 * 1024
        );
    }
}

impl DiskConfig {
    pub fn fuse_quota_binary(&self) -> &str {
        let binary = self.fuse_quota_binary.trim();
        if binary.is_empty() {
            "embedded"
        } else {
            binary
        }
    }
}

impl Default for DiskConfig {
    fn default() -> Self {
        Self {
            mode: DiskLimitMode::FuseQuota,
            project_id_base: 200_000,
            fuse_quota_binary: "embedded".to_string(),
            fuse_quota_binary_sha256: String::new(),
            fuse_quota_rescan_interval_seconds: 150,
        }
    }
}

#[cfg(test)]
mod disk_config_tests {
    use super::*;

    #[test]
    fn runtime_disk_mode_is_not_serialized_as_configuration() {
        let disk = DiskConfig {
            mode: DiskLimitMode::ProjectQuota,
            ..DiskConfig::default()
        };

        let yaml = serde_yaml::to_string(&disk).unwrap();

        assert!(!yaml.contains("mode:"));
        assert!(yaml.contains("project_id_base:"));
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DiskLimitMode {
    #[default]
    FuseQuota,
    ProjectQuota,
}

impl DiskLimitMode {
    pub fn enforced(self) -> bool {
        true
    }

    pub fn method(self) -> &'static str {
        match self {
            Self::FuseQuota => "fuse_quota",
            Self::ProjectQuota => "host_filesystem_quota",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImageConfig {
    pub postgres: String,
    pub redis: String,
    pub mariadb: String,
    pub mysql: String,
    pub mongodb: String,
    pub clickhouse: String,
    pub qdrant: String,
    pub allowed: ImageAllowlistConfig,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            postgres: "postgres:18.4".to_string(),
            redis: "redis:8.8.0".to_string(),
            mariadb: "mariadb:12.3.2".to_string(),
            mysql: "mysql:8.4".to_string(),
            mongodb: "mongo:7.0.37".to_string(),
            clickhouse: "clickhouse/clickhouse-server:25.8.25.37".to_string(),
            qdrant: "qdrant/qdrant:v1.18.2".to_string(),
            allowed: ImageAllowlistConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImageAllowlistConfig {
    pub postgres: Vec<String>,
    pub redis: Vec<String>,
    pub mariadb: Vec<String>,
    pub mysql: Vec<String>,
    pub mongodb: Vec<String>,
    pub clickhouse: Vec<String>,
    pub qdrant: Vec<String>,
}

impl ImageConfig {
    pub fn configured_for_protocol(&self, protocol: crate::shared::protocol::Protocol) -> &str {
        match protocol {
            crate::shared::protocol::Protocol::Postgres => &self.postgres,
            crate::shared::protocol::Protocol::Redis => &self.redis,
            crate::shared::protocol::Protocol::Mariadb => &self.mariadb,
            crate::shared::protocol::Protocol::Mysql => &self.mysql,
            crate::shared::protocol::Protocol::Mongodb => &self.mongodb,
            crate::shared::protocol::Protocol::Clickhouse => &self.clickhouse,
            crate::shared::protocol::Protocol::Qdrant => &self.qdrant,
        }
    }

    pub fn allowed_for_protocol(&self, protocol: crate::shared::protocol::Protocol) -> Vec<&str> {
        let configured = self.configured_for_protocol(protocol);
        let mut allowed = match protocol {
            crate::shared::protocol::Protocol::Postgres => self.allowed.postgres.iter(),
            crate::shared::protocol::Protocol::Redis => self.allowed.redis.iter(),
            crate::shared::protocol::Protocol::Mariadb => self.allowed.mariadb.iter(),
            crate::shared::protocol::Protocol::Mysql => self.allowed.mysql.iter(),
            crate::shared::protocol::Protocol::Mongodb => self.allowed.mongodb.iter(),
            crate::shared::protocol::Protocol::Clickhouse => self.allowed.clickhouse.iter(),
            crate::shared::protocol::Protocol::Qdrant => self.allowed.qdrant.iter(),
        }
        .map(String::as_str)
        .collect::<Vec<_>>();
        if !allowed.contains(&configured) {
            allowed.push(configured);
        }
        allowed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathConfig {
    pub data: String,
    pub metadata: String,
    pub volumes: String,
    pub backups: String,
    pub sockets: String,
    pub locks: String,
    pub logs: String,
    pub artifacts: String,
    pub exports: String,
    pub imports: String,
    pub fuse: String,
    pub tmp: String,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            data: defaults::DATA_PATH.to_string(),
            metadata: String::new(),
            volumes: String::new(),
            backups: String::new(),
            sockets: defaults::SOCKETS_PATH.to_string(),
            locks: defaults::LOCKS_PATH.to_string(),
            logs: defaults::LOGS_PATH.to_string(),
            artifacts: defaults::ARTIFACTS_PATH.to_string(),
            exports: String::new(),
            imports: String::new(),
            fuse: String::new(),
            tmp: String::new(),
        }
    }
}

impl PathConfig {
    pub fn metadata_root(&self) -> String {
        non_empty_or_else(&self.metadata, || format!("{}/metadata", self.data.trim()))
    }

    pub fn volumes_root(&self) -> String {
        non_empty_or_else(&self.volumes, || format!("{}/volumes", self.data.trim()))
    }

    pub fn backups_root(&self) -> String {
        non_empty_or_else(&self.backups, || format!("{}/backups", self.data.trim()))
    }

    pub fn exports_root(&self) -> String {
        non_empty_or_else(&self.exports, || {
            format!("{}/exports", self.artifacts.trim())
        })
    }

    pub fn imports_root(&self) -> String {
        non_empty_or_else(&self.imports, || {
            format!("{}/imports", self.artifacts.trim())
        })
    }

    pub fn fuse_root(&self) -> String {
        non_empty_or_else(&self.fuse, || format!("{}/fuse", self.data.trim()))
    }

    pub fn tmp_root(&self) -> String {
        non_empty_or_else(&self.tmp, || format!("{}/tmp", self.data.trim()))
    }
}

fn non_empty_or_else(value: &str, fallback: impl FnOnce() -> String) -> String {
    let value = value.trim();
    if value.is_empty() {
        fallback()
    } else {
        value.to_string()
    }
}
