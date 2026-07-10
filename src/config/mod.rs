pub mod load;
pub mod validate;

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::constants::{defaults, docker, ports};

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
    pub redis: ListenerConfig,
    pub mongodb: ListenerConfig,
    pub clickhouse: ClickhouseConfig,
    pub qdrant: ListenerConfig,
    pub api: ApiConfig,
    pub security: SecurityConfig,
    pub artifacts: ArtifactConfig,
    pub backups: BackupConfig,
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
    pub ssl: ApiSslConfig,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: ports::API,
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
    pub allow_insecure_public_listeners: bool,
    pub allow_private_remote_imports: bool,
    pub remote_import_allowed_hosts: Vec<String>,
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
            allow_insecure_public_listeners: false,
            allow_private_remote_imports: false,
            remote_import_allowed_hosts: Vec::new(),
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
    pub network: String,
    pub internal_network: bool,
    pub ipam: DaemonNetworkIpam,
    pub allow_public_backend_ports: bool,
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
            network: docker::DEFAULT_NETWORK.to_string(),
            internal_network: true,
            ipam: DaemonNetworkIpam::default(),
            allow_public_backend_ports: false,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonNetworkIpam {
    pub subnet: String,
    pub gateway: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiskConfig {
    pub mode: DiskLimitMode,
    pub project_id_base: u32,
    pub fuse_quota_binary: String,
    pub fuse_quota_binary_sha256: String,
    pub fuse_quota_rescan_interval_seconds: u64,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskLimitMode {
    Advisory,
    DockerStorageOpt,
    #[default]
    FuseQuota,
    ProjectQuota,
}

impl DiskLimitMode {
    pub fn enforced(self) -> bool {
        !matches!(self, Self::Advisory)
    }

    pub fn method(self) -> &'static str {
        match self {
            Self::Advisory => "not_supported",
            Self::DockerStorageOpt => "docker_storage_opt_size_bind_mount_probe",
            Self::FuseQuota => "fuse_quota",
            Self::ProjectQuota => "host_filesystem_quota",
        }
    }

    pub fn uses_docker_storage_opt(self) -> bool {
        matches!(self, Self::DockerStorageOpt)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImageConfig {
    pub postgres: String,
    pub redis: String,
    pub mariadb: String,
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
