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
    pub valkey: ListenerConfig,
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
            valkey: ListenerConfig::disabled(format!("127.0.0.1:{}", ports::VALKEY)),
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
    pub fqdn: String,
    pub trusted_origins: Vec<String>,
    pub ssl: ApiSslConfig,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: ports::API,
            fqdn: String::new(),
            trusted_origins: Vec::new(),
            ssl: ApiSslConfig::default(),
        }
    }
}

impl Config {
    pub fn cors_allowed_origins(&self) -> Vec<String> {
        let mut origins = Vec::new();
        if let Some(origin) = url_origin(&self.remote) {
            push_unique(&mut origins, &origin);
        }
        for origin in &self.api.trusted_origins {
            if let Some(origin) = normalize_http_origin(origin) {
                push_unique(&mut origins, &origin);
            }
        }
        origins
    }

    pub fn request_allowed_hosts(&self) -> Vec<String> {
        let mut hosts = Vec::new();
        if let Some(fqdn) = self.api.fqdn() {
            push_unique(&mut hosts, fqdn);
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
    pub fn fqdn(&self) -> Option<&str> {
        let fqdn = self.fqdn.trim();
        (!fqdn.is_empty()).then_some(fqdn)
    }

    pub fn public_url(&self) -> Option<String> {
        self.fqdn().map(|fqdn| {
            let scheme = if self.ssl.enabled { "https" } else { "http" };
            format!("{scheme}://{fqdn}:{}", self.port)
        })
    }

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

pub(crate) fn url_host(value: &str) -> Option<String> {
    let uri = value.trim().parse::<http::Uri>().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    if authority.port_u16().is_none() && authority.as_str() != authority.host() {
        return None;
    }
    let host = authority.host().trim_matches(['[', ']']);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Canonicalizes an HTTP(S) origin as scheme + host + effective port.
/// Explicit origin values may omit the default port and may carry one trailing
/// slash, but paths, queries, fragments, and user information are rejected.
pub(crate) fn normalize_http_origin(value: &str) -> Option<String> {
    let uri = value.trim().parse::<http::Uri>().ok()?;
    if uri.query().is_some() || !matches!(uri.path(), "" | "/") {
        return None;
    }
    canonical_uri_origin(&uri)
}

fn url_origin(value: &str) -> Option<String> {
    let uri = value.trim().parse::<http::Uri>().ok()?;
    canonical_uri_origin(&uri)
}

fn canonical_uri_origin(uri: &http::Uri) -> Option<String> {
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority
        .host()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let port = match authority.port_u16() {
        Some(port) => port,
        None if authority.as_str() == authority.host() => default_port,
        None => return None,
    };
    let rendered_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Some(format!("{scheme}://{rendered_host}:{port}"))
}

pub(crate) fn normalize_remote_import_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Ok(address) = value.parse::<IpAddr>() {
        return Some(address.to_string());
    }
    if let Some(address) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.parse::<std::net::Ipv6Addr>().ok())
    {
        return Some(address.to_string());
    }

    let host = value.strip_suffix('.').unwrap_or(value);
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.bytes().any(|byte| byte.is_ascii_control())
        || host
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'\\' | b':' | b'@' | b'#' | b'?' | b'[' | b']'))
    {
        return None;
    }

    let labels = host.split('.').collect::<Vec<_>>();
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }

    // libc resolvers accept several legacy numeric IPv4 spellings such as
    // `2130706433`, `127.1`, and `0x7f.0.0.1`. Reject numeric-looking names so
    // they cannot bypass the canonical IpAddr classification in the caller.
    let numeric_notation = labels.iter().all(|label| {
        label.bytes().all(|byte| byte.is_ascii_digit())
            || label
                .strip_prefix("0x")
                .or_else(|| label.strip_prefix("0X"))
                .is_some_and(|digits| {
                    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
    });
    if numeric_notation {
        return None;
    }

    Some(host.to_ascii_lowercase())
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
    pub remote_import: RemoteImportSecurityConfig,
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
            remote_import: RemoteImportSecurityConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteImportSecurityConfig {
    pub enabled: bool,
    pub allow_plaintext: bool,
    pub allowed_private_hosts: Vec<String>,
    pub max_concurrent_jobs: usize,
    pub connect_timeout_seconds: u64,
    pub operation_timeout_seconds: u64,
    pub max_staged_bytes: u64,
}

impl Default for RemoteImportSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_plaintext: false,
            allowed_private_hosts: Vec::new(),
            max_concurrent_jobs: 4,
            connect_timeout_seconds: 15,
            operation_timeout_seconds: 15 * 60,
            max_staged_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PidsLimitConfig {
    pub postgres: Option<i64>,
    pub redis: Option<i64>,
    pub valkey: Option<i64>,
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
            valkey: None,
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
    /// When true, generated client exports are delivered from a private
    /// one-use spool and removed after download instead of entering the
    /// retained artifact inventory.
    pub stream_exports_only: bool,
    /// Maximum retained artifacts, or pending one-use exports, per instance.
    pub max_artifacts_per_instance: usize,
    pub import_upload_max_bytes: u64,
    pub import_upload_max_total_bytes: u64,
    pub import_upload_max_per_instance: usize,
    pub import_upload_max_concurrent: usize,
    pub import_upload_ttl_hours: u64,
    pub import_upload_timeout_seconds: u64,
    pub import_upload_idle_timeout_seconds: u64,
    pub import_export_scheduler: ImportExportSchedulerConfig,
}

impl Default for ArtifactConfig {
    fn default() -> Self {
        Self {
            retention_keep_latest: 20,
            retention_max_age_days: 30,
            stream_exports_only: false,
            max_artifacts_per_instance: 20,
            import_upload_max_bytes: 8 * 1024 * 1024 * 1024,
            import_upload_max_total_bytes: 32 * 1024 * 1024 * 1024,
            import_upload_max_per_instance: 4,
            import_upload_max_concurrent: 2,
            import_upload_ttl_hours: 24,
            import_upload_timeout_seconds: 3600,
            import_upload_idle_timeout_seconds: 30,
            import_export_scheduler: ImportExportSchedulerConfig::default(),
        }
    }
}

/// Bounds durable data-operation admission separately from active execution.
/// Dynamic mode accounts for estimated CPU, memory, and I/O work. Operators
/// can disable it and use `manual_max_active_jobs` as a fixed ceiling. Dynamic
/// work may remain queued when live memory cannot safely fit one estimated
/// job; CPU and I/O are concurrency weights that still allow one isolated,
/// memory-safe job.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImportExportSchedulerConfig {
    pub dynamic_limiter_enabled: bool,
    pub max_queued_jobs: usize,
    pub max_queued_jobs_per_instance: usize,
    pub manual_max_active_jobs: usize,
    pub dynamic_max_active_jobs: usize,
    /// Zero periodically derives a conservative budget from effective
    /// host-or-cgroup available memory.
    pub dynamic_memory_budget_mib: u64,
    /// Zero derives an in-flight work budget that covers configured uploads
    /// and one maximum physical restore.
    pub dynamic_io_budget_mib: u64,
    /// Zero periodically derives CPU tokens from the effective host-or-cgroup
    /// CPU quota.
    pub dynamic_cpu_units: usize,
    /// Maximum time an estimate that cannot fit the current dynamic capacity
    /// may wait for live auto-detected headroom to recover.
    pub starvation_timeout_seconds: u64,
    pub max_bypass: usize,
}

impl Default for ImportExportSchedulerConfig {
    fn default() -> Self {
        Self {
            dynamic_limiter_enabled: true,
            max_queued_jobs: 1_024,
            max_queued_jobs_per_instance: 32,
            manual_max_active_jobs: 16,
            dynamic_max_active_jobs: 256,
            dynamic_memory_budget_mib: 0,
            dynamic_io_budget_mib: 0,
            dynamic_cpu_units: 0,
            starvation_timeout_seconds: 30,
            max_bypass: 8,
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
    pub storage: BackupStorageConfig,
    pub browsing: BackupBrowsingConfig,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: 1440,
            run_on_startup: false,
            retention_keep_latest_per_instance: 7,
            retention_max_age_days: 30,
            storage: BackupStorageConfig::default(),
            browsing: BackupBrowsingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupStorageConfig {
    pub driver: BackupStorageDriver,
    pub s3: BackupS3Config,
    pub kopia: BackupKopiaConfig,
}

impl Default for BackupStorageConfig {
    fn default() -> Self {
        Self {
            driver: BackupStorageDriver::Local,
            s3: BackupS3Config::default(),
            kopia: BackupKopiaConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupStorageDriver {
    #[default]
    Local,
    S3,
    Kopia,
}

impl BackupStorageDriver {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::S3 => "s3",
            Self::Kopia => "kopia",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupS3Config {
    pub bucket: String,
    pub region: String,
    pub endpoint: String,
    pub prefix: String,
    pub access_key_id: String,
    pub secret_access_key: SensitiveString,
    pub session_token: SensitiveString,
    pub path_style: bool,
    pub allow_http: bool,
    pub request_timeout_seconds: u64,
    pub max_retries: usize,
}

impl Default for BackupS3Config {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            region: "us-east-1".to_string(),
            endpoint: String::new(),
            prefix: "dbev".to_string(),
            access_key_id: String::new(),
            secret_access_key: SensitiveString::default(),
            session_token: SensitiveString::default(),
            path_style: false,
            allow_http: false,
            request_timeout_seconds: 15 * 60,
            max_retries: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupKopiaConfig {
    pub executable: String,
    pub config_file: String,
    pub repository_password: SensitiveString,
    pub operation_timeout_seconds: u64,
}

impl Default for BackupKopiaConfig {
    fn default() -> Self {
        Self {
            executable: "/usr/local/bin/kopia".to_string(),
            config_file: String::new(),
            repository_password: SensitiveString::default(),
            operation_timeout_seconds: 60 * 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupBrowsingConfig {
    pub enabled: bool,
    pub max_objects: usize,
    pub max_preview_objects: usize,
    pub preview_rows_per_object: usize,
    pub max_row_bytes: usize,
    pub max_catalog_bytes: u64,
}

impl Default for BackupBrowsingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_objects: 256,
            max_preview_objects: 32,
            preview_rows_per_object: 10,
            max_row_bytes: 4 * 1024,
            max_catalog_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
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
    /// Operator selection. `auto` prefers native filesystem quotas and falls
    /// back to FuseQuota; Qdrant is always resolved to the soft scanner when
    /// that fallback would otherwise be FUSE-backed.
    #[serde(rename = "mode")]
    pub selection: DiskLimitSelection,
    pub project_id_base: u32,
    pub fuse_quota_binary: String,
    pub fuse_quota_binary_sha256: String,
    pub fuse_quota_rescan_interval_seconds: u64,
    pub soft_scanner: SoftDiskScannerConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DiskFileConfig {
    mode: DiskLimitSelection,
    project_id_base: u32,
    fuse_quota_binary: String,
    fuse_quota_binary_sha256: String,
    fuse_quota_rescan_interval_seconds: u64,
    soft_scanner: SoftDiskScannerConfig,
}

impl Default for DiskFileConfig {
    fn default() -> Self {
        let defaults = DiskConfig::default();
        Self {
            mode: defaults.selection,
            project_id_base: defaults.project_id_base,
            fuse_quota_binary: defaults.fuse_quota_binary,
            fuse_quota_binary_sha256: defaults.fuse_quota_binary_sha256,
            fuse_quota_rescan_interval_seconds: defaults.fuse_quota_rescan_interval_seconds,
            soft_scanner: defaults.soft_scanner,
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
            selection: file.mode,
            project_id_base: file.project_id_base,
            fuse_quota_binary: file.fuse_quota_binary,
            fuse_quota_binary_sha256: file.fuse_quota_binary_sha256,
            fuse_quota_rescan_interval_seconds: file.fuse_quota_rescan_interval_seconds,
            soft_scanner: file.soft_scanner,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllocationConfig {
    /// Reject CPU-limit reservations that would allocate more cores than the
    /// daemon host exposes. Disable only when deliberate CPU overcommit is
    /// acceptable.
    pub prevent_cpu_overallocation: bool,
    /// Reject memory-limit reservations that exceed the configured safe pool
    /// or consume the host memory reserve.
    pub prevent_memory_overallocation: bool,
    /// Reject disk-limit reservations that exceed the configured safe pool or
    /// consume the host disk reserve.
    pub prevent_disk_overallocation: bool,
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
            prevent_cpu_overallocation: true,
            prevent_memory_overallocation: true,
            prevent_disk_overallocation: true,
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
    fn overallocation_prevention_defaults_to_enabled() {
        let allocation = AllocationConfig::default();

        assert!(allocation.prevent_cpu_overallocation);
        assert!(allocation.prevent_memory_overallocation);
        assert!(allocation.prevent_disk_overallocation);
    }

    #[test]
    fn legacy_allocation_config_enables_new_guards() {
        let allocation: AllocationConfig = serde_yaml::from_str(
            r#"
max_memory_mib: null
max_disk_mib: null
reserved_memory_mib: 512
reserved_disk_mib: 2048
"#,
        )
        .unwrap();

        assert!(allocation.prevent_cpu_overallocation);
        assert!(allocation.prevent_memory_overallocation);
        assert!(allocation.prevent_disk_overallocation);
    }

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
            selection: DiskLimitSelection::Auto,
            project_id_base: 200_000,
            fuse_quota_binary: "embedded".to_string(),
            fuse_quota_binary_sha256: String::new(),
            fuse_quota_rescan_interval_seconds: 150,
            soft_scanner: SoftDiskScannerConfig::default(),
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

        assert!(yaml.contains("mode: auto"));
        assert!(!yaml.contains("host_filesystem_quota"));
        assert!(yaml.contains("project_id_base:"));
    }

    #[test]
    fn legacy_soft_scanner_config_receives_safe_hybrid_defaults() {
        let scanner: SoftDiskScannerConfig = serde_yaml::from_str(
            r#"
scan_interval_seconds: 20
max_concurrent_scans: 3
"#,
        )
        .unwrap();

        assert!(scanner.use_inotify);
        assert_eq!(scanner.full_scan_interval_seconds, 90);
        assert_eq!(scanner.inotify_debounce_milliseconds, 500);
        assert_eq!(scanner.max_dirty_paths_per_instance, 512);
        assert_eq!(scanner.scan_interval_seconds, 20);
        assert_eq!(scanner.max_concurrent_scans, 3);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskLimitSelection {
    /// Prefer native quotas; fall back to FuseQuota for compatible databases.
    #[default]
    Auto,
    /// Force the FuseQuota fallback for compatible databases.
    FuseQuota,
    /// Scanner-enforced soft limits. `none` is accepted as a compatibility
    /// alias, but API metadata deliberately calls the active mechanism a
    /// soft scanner rather than implying that limits are disabled.
    #[serde(alias = "none")]
    SoftScanner,
    /// Require a supported native filesystem quota implementation.
    ProjectQuota,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SoftDiskScannerConfig {
    /// Base scheduler interval. It is also the authoritative full-scan
    /// interval for protocols such as Qdrant whose mmap writes may not emit
    /// filesystem notifications.
    pub scan_interval_seconds: u64,
    /// Use one process-wide recursive inotify watcher to prioritize changed
    /// instances and perform bounded incremental subtree reconciliation.
    /// Periodic full scans remain authoritative when this is disabled or the
    /// host watcher is unavailable.
    pub use_inotify: bool,
    /// Maximum time between authoritative full scans while incremental
    /// inotify-driven scans are healthy.
    pub full_scan_interval_seconds: u64,
    /// Coalesce event bursts for this long before scanning dirty subtrees.
    pub inotify_debounce_milliseconds: u64,
    /// Maximum independent dirty subtrees retained for one instance. Hitting
    /// the bound discards the hints and forces a full reconciliation.
    pub max_dirty_paths_per_instance: usize,
    /// Concurrent directory walks across all instances.
    pub max_concurrent_scans: usize,
    /// Per-instance entry bound for a single walk.
    pub max_entries_per_scan: usize,
    /// Per-instance wall-clock budget for a single walk.
    pub scan_timeout_seconds: u64,
    /// Stop an active instance after this many consecutive scans cannot
    /// produce a trustworthy measurement. This prevents scanner bounds or
    /// filesystem errors from becoming a fail-open bypass.
    pub max_consecutive_scan_failures: u8,
    /// Minimum reserve used to absorb writes during detection and shutdown.
    pub safety_reserve_mib: u64,
    /// Clear a restart block only below this percentage of the configured
    /// limit. This hysteresis prevents stop/start oscillation.
    pub recovery_percent: u8,
    /// Graceful shutdown deadline before SIGKILL fallback.
    pub shutdown_grace_seconds: u64,
}

impl Default for SoftDiskScannerConfig {
    fn default() -> Self {
        Self {
            scan_interval_seconds: 15,
            use_inotify: true,
            full_scan_interval_seconds: 90,
            inotify_debounce_milliseconds: 500,
            max_dirty_paths_per_instance: 512,
            max_concurrent_scans: 2,
            max_entries_per_scan: 1_000_000,
            scan_timeout_seconds: 30,
            max_consecutive_scan_failures: 3,
            safety_reserve_mib: 64,
            recovery_percent: 85,
            shutdown_grace_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DiskLimitMode {
    #[default]
    FuseQuota,
    ProjectQuota,
    SoftScanner,
}

impl DiskLimitMode {
    /// This legacy API bit means a hard write-time filesystem limit. The soft
    /// scanner remains active enforcement, but is intentionally reported as
    /// non-hard so callers do not mistake it for quota isolation.
    pub fn enforced(self) -> bool {
        self != Self::SoftScanner
    }

    pub fn method(self) -> &'static str {
        match self {
            Self::FuseQuota => "fuse_quota",
            Self::ProjectQuota => "host_filesystem_quota",
            Self::SoftScanner => "soft_scanner",
        }
    }

    pub fn from_persisted_method(method: &str) -> Option<Self> {
        match method {
            "fuse_quota" => Some(Self::FuseQuota),
            "soft_scanner" => Some(Self::SoftScanner),
            "host_filesystem_quota"
            | "host_xfs_project_quota"
            | "host_linux_project_quota"
            | "host_btrfs_qgroup"
            | "host_zfs_refquota" => Some(Self::ProjectQuota),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImageConfig {
    pub postgres: String,
    pub redis: String,
    pub valkey: String,
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
            valkey: "valkey/valkey:9.1.1".to_string(),
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
    pub valkey: Vec<String>,
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
            crate::shared::protocol::Protocol::Valkey => &self.valkey,
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
            crate::shared::protocol::Protocol::Valkey => self.allowed.valkey.iter(),
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
