use serde::{Deserialize, Serialize};

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
