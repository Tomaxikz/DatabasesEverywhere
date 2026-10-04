mod allocation;
mod artifact;
mod backup;
mod daemon;
mod disk;
mod images;
mod limits;
mod listeners;
pub mod load;
mod origins;
pub mod path_policy;
mod paths;
mod scheduler;
mod security;
mod sensitive;
#[cfg(test)]
mod tests;
pub mod validate;

pub use allocation::AllocationConfig;
pub use artifact::ArtifactConfig;
pub use backup::{
    BackupBrowsingConfig, BackupConfig, BackupKopiaConfig, BackupS3Config, BackupStorageConfig,
    BackupStorageDriver,
};
pub use daemon::{DaemonConfig, DaemonEngine};
pub use disk::{DiskConfig, DiskLimitMode, DiskLimitSelection, SoftDiskScannerConfig};
pub use images::{ImageAllowlistConfig, ImageConfig};
pub use limits::RuntimeLimits;
pub use listeners::{ApiConfig, ApiSslConfig, ClickhouseConfig, ListenerConfig, TlsConfig};
pub(crate) use origins::{normalize_http_origin, normalize_remote_import_host, url_origin};
pub use paths::PathConfig;
pub use scheduler::ImportExportSchedulerConfig;
pub use security::{PidsLimitConfig, RemoteImportSecurityConfig, SecurityConfig};
pub use sensitive::SensitiveString;

use std::{ops::Deref, sync::Arc};

use serde::{Deserialize, Serialize};

use crate::utils::constants::ports;

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
            postgres: ListenerConfig::enabled(loopback_bind(ports::POSTGRES)),
            mariadb: ListenerConfig::enabled(loopback_bind(ports::MARIADB)),
            mysql: ListenerConfig::disabled(loopback_bind(ports::MYSQL)),
            redis: ListenerConfig::enabled(loopback_bind(ports::REDIS)),
            valkey: ListenerConfig::disabled(loopback_bind(ports::VALKEY)),
            mongodb: ListenerConfig::disabled(loopback_bind(ports::MONGODB)),
            clickhouse: ClickhouseConfig::default(),
            qdrant: ListenerConfig::disabled(loopback_bind(ports::QDRANT)),
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

fn loopback_bind(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// One immutable configuration and its shared resources for a daemon run.
/// Clone the Arc, not the budgets: all consumers must share the same capacity.
/// YAML remains represented by Config; changing it takes effect on restart.
#[derive(Debug)]
pub struct RuntimeConfig {
    settings: Arc<Config>,
    pub(crate) sql_buffer_budget: Arc<tokio::sync::Semaphore>,
    pub(crate) budgets: limits::SharedBudgets,
}

impl RuntimeConfig {
    pub fn new(settings: Config) -> Result<Self, validate::ConfigValidationError> {
        settings.daemon.validate_runtime_limits()?;
        let sql_buffer_bytes = settings.daemon.sql_buffer_global_bytes()?;
        tracing::info!(
            event = "sql_buffer_budget_initialized",
            global_mib = settings.daemon.sql_buffer_global_mib,
            global_bytes = sql_buffer_bytes,
            "shared SQL buffer capacity configured; changes require a restart"
        );
        Ok(Self {
            budgets: settings.daemon.limits.shared_budgets(),
            settings: Arc::new(settings),
            sql_buffer_budget: Arc::new(tokio::sync::Semaphore::new(sql_buffer_bytes)),
        })
    }

    /// Read-only YAML settings for jobs that do not need runtime resources.
    pub fn snapshot(&self) -> Arc<Config> {
        Arc::clone(&self.settings)
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::new(Config::default()).expect("default runtime limits must be valid")
    }
}

impl Deref for RuntimeConfig {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.settings
    }
}
