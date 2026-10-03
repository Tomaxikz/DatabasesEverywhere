use super::*;

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
