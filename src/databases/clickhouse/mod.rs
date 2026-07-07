pub mod docker;

pub mod config {
    #[derive(Debug, Clone)]
    pub struct ClickhouseInstanceConfig {
        pub database: String,
    }
}

pub mod credentials {
    pub type ClickhouseCredentials = crate::shared::credentials::TenantCredentials;
}

pub mod health {
    pub const HEALTH_COMMAND: &str = "clickhouse-client --query 'SELECT 1'";
}

pub mod protocol {
    pub const DEFAULT_PORT: u16 = 9000;
    pub const PROTOCOL_NAME: &str = "clickhouse";
}
