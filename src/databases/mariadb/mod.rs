pub mod docker;
pub mod provision;

pub mod config {
    #[derive(Debug, Clone)]
    pub struct MariadbInstanceConfig {
        pub database: String,
        pub username: String,
    }
}

pub mod credentials {
    pub type MariadbCredentials = crate::shared::credentials::TenantCredentials;
}

pub mod health {
    pub const HEALTH_COMMAND: &str = "mariadb-admin ping -h 127.0.0.1";
}

pub mod logs {
    pub const LOG_SOURCE: &str = "docker";
}

pub mod metadata {
    pub const PROTOCOL_NAME: &str = "mariadb";
}
