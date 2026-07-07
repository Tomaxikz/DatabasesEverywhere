pub mod docker;
pub mod provision;

pub mod config {
    #[derive(Debug, Clone)]
    pub struct RedisInstanceConfig {
        pub username: String,
    }
}

pub mod credentials {
    pub type RedisCredentials = crate::shared::credentials::TenantCredentials;
}

pub mod health {
    pub const HEALTH_COMMAND: &str = "redis-cli ping";
}

pub mod logs {
    pub const LOG_SOURCE: &str = "docker";
}

pub mod metadata {
    pub const PROTOCOL_NAME: &str = "redis";
}
