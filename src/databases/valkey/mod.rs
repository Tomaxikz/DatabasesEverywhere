pub mod docker;

pub mod provision {
    pub use crate::databases::redis::provision::{
        RedisProvisionError, restore_acl_file, write_acl_file,
    };
}

pub mod config {
    #[derive(Debug, Clone)]
    pub struct ValkeyInstanceConfig {
        pub username: String,
    }
}

pub mod credentials {
    pub type ValkeyCredentials = crate::shared::credentials::TenantCredentials;
}

pub mod health {
    pub const HEALTH_COMMAND: &str = "valkey-cli ping";
}

pub mod logs {
    pub const LOG_SOURCE: &str = "docker";
}

pub mod metadata {
    pub const PROTOCOL_NAME: &str = "valkey";
}
