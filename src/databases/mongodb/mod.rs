pub mod docker;
pub mod provision;

pub mod config {
    #[derive(Debug, Clone)]
    pub struct MongodbInstanceConfig {
        pub database: String,
        pub username: String,
    }
}

pub mod credentials {
    pub type MongodbCredentials = crate::shared::credentials::TenantCredentials;
}

pub mod health {
    pub const HEALTH_COMMAND: &str = "mongosh --eval 'db.adminCommand(\"ping\")'";
}

pub mod logs {
    pub const LOG_SOURCE: &str = "docker";
}

pub mod metadata {
    pub const PROTOCOL_NAME: &str = "mongodb";
}
