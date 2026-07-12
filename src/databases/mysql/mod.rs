pub mod docker;
pub mod provision;

#[cfg(test)]
mod integration_tests;

pub mod config {
    #[derive(Debug, Clone)]
    pub struct MysqlInstanceConfig {
        pub database: String,
        pub username: String,
    }
}

pub mod credentials {
    pub type MysqlCredentials = crate::shared::credentials::TenantCredentials;
}

pub mod health {
    pub const HEALTH_COMMAND: &str =
        "mysqladmin ping --protocol=socket --socket=/var/run/mysqld/mysqld.sock";
}

pub mod logs {
    pub const LOG_SOURCE: &str = "docker";
}

pub mod metadata {
    pub const PROTOCOL_NAME: &str = "mysql";
}
