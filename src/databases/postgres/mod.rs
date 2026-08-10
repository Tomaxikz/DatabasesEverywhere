pub mod docker;
pub mod hardening;
pub mod provision;

pub mod config {
    #[derive(Debug, Clone)]
    pub struct PostgresInstanceConfig {
        pub database: String,
        pub username: String,
    }
}

pub mod credentials {
    pub type PostgresCredentials = crate::shared::credentials::TenantCredentials;
}

pub mod health {
    pub const HEALTH_COMMAND: &str = "psql -X -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -Atqc 'SELECT 1' >/dev/null";
}

pub mod logs {
    pub const LOG_SOURCE: &str = "docker";
}

pub mod metadata {
    pub const PROTOCOL_NAME: &str = "postgres";
}

#[cfg(test)]
mod integration_tests;
