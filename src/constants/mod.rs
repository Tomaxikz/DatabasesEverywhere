pub const AUTHORIZATION_HEADER: &str = "authorization";
pub const RUST_LOG_ENV: &str = "RUST_LOG";

pub mod defaults {
    pub const CONFIG_PATH: &str = "/etc/databases-everywhere/config.yml";
    pub const DATA_PATH: &str = "/var/lib/dbev";
    pub const SOCKETS_PATH: &str = "/run/dbev/sockets";
    pub const LOCKS_PATH: &str = "/run/dbev/locks";
    pub const LOGS_PATH: &str = "/var/log/dbev";
    pub const ARTIFACTS_PATH: &str = "/var/lib/dbev/artifacts";
}

pub mod docker {
    pub const DEFAULT_NETWORK: &str = "databases-everywhere";
    pub const MANAGED_LABEL: &str = "databases-everywhere.managed";
    pub const INSTANCE_LABEL: &str = "databases-everywhere.instance_id";
    pub const PROTOCOL_LABEL: &str = "databases-everywhere.protocol";
    pub const PROJECT_LABEL: &str = "databases-everywhere.project";
}

pub mod jwt {
    pub const AUDIENCE: &str = "databases-everywhere-daemon";
    pub const ISSUER: &str = "panel";
}

pub mod ports {
    pub const POSTGRES: u16 = 5433;
    pub const MARIADB: u16 = 3307;
    pub const REDIS: u16 = 6380;
    pub const MONGODB: u16 = 27017;
    pub const CLICKHOUSE: u16 = 9000;
    pub const CLICKHOUSE_HTTP: u16 = 8123;
    pub const QDRANT: u16 = 6334;
    pub const API: u16 = 8090;
}
