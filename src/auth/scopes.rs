pub const ALL: &str = "*";

pub const SYSTEM_READ: &str = "system:read";
pub const INSTANCES_READ: &str = "instances:read";
pub const INSTANCES_WRITE: &str = "instances:write";
pub const INSTANCES_ADMIN: &str = "instances:admin";
pub const RESOURCES_READ: &str = "resources:read";
pub const RESOURCES_ADMIN: &str = "resources:admin";
pub const LOGS_READ: &str = "logs:read";
pub const METRICS_READ: &str = "metrics:read";
pub const ARTIFACTS_READ: &str = "artifacts:read";
pub const ARTIFACTS_WRITE: &str = "artifacts:write";
pub const BACKUPS_READ: &str = "backups:read";
pub const BACKUPS_WRITE: &str = "backups:write";
pub const BACKUPS_ADMIN: &str = "backups:admin";
pub const IMPORT_EXPORT_READ: &str = "import-export:read";
pub const IMPORT_EXPORT_WRITE: &str = "import-export:write";
pub const RECOVERY_ADMIN: &str = "recovery:admin";
pub const IMAGES_ADMIN: &str = "images:admin";
pub const CONFIG_ADMIN: &str = "config:admin";
pub const WS_TOKENS_WRITE: &str = "ws-tokens:write";

pub const MONITOR_READ: &str = "monitor:read";

pub const KNOWN: &[&str] = &[
    ALL,
    SYSTEM_READ,
    INSTANCES_READ,
    INSTANCES_WRITE,
    INSTANCES_ADMIN,
    RESOURCES_READ,
    RESOURCES_ADMIN,
    LOGS_READ,
    METRICS_READ,
    ARTIFACTS_READ,
    ARTIFACTS_WRITE,
    BACKUPS_READ,
    BACKUPS_WRITE,
    BACKUPS_ADMIN,
    IMPORT_EXPORT_READ,
    IMPORT_EXPORT_WRITE,
    RECOVERY_ADMIN,
    IMAGES_ADMIN,
    CONFIG_ADMIN,
    WS_TOKENS_WRITE,
    MONITOR_READ,
];

pub fn is_known(scope: &str) -> bool {
    KNOWN.contains(&scope)
}

pub fn allows(granted: &[String], required: &str) -> bool {
    granted
        .iter()
        .any(|scope| scope.as_str() == ALL || scope == required)
}
