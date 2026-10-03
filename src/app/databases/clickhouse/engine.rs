use crate::{
    databases::engine::{
        EngineCompatibility, EngineFamily, EngineInfo, JobCostProfile, SharedPoolProfile,
    },
    databases::protocol::Protocol,
    server::compatibility::EngineVersion,
    utils::backend::CONTAINER_SOCKET_DIRECTORY,
};

pub(crate) struct Clickhouse;

impl EngineInfo for Clickhouse {
    fn protocol(&self) -> Protocol {
        Protocol::Clickhouse
    }

    fn family(&self) -> EngineFamily {
        EngineFamily::Columnar
    }

    fn default_container_port(&self) -> u16 {
        9000
    }

    fn container_data_target(&self) -> &'static str {
        "/var/lib/clickhouse"
    }

    fn container_socket_directory(&self) -> &'static str {
        CONTAINER_SOCKET_DIRECTORY
    }

    fn socket_filename(&self) -> &'static str {
        "clickhouse-native.sock"
    }

    fn rootless_podman_identity(&self) -> (&'static str, &'static str) {
        ("0:0", "host")
    }

    fn startup_readiness_script(&self) -> &'static str {
        "clickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query 'SELECT 1' >/dev/null"
    }

    fn allows_socket_bridges(&self) -> bool {
        true
    }

    fn shared_pool(&self) -> Option<SharedPoolProfile> {
        Some(SharedPoolProfile {
            disk_overhead_mib: 1024,
            max_database_name_bytes: 128,
            reserved_databases: &["dbe_control", "default", "system"],
        })
    }

    fn dump_extension(&self) -> &'static str {
        "clickhouse.sql"
    }

    fn dump_candidate_suffixes(&self) -> &'static [&'static str] {
        &[".clickhouse.sql", ".sql"]
    }

    fn database_env_key(&self) -> Option<&'static str> {
        Some("CLICKHOUSE_DB")
    }

    fn export_expansion_factor(&self) -> u64 {
        4
    }

    fn job_cost(&self) -> JobCostProfile {
        JobCostProfile {
            base_memory_mib: 192,
            io_multiplier: 3,
            base_cpu_units: 2,
            stream_memory_divisor: 32,
            stream_memory_cap_mib: 256,
        }
    }

    fn default_remote_port(&self, tls: bool) -> u16 {
        if tls { 9440 } else { 9000 }
    }

    fn sql_backslash_strings(&self) -> bool {
        true
    }

    fn is_driver_placeholder_database(&self, _username: &str, database: Option<&str>) -> bool {
        database == Some("default")
    }

    fn requires_heavy_memory(&self) -> bool {
        true
    }
}

impl EngineCompatibility for Clickhouse {
    fn is_supported_version(&self, version: EngineVersion) -> bool {
        matches!(version.major, 25 | 26)
    }

    fn supported_versions(&self) -> &'static str {
        "ClickHouse 25.x or 26.x"
    }

    fn version_script(&self) -> &'static str {
        "clickhouse-server --version 2>/dev/null || clickhouse --version"
    }

    fn normalize_version<'a>(&self, line: &'a str) -> &'a str {
        line.strip_prefix("ClickHouse server version ")
            .or_else(|| line.strip_prefix("ClickHouse local version "))
            .or_else(|| line.strip_prefix("ClickHouse client version "))
            .unwrap_or(line)
            .split(" (")
            .next()
            .unwrap_or(line)
    }
}
