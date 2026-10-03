use crate::{
    databases::engine::{
        EngineCompatibility, EngineFamily, EngineInfo, JobCostProfile, SQL_JOB_COST,
        SharedPoolProfile,
    },
    databases::protocol::Protocol,
    server::compatibility::{EngineVersion, distrib_version},
    utils::backend::MARIADB_SOCKET_DIRECTORY,
};

pub(crate) struct Mariadb;

impl EngineInfo for Mariadb {
    fn protocol(&self) -> Protocol {
        Protocol::Mariadb
    }

    fn family(&self) -> EngineFamily {
        EngineFamily::Mysql
    }

    fn default_container_port(&self) -> u16 {
        3306
    }

    fn container_data_target(&self) -> &'static str {
        "/var/lib/mysql"
    }

    fn container_socket_directory(&self) -> &'static str {
        MARIADB_SOCKET_DIRECTORY
    }

    fn socket_filename(&self) -> &'static str {
        "mysqld.sock"
    }

    fn rootless_podman_identity(&self) -> (&'static str, &'static str) {
        ("999:999", "keep-id:uid=999,gid=999")
    }

    fn startup_readiness_script(&self) -> &'static str {
        "test \"$(cat /proc/1/comm)\" = mariadbd || exit 1; root_password=\"${DBE_MARIADB_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}\"; MYSQL_PWD=\"$root_password\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -u root -N -B -e 'SELECT 1' >/dev/null"
    }

    fn shared_pool(&self) -> Option<SharedPoolProfile> {
        Some(SharedPoolProfile {
            disk_overhead_mib: 512,
            max_database_name_bytes: 64,
            reserved_databases: &["performance_schema", "sys"],
        })
    }

    fn dump_extension(&self) -> &'static str {
        "mariadb.sql"
    }

    fn dump_candidate_suffixes(&self) -> &'static [&'static str] {
        &[".mariadb.sql", ".mysql.sql", ".sql"]
    }

    fn database_env_key(&self) -> Option<&'static str> {
        Some("MARIADB_DATABASE")
    }

    fn export_expansion_factor(&self) -> u64 {
        4
    }

    fn job_cost(&self) -> JobCostProfile {
        SQL_JOB_COST
    }

    fn default_remote_port(&self, _tls: bool) -> u16 {
        3306
    }

    fn sql_backslash_strings(&self) -> bool {
        true
    }

    fn gateway_counts_operations(&self) -> bool {
        true
    }
}

impl EngineCompatibility for Mariadb {
    fn is_supported_version(&self, version: EngineVersion) -> bool {
        matches!(
            (version.major, version.minor),
            (10, 11) | (11, 4 | 8) | (12, 3)
        )
    }

    fn supported_versions(&self) -> &'static str {
        "MariaDB 10.11, 11.4, 11.8, or 12.3"
    }

    fn version_script(&self) -> &'static str {
        "mariadb --version 2>/dev/null || mysqld --version"
    }

    fn normalize_version<'a>(&self, line: &'a str) -> &'a str {
        distrib_version(line).unwrap_or(line)
    }
}
