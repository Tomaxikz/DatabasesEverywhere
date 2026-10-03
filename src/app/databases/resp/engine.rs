use crate::{
    databases::engine::{
        EngineCompatibility, EngineFamily, EngineInfo, JobCostProfile, PHYSICAL_JOB_COST,
    },
    databases::protocol::Protocol,
    server::compatibility::{EngineVersion, ProtocolCapabilities},
    utils::backend::CONTAINER_SOCKET_DIRECTORY,
};

pub(crate) struct Redis;

pub(crate) struct Valkey;

fn resp_capabilities(version: EngineVersion) -> ProtocolCapabilities {
    ProtocolCapabilities {
        redis_resp3: version.major >= 6,
        ..ProtocolCapabilities::default()
    }
}

fn resp_remote_port(tls: bool) -> u16 {
    if tls { 6380 } else { 6379 }
}

fn resp_server_version(line: &str) -> &str {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix("v="))
        .unwrap_or(line)
}

impl EngineInfo for Redis {
    fn protocol(&self) -> Protocol {
        Protocol::Redis
    }

    fn family(&self) -> EngineFamily {
        EngineFamily::Resp
    }

    fn default_container_port(&self) -> u16 {
        6379
    }

    fn container_data_target(&self) -> &'static str {
        "/data"
    }

    fn container_socket_directory(&self) -> &'static str {
        CONTAINER_SOCKET_DIRECTORY
    }

    fn socket_filename(&self) -> &'static str {
        "redis.sock"
    }

    fn rootless_podman_identity(&self) -> (&'static str, &'static str) {
        ("0:0", "host")
    }

    fn startup_readiness_script(&self) -> &'static str {
        "redis-cli -s /run/dbev/redis.sock --user dbe_health -a healthcheck --no-auth-warning ping >/dev/null"
    }

    fn dump_extension(&self) -> &'static str {
        "redis.tar.gz"
    }

    fn dump_candidate_suffixes(&self) -> &'static [&'static str] {
        &[".redis.tar.gz", ".tar.gz"]
    }

    fn export_expansion_factor(&self) -> u64 {
        1
    }

    fn job_cost(&self) -> JobCostProfile {
        PHYSICAL_JOB_COST
    }

    fn remote_import_recovery_kind(&self) -> &'static str {
        "redis_remote_import"
    }

    fn default_remote_port(&self, tls: bool) -> u16 {
        resp_remote_port(tls)
    }
}

impl EngineCompatibility for Redis {
    fn is_supported_version(&self, version: EngineVersion) -> bool {
        matches!((version.major, version.minor), (6, 2) | (7, 2 | 4)) || version.major == 8
    }

    fn supported_versions(&self) -> &'static str {
        "Redis 6.2, 7.2, 7.4, or 8.x"
    }

    fn capabilities(&self, version: EngineVersion) -> ProtocolCapabilities {
        resp_capabilities(version)
    }

    fn version_script(&self) -> &'static str {
        "redis-server --version"
    }

    fn normalize_version<'a>(&self, line: &'a str) -> &'a str {
        resp_server_version(line)
    }
}

impl EngineInfo for Valkey {
    fn protocol(&self) -> Protocol {
        Protocol::Valkey
    }

    fn family(&self) -> EngineFamily {
        EngineFamily::Resp
    }

    fn default_container_port(&self) -> u16 {
        6379
    }

    fn container_data_target(&self) -> &'static str {
        "/data"
    }

    fn container_socket_directory(&self) -> &'static str {
        CONTAINER_SOCKET_DIRECTORY
    }

    fn socket_filename(&self) -> &'static str {
        "valkey.sock"
    }

    fn rootless_podman_identity(&self) -> (&'static str, &'static str) {
        ("0:0", "host")
    }

    fn startup_readiness_script(&self) -> &'static str {
        "valkey-cli -s /run/dbev/valkey.sock --user dbe_health -a healthcheck --no-auth-warning ping >/dev/null"
    }

    fn dump_extension(&self) -> &'static str {
        "valkey.tar.gz"
    }

    fn dump_candidate_suffixes(&self) -> &'static [&'static str] {
        &[".valkey.tar.gz", ".tar.gz"]
    }

    fn export_expansion_factor(&self) -> u64 {
        1
    }

    fn job_cost(&self) -> JobCostProfile {
        PHYSICAL_JOB_COST
    }

    fn remote_import_recovery_kind(&self) -> &'static str {
        "valkey_remote_import"
    }

    fn default_remote_port(&self, tls: bool) -> u16 {
        resp_remote_port(tls)
    }
}

impl EngineCompatibility for Valkey {
    fn is_supported_version(&self, version: EngineVersion) -> bool {
        matches!((version.major, version.minor), (7, 2)) || matches!(version.major, 8 | 9)
    }

    fn supported_versions(&self) -> &'static str {
        "Valkey 7.2, 8.x, or 9.x"
    }

    fn capabilities(&self, version: EngineVersion) -> ProtocolCapabilities {
        resp_capabilities(version)
    }

    fn version_script(&self) -> &'static str {
        "valkey-server --version"
    }

    fn normalize_version<'a>(&self, line: &'a str) -> &'a str {
        resp_server_version(line)
    }
}
