use crate::{
    databases::engine::{
        EngineCompatibility, EngineFamily, EngineInfo, JobCostProfile, SharedPoolProfile,
    },
    instance::compatibility::{EngineVersion, ProtocolCapabilities},
    utils::{backend::CONTAINER_SOCKET_DIRECTORY, protocol::Protocol},
};

pub(crate) struct Mongodb;

impl EngineInfo for Mongodb {
    fn protocol(&self) -> Protocol {
        Protocol::Mongodb
    }

    fn family(&self) -> EngineFamily {
        EngineFamily::Document
    }

    fn default_container_port(&self) -> u16 {
        27017
    }

    fn container_data_target(&self) -> &'static str {
        "/data/db"
    }

    fn container_socket_directory(&self) -> &'static str {
        CONTAINER_SOCKET_DIRECTORY
    }

    fn socket_filename(&self) -> &'static str {
        "mongodb-27017.sock"
    }

    fn rootless_podman_identity(&self) -> (&'static str, &'static str) {
        ("999:999", "keep-id:uid=999,gid=999")
    }

    fn startup_readiness_script(&self) -> &'static str {
        "mongosh --quiet --host 127.0.0.1 --username \"$DBE_MONGO_ROOT_USER\" --password \"$DBE_MONGO_ROOT_PASSWORD\" --authenticationDatabase admin admin --eval 'db.adminCommand({ ping: 1 })' >/dev/null"
    }

    fn shared_pool(&self) -> Option<SharedPoolProfile> {
        Some(SharedPoolProfile {
            disk_overhead_mib: 512,
            max_database_name_bytes: 63,
            reserved_databases: &["config"],
        })
    }

    fn dump_extension(&self) -> &'static str {
        "mongodb.archive.gz"
    }

    fn dump_candidate_suffixes(&self) -> &'static [&'static str] {
        &[".mongodb.archive.gz", ".archive.gz"]
    }

    fn database_env_key(&self) -> Option<&'static str> {
        Some("DBE_MONGO_DATABASE")
    }

    fn native_export_compression(&self) -> bool {
        true
    }

    fn export_expansion_factor(&self) -> u64 {
        2
    }

    fn job_cost(&self) -> JobCostProfile {
        JobCostProfile {
            base_memory_mib: 256,
            io_multiplier: 4,
            base_cpu_units: 2,
            stream_memory_divisor: 16,
            stream_memory_cap_mib: 512,
        }
    }

    fn default_remote_port(&self, _tls: bool) -> u16 {
        27017
    }

    fn requires_heavy_memory(&self) -> bool {
        true
    }

    fn gateway_counts_operations(&self) -> bool {
        true
    }
}

impl EngineCompatibility for Mongodb {
    fn is_supported_version(&self, version: EngineVersion) -> bool {
        matches!(version.major, 7 | 8)
    }

    fn supported_versions(&self) -> &'static str {
        "MongoDB 7 or 8"
    }

    fn capabilities(&self, _version: EngineVersion) -> ProtocolCapabilities {
        ProtocolCapabilities {
            mongodb_scram_sha256: true,
            ..ProtocolCapabilities::default()
        }
    }

    fn version_script(&self) -> &'static str {
        "mongod --version | awk '/db version/ {print $3; exit}'"
    }

    fn normalize_version<'a>(&self, line: &'a str) -> &'a str {
        line.strip_prefix('v').unwrap_or(line)
    }
}
