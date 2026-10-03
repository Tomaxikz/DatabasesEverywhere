use crate::{
    databases::engine::{
        EngineCompatibility, EngineFamily, EngineInfo, JobCostProfile, PHYSICAL_JOB_COST,
    },
    instance::compatibility::{EngineVersion, ProtocolCapabilities},
    utils::{backend::CONTAINER_SOCKET_DIRECTORY, protocol::Protocol},
};

pub(crate) struct Qdrant;

impl EngineInfo for Qdrant {
    fn protocol(&self) -> Protocol {
        Protocol::Qdrant
    }

    fn family(&self) -> EngineFamily {
        EngineFamily::Vector
    }

    fn default_container_port(&self) -> u16 {
        6334
    }

    fn container_data_target(&self) -> &'static str {
        "/dbe-qdrant"
    }

    fn container_socket_directory(&self) -> &'static str {
        CONTAINER_SOCKET_DIRECTORY
    }

    fn socket_filename(&self) -> &'static str {
        "qdrant-grpc.sock"
    }

    fn rootless_podman_identity(&self) -> (&'static str, &'static str) {
        ("0:0", "host")
    }

    fn startup_readiness_script(&self) -> &'static str {
        "/opt/dbev/dbev-socket-bridge __socket-bridge-healthcheck 127.0.0.1:6334"
    }

    fn allows_socket_bridges(&self) -> bool {
        true
    }

    fn dump_extension(&self) -> &'static str {
        "qdrant.tar.gz"
    }

    fn dump_candidate_suffixes(&self) -> &'static [&'static str] {
        &[".qdrant.tar.gz", ".tar.gz"]
    }

    fn export_expansion_factor(&self) -> u64 {
        1
    }

    fn job_cost(&self) -> JobCostProfile {
        PHYSICAL_JOB_COST
    }

    fn remote_import_recovery_kind(&self) -> &'static str {
        "qdrant_remote_import"
    }

    fn default_remote_port(&self, _tls: bool) -> u16 {
        6333
    }

    fn mmap_writes_bypass_inotify(&self) -> bool {
        true
    }

    fn fuse_quota_unsupported(&self) -> bool {
        true
    }
}

impl EngineCompatibility for Qdrant {
    fn is_supported_version(&self, version: EngineVersion) -> bool {
        version.major == 1 && matches!(version.minor, 17 | 18)
    }

    fn supported_versions(&self) -> &'static str {
        "Qdrant 1.17 or 1.18"
    }

    fn capabilities(&self, _version: EngineVersion) -> ProtocolCapabilities {
        ProtocolCapabilities {
            qdrant_rest: true,
            qdrant_grpc: true,
            ..ProtocolCapabilities::default()
        }
    }

    fn version_script(&self) -> &'static str {
        "if command -v qdrant >/dev/null 2>&1; then qdrant --version; elif [ -x /qdrant/qdrant ]; then /qdrant/qdrant --version; else cat /qdrant/VERSION 2>/dev/null; fi"
    }

    fn normalize_version<'a>(&self, line: &'a str) -> &'a str {
        line.strip_prefix("qdrant ")
            .or_else(|| line.strip_prefix("Qdrant "))
            .unwrap_or(line)
    }
}
