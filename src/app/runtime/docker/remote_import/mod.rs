use std::{path::PathBuf, time::Duration};

use super::DockerEnv;
use crate::databases::protocol::Protocol;

const HELPER_LABEL: &str = "databases-everywhere.remote-import-helper";
const HELPER_NAME_PREFIX: &str = "dbe-remote-import-";
const HELPER_WORK_DIR: &str = "/work";
pub const IMPORT_HELPER_INPUT_PATH: &str = "/dbev/input";
const HELPER_TMPFS: &str = "rw,noexec,nosuid,nodev,size=64m,mode=1777";
const HELPER_CPU_CORES: f64 = 1.0;
const HELPER_MEMORY_MIB: u64 = 1024;
const HELPER_PIDS_LIMIT: i64 = 128;
const HELPER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const HELPER_LOG_TAIL_CHARS: usize = 16 * 1024;
const HELPER_FAILURE_TAIL_CHARS: usize = 4_000;
const OUTPUT_SIZE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_WORK_DIRECTORY_ENTRIES: usize = 4096;
const MAX_WORK_DIRECTORY_DEPTH: usize = 32;
const MAX_HELPER_SCRIPT_BYTES: usize = 256 * 1024;
const MAX_EXTRA_HOSTS: usize = 64;
const MAX_EXTRA_HOST_BYTES: usize = 512;
const HELPER_NAME_SUFFIX_LEN: usize = 32;
const HELPER_STOP_TIMEOUT_SECONDS: i64 = 10;
const MAX_HELPER_ENVIRONMENT_ENTRIES: usize = 64;
const MAX_HELPER_ENVIRONMENT_BYTES: usize = 64 * 1024;

/// Description of a one-shot import helper. Outbound acquisition helpers use
/// an isolated bridge; shared restores join one verified pool's network
/// namespace without mounting its data. `script` is stored in Docker's
/// container configuration and therefore must never contain secrets.
#[derive(Clone)]
pub struct RemoteImportHelperSpec {
    pub image: String,
    pub work_dir: PathBuf,
    pub script: String,
    pub extra_hosts: Vec<String>,
    pub timeout: Duration,
    pub max_output_bytes: u64,
    pub network: ImportHelperNetwork,
    pub input: Option<ImportHelperInput>,
    pub environment: Vec<DockerEnv>,
    pub read_only_work_dir: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportHelperNetwork {
    Outbound,
    ManagedRuntime {
        protocol: Protocol,
        runtime_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportHelperInput {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug)]
struct ResolvedHelperNetwork {
    mode: String,
}

mod cancellation;
mod container;
mod output;
mod runtime;
#[cfg(test)]
mod tests;
mod validation;
