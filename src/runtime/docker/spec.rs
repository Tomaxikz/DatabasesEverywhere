use std::path::PathBuf;

use secrecy::SecretString;

use crate::{runtime::socket_bridge::SocketBridge, shared::protocol::Protocol};

#[derive(Debug, Clone)]
pub struct DockerInstanceSpec {
    pub instance_id: String,
    pub protocol: Protocol,
    pub image: String,
    pub project_id: Option<String>,
    pub user: Option<String>,
    pub working_dir: Option<String>,
    pub entrypoint: Option<Vec<String>>,
    pub cpu_cores: f64,
    pub memory_mib: u64,
    pub disk_mib: u64,
    pub pids_limit: Option<i64>,
    pub data_path: PathBuf,
    pub data_target: String,
    pub logs_path: PathBuf,
    pub logs_target: String,
    pub extra_mounts: Vec<DockerMount>,
    pub socket_bridges: Vec<SocketBridge>,
    pub env: Vec<DockerEnv>,
    pub command: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DockerEnv {
    pub key: String,
    pub value: SecretString,
}

#[derive(Debug, Clone)]
pub struct DockerMount {
    pub source: PathBuf,
    pub target: String,
    pub read_only: bool,
}
