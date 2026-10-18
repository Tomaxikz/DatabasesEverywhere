use std::path::PathBuf;

use secrecy::SecretString;

use crate::{databases::protocol::Protocol, runtime::socket_bridge::SocketBridge};

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
    pub extra_mounts: Vec<DockerMount>,
    pub socket_bridges: Vec<SocketBridge>,
    pub env: Vec<DockerEnv>,
    pub command: Vec<String>,
}

impl DockerInstanceSpec {
    /// A spec with the managed defaults (1 CPU, 1 GiB memory, 10 GiB disk,
    /// image user, entrypoint and working directory, no extra mounts, bridges,
    /// environment or command). Engines override fields with struct update.
    pub fn with_defaults(
        instance_id: &str,
        protocol: Protocol,
        image: &str,
        data_path: PathBuf,
        data_target: &str,
    ) -> Self {
        Self {
            instance_id: instance_id.to_string(),
            protocol,
            image: image.to_string(),
            project_id: None,
            user: None,
            working_dir: None,
            entrypoint: None,
            cpu_cores: 1.0,
            memory_mib: 1024,
            disk_mib: 10240,
            pids_limit: None,
            data_path,
            data_target: data_target.to_string(),
            extra_mounts: Vec::new(),
            socket_bridges: Vec::new(),
            env: Vec::new(),
            command: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DockerEnv {
    pub key: String,
    pub value: SecretString,
}

impl DockerEnv {
    pub fn new(key: &str, value: SecretString) -> Self {
        Self {
            key: key.to_string(),
            value,
        }
    }

    /// A non-secret value; it is still stored redacted like every entry.
    pub fn plain(key: &str, value: &str) -> Self {
        Self::new(key, SecretString::from(value.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct DockerMount {
    pub source: PathBuf,
    pub target: String,
    pub read_only: bool,
}
