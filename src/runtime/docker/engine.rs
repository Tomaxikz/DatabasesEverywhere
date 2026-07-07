use std::path::Path;

use bollard::{API_DEFAULT_VERSION, Docker};

use crate::config::{DaemonConfig, DaemonEngine};

const API_TIMEOUT_SECONDS: u64 = 120;
const PODMAN_SYSTEM_SOCKET: &str = "/run/podman/podman.sock";

#[derive(Debug, Clone)]
pub struct DaemonEngineConnection {
    pub engine: DaemonEngine,
    pub socket_path: Option<String>,
}

impl DaemonEngineConnection {
    pub fn from_config(config: &DaemonConfig) -> Self {
        Self {
            engine: config.engine,
            socket_path: configured_or_default_socket(config),
        }
    }

    pub fn connect(&self) -> Result<Docker, bollard::errors::Error> {
        if let Some(socket_path) = self.socket_path.as_deref() {
            return Docker::connect_with_socket(
                socket_path,
                API_TIMEOUT_SECONDS,
                API_DEFAULT_VERSION,
            );
        }

        match self.engine {
            DaemonEngine::Docker => Docker::connect_with_local_defaults(),
            DaemonEngine::Podman => Docker::connect_with_socket(
                PODMAN_SYSTEM_SOCKET,
                API_TIMEOUT_SECONDS,
                API_DEFAULT_VERSION,
            ),
        }
    }

    pub fn socket_path_for_logs(&self) -> &str {
        self.socket_path.as_deref().unwrap_or("auto")
    }
}

fn configured_or_default_socket(config: &DaemonConfig) -> Option<String> {
    if let Some(socket_path) = config.configured_socket_path() {
        return Some(socket_path.to_string());
    }

    match config.engine {
        DaemonEngine::Docker => None,
        DaemonEngine::Podman => discover_podman_socket(),
    }
}

fn discover_podman_socket() -> Option<String> {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let socket = format!("{runtime_dir}/podman/podman.sock");
        if Path::new(&socket).exists() {
            return Some(socket);
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if let Ok(metadata) = std::fs::metadata("/proc/self") {
            let socket = format!("/run/user/{}/podman/podman.sock", metadata.uid());
            if Path::new(&socket).exists() {
                return Some(socket);
            }
        }
    }

    if Path::new(PODMAN_SYSTEM_SOCKET).exists() {
        return Some(PODMAN_SYSTEM_SOCKET.to_string());
    }

    None
}
