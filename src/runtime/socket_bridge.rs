use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::Context;

use crate::{bins, config::PathConfig, shared::backend::CONTAINER_SOCKET_DIRECTORY};

pub const SOCKET_BRIDGE_SUBCOMMAND: &str = "__socket-bridge-supervisor";
pub const SOCKET_BRIDGE_HEALTHCHECK: &str = "__socket-bridge-healthcheck";
const HELPER_DIRECTORY: &str = "runtime";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketBridge {
    pub socket_path: String,
    pub target: SocketAddr,
}

pub fn helper_host_path(paths: &PathConfig) -> PathBuf {
    Path::new(&paths.metadata_root())
        .join(HELPER_DIRECTORY)
        .join("bin")
        .join(bins::SOCKET_BRIDGE_FILENAME)
}

pub async fn install_helper(paths: &PathConfig) -> anyhow::Result<PathBuf> {
    let runtime_root = Path::new(&paths.metadata_root()).join(HELPER_DIRECTORY);
    let installed = bins::get_socket_bridge_bin_path(&runtime_root)
        .await
        .context("failed to install the embedded static socket bridge")?;
    anyhow::ensure!(
        installed == helper_host_path(paths),
        "embedded socket bridge was installed at an unexpected path"
    );
    Ok(installed)
}

pub fn supervisor_arguments(bridges: &[SocketBridge], command: &[String]) -> Vec<String> {
    let mut arguments = vec![SOCKET_BRIDGE_SUBCOMMAND.to_string()];
    for bridge in bridges {
        arguments.extend([
            "--socket".to_string(),
            bridge.socket_path.clone(),
            "--tcp".to_string(),
            bridge.target.to_string(),
        ]);
    }
    arguments.push("--".to_string());
    arguments.extend_from_slice(command);
    arguments
}

pub fn loopback_target(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)
}

pub fn is_valid_bridge(bridge: &SocketBridge) -> bool {
    let path = Path::new(&bridge.socket_path);
    path.is_absolute()
        && path.starts_with(CONTAINER_SOCKET_DIRECTORY)
        && path.parent() == Some(Path::new(CONTAINER_SOCKET_DIRECTORY))
        && bridge.target.ip().is_loopback()
        && bridge.target.port() != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_strict_supervisor_arguments() {
        let bridge = SocketBridge {
            socket_path: "/run/dbev/native.sock".to_string(),
            target: loopback_target(9000),
        };

        assert!(is_valid_bridge(&bridge));
        assert_eq!(
            supervisor_arguments(&[bridge], &["/entrypoint.sh".to_string()]),
            [
                "__socket-bridge-supervisor",
                "--socket",
                "/run/dbev/native.sock",
                "--tcp",
                "127.0.0.1:9000",
                "--",
                "/entrypoint.sh"
            ]
        );
    }

    #[test]
    fn rejects_non_loopback_and_nested_bridges() {
        assert!(!is_valid_bridge(&SocketBridge {
            socket_path: "/run/dbev/nested/native.sock".to_string(),
            target: loopback_target(9000),
        }));
        assert!(!is_valid_bridge(&SocketBridge {
            socket_path: "/run/dbev/native.sock".to_string(),
            target: "0.0.0.0:9000".parse().unwrap(),
        }));
    }
}
