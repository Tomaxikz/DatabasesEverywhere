use std::path::PathBuf;

use crate::{
    runtime::docker::{DockerInstanceSpec, DockerMount},
    shared::{backend::CONTAINER_SOCKET_DIRECTORY, protocol::Protocol},
};

pub fn instance_spec(
    instance_id: &str,
    image: &str,
    data_path: PathBuf,
    logs_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    DockerInstanceSpec {
        instance_id: instance_id.to_string(),
        protocol: Protocol::Valkey,
        image: image.to_string(),
        project_id: None,
        user: None,
        working_dir: None,
        entrypoint: None,
        cpu_cores: 1.0,
        memory_mib: 512,
        disk_mib: 10240,
        pids_limit: None,
        data_path,
        data_target: "/data".to_string(),
        logs_path,
        logs_target: "/logs".to_string(),
        extra_mounts: vec![DockerMount {
            source: runtime_path,
            target: CONTAINER_SOCKET_DIRECTORY.to_string(),
            read_only: false,
        }],
        socket_bridges: Vec::new(),
        env: Vec::new(),
        command: vec![
            "valkey-server".to_string(),
            "--appendonly".to_string(),
            "yes".to_string(),
            "--aclfile".to_string(),
            "/data/users.acl".to_string(),
            "--port".to_string(),
            "0".to_string(),
            "--unixsocket".to_string(),
            "/run/dbev/valkey.sock".to_string(),
            "--unixsocketperm".to_string(),
            "660".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disables_tcp_and_exposes_only_the_private_socket() {
        let spec = instance_spec(
            "inst_valkey_1",
            "valkey/valkey:9.1.1",
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/logs"),
            PathBuf::from("/tmp/run"),
        );

        assert_eq!(spec.extra_mounts[0].target, CONTAINER_SOCKET_DIRECTORY);
        assert!(spec.command.windows(2).any(|args| args == ["--port", "0"]));
        assert!(
            spec.command
                .windows(2)
                .any(|args| args == ["--unixsocket", "/run/dbev/valkey.sock"])
        );
        assert!(spec.socket_bridges.is_empty());
    }
}
