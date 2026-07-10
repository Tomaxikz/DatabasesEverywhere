use std::path::PathBuf;

use secrecy::SecretString;

use crate::{
    runtime::{
        docker::{DockerEnv, DockerInstanceSpec, DockerMount},
        socket_bridge::{SocketBridge, loopback_target},
    },
    shared::{
        backend::{
            CONTAINER_SOCKET_DIRECTORY, SOCKET_BRIDGE_CONTAINER_PATH, container_backend_socket_path,
        },
        protocol::Protocol,
    },
};

pub fn instance_spec(
    instance_id: &str,
    image: &str,
    api_key: SecretString,
    data_path: PathBuf,
    logs_path: PathBuf,
    runtime_path: PathBuf,
    bridge_binary_path: PathBuf,
) -> DockerInstanceSpec {
    DockerInstanceSpec {
        instance_id: instance_id.to_string(),
        protocol: Protocol::Qdrant,
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
        data_target: "/dbe-qdrant".to_string(),
        logs_path,
        logs_target: "/logs".to_string(),
        extra_mounts: vec![
            DockerMount {
                source: runtime_path,
                target: CONTAINER_SOCKET_DIRECTORY.to_string(),
                read_only: false,
            },
            DockerMount {
                source: bridge_binary_path,
                target: SOCKET_BRIDGE_CONTAINER_PATH.to_string(),
                read_only: true,
            },
        ],
        socket_bridges: vec![SocketBridge {
            socket_path: container_backend_socket_path(Protocol::Qdrant),
            target: loopback_target(6334),
        }],
        env: vec![
            DockerEnv {
                key: "QDRANT__SERVICE__HOST".to_string(),
                value: SecretString::from("127.0.0.1"),
            },
            DockerEnv {
                key: "QDRANT__SERVICE__HTTP_PORT".to_string(),
                value: SecretString::from("6333"),
            },
            DockerEnv {
                key: "QDRANT__SERVICE__GRPC_PORT".to_string(),
                value: SecretString::from("6334"),
            },
            DockerEnv {
                key: "QDRANT__SERVICE__API_KEY".to_string(),
                value: api_key,
            },
            DockerEnv {
                key: "QDRANT__STORAGE__STORAGE_PATH".to_string(),
                value: SecretString::from("/dbe-qdrant/storage"),
            },
            DockerEnv {
                key: "QDRANT__STORAGE__SNAPSHOTS_PATH".to_string(),
                value: SecretString::from("/dbe-qdrant/snapshots"),
            },
            DockerEnv {
                key: "QDRANT_INIT_FILE_PATH".to_string(),
                value: SecretString::from("/dbe-qdrant/.qdrant-initialized"),
            },
        ],
        command: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn uses_qdrant_storage_and_grpc_port() {
        let spec = instance_spec(
            "inst_qdrant_1",
            "qdrant/qdrant:v1.18.2",
            SecretString::from("api-key"),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/logs"),
            PathBuf::from("/tmp/run"),
            PathBuf::from("/tmp/dbev-socket-bridge"),
        );

        assert_eq!(spec.protocol, Protocol::Qdrant);
        assert_eq!(spec.data_target, "/dbe-qdrant");
        assert_eq!(spec.working_dir, None);
        assert_eq!(spec.entrypoint, None);
        assert_eq!(spec.extra_mounts[0].target, CONTAINER_SOCKET_DIRECTORY);
        assert_eq!(spec.extra_mounts[1].target, SOCKET_BRIDGE_CONTAINER_PATH);
        assert_eq!(spec.socket_bridges.len(), 1);
        assert_eq!(spec.socket_bridges[0].target, loopback_target(6334));
        assert!(
            spec.env
                .iter()
                .any(|env| env.key == "QDRANT__SERVICE__API_KEY")
        );
        assert!(
            spec.env
                .iter()
                .any(|env| env.key == "QDRANT__SERVICE__GRPC_PORT")
        );
        assert!(spec.env.iter().any(|env| {
            env.key == "QDRANT__STORAGE__SNAPSHOTS_PATH"
                && env.value.expose_secret() == "/dbe-qdrant/snapshots"
        }));
        assert!(spec.env.iter().any(|env| {
            env.key == "QDRANT__SERVICE__HOST" && env.value.expose_secret() == "127.0.0.1"
        }));
        assert!(spec.env.iter().any(|env| {
            env.key == "QDRANT_INIT_FILE_PATH"
                && env.value.expose_secret() == "/dbe-qdrant/.qdrant-initialized"
        }));
    }
}
