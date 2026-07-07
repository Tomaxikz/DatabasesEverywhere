use std::path::PathBuf;

use crate::{runtime::docker::DockerInstanceSpec, shared::protocol::Protocol};

pub fn instance_spec(
    instance_id: &str,
    image: &str,
    data_path: PathBuf,
    logs_path: PathBuf,
) -> DockerInstanceSpec {
    DockerInstanceSpec {
        instance_id: instance_id.to_string(),
        protocol: Protocol::Redis,
        image: image.to_string(),
        project_id: None,
        user: None,
        working_dir: None,
        entrypoint: None,
        cpu_cores: 1.0,
        memory_mib: 512,
        disk_mib: 10240,
        pids_limit: None,
        container_port: Protocol::Redis.default_container_port(),
        public_backend_port: None,
        data_path,
        data_target: "/data".to_string(),
        logs_path,
        logs_target: "/logs".to_string(),
        extra_mounts: Vec::new(),
        env: Vec::new(),
        command: vec![
            "redis-server".to_string(),
            "--appendonly".to_string(),
            "yes".to_string(),
            "--aclfile".to_string(),
            "/data/users.acl".to_string(),
        ],
    }
}
