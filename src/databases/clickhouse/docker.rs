use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::{
    runtime::docker::{DockerEnv, DockerInstanceSpec, DockerMount},
    runtime::socket_bridge::{SocketBridge, loopback_target},
    shared::{
        backend::{
            CONTAINER_SOCKET_DIRECTORY, SOCKET_BRIDGE_CONTAINER_PATH,
            container_backend_socket_path, container_clickhouse_http_socket_path,
        },
        files::atomic_write_private,
        protocol::Protocol,
    },
};

const HOSTED_CONFIG_FILENAME: &str = "dbe-hosted-overrides.xml";
const HOSTED_CONFIG_TARGET: &str = "/etc/clickhouse-server/config.d/dbe-hosted-overrides.xml";

#[allow(clippy::too_many_arguments)]
pub fn instance_spec(
    instance_id: &str,
    image: &str,
    database: &str,
    username: &str,
    password: SecretString,
    data_path: PathBuf,
    logs_path: PathBuf,
    hosted_config_path: PathBuf,
    runtime_path: PathBuf,
    bridge_binary_path: PathBuf,
) -> DockerInstanceSpec {
    DockerInstanceSpec {
        instance_id: instance_id.to_string(),
        protocol: Protocol::Clickhouse,
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
        data_target: "/var/lib/clickhouse".to_string(),
        logs_path,
        logs_target: "/var/log/clickhouse-server".to_string(),
        extra_mounts: vec![
            DockerMount {
                source: hosted_config_path,
                target: HOSTED_CONFIG_TARGET.to_string(),
                read_only: true,
            },
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
        socket_bridges: vec![
            SocketBridge {
                socket_path: container_backend_socket_path(Protocol::Clickhouse),
                target: loopback_target(9000),
            },
            SocketBridge {
                socket_path: container_clickhouse_http_socket_path(),
                target: loopback_target(8123),
            },
        ],
        env: vec![
            DockerEnv {
                key: "CLICKHOUSE_DB".to_string(),
                value: SecretString::from(database.to_string()),
            },
            DockerEnv {
                key: "CLICKHOUSE_USER".to_string(),
                value: SecretString::from(username.to_string()),
            },
            DockerEnv {
                key: "CLICKHOUSE_PASSWORD".to_string(),
                value: password,
            },
            DockerEnv {
                key: "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT".to_string(),
                value: SecretString::from("1"),
            },
            DockerEnv {
                key: "CLICKHOUSE_RUN_AS_ROOT".to_string(),
                value: SecretString::from("1"),
            },
            DockerEnv {
                key: "CLICKHOUSE_DO_NOT_CHOWN".to_string(),
                value: SecretString::from("1"),
            },
        ],
        command: Vec::new(),
    }
}

pub async fn write_hosted_config(runtime_config_path: &Path) -> Result<PathBuf, std::io::Error> {
    let runtime_config_path = runtime_config_path.to_path_buf();
    tokio::task::spawn_blocking(move || write_hosted_config_blocking(&runtime_config_path))
        .await
        .map_err(std::io::Error::other)?
}

fn write_hosted_config_blocking(runtime_config_path: &Path) -> Result<PathBuf, std::io::Error> {
    std::fs::create_dir_all(runtime_config_path)?;
    let metadata = std::fs::symlink_metadata(runtime_config_path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is not a real runtime configuration directory",
                runtime_config_path.display()
            ),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(runtime_config_path, std::fs::Permissions::from_mode(0o700))?;
    }
    let path = runtime_config_path.join(HOSTED_CONFIG_FILENAME);
    atomic_write_private(&path, hosted_config_xml().as_bytes())?;
    Ok(path)
}

fn hosted_config_xml() -> &'static str {
    r#"<clickhouse>
    <!-- DBE hosted instances keep ClickHouse file logs, but disable internal
         system.*_log MergeTree tables so small tenant quotas are not consumed
         by server diagnostics instead of user data. -->
    <query_log remove="1"/>
    <query_thread_log remove="1"/>
    <query_views_log remove="1"/>
    <trace_log remove="1"/>
    <text_log remove="1"/>
    <part_log remove="1"/>
    <metric_log remove="1"/>
    <asynchronous_metric_log remove="1"/>
    <processors_profile_log remove="1"/>
    <error_log remove="1"/>
    <crash_log remove="1"/>
    <session_log remove="1"/>
    <zookeeper_log remove="1"/>
    <asynchronous_insert_log remove="1"/>
    <backup_log remove="1"/>
    <blob_storage_log remove="1"/>
    <background_schedule_pool_log remove="1"/>
    <listen_host>127.0.0.1</listen_host>
    <interserver_listen_host>127.0.0.1</interserver_listen_host>
</clickhouse>
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_clickhouse_data_directory_and_native_port() {
        let spec = instance_spec(
            "inst_ch_1",
            "clickhouse/clickhouse-server:25.8.25.37",
            "ch_1",
            "app_ch_1",
            SecretString::from("secret"),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/logs"),
            PathBuf::from("/tmp/logs/dbe-hosted-overrides.xml"),
            PathBuf::from("/tmp/run"),
            PathBuf::from("/tmp/dbev-socket-bridge"),
        );

        assert_eq!(spec.protocol, Protocol::Clickhouse);
        assert_eq!(spec.data_target, "/var/lib/clickhouse");
        assert_eq!(spec.logs_target, "/var/log/clickhouse-server");
        assert_eq!(spec.pids_limit, None);
        assert_eq!(spec.extra_mounts[0].target, HOSTED_CONFIG_TARGET);
        assert!(spec.extra_mounts[0].read_only);
        assert_eq!(spec.extra_mounts[1].target, CONTAINER_SOCKET_DIRECTORY);
        assert_eq!(spec.extra_mounts[2].target, SOCKET_BRIDGE_CONTAINER_PATH);
        assert_eq!(spec.socket_bridges.len(), 2);
        assert_eq!(spec.socket_bridges[0].target, loopback_target(9000));
        assert_eq!(spec.socket_bridges[1].target, loopback_target(8123));
        assert!(
            spec.env
                .iter()
                .any(|env| env.key == "CLICKHOUSE_DO_NOT_CHOWN")
        );
    }

    #[tokio::test]
    async fn writes_hosted_config_that_disables_internal_log_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_hosted_config(dir.path()).await.unwrap();
        let config = tokio::fs::read_to_string(path).await.unwrap();

        assert!(config.contains("<trace_log remove=\"1\"/>"));
        assert!(config.contains("<text_log remove=\"1\"/>"));
        assert!(config.contains("<part_log remove=\"1\"/>"));
        assert!(config.contains("<metric_log remove=\"1\"/>"));
        assert!(config.contains("<asynchronous_metric_log remove=\"1\"/>"));
        assert!(config.contains("<listen_host>127.0.0.1</listen_host>"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replaces_a_hosted_config_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim");
        let config_directory = directory.path().join("runtime-config");
        std::fs::create_dir(&config_directory).unwrap();
        std::fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, config_directory.join(HOSTED_CONFIG_FILENAME)).unwrap();

        let path = write_hosted_config(&config_directory).await.unwrap();

        assert_eq!(std::fs::read(victim).unwrap(), b"untouched");
        assert!(
            !std::fs::symlink_metadata(path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
