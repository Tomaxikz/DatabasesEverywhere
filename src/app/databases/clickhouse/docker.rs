use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::{
    runtime::docker::{DockerEnv, DockerInstanceSpec, DockerMount},
    runtime::socket_bridge::{SocketBridge, loopback_target},
    shared::{
        backend::{
            CONTAINER_SOCKET_DIRECTORY, SOCKET_BRIDGE_CONTAINER_PATH, clickhouse_http_socket,
            container_backend_socket_path,
        },
        files::atomic_write_private,
        protocol::Protocol,
    },
};

const HOSTED_CONFIG_FILENAME: &str = "dbe-hosted-overrides.xml";
const HOSTED_CONFIG_TARGET: &str = "/etc/clickhouse-server/config.d/dbe-hosted-overrides.xml";
pub const INTERNAL_ADMIN_USERNAME: &str = "dbe_admin";
pub const CONTROL_DATABASE: &str = "dbe_control";

struct Bootstrap {
    database: String,
    username: String,
    password: SecretString,
}

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
    build_spec(
        instance_id,
        image,
        Bootstrap {
            database: database.to_string(),
            username: username.to_string(),
            password,
        },
        data_path,
        logs_path,
        hosted_config_path,
        runtime_path,
        bridge_binary_path,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn shared_spec(
    runtime_id: &str,
    image: &str,
    admin_password: SecretString,
    data_path: PathBuf,
    logs_path: PathBuf,
    hosted_config_path: PathBuf,
    runtime_path: PathBuf,
    bridge_binary_path: PathBuf,
) -> DockerInstanceSpec {
    build_spec(
        runtime_id,
        image,
        Bootstrap {
            database: CONTROL_DATABASE.to_string(),
            username: INTERNAL_ADMIN_USERNAME.to_string(),
            password: admin_password,
        },
        data_path,
        logs_path,
        hosted_config_path,
        runtime_path,
        bridge_binary_path,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_spec(
    runtime_id: &str,
    image: &str,
    bootstrap: Bootstrap,
    data_path: PathBuf,
    logs_path: PathBuf,
    hosted_config_path: PathBuf,
    runtime_path: PathBuf,
    bridge_binary_path: PathBuf,
) -> DockerInstanceSpec {
    DockerInstanceSpec {
        instance_id: runtime_id.to_string(),
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
                socket_path: clickhouse_http_socket(),
                target: loopback_target(8123),
            },
        ],
        env: vec![
            DockerEnv {
                key: "CLICKHOUSE_DB".to_string(),
                value: SecretString::from(bootstrap.database),
            },
            DockerEnv {
                key: "CLICKHOUSE_USER".to_string(),
                value: SecretString::from(bootstrap.username),
            },
            DockerEnv {
                key: "CLICKHOUSE_PASSWORD".to_string(),
                value: bootstrap.password,
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
    write_config(runtime_config_path, false).await
}

pub async fn write_shared_hosted_config(
    runtime_config_path: &Path,
) -> Result<PathBuf, std::io::Error> {
    write_config(runtime_config_path, true).await
}

async fn write_config(runtime_config_path: &Path, shared: bool) -> Result<PathBuf, std::io::Error> {
    let runtime_config_path = runtime_config_path.to_path_buf();
    tokio::task::spawn_blocking(move || write_hosted_config_sync(&runtime_config_path, shared))
        .await
        .map_err(std::io::Error::other)?
}

fn write_hosted_config_sync(
    runtime_config_path: &Path,
    shared: bool,
) -> Result<PathBuf, std::io::Error> {
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
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(runtime_config_path, std::fs::Permissions::from_mode(0o700))?;
    }
    let path = runtime_config_path.join(HOSTED_CONFIG_FILENAME);
    atomic_write_private(&path, hosted_config_xml(shared).as_bytes())?;
    {
        use std::os::unix::fs::PermissionsExt;

        // The host parent remains private, while the file itself must be
        // readable by the non-root ClickHouse user through its read-only bind
        // mount. Keeping the file read-only also prevents the container from
        // modifying daemon-owned configuration.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))?;
    }
    Ok(path)
}

fn hosted_config_xml(shared: bool) -> String {
    let shared_access_control = if shared {
        r#"    <access_control_improvements>
        <table_engines_require_grant>true</table_engines_require_grant>
        <on_cluster_queries_require_cluster_grant>true</on_cluster_queries_require_cluster_grant>
    </access_control_improvements>
"#
    } else {
        ""
    };
    let query_log = if shared {
        r#"    <query_log>
        <database>system</database>
        <table>query_log</table>
        <partition_by>toStartOfHour(event_time)</partition_by>
        <ttl>event_time + INTERVAL 2 HOUR DELETE</ttl>
        <flush_interval_milliseconds>7500</flush_interval_milliseconds>
    </query_log>
"#
    } else {
        "    <query_log remove=\"1\"/>\n"
    };
    format!(
        r#"<clickhouse>
    <!-- Dedicated instances disable internal system logs. Shared pools retain
         one short-lived query log for aggregate tenant accounting; every
         other diagnostic MergeTree log remains disabled. -->
{query_log}
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
{shared_access_control}    <listen_host>127.0.0.1</listen_host>
    <interserver_listen_host>127.0.0.1</interserver_listen_host>
</clickhouse>
"#
    )
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

    #[test]
    fn shared_runtime_bootstraps_only_control_admin() {
        use secrecy::ExposeSecret;

        let spec = shared_spec(
            "pool_ch_1",
            "clickhouse/clickhouse-server:26.4",
            SecretString::from("admin-secret"),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/logs"),
            PathBuf::from("/tmp/logs/dbe-hosted-overrides.xml"),
            PathBuf::from("/tmp/run"),
            PathBuf::from("/tmp/dbev-socket-bridge"),
        );
        let env = spec
            .env
            .iter()
            .map(|env| (env.key.as_str(), env.value.expose_secret()))
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(env["CLICKHOUSE_DB"], CONTROL_DATABASE);
        assert_eq!(env["CLICKHOUSE_USER"], INTERNAL_ADMIN_USERNAME);
        assert_eq!(env["CLICKHOUSE_PASSWORD"], "admin-secret");
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
        assert!(!config.contains("<access_control_improvements>"));
        assert!(config.contains("<listen_host>127.0.0.1</listen_host>"));
    }

    #[tokio::test]
    async fn shared_hosted_config_requires_explicit_engine_grants() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_shared_hosted_config(dir.path()).await.unwrap();
        let config = tokio::fs::read_to_string(path).await.unwrap();

        assert!(config.contains("<table_engines_require_grant>true</table_engines_require_grant>"));
        assert!(
            config.contains(
                "<on_cluster_queries_require_cluster_grant>true</on_cluster_queries_require_cluster_grant>"
            )
        );
        assert!(config.contains("<query_log>"));
        assert!(config.contains("toStartOfHour(event_time)"));
        assert!(config.contains("event_time + INTERVAL 2 HOUR DELETE"));
        assert!(!config.contains("<query_log remove=\"1\"/>"));
    }

    #[tokio::test]
    async fn hosted_config_is_private_on_host_but_readable_in_container() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = write_hosted_config(dir.path()).await.unwrap();

        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o444
        );
    }

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
