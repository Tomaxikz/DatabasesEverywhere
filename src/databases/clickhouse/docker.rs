use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::{
    runtime::docker::{DockerEnv, DockerInstanceSpec, DockerMount},
    shared::protocol::Protocol,
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
        container_port: Protocol::Clickhouse.default_container_port(),
        public_backend_port: None,
        data_path,
        data_target: "/var/lib/clickhouse".to_string(),
        logs_path,
        logs_target: "/var/log/clickhouse-server".to_string(),
        extra_mounts: vec![DockerMount {
            source: hosted_config_path,
            target: HOSTED_CONFIG_TARGET.to_string(),
            read_only: true,
        }],
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

pub async fn write_hosted_config(logs_path: &Path) -> Result<PathBuf, std::io::Error> {
    tokio::fs::create_dir_all(logs_path).await?;
    let path = logs_path.join(HOSTED_CONFIG_FILENAME);
    tokio::fs::write(&path, hosted_config_xml()).await?;
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
        );

        assert_eq!(spec.protocol, Protocol::Clickhouse);
        assert_eq!(spec.data_target, "/var/lib/clickhouse");
        assert_eq!(spec.logs_target, "/var/log/clickhouse-server");
        assert_eq!(spec.container_port, 9000);
        assert_eq!(spec.public_backend_port, None);
        assert_eq!(spec.pids_limit, None);
        assert_eq!(spec.extra_mounts[0].target, HOSTED_CONFIG_TARGET);
        assert!(spec.extra_mounts[0].read_only);
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
    }
}
