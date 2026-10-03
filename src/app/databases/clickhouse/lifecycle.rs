use std::path::{Path, PathBuf};

use futures::future::{BoxFuture, FutureExt};

use crate::{
    databases::engine::{DedicatedSpecInput, EngineLifecycle, SharedSpecInput},
    instance::metadata::InstanceMetadata,
    runtime::docker::DockerInstanceSpec,
    utils::shell::sh_quote,
};

use super::{
    docker::{instance_spec, shared_spec, write_hosted_config, write_shared_hosted_config},
    engine::Clickhouse,
};

impl EngineLifecycle for Clickhouse {
    fn runtime_admin_secret<'a>(&self, metadata: &'a InstanceMetadata) -> Option<&'a str> {
        metadata.tenant_password.as_deref()
    }

    fn write_hosted_config<'a>(
        &self,
        runtime_config: &'a Path,
        shared: bool,
    ) -> BoxFuture<'a, Result<Option<PathBuf>, String>> {
        async move {
            let written = if shared {
                write_shared_hosted_config(runtime_config).await
            } else {
                write_hosted_config(runtime_config).await
            };
            written.map(Some).map_err(|error| error.to_string())
        }
        .boxed()
    }

    fn dedicated_spec(&self, input: DedicatedSpecInput<'_>) -> DockerInstanceSpec {
        instance_spec(
            input.instance_id,
            input.image,
            input.database,
            input.username,
            input.password,
            input.data_path,
            input.hosted_config.unwrap_or_default(),
            input.sockets,
            input.socket_bridge_binary,
        )
    }

    fn shared_spec(&self, input: SharedSpecInput<'_>) -> Option<DockerInstanceSpec> {
        Some(shared_spec(
            input.runtime_id,
            input.image,
            input.admin_password,
            input.data_path,
            input.hosted_config.unwrap_or_default(),
            input.sockets,
            input.socket_bridge_binary,
        ))
    }

    fn replacement_check_command(&self, username: &str, database: &str) -> Option<String> {
        Some(format!(
            "clickhouse-client --host 127.0.0.1 --user {} --password \"$DBE_UPGRADE_PASSWORD\" --database {} --query 'SELECT 1' >/dev/null",
            sh_quote(username),
            sh_quote(database),
        ))
    }
}
