use std::collections::HashMap;

use futures::future::BoxFuture;

use crate::{
    runtime::docker::DockerRuntime,
    server::{
        monitoring::engine::{
            Capabilities, CollectError, EngineSample, SampleMode, backends::EngineTelemetry,
            queries,
        },
        placement::{EngineRuntime, tenant},
    },
};

pub(crate) struct MysqlTelemetry;

impl EngineTelemetry for MysqlTelemetry {
    fn requires_preparation(&self) -> bool {
        true
    }

    fn prepare<'a>(
        &self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
    ) -> BoxFuture<'a, Result<Option<Capabilities>, CollectError>> {
        Box::pin(async move {
            let output = tenant::telemetry_sql(docker, runtime, queries::mysql_prepare_sql())
                .await
                .map_err(|_| CollectError::Unavailable)?;
            queries::parse_mysql_capabilities(&output.stdout).map(Some)
        })
    }

    fn collect<'a>(
        &self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        capabilities: Capabilities,
        _checkpoint: Option<u64>,
    ) -> BoxFuture<'a, Result<EngineSample, CollectError>> {
        Box::pin(async move {
            let rows = if capabilities.cpu || capabilities.memory {
                let output = tenant::telemetry_sql(
                    docker,
                    runtime,
                    queries::mysql_collect_sql(capabilities),
                )
                .await
                .map_err(|_| CollectError::Unavailable)?;
                queries::parse_mysql_rows(&output.stdout, capabilities)?
            } else {
                HashMap::new()
            };
            Ok(EngineSample {
                capabilities,
                rows,
                mode: SampleMode::Cumulative,
                next_clickhouse_checkpoint: None,
            })
        })
    }
}
