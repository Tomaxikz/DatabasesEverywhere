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

pub(crate) struct MariadbTelemetry;

impl EngineTelemetry for MariadbTelemetry {
    fn requires_preparation(&self) -> bool {
        true
    }

    fn prepare<'a>(
        &self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
    ) -> BoxFuture<'a, Result<Option<Capabilities>, CollectError>> {
        Box::pin(async move {
            let output = tenant::telemetry_sql(docker, runtime, queries::mariadb_prepare_sql())
                .await
                .map_err(|_| CollectError::Unavailable)?;
            queries::parse_mariadb_ready(&output.stdout).map(Some)
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
            let output = tenant::telemetry_sql(docker, runtime, queries::mariadb_collect_sql())
                .await
                .map_err(|_| CollectError::Unavailable)?;
            Ok(EngineSample {
                capabilities,
                rows: queries::parse_mariadb_rows(&output.stdout)?,
                mode: SampleMode::Cumulative,
                next_clickhouse_checkpoint: None,
            })
        })
    }
}
