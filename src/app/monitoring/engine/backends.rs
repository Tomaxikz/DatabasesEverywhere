use std::collections::HashMap;

use futures::future::BoxFuture;

use super::{Capabilities, CollectError, EngineSample, SampleMode, queries};
use crate::{
    placement::{EngineRuntime, tenant},
    runtime::docker::DockerRuntime,
    shared::protocol::Protocol,
};

/// Engine-specific collection only: generation checks, failure backoff, tenant
/// attribution, and committing a successful checkpoint belong to the sampler.
pub(super) trait EngineTelemetry: Sync {
    fn requires_preparation(&self) -> bool;

    /// `None` leaves existing capabilities unchanged when no setup is needed.
    fn prepare<'a>(
        &self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
    ) -> BoxFuture<'a, Result<Option<Capabilities>, CollectError>>;

    fn collect<'a>(
        &self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        capabilities: Capabilities,
        checkpoint: Option<u64>,
    ) -> BoxFuture<'a, Result<EngineSample, CollectError>>;
}

pub(super) fn for_protocol(protocol: Protocol) -> Option<&'static dyn EngineTelemetry> {
    match protocol {
        Protocol::Mysql => Some(&MysqlTelemetry),
        Protocol::Mariadb => Some(&MariadbTelemetry),
        Protocol::Clickhouse => Some(&ClickhouseTelemetry),
        _ => None,
    }
}

struct MysqlTelemetry;

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

struct MariadbTelemetry;

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

struct ClickhouseTelemetry;

impl EngineTelemetry for ClickhouseTelemetry {
    fn requires_preparation(&self) -> bool {
        false
    }

    fn prepare<'a>(
        &self,
        _docker: &'a DockerRuntime,
        _runtime: &'a EngineRuntime,
    ) -> BoxFuture<'a, Result<Option<Capabilities>, CollectError>> {
        Box::pin(async { Ok(None) })
    }

    fn collect<'a>(
        &self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        _capabilities: Capabilities,
        checkpoint: Option<u64>,
    ) -> BoxFuture<'a, Result<EngineSample, CollectError>> {
        Box::pin(async move {
            let output = tenant::clickhouse_telemetry_window(
                docker,
                runtime,
                checkpoint,
                queries::clickhouse_collect_sql(),
            )
            .await
            .map_err(|_| CollectError::Unavailable)?;
            Self::sample(&output.stdout, checkpoint)
        })
    }
}

impl ClickhouseTelemetry {
    fn sample(output: &str, previous: Option<u64>) -> Result<EngineSample, CollectError> {
        let (checkpoint, rows) = queries::parse_clickhouse_window(output)?;
        if previous.is_some_and(|previous| checkpoint < previous) {
            return Err(CollectError::InvalidOutput);
        }
        Ok(EngineSample {
            capabilities: Capabilities {
                cpu: true,
                memory: true,
                operations: true,
            },
            rows,
            mode: SampleMode::Interval,
            next_clickhouse_checkpoint: Some(checkpoint),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime(protocol: Protocol) -> EngineRuntime {
        let mut runtime = crate::placement::test_support::runtime("pool_test", protocol, "test");
        // Fail before executing any command, even if a local daemon is running.
        runtime.admin_secret = None;
        runtime
    }

    fn assert_send<T: Send>(value: T) -> T {
        value
    }

    #[tokio::test]
    async fn registry_preserves_preparation_and_send_contracts() {
        let docker = DockerRuntime::offline_for_tests(&Default::default(), false);
        for protocol in [Protocol::Mysql, Protocol::Mariadb, Protocol::Clickhouse] {
            let backend = for_protocol(protocol).unwrap();
            let runtime = runtime(protocol);
            let result = assert_send(backend.prepare(&docker, &runtime)).await;
            if protocol == Protocol::Clickhouse {
                assert!(!backend.requires_preparation());
                assert_eq!(result.unwrap(), None);
            } else {
                assert!(backend.requires_preparation());
                assert!(matches!(result, Err(CollectError::Unavailable)));
            }
            let result = assert_send(backend.collect(
                &docker,
                &runtime,
                Capabilities {
                    cpu: true,
                    ..Capabilities::default()
                },
                Some(42),
            ))
            .await;
            assert!(matches!(result, Err(CollectError::Unavailable)));
        }
    }

    #[test]
    fn registry_rejects_engines_without_attributable_cpu_collectors() {
        for protocol in [
            Protocol::Postgres,
            Protocol::Mongodb,
            Protocol::Redis,
            Protocol::Valkey,
            Protocol::Qdrant,
        ] {
            assert!(for_protocol(protocol).is_none());
        }
    }

    #[tokio::test]
    async fn mysql_without_capabilities_does_not_execute_a_command() {
        let docker = DockerRuntime::offline_for_tests(&Default::default(), false);
        let runtime = runtime(Protocol::Mysql);
        let capabilities = Capabilities::default();
        let sample = for_protocol(runtime.protocol)
            .unwrap()
            .collect(&docker, &runtime, capabilities, Some(42))
            .await
            .unwrap();

        assert_eq!(sample.capabilities, capabilities);
        assert_eq!(sample.mode, SampleMode::Cumulative);
        assert!(sample.rows.is_empty());
        assert_eq!(sample.next_clickhouse_checkpoint, None);
    }

    #[test]
    fn clickhouse_sample_preserves_interval_capabilities_and_checkpoint() {
        let output = "__DBE_CUTOFF__\t42\nuser_a\t25\t4096\t2\t1\t0\t1\n";
        for previous in [None, Some(41), Some(42)] {
            let sample = ClickhouseTelemetry::sample(output, previous).unwrap();
            assert_eq!(sample.mode, SampleMode::Interval);
            assert_eq!(sample.next_clickhouse_checkpoint, Some(42));
            assert_eq!(
                sample.capabilities,
                Capabilities {
                    cpu: true,
                    memory: true,
                    operations: true,
                }
            );
            let row = sample.rows.get("user_a").unwrap();
            assert_eq!(row.cpu_time_micros, 25);
            assert_eq!(row.peak_query_memory_bytes, 4096);
            assert_eq!(row.operations.read, 2);
            assert_eq!(row.operations.write, 1);
            assert_eq!(row.operations.ddl, 0);
            assert_eq!(row.operations.other, 1);
        }
    }

    #[test]
    fn clickhouse_rejects_backwards_or_invalid_windows() {
        for (output, previous) in [
            ("__DBE_CUTOFF__\t41\n", Some(42)),
            ("invalid\n", None),
            ("__DBE_CUTOFF__\t42\nuser_a\tinvalid\n", Some(41)),
        ] {
            assert!(matches!(
                ClickhouseTelemetry::sample(output, previous),
                Err(CollectError::InvalidOutput)
            ));
        }
    }
}
