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

pub(crate) struct ClickhouseTelemetry;

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
