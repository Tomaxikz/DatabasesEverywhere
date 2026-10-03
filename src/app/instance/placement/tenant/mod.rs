use std::time::Duration;

use secrecy::SecretString;

use crate::{
    databases,
    instance::placement::{DeploymentMode, EngineRuntime},
    runtime::docker::{CommandOutput, DockerError, DockerRuntime},
    utils::{limits::InstanceLimits, protocol::Protocol, shell::sh_quote},
};

const TENANT_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const TELEMETRY_OPERATION_TIMEOUT: Duration = Duration::from_secs(8);

pub(crate) mod backends;
pub(crate) mod disk;
mod manifest;
pub(crate) mod recovery;

#[cfg(test)]
use backends::clickhouse_telemetry_script;
use backends::{TenantOperation, postgres_sql};
pub(crate) use manifest::{ManifestChallenge, TenantManifest, measure_manifest};

#[derive(Clone, Copy)]
pub(crate) struct TenantTarget<'a> {
    pub database: &'a str,
    pub username: &'a str,
}

/// Reconciles engine-wide isolation that cannot be expressed per tenant.
/// This is intentionally a no-op for dedicated instances.
pub(crate) async fn secure_pool(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
) -> Result<(), TenantEngineError> {
    if runtime.deployment_mode != DeploymentMode::Shared {
        return Ok(());
    }
    if let Some(backend) = runtime.protocol.engine().tenant_backend() {
        backend.secure_pool(docker, runtime).await?;
    }
    Ok(())
}

/// Runs one bounded engine telemetry statement inside a shared runtime.
///
/// Telemetry uses the same private administrator channel as tenant lifecycle
/// operations, but with a short timeout and shared-runtime recovery semantics:
/// an exec failure is returned to the sampler and never restarts or fences the
/// physical pool.
pub(crate) async fn telemetry_sql(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    sql: &str,
) -> Result<CommandOutput, TenantEngineError> {
    if runtime.deployment_mode != DeploymentMode::Shared {
        return Err(TenantEngineError::DedicatedTelemetry);
    }
    backends::for_protocol(runtime.protocol)?
        .telemetry_sql(docker, runtime, sql)
        .await
}

/// Reads one bounded ClickHouse query-log window from a shared runtime.
///
/// The cutoff is captured on the database server before its logs are flushed.
/// A missing prior cutoff deliberately uses the new cutoff, establishing an
/// empty first interval instead of charging retained history to the tenant.
pub(crate) async fn clickhouse_telemetry_window(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    prior_cutoff_micros: Option<u64>,
    sql: &str,
) -> Result<CommandOutput, TenantEngineError> {
    if runtime.deployment_mode != DeploymentMode::Shared {
        return Err(TenantEngineError::DedicatedTelemetry);
    }
    backends::for_protocol(runtime.protocol)?
        .telemetry_window(docker, runtime, prior_cutoff_micros, sql)
        .await
}

pub(crate) async fn create(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    password: &str,
    limits: &InstanceLimits,
) -> Result<(), TenantEngineError> {
    let admin = admin_secret(runtime)?;
    backends::for_protocol(runtime.protocol)?
        .apply(
            docker,
            runtime,
            target,
            TenantOperation::Create {
                password,
                limits,
                admin,
            },
        )
        .await
}

pub(crate) async fn fence(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
) -> Result<(), TenantEngineError> {
    backends::for_protocol(runtime.protocol)?
        .apply(docker, runtime, target, TenantOperation::Fence)
        .await
}

pub(crate) async fn unfence(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
) -> Result<(), TenantEngineError> {
    backends::for_protocol(runtime.protocol)?
        .apply(docker, runtime, target, TenantOperation::Unfence)
        .await
}

/// Fails closed when a MySQL-family tenant contains objects omitted from the
/// tenant-only rollback dump. The caller must fence the route first so the
/// catalog cannot change between this check and snapshot creation.
pub(crate) async fn check_rollback_objects(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
) -> Result<(), TenantEngineError> {
    if runtime.deployment_mode != DeploymentMode::Shared {
        return Ok(());
    }
    let engine = runtime.protocol.engine();
    let Some(sql) = engine.rollback_gap_sql(target.database, target.username) else {
        return Ok(());
    };
    let output = backends::for_protocol(runtime.protocol)?
        .admin_sql(docker, runtime, &sql)
        .await?;
    let count = parse_rollback_gap(&output.stdout)?;
    if count != 0 {
        return Err(TenantEngineError::RollbackGap {
            protocol: runtime.protocol,
            count,
        });
    }
    Ok(())
}

fn parse_rollback_gap(output: &str) -> Result<u64, TenantEngineError> {
    output
        .trim()
        .parse()
        .map_err(|_| TenantEngineError::InvalidRollbackObjectCount(output.to_string()))
}

pub(crate) async fn drop_tenant(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
) -> Result<(), TenantEngineError> {
    backends::for_protocol(runtime.protocol)?
        .apply(docker, runtime, target, TenantOperation::Drop)
        .await
}

pub(crate) async fn set_quota(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    limits: &InstanceLimits,
) -> Result<(), TenantEngineError> {
    backends::for_protocol(runtime.protocol)?
        .apply(
            docker,
            runtime,
            target,
            TenantOperation::SetQuota { limits },
        )
        .await
}

pub(crate) async fn rotate_password(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    password: &str,
) -> Result<(), TenantEngineError> {
    backends::for_protocol(runtime.protocol)?
        .apply(
            docker,
            runtime,
            target,
            TenantOperation::RotatePassword { password },
        )
        .await
}

pub(crate) async fn verify_password(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    password: &str,
) -> Result<(), TenantEngineError> {
    let password = SecretString::from(password.to_string());
    let command = backends::for_protocol(runtime.protocol)?.verify_command(target);
    docker
        .exec_tenant_shell(
            runtime.protocol,
            &runtime.runtime_id,
            &command,
            &[("DBE_TENANT_PASSWORD", &password)],
            TENANT_OPERATION_TIMEOUT,
        )
        .await?;
    Ok(())
}

/// Enables a fenced tenant and proves that its durable credential works before
/// the caller republishes a gateway route. A failed check immediately fences
/// the engine account again; if that rollback also fails the combined error
/// tells the caller to contain the whole shared runtime.
pub(crate) async fn open_verified(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    password: &str,
) -> Result<(), TenantEngineError> {
    unfence(docker, runtime, target).await?;
    if let Err(verify) = verify_password(docker, runtime, target, password).await {
        if let Err(refence) = fence(docker, runtime, target).await {
            return Err(TenantEngineError::OpenRollback {
                verify: verify.to_string(),
                refence: refence.to_string(),
            });
        }
        return Err(verify);
    }
    Ok(())
}

/// Measures tenant-owned database storage from the engine catalog. Shared
/// tenants do not have separate host directories, so directory scans would
/// either report zero or incorrectly expose the whole pool. Results preserve
/// input order and fail closed if a client emits an unexpected shape.
pub(crate) async fn measure_storage(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    targets: &[TenantTarget<'_>],
) -> Result<Vec<u64>, TenantEngineError> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let database_names = targets
        .iter()
        .map(|target| target.database)
        .collect::<Vec<_>>();
    let output = backends::for_protocol(runtime.protocol)?
        .measure_storage(docker, runtime, &database_names)
        .await?;
    parse_storage(&output.stdout, targets.len())
}

fn parse_storage(stdout: &str, expected: usize) -> Result<Vec<u64>, TenantEngineError> {
    let values = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse::<u64>()
                .map_err(|_| TenantEngineError::InvalidStorage(line.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != expected {
        return Err(TenantEngineError::StorageCount {
            expected,
            actual: values.len(),
        });
    }
    Ok(values)
}

fn admin_secret(runtime: &EngineRuntime) -> Result<SecretString, TenantEngineError> {
    runtime
        .admin_secret
        .as_deref()
        .map(|secret| SecretString::from(secret.to_string()))
        .ok_or_else(|| TenantEngineError::MissingAdminSecret(runtime.runtime_id.clone()))
}

fn telemetry_command(script: String) -> String {
    format!("exec timeout -k 1s 6s sh -c {}", sh_quote(&script))
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum TenantEngineError {
    #[error("{0} cannot be provisioned in a shared runtime")]
    Unsupported(Protocol),
    #[error("shared runtime {0} is missing its encrypted administrator credential")]
    MissingAdminSecret(String),
    #[error("shared tenant {0} is missing its encrypted login credential")]
    MissingTenantCredential(String),
    #[error("engine telemetry is only available for shared runtimes")]
    DedicatedTelemetry,
    #[error("database engine command failed: {0}")]
    Docker(#[from] DockerError),
    #[error("MySQL tenant statement is invalid: {0}")]
    Mysql(#[from] databases::mysql::provision::MysqlProvisionError),
    #[error("MariaDB tenant statement is invalid: {0}")]
    Mariadb(#[from] databases::mariadb::provision::MariadbProvisionError),
    #[error("MongoDB tenant statement is invalid: {0}")]
    Mongodb(#[from] databases::mongodb::provision::MongodbProvisionError),
    #[error("ClickHouse tenant statement is invalid: {0}")]
    Clickhouse(#[from] databases::clickhouse::provision::ClickhouseProvisionError),
    #[error("database engine returned an invalid connection id {0:?}")]
    InvalidConnectionId(String),
    #[error("database engine returned an invalid storage byte count {0:?}")]
    InvalidStorage(String),
    #[error("database engine returned an invalid rollback object count {0:?}")]
    InvalidRollbackObjectCount(String),
    #[error(
        "shared {protocol} tenant contains {count} routine, trigger, event, or foreign-definer view object(s) that cannot be represented by a safe rollback"
    )]
    RollbackGap { protocol: Protocol, count: u64 },
    #[error("database engine returned {actual} storage rows for {expected} tenants")]
    StorageCount { expected: usize, actual: usize },
    #[error(
        "shared tenant credential verification failed ({verify}) and its engine account could not be fenced again ({refence})"
    )]
    OpenRollback { verify: String, refence: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_id_parser_rejects_sql_text() {
        assert!("12; DROP DATABASE x".parse::<u64>().is_err());
    }

    #[test]
    fn unsupported_engines_are_explicit() {
        for protocol in [Protocol::Redis, Protocol::Valkey, Protocol::Qdrant] {
            assert!(matches!(
                backends::for_protocol(protocol),
                Err(TenantEngineError::Unsupported(actual)) if actual == protocol
            ));
        }
    }

    #[test]
    fn storage_output_is_strict_and_ordered() {
        assert_eq!(parse_storage("12\n0\n", 2).unwrap(), vec![12, 0]);
        assert!(matches!(
            parse_storage("column\n12\n", 1),
            Err(TenantEngineError::InvalidStorage(_))
        ));
        assert!(matches!(
            parse_storage("12\n", 2),
            Err(TenantEngineError::StorageCount {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn rollback_gap_output_is_one_strict_count() {
        assert_eq!(parse_rollback_gap("0\n").unwrap(), 0);
        assert_eq!(parse_rollback_gap("12\n").unwrap(), 12);
        for invalid in ["", "-1", "1\n2", "count\n0"] {
            assert!(matches!(
                parse_rollback_gap(invalid),
                Err(TenantEngineError::InvalidRollbackObjectCount(_))
            ));
        }
    }

    #[test]
    fn clickhouse_window_captures_cutoff_before_flushing_and_bounds_the_client() {
        let script = clickhouse_telemetry_script(
            None,
            "SELECT 1 WHERE x > {dbe_previous:Int64} AND x <= {dbe_cutoff:Int64}",
        );
        let command = telemetry_command(script.clone());
        let cutoff = script.find("toUnixTimestamp64Micro(now64(6))").unwrap();
        let flush = script.find("SYSTEM FLUSH LOGS").unwrap();
        let aggregate = script.find("--param_dbe_previous").unwrap();

        assert!(command.starts_with("exec timeout -k 1s 6s sh -c "));
        assert!(cutoff < flush && flush < aggregate);
        assert!(script.contains("previous=''"));
        assert!(script.contains("previous=\"$cutoff\""));
        assert!(script.contains("--max_execution_time 3"));
        assert!(script.contains("--timeout_before_checking_execution_speed 0"));
    }

    #[test]
    fn clickhouse_window_uses_only_a_numeric_saved_checkpoint() {
        let script = clickhouse_telemetry_script(Some(42), "SELECT 1");
        assert!(script.contains("previous='42'"));
        assert!(!script.contains("previous=''"));
    }
}

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
mod dispatch_tests;
