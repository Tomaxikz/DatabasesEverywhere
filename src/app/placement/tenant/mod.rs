use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrecy::SecretString;

use crate::{
    databases,
    placement::{DeploymentMode, EngineRuntime, policy},
    runtime::docker::{CommandOutput, DockerError, DockerRuntime, ExecRecovery},
    shared::{
        limits::{InstanceLimits, mib_to_bytes},
        protocol::Protocol,
        shell::sh_quote,
    },
};

const TENANT_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const TELEMETRY_OPERATION_TIMEOUT: Duration = Duration::from_secs(8);

mod manifest;
pub(crate) mod recovery;
pub(crate) use manifest::{ManifestChallenge, TenantManifest, measure_manifest};
pub(crate) mod disk;

#[derive(Clone, Copy)]
pub(crate) struct TenantTarget<'a> {
    pub database: &'a str,
    pub username: &'a str,
}

#[derive(Clone, Copy)]
enum MysqlFlavor {
    Mysql,
    Mariadb,
}

impl TryFrom<Protocol> for MysqlFlavor {
    type Error = TenantEngineError;

    fn try_from(protocol: Protocol) -> Result<Self, Self::Error> {
        match protocol {
            Protocol::Mysql => Ok(Self::Mysql),
            Protocol::Mariadb => Ok(Self::Mariadb),
            protocol => Err(TenantEngineError::Unsupported(protocol)),
        }
    }
}

impl MysqlFlavor {
    fn protocol(self) -> Protocol {
        match self {
            Self::Mysql => Protocol::Mysql,
            Self::Mariadb => Protocol::Mariadb,
        }
    }

    fn client(self) -> (&'static str, &'static str) {
        match self {
            Self::Mysql => ("mysql", "/var/run/mysqld/mysqld.sock"),
            Self::Mariadb => ("mariadb", "/run/mysqld/mysqld.sock"),
        }
    }

    fn quota_sql(self, username: &str, limits: &InstanceLimits) -> String {
        match self {
            Self::Mysql => {
                databases::mysql::provision::tenant_quota_sql(username, policy::mysql_quota(limits))
            }
            Self::Mariadb => databases::mariadb::provision::tenant_quota_sql(
                username,
                policy::mariadb_quota(limits),
            ),
        }
    }

    async fn sql(
        self,
        docker: &DockerRuntime,
        runtime: &EngineRuntime,
        sql: &str,
    ) -> Result<CommandOutput, TenantEngineError> {
        sql_client(docker, runtime, self, sql, TENANT_OPERATION_TIMEOUT, false).await
    }

    async fn telemetry(
        self,
        docker: &DockerRuntime,
        runtime: &EngineRuntime,
        sql: &str,
    ) -> Result<CommandOutput, TenantEngineError> {
        sql_client(
            docker,
            runtime,
            self,
            sql,
            TELEMETRY_OPERATION_TIMEOUT,
            true,
        )
        .await
    }

    async fn terminate(
        self,
        docker: &DockerRuntime,
        runtime: &EngineRuntime,
        username: &str,
    ) -> Result<(), TenantEngineError> {
        let output = self
            .sql(docker, runtime, &databases::mysql_session_ids_sql(username))
            .await?;
        for line in output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let id = line
                .parse::<u64>()
                .map_err(|_| TenantEngineError::InvalidConnectionId(line.to_string()))?;
            self.sql(docker, runtime, &databases::mysql_kill_sql(id))
                .await?;
        }
        Ok(())
    }

    fn verify_command(self, target: TenantTarget<'_>) -> String {
        let (client, socket) = self.client();
        format!(
            "MYSQL_PWD=\"$DBE_TENANT_PASSWORD\" {client} --protocol=socket --socket={socket} -u {} {} -N -B -e 'SELECT 1' >/dev/null",
            sh_quote(target.username),
            sh_quote(target.database),
        )
    }
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
    if runtime.protocol == Protocol::Postgres {
        postgres_sql(
            docker,
            runtime,
            databases::postgres::docker::CONTROL_DATABASE,
            &databases::postgres::provision::shared_catalog_lockdown_sql(),
        )
        .await?;
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
    match runtime.protocol {
        protocol @ (Protocol::Mysql | Protocol::Mariadb) => {
            MysqlFlavor::try_from(protocol)?
                .telemetry(docker, runtime, sql)
                .await
        }
        protocol => Err(TenantEngineError::Unsupported(protocol)),
    }
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
    if runtime.protocol != Protocol::Clickhouse {
        return Err(TenantEngineError::Unsupported(runtime.protocol));
    }

    let admin = admin_secret(runtime)?;
    let command = clickhouse_telemetry_command(prior_cutoff_micros, sql);
    Ok(docker
        .exec_telemetry(
            Protocol::Clickhouse,
            &runtime.runtime_id,
            &command,
            &[("DBE_ADMIN_PASSWORD", &admin)],
            TELEMETRY_OPERATION_TIMEOUT,
        )
        .await?)
}

fn clickhouse_telemetry_command(prior_cutoff_micros: Option<u64>, sql: &str) -> String {
    telemetry_command(clickhouse_telemetry_script(prior_cutoff_micros, sql))
}

fn clickhouse_telemetry_script(prior_cutoff_micros: Option<u64>, sql: &str) -> String {
    let prior = prior_cutoff_micros
        .map(|value| value.to_string())
        .unwrap_or_default();
    format!(
        "set -eu\ncutoff=\"$(CLICKHOUSE_PASSWORD=\"$DBE_ADMIN_PASSWORD\" clickhouse-client --user dbe_admin --max_execution_time 3 --timeout_before_checking_execution_speed 0 --query 'SELECT toUnixTimestamp64Micro(now64(6))')\"\ncase \"$cutoff\" in ''|*[!0-9]*) exit 2 ;; esac\nprevious={}\nif [ -z \"$previous\" ]; then previous=\"$cutoff\"; fi\nCLICKHOUSE_PASSWORD=\"$DBE_ADMIN_PASSWORD\" clickhouse-client --user dbe_admin --max_execution_time 3 --timeout_before_checking_execution_speed 0 --query 'SYSTEM FLUSH LOGS'\nprintf '__DBE_CUTOFF__\\t%s\\n' \"$cutoff\"\nCLICKHOUSE_PASSWORD=\"$DBE_ADMIN_PASSWORD\" clickhouse-client --user dbe_admin --max_execution_time 3 --timeout_before_checking_execution_speed 0 --param_dbe_previous=\"$previous\" --param_dbe_cutoff=\"$cutoff\" --query {}",
        sh_quote(&prior),
        sh_quote(sql),
    )
}

pub(crate) async fn create(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    password: &str,
    limits: &InstanceLimits,
) -> Result<(), TenantEngineError> {
    let admin = admin_secret(runtime)?;
    match runtime.protocol {
        Protocol::Postgres => {
            databases::postgres::hardening::provision_shared_tenant_role(
                docker,
                &runtime.runtime_id,
                target.database,
                target.username,
                &SecretString::from(password.to_string()),
                &admin,
                ExecRecovery::CallerHandles,
            )
            .await?;
            postgres_sql(
                docker,
                runtime,
                "dbe_control",
                &databases::postgres::provision::tenant_quota_sql(
                    target.database,
                    target.username,
                    policy::postgres_quota(limits),
                ),
            )
            .await?;
        }
        Protocol::Mysql => {
            mysql_password_sql(
                docker,
                runtime,
                &databases::mysql::provision::shared_tenant_user_sql(
                    target.database,
                    target.username,
                ),
                password,
            )
            .await?;
            MysqlFlavor::Mysql
                .sql(
                    docker,
                    runtime,
                    &MysqlFlavor::Mysql.quota_sql(target.username, limits),
                )
                .await?;
        }
        Protocol::Mariadb => {
            let flavor = MysqlFlavor::Mariadb;
            let verifier = crate::protocols::mariadb::native_password_sha1_stage2_hex(password);
            flavor
                .sql(
                    docker,
                    runtime,
                    &databases::mariadb::provision::shared_tenant_user_sql(
                        target.database,
                        target.username,
                        &verifier,
                    )?,
                )
                .await?;
            flavor
                .sql(docker, runtime, &flavor.quota_sql(target.username, limits))
                .await?;
        }
        Protocol::Mongodb => {
            let script = databases::mongodb::provision::create_tenant_script(
                target.database,
                target.username,
            )?;
            mongo_script(
                docker,
                runtime,
                &script,
                &[(
                    "DBE_TENANT_PASSWORD",
                    SecretString::from(password.to_string()),
                )],
            )
            .await?;
        }
        Protocol::Clickhouse => {
            let create = databases::clickhouse::provision::create_tenant_sql(
                target.database,
                target.username,
            );
            let admin = admin_secret(runtime)?;
            clickhouse_password_sql(
                docker,
                runtime,
                databases::clickhouse::docker::INTERNAL_ADMIN_USERNAME,
                admin,
                &create,
                password,
            )
            .await?;
            clickhouse_sql(
                docker,
                runtime,
                &databases::clickhouse::provision::tenant_quota_sql(
                    target.username,
                    policy::clickhouse_quota(limits),
                ),
            )
            .await?;
        }
        protocol => return Err(TenantEngineError::Unsupported(protocol)),
    }
    Ok(())
}

pub(crate) async fn fence(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
) -> Result<(), TenantEngineError> {
    match runtime.protocol {
        Protocol::Postgres => {
            postgres_sql(
                docker,
                runtime,
                "dbe_control",
                &format!(
                    "{}\n{}",
                    databases::postgres::provision::fence_tenant_sql(
                        target.database,
                        target.username,
                    ),
                    databases::postgres::provision::terminate_tenant_sql(
                        target.database,
                        target.username,
                    ),
                ),
            )
            .await?;
        }
        protocol @ (Protocol::Mysql | Protocol::Mariadb) => {
            let flavor = MysqlFlavor::try_from(protocol)?;
            flavor
                .sql(
                    docker,
                    runtime,
                    &databases::mysql_fence_sql(target.username),
                )
                .await?;
            flavor.terminate(docker, runtime, target.username).await?;
        }
        Protocol::Mongodb => {
            let fence = databases::mongodb::provision::fence_tenant_script(
                target.database,
                target.username,
            )?;
            let terminate = databases::mongodb::provision::terminate_tenant_script(
                target.database,
                target.username,
            )?;
            mongo_script(docker, runtime, &format!("{fence}\n{terminate}"), &[]).await?;
        }
        Protocol::Clickhouse => {
            clickhouse_sql(
                docker,
                runtime,
                &format!(
                    "{}\n{}",
                    databases::clickhouse::provision::fence_tenant_sql(target.username),
                    databases::clickhouse::provision::terminate_tenant_sql(target.username),
                ),
            )
            .await?;
        }
        protocol => return Err(TenantEngineError::Unsupported(protocol)),
    }
    Ok(())
}

pub(crate) async fn unfence(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
) -> Result<(), TenantEngineError> {
    match runtime.protocol {
        Protocol::Postgres => {
            postgres_sql(
                docker,
                runtime,
                "dbe_control",
                &databases::postgres::provision::unfence_tenant_sql(
                    target.database,
                    target.username,
                ),
            )
            .await?;
        }
        protocol @ (Protocol::Mysql | Protocol::Mariadb) => {
            MysqlFlavor::try_from(protocol)?
                .sql(
                    docker,
                    runtime,
                    &databases::mysql_unfence_sql(target.username),
                )
                .await?;
        }
        Protocol::Mongodb => {
            let script = databases::mongodb::provision::unfence_tenant_script(
                target.database,
                target.username,
            )?;
            mongo_script(docker, runtime, &script, &[]).await?;
        }
        Protocol::Clickhouse => {
            clickhouse_sql(
                docker,
                runtime,
                &databases::clickhouse::provision::unfence_tenant_sql(target.username),
            )
            .await?;
        }
        protocol => return Err(TenantEngineError::Unsupported(protocol)),
    }
    Ok(())
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
    let Ok(flavor) = MysqlFlavor::try_from(runtime.protocol) else {
        return Ok(());
    };
    let sql = databases::mysql_rollback_gap_sql(target.database, target.username);
    let output = flavor.sql(docker, runtime, &sql).await?;
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
    match runtime.protocol {
        Protocol::Postgres => {
            let sql =
                databases::postgres::provision::drop_tenant_sql(target.database, target.username);
            let exists = postgres_sql(
                docker,
                runtime,
                "dbe_control",
                &databases::postgres::provision::tenant_database_exists_sql(target.database),
            )
            .await?;
            if exists.stdout.lines().any(|line| line.trim() == "1") {
                postgres_sql(docker, runtime, target.database, &sql.database_sql).await?;
                postgres_sql(docker, runtime, "dbe_control", &sql.maintenance_sql).await?;
            } else {
                postgres_sql(
                    docker,
                    runtime,
                    "dbe_control",
                    &databases::postgres::provision::drop_tenant_identity_sql(
                        target.database,
                        target.username,
                    ),
                )
                .await?;
            }
        }
        protocol @ (Protocol::Mysql | Protocol::Mariadb) => {
            let flavor = MysqlFlavor::try_from(protocol)?;
            flavor.terminate(docker, runtime, target.username).await?;
            flavor
                .sql(
                    docker,
                    runtime,
                    &databases::mysql_drop_sql(target.database, target.username),
                )
                .await?;
        }
        Protocol::Mongodb => {
            let script = databases::mongodb::provision::drop_tenant_script(
                target.database,
                target.username,
            )?;
            mongo_script(docker, runtime, &script, &[]).await?;
        }
        Protocol::Clickhouse => {
            clickhouse_sql(
                docker,
                runtime,
                &databases::clickhouse::provision::drop_tenant_sql(
                    target.database,
                    target.username,
                ),
            )
            .await?;
        }
        protocol => return Err(TenantEngineError::Unsupported(protocol)),
    }
    Ok(())
}

pub(crate) async fn set_quota(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    limits: &InstanceLimits,
) -> Result<(), TenantEngineError> {
    match runtime.protocol {
        Protocol::Postgres => {
            postgres_sql(
                docker,
                runtime,
                "dbe_control",
                &databases::postgres::provision::tenant_quota_sql(
                    target.database,
                    target.username,
                    policy::postgres_quota(limits),
                ),
            )
            .await?;
        }
        protocol @ (Protocol::Mysql | Protocol::Mariadb) => {
            let flavor = MysqlFlavor::try_from(protocol)?;
            flavor
                .sql(docker, runtime, &flavor.quota_sql(target.username, limits))
                .await?;
        }
        Protocol::Mongodb => {
            let policy = databases::mongodb::provision::tenant_quota_policy(
                databases::mongodb::provision::TenantQuota {
                    max_connections: policy::max_connections(limits),
                    max_operation_time_ms: 15 * 60 * 1_000,
                    storage_bytes: mib_to_bytes(limits.disk_mib),
                },
            );
            debug_assert!(!policy.engine_enforced);
        }
        Protocol::Clickhouse => {
            clickhouse_sql(
                docker,
                runtime,
                &databases::clickhouse::provision::tenant_quota_sql(
                    target.username,
                    policy::clickhouse_quota(limits),
                ),
            )
            .await?;
        }
        protocol => return Err(TenantEngineError::Unsupported(protocol)),
    }
    Ok(())
}

pub(crate) async fn rotate_password(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    password: &str,
) -> Result<(), TenantEngineError> {
    match runtime.protocol {
        Protocol::Postgres => {
            postgres_password_sql(
                docker,
                runtime,
                &databases::postgres::provision::reset_tenant_password_sql(target.username),
                password,
            )
            .await?;
        }
        Protocol::Mysql => {
            mysql_password_sql(
                docker,
                runtime,
                &databases::mysql::provision::reset_tenant_password_sql(target.username),
                password,
            )
            .await?;
            MysqlFlavor::Mysql
                .sql(
                    docker,
                    runtime,
                    &databases::mysql_shared_grant_sql(target.database, target.username),
                )
                .await?;
        }
        Protocol::Mariadb => {
            let flavor = MysqlFlavor::Mariadb;
            let verifier = crate::protocols::mariadb::native_password_sha1_stage2_hex(password);
            flavor
                .sql(
                    docker,
                    runtime,
                    &databases::mariadb::provision::reset_tenant_password_sql(
                        target.username,
                        &verifier,
                    )?,
                )
                .await?;
            flavor
                .sql(
                    docker,
                    runtime,
                    &databases::mysql_shared_grant_sql(target.database, target.username),
                )
                .await?;
        }
        Protocol::Mongodb => {
            let script = databases::mongodb::provision::password_update_script(
                target.database,
                target.username,
            )?;
            mongo_script(
                docker,
                runtime,
                &script,
                &[(
                    "DBE_ROTATED_PASSWORD",
                    SecretString::from(password.to_string()),
                )],
            )
            .await?;
        }
        Protocol::Clickhouse => {
            let admin = admin_secret(runtime)?;
            clickhouse_password_sql(
                docker,
                runtime,
                databases::clickhouse::docker::INTERNAL_ADMIN_USERNAME,
                admin,
                &databases::clickhouse::provision::reset_tenant_password_sql(target.username),
                password,
            )
            .await?;
            clickhouse_sql(
                docker,
                runtime,
                &databases::clickhouse::provision::shared_grant_sql(
                    target.database,
                    target.username,
                ),
            )
            .await?;
        }
        protocol => return Err(TenantEngineError::Unsupported(protocol)),
    }
    Ok(())
}

pub(crate) async fn verify_password(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    password: &str,
) -> Result<(), TenantEngineError> {
    let password = SecretString::from(password.to_string());
    let command = match runtime.protocol {
        Protocol::Postgres => format!(
            "PGPASSWORD=\"$DBE_TENANT_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -Atqc 'SELECT 1' >/dev/null",
            sh_quote(target.username),
            sh_quote(target.database),
        ),
        protocol @ (Protocol::Mysql | Protocol::Mariadb) => {
            MysqlFlavor::try_from(protocol)?.verify_command(target)
        }
        Protocol::Mongodb => format!(
            "mongosh --quiet --host 127.0.0.1 --username {} --password \"$DBE_TENANT_PASSWORD\" --authenticationDatabase {} {} --eval 'quit(db.runCommand({{ ping: 1 }}).ok === 1 ? 0 : 2)' >/dev/null",
            sh_quote(target.username),
            sh_quote(target.database),
            sh_quote(target.database),
        ),
        Protocol::Clickhouse => format!(
            "clickhouse-client --host 127.0.0.1 --user {} --password \"$DBE_TENANT_PASSWORD\" --database {} --query 'SELECT 1' >/dev/null",
            sh_quote(target.username),
            sh_quote(target.database),
        ),
        protocol => return Err(TenantEngineError::Unsupported(protocol)),
    };
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
    let output = match runtime.protocol {
        Protocol::Postgres => {
            postgres_sql(
                docker,
                runtime,
                "dbe_control",
                &databases::postgres::provision::tenant_storage_sql(&database_names),
            )
            .await?
        }
        protocol @ (Protocol::Mysql | Protocol::Mariadb) => {
            MysqlFlavor::try_from(protocol)?
                .sql(
                    docker,
                    runtime,
                    &databases::mysql_storage_sql(&database_names),
                )
                .await?
        }
        Protocol::Mongodb => {
            let script = databases::mongodb::provision::tenant_storage_script(&database_names)?;
            mongo_script(docker, runtime, &script, &[]).await?
        }
        Protocol::Clickhouse => {
            clickhouse_sql(
                docker,
                runtime,
                &databases::clickhouse::provision::tenant_storage_sql(&database_names),
            )
            .await?
        }
        protocol => return Err(TenantEngineError::Unsupported(protocol)),
    };
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

async fn postgres_sql(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    database: &str,
    sql: &str,
) -> Result<CommandOutput, TenantEngineError> {
    let admin = admin_secret(runtime)?;
    let script = format!(
        "set -eu\nprintf %s {} | PGPASSWORD=\"$DBE_ADMIN_PASSWORD\" psql -X -A -t -q -h /var/run/postgresql -U dbe_admin -d {} -v ON_ERROR_STOP=1",
        sh_quote(sql),
        sh_quote(database),
    );
    Ok(docker
        .exec_tenant_shell(
            Protocol::Postgres,
            &runtime.runtime_id,
            &script,
            &[("DBE_ADMIN_PASSWORD", &admin)],
            TENANT_OPERATION_TIMEOUT,
        )
        .await?)
}

async fn postgres_password_sql(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    sql: &str,
    password: &str,
) -> Result<(), TenantEngineError> {
    let admin = admin_secret(runtime)?;
    let password = SecretString::from(password.to_string());
    let script = format!(
        "set -eu\n{{ printf '%s\\n' '\\getenv tenant_password DBE_TENANT_PASSWORD'; printf %s {}; }} | PGPASSWORD=\"$DBE_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U dbe_admin -d dbe_control -v ON_ERROR_STOP=1",
        sh_quote(sql),
    );
    docker
        .exec_tenant_shell(
            Protocol::Postgres,
            &runtime.runtime_id,
            &script,
            &[
                ("DBE_ADMIN_PASSWORD", &admin),
                ("DBE_TENANT_PASSWORD", &password),
            ],
            TENANT_OPERATION_TIMEOUT,
        )
        .await?;
    Ok(())
}

async fn mysql_password_sql(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    sql: &str,
    password: &str,
) -> Result<(), TenantEngineError> {
    let (before, after) = databases::mysql::provision::password_sql_fragments(sql)?;
    let password = SecretString::from(STANDARD.encode(password));
    let admin = admin_secret(runtime)?;
    let script = format!(
        "set -eu\n{{ printf %s {}; printf %s \"$DBE_PASSWORD_B64\"; printf %s {}; }} | MYSQL_PWD=\"$DBE_ADMIN_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -uroot",
        sh_quote(before),
        sh_quote(after),
    );
    docker
        .exec_tenant_shell(
            Protocol::Mysql,
            &runtime.runtime_id,
            &script,
            &[
                ("DBE_ADMIN_PASSWORD", &admin),
                ("DBE_PASSWORD_B64", &password),
            ],
            TENANT_OPERATION_TIMEOUT,
        )
        .await?;
    Ok(())
}

async fn sql_client(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    flavor: MysqlFlavor,
    sql: &str,
    timeout: Duration,
    telemetry: bool,
) -> Result<CommandOutput, TenantEngineError> {
    let protocol = flavor.protocol();
    let (client, socket) = flavor.client();
    let admin = admin_secret(runtime)?;
    let script = format!(
        "set -eu\nprintf %s {} | MYSQL_PWD=\"$DBE_ADMIN_PASSWORD\" {client} --protocol=socket --socket={} --batch --skip-column-names --raw -uroot",
        sh_quote(sql),
        sh_quote(socket),
    );
    let script = if telemetry {
        telemetry_command(script)
    } else {
        script
    };
    let output = if telemetry {
        docker
            .exec_telemetry(
                protocol,
                &runtime.runtime_id,
                &script,
                &[("DBE_ADMIN_PASSWORD", &admin)],
                timeout,
            )
            .await?
    } else {
        docker
            .exec_tenant_shell(
                protocol,
                &runtime.runtime_id,
                &script,
                &[("DBE_ADMIN_PASSWORD", &admin)],
                timeout,
            )
            .await?
    };
    Ok(output)
}

fn telemetry_command(script: String) -> String {
    format!("exec timeout -k 1s 6s sh -c {}", sh_quote(&script))
}

async fn mongo_script(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    script: &str,
    extra: &[(&str, SecretString)],
) -> Result<CommandOutput, TenantEngineError> {
    let admin = admin_secret(runtime)?;
    let mut secrets = vec![("DBE_ADMIN_PASSWORD", &admin)];
    secrets.extend(extra.iter().map(|(key, value)| (*key, value)));
    let script = databases::mongodb::provision::admin_script(script);
    let command = format!(
        "set -eu\nmongosh --quiet --nodb --eval {}",
        sh_quote(&script)
    );
    Ok(docker
        .exec_tenant_shell(
            Protocol::Mongodb,
            &runtime.runtime_id,
            &command,
            &secrets,
            TENANT_OPERATION_TIMEOUT,
        )
        .await?)
}

async fn clickhouse_password_sql(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    admin_user: &str,
    admin: SecretString,
    sql: &str,
    password: &str,
) -> Result<(), TenantEngineError> {
    let (before, after) = databases::clickhouse::provision::password_sql_fragments(sql)?;
    let password_literal = databases::clickhouse::provision::password_literal(password);
    let password = SecretString::from(STANDARD.encode(password_literal));
    let command = format!(
        "set -eu\n{{ printf %s {}; printf %s \"$DBE_PASSWORD_B64\" | base64 -d; printf %s {}; }} | CLICKHOUSE_PASSWORD=\"$DBE_ADMIN_PASSWORD\" clickhouse-client --user {} --multiquery",
        sh_quote(before),
        sh_quote(after),
        sh_quote(admin_user),
    );
    docker
        .exec_tenant_shell(
            Protocol::Clickhouse,
            &runtime.runtime_id,
            &command,
            &[
                ("DBE_ADMIN_PASSWORD", &admin),
                ("DBE_PASSWORD_B64", &password),
            ],
            TENANT_OPERATION_TIMEOUT,
        )
        .await?;
    Ok(())
}

async fn clickhouse_sql(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    sql: &str,
) -> Result<CommandOutput, TenantEngineError> {
    let admin = admin_secret(runtime)?;
    let command = format!(
        "set -eu\nprintf %s {} | CLICKHOUSE_PASSWORD=\"$DBE_ADMIN_PASSWORD\" clickhouse-client --user dbe_admin --multiquery",
        sh_quote(sql),
    );
    Ok(docker
        .exec_tenant_shell(
            Protocol::Clickhouse,
            &runtime.runtime_id,
            &command,
            &[("DBE_ADMIN_PASSWORD", &admin)],
            TENANT_OPERATION_TIMEOUT,
        )
        .await?)
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
            assert!(policy::engine_disk_overhead(protocol).is_none());
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
