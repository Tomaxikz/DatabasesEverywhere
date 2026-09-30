use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::future::BoxFuture;
use secrecy::SecretString;

use super::super::{
    TENANT_OPERATION_TIMEOUT, TenantEngineError, TenantTarget, admin_secret, telemetry_command,
};
use super::{TenantBackend, TenantOperation};
use crate::{
    databases::{self, clickhouse::docker::INTERNAL_ADMIN_USERNAME},
    placement::{EngineRuntime, policy},
    runtime::docker::{CommandOutput, DockerRuntime},
    shared::{limits::InstanceLimits, protocol::Protocol, shell::sh_quote},
};

pub(super) struct Clickhouse;

impl TenantBackend for Clickhouse {
    fn apply<'a>(
        &'a self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        target: TenantTarget<'a>,
        operation: TenantOperation<'a>,
    ) -> BoxFuture<'a, Result<(), TenantEngineError>> {
        Box::pin(async move {
            match operation {
                TenantOperation::Create {
                    password,
                    limits,
                    admin,
                } => {
                    let create = databases::clickhouse::provision::create_tenant_sql(
                        target.database,
                        target.username,
                    );
                    clickhouse_password_sql(
                        docker,
                        runtime,
                        INTERNAL_ADMIN_USERNAME,
                        admin,
                        &create,
                        password,
                    )
                    .await?;
                    clickhouse_sql(docker, runtime, &quota_sql(target, limits)).await?;
                }
                TenantOperation::Fence => {
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
                TenantOperation::Unfence => {
                    clickhouse_sql(
                        docker,
                        runtime,
                        &databases::clickhouse::provision::unfence_tenant_sql(target.username),
                    )
                    .await?;
                }
                TenantOperation::Drop => {
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
                TenantOperation::SetQuota { limits } => {
                    clickhouse_sql(docker, runtime, &quota_sql(target, limits)).await?;
                }
                TenantOperation::RotatePassword { password } => {
                    let admin = admin_secret(runtime)?;
                    clickhouse_password_sql(
                        docker,
                        runtime,
                        INTERNAL_ADMIN_USERNAME,
                        admin,
                        &databases::clickhouse::provision::reset_tenant_password_sql(
                            target.username,
                        ),
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
            }
            Ok(())
        })
    }

    fn verify_command(&self, target: TenantTarget<'_>) -> String {
        format!(
            "clickhouse-client --host 127.0.0.1 --user {} --password \"$DBE_TENANT_PASSWORD\" --database {} --query 'SELECT 1' >/dev/null",
            sh_quote(target.username),
            sh_quote(target.database),
        )
    }

    fn measure_storage<'a>(
        &'a self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        database_names: &'a [&'a str],
    ) -> BoxFuture<'a, Result<CommandOutput, TenantEngineError>> {
        Box::pin(async move {
            clickhouse_sql(
                docker,
                runtime,
                &databases::clickhouse::provision::tenant_storage_sql(database_names),
            )
            .await
        })
    }
}

fn quota_sql(target: TenantTarget<'_>, limits: &InstanceLimits) -> String {
    databases::clickhouse::provision::tenant_quota_sql(
        target.username,
        policy::clickhouse_quota(limits),
    )
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

pub(in crate::placement::tenant) fn clickhouse_telemetry_command(
    prior_cutoff_micros: Option<u64>,
    sql: &str,
) -> String {
    telemetry_command(clickhouse_telemetry_script(prior_cutoff_micros, sql))
}

pub(in crate::placement::tenant) fn clickhouse_telemetry_script(
    prior_cutoff_micros: Option<u64>,
    sql: &str,
) -> String {
    let prior = prior_cutoff_micros
        .map(|value| value.to_string())
        .unwrap_or_default();
    format!(
        "set -eu\ncutoff=\"$(CLICKHOUSE_PASSWORD=\"$DBE_ADMIN_PASSWORD\" clickhouse-client --user dbe_admin --max_execution_time 3 --timeout_before_checking_execution_speed 0 --query 'SELECT toUnixTimestamp64Micro(now64(6))')\"\ncase \"$cutoff\" in ''|*[!0-9]*) exit 2 ;; esac\nprevious={}\nif [ -z \"$previous\" ]; then previous=\"$cutoff\"; fi\nCLICKHOUSE_PASSWORD=\"$DBE_ADMIN_PASSWORD\" clickhouse-client --user dbe_admin --max_execution_time 3 --timeout_before_checking_execution_speed 0 --query 'SYSTEM FLUSH LOGS'\nprintf '__DBE_CUTOFF__\\t%s\\n' \"$cutoff\"\nCLICKHOUSE_PASSWORD=\"$DBE_ADMIN_PASSWORD\" clickhouse-client --user dbe_admin --max_execution_time 3 --timeout_before_checking_execution_speed 0 --param_dbe_previous=\"$previous\" --param_dbe_cutoff=\"$cutoff\" --query {}",
        sh_quote(&prior),
        sh_quote(sql),
    )
}
