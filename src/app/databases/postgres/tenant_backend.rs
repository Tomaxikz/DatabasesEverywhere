use futures::future::BoxFuture;
use secrecy::SecretString;

use crate::server::placement::tenant::backends::{TenantBackend, TenantOperation};
use crate::server::placement::tenant::{
    TENANT_OPERATION_TIMEOUT, TenantEngineError, TenantTarget, admin_secret,
};
use crate::{
    databases::protocol::Protocol,
    databases::{self, postgres::docker::CONTROL_DATABASE},
    runtime::docker::{CommandOutput, DockerRuntime, ExecRecovery},
    server::placement::EngineRuntime,
    utils::{limits::InstanceLimits, shell::sh_quote},
};

pub(crate) struct Postgres;

impl TenantBackend for Postgres {
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
                        CONTROL_DATABASE,
                        &quota_sql(target, limits),
                    )
                    .await?;
                }
                TenantOperation::Fence => {
                    postgres_sql(
                        docker,
                        runtime,
                        CONTROL_DATABASE,
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
                TenantOperation::Unfence => {
                    postgres_sql(
                        docker,
                        runtime,
                        CONTROL_DATABASE,
                        &databases::postgres::provision::unfence_tenant_sql(
                            target.database,
                            target.username,
                        ),
                    )
                    .await?;
                }
                TenantOperation::Drop => {
                    let sql = databases::postgres::provision::drop_tenant_sql(
                        target.database,
                        target.username,
                    );
                    let existence = postgres_sql(
                        docker,
                        runtime,
                        CONTROL_DATABASE,
                        &databases::postgres::provision::tenant_database_exists_sql(
                            target.database,
                        ),
                    )
                    .await?;
                    let database_exists = existence.stdout.lines().any(|line| line.trim() == "1");
                    if database_exists {
                        postgres_sql(docker, runtime, target.database, &sql.database_sql).await?;
                        postgres_sql(docker, runtime, CONTROL_DATABASE, &sql.maintenance_sql)
                            .await?;
                    } else {
                        postgres_sql(
                            docker,
                            runtime,
                            CONTROL_DATABASE,
                            &databases::postgres::provision::drop_tenant_identity_sql(
                                target.database,
                                target.username,
                            ),
                        )
                        .await?;
                    }
                }
                TenantOperation::SetQuota { limits } => {
                    postgres_sql(
                        docker,
                        runtime,
                        CONTROL_DATABASE,
                        &quota_sql(target, limits),
                    )
                    .await?;
                }
                TenantOperation::RotatePassword { password } => {
                    postgres_password_sql(
                        docker,
                        runtime,
                        &databases::postgres::provision::reset_tenant_password_sql(target.username),
                        password,
                    )
                    .await?;
                }
            }
            Ok(())
        })
    }

    fn verify_command(&self, target: TenantTarget<'_>) -> String {
        format!(
            "PGPASSWORD=\"$DBE_TENANT_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -Atqc 'SELECT 1' >/dev/null",
            sh_quote(target.username),
            sh_quote(target.database),
        )
    }

    fn secure_pool<'a>(
        &'a self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
    ) -> BoxFuture<'a, Result<(), TenantEngineError>> {
        Box::pin(async move {
            postgres_sql(
                docker,
                runtime,
                CONTROL_DATABASE,
                &databases::postgres::provision::shared_catalog_lockdown_sql(),
            )
            .await?;
            Ok(())
        })
    }

    fn measure_storage<'a>(
        &'a self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        database_names: &'a [&'a str],
    ) -> BoxFuture<'a, Result<CommandOutput, TenantEngineError>> {
        Box::pin(async move {
            postgres_sql(
                docker,
                runtime,
                CONTROL_DATABASE,
                &databases::postgres::provision::tenant_storage_sql(database_names),
            )
            .await
        })
    }
}

fn quota_sql(target: TenantTarget<'_>, limits: &InstanceLimits) -> String {
    databases::postgres::provision::tenant_quota_sql(
        target.database,
        target.username,
        databases::postgres::tenancy::tenant_quota(limits),
    )
}

pub(crate) async fn postgres_sql(
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
