use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::future::BoxFuture;
use secrecy::SecretString;

use super::super::{
    TELEMETRY_OPERATION_TIMEOUT, TENANT_OPERATION_TIMEOUT, TenantEngineError, TenantTarget,
    admin_secret, telemetry_command,
};
use super::{TenantBackend, TenantOperation};
use crate::{
    databases,
    databases::protocol::Protocol,
    runtime::docker::{CommandOutput, DockerRuntime},
    server::placement::EngineRuntime,
    utils::{limits::InstanceLimits, shell::sh_quote},
};

const MYSQL_SOCKET: &str = "/var/run/mysqld/mysqld.sock";
const MARIADB_SOCKET: &str = "/run/mysqld/mysqld.sock";

#[derive(Clone, Copy)]
pub(crate) enum MysqlFlavor {
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
            Self::Mysql => ("mysql", MYSQL_SOCKET),
            Self::Mariadb => ("mariadb", MARIADB_SOCKET),
        }
    }

    fn quota_sql(self, username: &str, limits: &InstanceLimits) -> String {
        match self {
            Self::Mysql => databases::mysql::provision::tenant_quota_sql(
                username,
                databases::mysql::tenancy::tenant_quota(limits),
            ),
            Self::Mariadb => databases::mariadb::provision::tenant_quota_sql(
                username,
                databases::mariadb::tenancy::tenant_quota(limits),
            ),
        }
    }

    pub(in crate::server::placement::tenant) async fn sql(
        self,
        docker: &DockerRuntime,
        runtime: &EngineRuntime,
        sql: &str,
    ) -> Result<CommandOutput, TenantEngineError> {
        sql_client(docker, runtime, self, sql, TENANT_OPERATION_TIMEOUT, false).await
    }

    pub(in crate::server::placement::tenant) async fn telemetry(
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
        let session_lines = output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        for line in session_lines {
            let connection_id = line
                .parse::<u64>()
                .map_err(|_| TenantEngineError::InvalidConnectionId(line.to_string()))?;
            self.sql(docker, runtime, &databases::mysql_kill_sql(connection_id))
                .await?;
        }
        Ok(())
    }

    async fn create_tenant(
        self,
        docker: &DockerRuntime,
        runtime: &EngineRuntime,
        target: TenantTarget<'_>,
        password: &str,
        limits: &InstanceLimits,
    ) -> Result<(), TenantEngineError> {
        match self {
            Self::Mysql => {
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
            }
            Self::Mariadb => {
                let verifier =
                    crate::gateway::protocols::mariadb::native_password_sha1_stage2_hex(password);
                self.sql(
                    docker,
                    runtime,
                    &databases::mariadb::provision::shared_tenant_user_sql(
                        target.database,
                        target.username,
                        &verifier,
                    )?,
                )
                .await?;
            }
        }
        self.sql(docker, runtime, &self.quota_sql(target.username, limits))
            .await?;
        Ok(())
    }

    async fn rotate_password(
        self,
        docker: &DockerRuntime,
        runtime: &EngineRuntime,
        target: TenantTarget<'_>,
        password: &str,
    ) -> Result<(), TenantEngineError> {
        match self {
            Self::Mysql => {
                mysql_password_sql(
                    docker,
                    runtime,
                    &databases::mysql::provision::reset_tenant_password_sql(target.username),
                    password,
                )
                .await?;
            }
            Self::Mariadb => {
                let verifier =
                    crate::gateway::protocols::mariadb::native_password_sha1_stage2_hex(password);
                self.sql(
                    docker,
                    runtime,
                    &databases::mariadb::provision::reset_tenant_password_sql(
                        target.username,
                        &verifier,
                    )?,
                )
                .await?;
            }
        }
        self.sql(
            docker,
            runtime,
            &databases::mysql_shared_grant_sql(target.database, target.username),
        )
        .await?;
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

impl TenantBackend for MysqlFlavor {
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
                    admin: _,
                } => {
                    self.create_tenant(docker, runtime, target, password, limits)
                        .await?;
                }
                TenantOperation::Fence => {
                    self.sql(
                        docker,
                        runtime,
                        &databases::mysql_fence_sql(target.username),
                    )
                    .await?;
                    self.terminate(docker, runtime, target.username).await?;
                }
                TenantOperation::Unfence => {
                    self.sql(
                        docker,
                        runtime,
                        &databases::mysql_unfence_sql(target.username),
                    )
                    .await?;
                }
                TenantOperation::Drop => {
                    self.terminate(docker, runtime, target.username).await?;
                    self.sql(
                        docker,
                        runtime,
                        &databases::mysql_drop_sql(target.database, target.username),
                    )
                    .await?;
                }
                TenantOperation::SetQuota { limits } => {
                    self.sql(docker, runtime, &self.quota_sql(target.username, limits))
                        .await?;
                }
                TenantOperation::RotatePassword { password } => {
                    self.rotate_password(docker, runtime, target, password)
                        .await?;
                }
            }
            Ok(())
        })
    }

    fn verify_command(&self, target: TenantTarget<'_>) -> String {
        MysqlFlavor::verify_command(*self, target)
    }

    fn admin_sql<'a>(
        &'a self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        sql: &'a str,
    ) -> BoxFuture<'a, Result<CommandOutput, TenantEngineError>> {
        Box::pin(async move { self.sql(docker, runtime, sql).await })
    }

    fn telemetry_sql<'a>(
        &'a self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        sql: &'a str,
    ) -> BoxFuture<'a, Result<CommandOutput, TenantEngineError>> {
        Box::pin(async move { self.telemetry(docker, runtime, sql).await })
    }

    fn measure_storage<'a>(
        &'a self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        database_names: &'a [&'a str],
    ) -> BoxFuture<'a, Result<CommandOutput, TenantEngineError>> {
        Box::pin(async move {
            self.sql(
                docker,
                runtime,
                &databases::mysql_storage_sql(database_names),
            )
            .await
        })
    }
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
        "set -eu\n{{ printf %s {}; printf %s \"$DBE_PASSWORD_B64\"; printf %s {}; }} | MYSQL_PWD=\"$DBE_ADMIN_PASSWORD\" mysql --protocol=socket --socket={MYSQL_SOCKET} -uroot",
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
    let output = if telemetry {
        docker
            .exec_telemetry(
                protocol,
                &runtime.runtime_id,
                &telemetry_command(script),
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
