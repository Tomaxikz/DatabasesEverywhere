use futures::future::BoxFuture;
use secrecy::SecretString;

use super::super::{TENANT_OPERATION_TIMEOUT, TenantEngineError, TenantTarget, admin_secret};
use super::{TenantBackend, TenantOperation};
use crate::{
    databases,
    placement::{EngineRuntime, policy},
    runtime::docker::{CommandOutput, DockerRuntime},
    shared::{limits::mib_to_bytes, protocol::Protocol, shell::sh_quote},
};

pub(super) struct Mongodb;

impl TenantBackend for Mongodb {
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
                    limits: _,
                    admin: _,
                } => {
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
                TenantOperation::Fence => {
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
                TenantOperation::Unfence => {
                    let script = databases::mongodb::provision::unfence_tenant_script(
                        target.database,
                        target.username,
                    )?;
                    mongo_script(docker, runtime, &script, &[]).await?;
                }
                TenantOperation::Drop => {
                    let script = databases::mongodb::provision::drop_tenant_script(
                        target.database,
                        target.username,
                    )?;
                    mongo_script(docker, runtime, &script, &[]).await?;
                }
                TenantOperation::SetQuota { limits } => {
                    // MongoDB quotas remain gateway/catalog policy, not an
                    // engine-enforced limit. Keep that capability explicit.
                    let policy = databases::mongodb::provision::tenant_quota_policy(
                        databases::mongodb::provision::TenantQuota {
                            max_connections: policy::max_connections(limits),
                            max_operation_time_ms: 15 * 60 * 1_000,
                            storage_bytes: mib_to_bytes(limits.disk_mib),
                        },
                    );
                    debug_assert!(!policy.engine_enforced);
                }
                TenantOperation::RotatePassword { password } => {
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
            }
            Ok(())
        })
    }

    fn verify_command(&self, target: TenantTarget<'_>) -> String {
        format!(
            "mongosh --quiet --host 127.0.0.1 --username {} --password \"$DBE_TENANT_PASSWORD\" --authenticationDatabase {} {} --eval 'quit(db.runCommand({{ ping: 1 }}).ok === 1 ? 0 : 2)' >/dev/null",
            sh_quote(target.username),
            sh_quote(target.database),
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
            let script = databases::mongodb::provision::tenant_storage_script(database_names)?;
            mongo_script(docker, runtime, &script, &[]).await
        })
    }
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
