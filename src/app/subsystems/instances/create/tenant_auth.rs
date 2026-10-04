use super::mysql_hardening;
use super::mysql_hardening::harden_mysql_tenant_auth;
use super::{DATABASE_READINESS_TIMEOUT, READINESS_RETRY_INTERVAL, fail_bad_request, fail_runtime};
use crate::databases;
use crate::databases::engine::{CredentialKind, LifecycleFlow, LifecycleRejection, TenantAuthStep};
use crate::databases::protocol::Protocol;
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::runtime::docker::ExecRecovery;
use crate::server::metadata::InstanceMetadata;
use crate::utils::shell::sh_quote;
use secrecy::SecretString;
use std::time::Duration;
use tokio::time::sleep;

pub(crate) async fn provision_mariadb_tenant_user(
    state: &AppState,
    instance_id: &str,
    database: &str,
    username: &str,
    password: &str,
    root_password: &str,
) -> Result<(), ApiError> {
    wait_for_mariadb_localhost(state, instance_id).await?;
    let verifier = crate::gateway::protocols::mariadb::native_password_sha1_stage2_hex(password);
    let sql = databases::mariadb::provision::tenant_user_sql(database, username, &verifier)
        .map_err(|error| fail_bad_request(state, instance_id, error))?;
    let script = format!(
        "set -eu\nprintf %s {} | MYSQL_PWD=\"$DBE_MARIADB_ROOT_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -uroot\n",
        sh_quote(&sql)
    );
    let root_password = SecretString::from(root_password.to_string());
    state
        .docker
        .exec_shell_with_secrets(
            Protocol::Mariadb,
            instance_id,
            &script,
            &[("DBE_MARIADB_ROOT_PASSWORD", &root_password)],
        )
        .await
        .map_err(|error| fail_runtime(state, instance_id, error))?;
    Ok(())
}

pub(crate) async fn provision_mysql_tenant_user(
    state: &AppState,
    instance_id: &str,
    database: &str,
    username: &str,
    password: &str,
    root_password: &str,
) -> Result<(), ApiError> {
    let root_password_secret = SecretString::from(root_password.to_string());
    mysql_hardening::probe_mysql_root_auth(
        state,
        instance_id,
        &root_password_secret,
        DATABASE_READINESS_TIMEOUT,
    )
    .await?;
    let sql = databases::mysql::provision::tenant_user_sql(database, username);
    mysql_hardening::run_protected_mysql_sql(state, instance_id, &sql, password, root_password)
        .await
}

pub(crate) async fn provision_postgres_tenant_role(
    state: &AppState,
    instance_id: &str,
    database: &str,
    tenant_username: &str,
    tenant_password: &str,
    admin_password: &str,
) -> Result<(), ApiError> {
    databases::postgres::hardening::provision_tenant_role(
        &state.docker,
        instance_id,
        database,
        tenant_username,
        &SecretString::from(tenant_password.to_string()),
        &SecretString::from(admin_password.to_string()),
        ExecRecovery::RestartRuntime,
    )
    .await
    .map_err(|error| fail_runtime(state, instance_id, error))
}

pub(crate) async fn harden_postgres_instance_auth(
    state: &AppState,
    instance_id: &str,
    database: &str,
    tenant_username: &str,
    tenant_password: &str,
    admin_password: &str,
) -> Result<bool, ApiError> {
    let metadata = state.instances.get(instance_id).await.filter(|metadata| {
        metadata.protocol == Protocol::Postgres
            && metadata.database.name == database
            && metadata.database.username == tenant_username
            && metadata.tenant_password.as_deref() == Some(tenant_password)
            && metadata.postgres_admin_password.as_deref() == Some(admin_password)
    });
    let attestation = if let Some(metadata) = metadata.as_ref() {
        match crate::server::auth_hardening::begin_attestation(
            &state.manager,
            &state.docker,
            metadata,
        )
        .await
        {
            Ok(check) if check.current => return Ok(false),
            Ok(check) => {
                if let Some(error) = check.cache_warning.as_deref() {
                    tracing::warn!(
                        event = "audit auth_hardening_attestation_check_failed",
                        instance_id,
                        protocol = %Protocol::Postgres,
                        %error,
                        "could not validate the cached hardening attestation; running full PostgreSQL hardening"
                    );
                }
                Some(check)
            }
            Err(error) => return Err(fail_runtime(state, instance_id, error)),
        }
    } else {
        None
    };
    let changed = databases::postgres::hardening::harden_instance_auth(
        &state.docker,
        instance_id,
        database,
        tenant_username,
        &SecretString::from(tenant_password.to_string()),
        &SecretString::from(admin_password.to_string()),
        ExecRecovery::RestartRuntime,
    )
    .await
    .map_err(|error| fail_runtime(state, instance_id, error))?;
    if let (Some(metadata), Some(attestation)) = (metadata.as_ref(), attestation.as_ref())
        && let Err(error) = crate::server::auth_hardening::complete_attestation(
            &state.manager,
            &state.docker,
            metadata,
            attestation.generation(),
        )
        .await
    {
        if error.is_storage() {
            tracing::warn!(
                event = "audit auth_hardening_attestation_write_failed",
                instance_id,
                protocol = %Protocol::Postgres,
                %error,
                "PostgreSQL hardening succeeded, but its optimization attestation could not be persisted"
            );
        } else {
            return Err(fail_runtime(state, instance_id, error));
        }
    }
    Ok(changed)
}

pub(crate) fn lifecycle_rejection(rejection: LifecycleRejection) -> ApiError {
    match rejection {
        LifecycleRejection::BadRequest(message) => ApiError::BadRequest(message),
        LifecycleRejection::Conflict(message) => ApiError::Conflict(message),
    }
}

pub(crate) fn missing_credential_error(
    protocol: Protocol,
    flow: LifecycleFlow,
    kind: CredentialKind,
) -> ApiError {
    lifecycle_rejection(protocol.engine().missing_credential(flow, kind))
}

pub(crate) fn flow_maintenance_credential(
    metadata: &InstanceMetadata,
    flow: LifecycleFlow,
) -> Result<&str, ApiError> {
    let engine = metadata.protocol.engine();
    engine.stored_maintenance_password(metadata).ok_or_else(|| {
        missing_credential_error(metadata.protocol, flow, CredentialKind::Maintenance)
    })
}

pub(crate) async fn run_tenant_auth_step(
    state: &AppState,
    metadata: &InstanceMetadata,
    step: TenantAuthStep,
    tenant_password: &str,
    maintenance_password: &str,
) -> Result<(), ApiError> {
    let instance_id = &metadata.instance_id;
    let database = &metadata.database.name;
    let username = &metadata.database.username;
    match step {
        TenantAuthStep::PostgresProvisionRole => {
            provision_postgres_tenant_role(
                state,
                instance_id,
                database,
                username,
                tenant_password,
                maintenance_password,
            )
            .await
        }
        TenantAuthStep::PostgresHarden => harden_postgres_instance_auth(
            state,
            instance_id,
            database,
            username,
            tenant_password,
            maintenance_password,
        )
        .await
        .map(|_| ()),
        TenantAuthStep::MariadbProvisionUser => {
            provision_mariadb_tenant_user(
                state,
                instance_id,
                database,
                username,
                tenant_password,
                maintenance_password,
            )
            .await
        }
        TenantAuthStep::MysqlProvisionUser => {
            provision_mysql_tenant_user(
                state,
                instance_id,
                database,
                username,
                tenant_password,
                maintenance_password,
            )
            .await
        }
        TenantAuthStep::MysqlHarden => {
            harden_mysql_tenant_auth(
                state,
                instance_id,
                username,
                tenant_password,
                maintenance_password,
            )
            .await
        }
    }
}

pub(super) async fn wait_for_mariadb_localhost(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    state.install_progress.stage(
        instance_id,
        "readiness",
        "waiting for MariaDB local socket to become available",
    );
    wait_for_shell_command(
        state,
        Protocol::Mariadb,
        instance_id,
        "test \"$(cat /proc/1/comm)\" = mariadbd || exit 1; root_password=\"${DBE_MARIADB_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}\"; MYSQL_PWD=\"$root_password\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -u root -N -B -e 'SELECT 1' >/dev/null",
        DATABASE_READINESS_TIMEOUT,
    )
    .await
}

pub(super) async fn wait_for_shell_command(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
    command: &str,
    timeout: Duration,
) -> Result<(), ApiError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_error = String::new();
    while tokio::time::Instant::now() < deadline {
        match state
            .docker
            .exec_shell(protocol, instance_id, command)
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) => {
                last_error = error.to_string();
                sleep(READINESS_RETRY_INTERVAL).await;
            }
        }
    }

    let message = format!("database local readiness did not succeed before timeout: {last_error}");
    state
        .install_progress
        .fail_internal(instance_id, "database readiness", &message);
    Err(ApiError::Runtime(message))
}
