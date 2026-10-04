use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::Engine;
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use tokio::time::{Instant, sleep};

use super::{
    PASSWORD_EXEC_TIMEOUT, PreviousCredential, ROTATION_READINESS_TIMEOUT,
    supervision::InPlaceResetContext,
};
use crate::{
    databases::protocol::Protocol,
    databases::{
        self,
        engine::{LiveRotation, MaintenanceAuthCheck, MaintenanceCredential},
    },
    routes::http::{response::ApiError, router::AppState},
    runtime::docker::{DockerError, ExecRecovery},
    server::metadata::InstanceMetadata,
    subsystems::instances::docker_error,
    utils::shell::sh_quote,
};

const ADMIN_AUTH_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const ADMIN_AUTH_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_CAPTURED_AUTH_BYTES: usize = 4_096;

pub(super) async fn reset_password_in_place(
    context: &InPlaceResetContext<'_>,
    new_verifier: Option<&str>,
    credential_changed: Arc<AtomicBool>,
) -> Result<(), ApiError> {
    if context.metadata.protocol.engine().family().is_resp() {
        write_resp_acl(
            context.metadata.protocol,
            context.credential_data_path,
            &context.metadata.database.username,
            context.new_password,
        )
        .await?;
        context
            .paths
            .restore_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        activate_resp_acl(
            context.state,
            context.metadata,
            context.previous.environment.as_ref().ok_or_else(|| {
                ApiError::Conflict(
                    "the current RESP credential is unavailable for live ACL rotation".to_string(),
                )
            })?,
        )
        .await?;
        credential_changed.store(true, Ordering::Release);
    } else {
        apply_db_credential(
            context.state,
            context.metadata,
            context.previous,
            Some(context.new_password),
            new_verifier,
            Some(credential_changed.as_ref()),
        )
        .await?;
    }
    verify_tenant_credential(context.state, context.metadata, context.new_password).await
}

pub(super) async fn activate_resp_acl(
    state: &AppState,
    metadata: &InstanceMetadata,
    current_password: &SecretString,
) -> Result<(), ApiError> {
    let command = metadata
        .protocol
        .engine()
        .acl_reload_command()
        .ok_or_else(|| {
            ApiError::Runtime("ACL activation requested for a non-RESP database".to_string())
        })?;
    let tenant_user = SecretString::from(metadata.database.username.clone());
    state
        .docker
        .exec_shell_with_secrets_timeout(
            metadata.protocol,
            &metadata.instance_id,
            command,
            &[
                ("DBE_TENANT_USER", &tenant_user),
                ("DBE_CURRENT_PASSWORD", current_password),
            ],
            PASSWORD_EXEC_TIMEOUT,
        )
        .await
        .map_err(|error| ApiError::Runtime(format!("database ACL reload failed: {error}")))?;
    Ok(())
}

pub(super) async fn apply_db_credential(
    state: &AppState,
    metadata: &InstanceMetadata,
    previous: &PreviousCredential,
    target_password: Option<&SecretString>,
    native_password_verifier: Option<&str>,
    credential_change_possible: Option<&AtomicBool>,
) -> Result<(), ApiError> {
    wait_for_admin_auth(state, metadata, previous).await?;
    let engine = metadata.protocol.engine();
    let rotation = engine
        .live_rotation_script(&LiveRotation {
            username: &metadata.database.username,
            database: &metadata.database.name,
            rotating: target_password.is_some(),
            native_password_verifier,
            previous_mysql_auth_plugin: previous.mysql_auth_plugin.as_deref(),
        })
        .map_err(ApiError::Runtime)?;
    let mysql_password_b64 = if rotation.passes_password_as_base64 {
        target_password.map(|password| {
            SecretString::from(
                base64::engine::general_purpose::STANDARD
                    .encode(password.expose_secret().as_bytes()),
            )
        })
    } else {
        None
    };
    let postgres_admin_password = if rotation.passes_postgres_admin_password {
        previous.maintenance.as_ref()
    } else {
        None
    };
    let maintenance_password = previous.maintenance.as_ref();
    let mut environment = Vec::with_capacity(5);
    if let Some(password) = target_password {
        environment.push(("DBE_ROTATED_PASSWORD", password));
    }
    if let Some(password_b64) = mysql_password_b64.as_ref() {
        environment.push(("DBE_ROTATED_PASSWORD_B64", password_b64));
    }
    if let Some(admin_password) = postgres_admin_password {
        environment.push(("DBE_POSTGRES_ADMIN_PASSWORD", admin_password));
    }
    if let Some(password) = maintenance_password {
        environment.push(("DBE_ROTATION_ADMIN_PASSWORD", password));
    }
    let previous_verifier = native_password_verifier.map(SecretString::from);
    if target_password.is_none()
        && let Some(verifier) = previous_verifier.as_ref()
    {
        environment.push(("DBE_PREVIOUS_PASSWORD_VERIFIER", verifier));
    }
    if target_password.is_none()
        && let Some(authentication_string) = previous.mysql_auth_string_b64.as_ref()
    {
        environment.push(("DBE_PREVIOUS_MYSQL_AUTH_B64", authentication_string));
    }
    if let Some(changed) = credential_change_possible {
        changed.store(true, Ordering::Release);
    }
    state
        .docker
        .exec_shell_with_secrets_timeout(
            metadata.protocol,
            &metadata.instance_id,
            &rotation.script,
            &environment,
            PASSWORD_EXEC_TIMEOUT,
        )
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("database password rotation failed: {error}"))
        })?;
    if needs_postgres_hardening(metadata.protocol, target_password)
        && let Some(password) = target_password
    {
        let admin_password = previous.maintenance.as_ref().ok_or_else(|| {
            ApiError::Runtime(
                "the PostgreSQL maintenance credential disappeared during password rotation"
                    .to_string(),
            )
        })?;
        databases::postgres::hardening::harden_instance_auth(
            &state.docker,
            &metadata.instance_id,
            &metadata.database.name,
            &metadata.database.username,
            password,
            admin_password,
            ExecRecovery::RestartRuntime,
        )
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "PostgreSQL password rotation succeeded, but local authentication hardening failed: {error}"
            ))
        })?;
    }
    Ok(())
}

pub(super) fn needs_postgres_hardening(
    protocol: Protocol,
    target_password: Option<&SecretString>,
) -> bool {
    protocol.engine().family().is_postgres() && target_password.is_some()
}

pub(super) async fn verify_tenant_credential(
    state: &AppState,
    metadata: &InstanceMetadata,
    new_password: &SecretString,
) -> Result<(), ApiError> {
    let Some(script) = metadata
        .protocol
        .engine()
        .tenant_auth_probe(&metadata.database.username, &metadata.database.name)
    else {
        return Ok(());
    };
    state
        .docker
        .exec_shell_with_secrets_timeout(
            metadata.protocol,
            &metadata.instance_id,
            &script,
            &[("DBE_ROTATED_PASSWORD", new_password)],
            PASSWORD_EXEC_TIMEOUT,
        )
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("database credential verification failed: {error}"))
        })?;
    Ok(())
}

pub(super) async fn write_resp_acl(
    protocol: Protocol,
    data_path: &std::path::Path,
    username: &str,
    password: &SecretString,
) -> Result<(), ApiError> {
    if !protocol.engine().family().is_resp() {
        return Err(ApiError::Runtime(
            "ACL rotation requested for a non-RESP database".to_string(),
        ));
    }
    databases::resp::write_acl_file(data_path, username, password)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))
}

pub(super) async fn restore_resp_acl(
    protocol: Protocol,
    data_path: &std::path::Path,
    acl: &[u8],
) -> Result<(), ApiError> {
    if !protocol.engine().family().is_resp() {
        return Err(ApiError::Runtime(
            "ACL rollback requested for a non-RESP database".to_string(),
        ));
    }
    databases::resp::restore_acl_file(data_path, acl)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))
}

pub(super) async fn capture_maintenance_credential(
    state: &AppState,
    metadata: &InstanceMetadata,
    previous: &mut PreviousCredential,
) -> Result<(), ApiError> {
    let engine = metadata.protocol.engine();
    let (keys, username) = match engine.maintenance_credential() {
        MaintenanceCredential::PostgresInternalAdmin => {
            return capture_postgres_maintenance_credential(state, metadata, previous).await;
        }
        MaintenanceCredential::Stored {
            container_keys,
            username,
        } => (container_keys, username),
        MaintenanceCredential::None => return Ok(()),
    };
    previous.maintenance = engine
        .stored_maintenance_password(metadata)
        .filter(|value| !value.is_empty())
        .map(|value| SecretString::from(value.to_string()));
    if previous.maintenance.is_none() {
        previous.maintenance = first_container_secret(state, metadata, keys).await?;
    }
    if previous.maintenance.is_none() {
        return Err(ApiError::Conflict(format!(
            "the current {} maintenance credential is unavailable; password rotation cannot be authenticated safely",
            metadata.protocol
        )));
    }
    previous.maintenance_username = Some(username.to_string());
    Ok(())
}

async fn capture_postgres_maintenance_credential(
    state: &AppState,
    metadata: &InstanceMetadata,
    previous: &mut PreviousCredential,
) -> Result<(), ApiError> {
    previous.maintenance = metadata
        .postgres_admin_password
        .as_deref()
        .filter(|password| !password.is_empty())
        .map(|password| SecretString::from(password.to_string()));
    if previous.maintenance.is_none() {
        let (username, password) = state
            .docker
            .postgres_bootstrap_credentials(&metadata.instance_id)
            .await
            .map_err(docker_error)?;
        if username != databases::postgres::docker::INTERNAL_ADMIN_USERNAME {
            return Err(ApiError::Conflict(
                    "this legacy PostgreSQL instance does not have DBEV's restricted internal administrator; export and recreate it before rotating credentials"
                        .to_string(),
                ));
        }
        previous.maintenance = Some(password);
    }
    previous.maintenance_username =
        Some(databases::postgres::docker::INTERNAL_ADMIN_USERNAME.to_string());
    Ok(())
}

pub(super) async fn first_container_secret(
    state: &AppState,
    metadata: &InstanceMetadata,
    environment_keys: &[&str],
) -> Result<Option<SecretString>, ApiError> {
    for key in environment_keys {
        let value = state
            .docker
            .container_environment_value(metadata.protocol, &metadata.instance_id, key)
            .await
            .map_err(docker_error)?
            .filter(|value| !value.expose_secret().is_empty());
        if value.is_some() {
            return Ok(value);
        }
    }
    Ok(None)
}

pub(super) async fn capture_postgres_verifier(
    state: &AppState,
    metadata: &InstanceMetadata,
    previous: &PreviousCredential,
) -> Result<String, ApiError> {
    let admin_password = previous.maintenance.as_ref().ok_or_else(|| {
        ApiError::Conflict(
            "the PostgreSQL maintenance credential is unavailable for rollback capture".to_string(),
        )
    })?;
    let admin_username = previous.maintenance_username.as_deref().ok_or_else(|| {
        ApiError::Conflict("the PostgreSQL maintenance username is unavailable".to_string())
    })?;
    let sql =
        databases::postgres::provision::tenant_password_verifier_sql(&metadata.database.username);
    let script = format!(
        "PGPASSWORD=\"$DBE_ROTATION_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -Atqc {}",
        sh_quote(admin_username),
        sh_quote(&metadata.database.name),
        sh_quote(&sql),
    );
    let output = state
        .docker
        .exec_shell_with_secrets_timeout(
            Protocol::Postgres,
            &metadata.instance_id,
            &script,
            &[("DBE_ROTATION_ADMIN_PASSWORD", admin_password)],
            PASSWORD_EXEC_TIMEOUT,
        )
        .await
        .map_err(|error| {
            ApiError::Conflict(format!(
                "the current PostgreSQL password verifier could not be captured before rotation: {error}"
            ))
        })?;
    let verifier = output.stdout.trim();
    if verifier.is_empty()
        || verifier.len() > MAX_CAPTURED_AUTH_BYTES
        || verifier.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Err(ApiError::Conflict(
            "the current PostgreSQL role has no valid password verifier to restore".to_string(),
        ));
    }
    Ok(verifier.to_string())
}

pub(super) async fn capture_mysql_tenant_auth(
    state: &AppState,
    metadata: &InstanceMetadata,
    previous: &PreviousCredential,
) -> Result<(String, SecretString), ApiError> {
    let root_password = previous.maintenance.as_ref().ok_or_else(|| {
        ApiError::Conflict(
            "the MySQL maintenance credential is unavailable for rollback capture".to_string(),
        )
    })?;
    let sql = databases::mysql::provision::tenant_auth_state_sql(&metadata.database.username);
    let script = format!(
        "MYSQL_PWD=\"$DBE_ROTATION_ADMIN_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -uroot -N -B --raw -e {}",
        sh_quote(&sql),
    );
    let output = state
        .docker
        .exec_shell_with_secrets_timeout(
            Protocol::Mysql,
            &metadata.instance_id,
            &script,
            &[("DBE_ROTATION_ADMIN_PASSWORD", root_password)],
            PASSWORD_EXEC_TIMEOUT,
        )
        .await
        .map_err(|error| {
            ApiError::Conflict(format!(
                "the current MySQL tenant authentication state could not be captured before rotation: {error}"
            ))
        })?;
    let mut lines = output.stdout.lines();
    let line = lines.next().unwrap_or_default();
    if lines.next().is_some() {
        return Err(ApiError::Conflict(
            "the managed MySQL tenant resolves to multiple authentication records".to_string(),
        ));
    }
    let (plugin, authentication_string_b64) = line.split_once('\t').ok_or_else(|| {
        ApiError::Conflict(
            "the managed MySQL tenant has no restorable authentication record".to_string(),
        )
    })?;
    databases::mysql::provision::restore_tenant_auth_sql(&metadata.database.username, plugin)
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(authentication_string_b64)
        .map_err(|_| {
            ApiError::Conflict(
                "the managed MySQL tenant authentication string is malformed".to_string(),
            )
        })?;
    if decoded.is_empty() || decoded.len() > MAX_CAPTURED_AUTH_BYTES {
        return Err(ApiError::Conflict(
            "the managed MySQL tenant authentication string has an invalid size".to_string(),
        ));
    }
    Ok((
        plugin.to_string(),
        SecretString::from(authentication_string_b64.to_string()),
    ))
}

async fn wait_for_admin_auth(
    state: &AppState,
    metadata: &InstanceMetadata,
    previous: &PreviousCredential,
) -> Result<(), ApiError> {
    let maintenance = previous.maintenance.as_ref().ok_or_else(|| {
        ApiError::Conflict(format!(
            "the {} maintenance credential is unavailable for password rotation",
            metadata.protocol
        ))
    })?;
    let command = match metadata.protocol.engine().maintenance_auth_check() {
        MaintenanceAuthCheck::MysqlRoot => {
            return crate::subsystems::instances::create::verify_mysql_root_auth(
                state,
                &metadata.instance_id,
                maintenance,
            )
            .await;
        }
        MaintenanceAuthCheck::PostgresScram => {
            return match databases::postgres::hardening::verify_admin_password(
                &state.docker,
                &metadata.instance_id,
                maintenance,
            )
            .await
            {
                Ok(()) => Ok(()),
                Err(DockerError::PostgresAuthHardeningFailed { .. }) => Err(ApiError::Conflict(
                    "the PostgreSQL maintenance credential does not match the database SCRAM secret"
                        .to_string(),
                )),
                Err(error) => Err(ApiError::Runtime(format!(
                    "PostgreSQL maintenance credential verification failed: {error}"
                ))),
            };
        }
        MaintenanceAuthCheck::Probe(command) => command,
        MaintenanceAuthCheck::Unsupported => {
            return Err(ApiError::Runtime(format!(
                "{} does not support live password rotation",
                metadata.protocol
            )));
        }
    };
    let deadline = Instant::now() + ROTATION_READINESS_TIMEOUT;
    let mut last_error = None;
    while Instant::now() < deadline {
        match probe_admin_auth(state, metadata, command, maintenance).await {
            Ok(()) => {
                return confirm_password_enforcement(state, metadata, command, maintenance).await;
            }
            Err(error) => {
                last_error = Some(error.to_string());
                sleep(ADMIN_AUTH_RETRY_INTERVAL).await;
            }
        }
    }
    let last_error = last_error
        .as_deref()
        .unwrap_or("no readiness attempt completed");
    Err(ApiError::Runtime(format!(
        "database administrator connection did not become ready for password rotation: {last_error}"
    )))
}

async fn confirm_password_enforcement(
    state: &AppState,
    metadata: &InstanceMetadata,
    command: &str,
    maintenance: &SecretString,
) -> Result<(), ApiError> {
    let invalid_password =
        SecretString::from(format!("dbe-invalid-{}", uuid::Uuid::new_v4().simple()));
    match probe_admin_auth(state, metadata, command, &invalid_password).await {
        Err(error) if is_password_rejection(metadata.protocol, &error) => {}
        Err(error) => {
            return Err(ApiError::Runtime(format!(
                "incorrect-password enforcement verification failed ambiguously: {error}"
            )));
        }
        Ok(()) => {
            return Err(ApiError::Conflict(format!(
                "{} maintenance authentication accepted an incorrect password; refusing to adopt or rotate credentials while password enforcement is bypassed",
                metadata.protocol
            )));
        }
    }
    probe_admin_auth(state, metadata, command, maintenance)
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "maintenance authentication became unavailable after password-enforcement verification: {error}"
            ))
        })
}

async fn probe_admin_auth(
    state: &AppState,
    metadata: &InstanceMetadata,
    command: &str,
    admin_password: &SecretString,
) -> Result<(), DockerError> {
    state
        .docker
        .exec_secret_readiness_probe(
            metadata.protocol,
            &metadata.instance_id,
            command,
            &[("DBE_ROTATION_ADMIN_PASSWORD", admin_password)],
            ADMIN_AUTH_PROBE_TIMEOUT,
        )
        .await
        .map(|_| ())
}

pub(super) fn is_password_rejection(protocol: Protocol, error: &DockerError) -> bool {
    let DockerError::ExecFailed { failure_output, .. } = error else {
        return false;
    };
    protocol
        .engine()
        .is_password_rejection(&failure_output.to_ascii_lowercase())
}

pub(super) fn protected_value_matches(expected: &str, actual: &str) -> bool {
    bool::from(expected.as_bytes().ct_eq(actual.as_bytes()))
}
