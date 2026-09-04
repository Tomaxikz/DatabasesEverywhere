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
    api::{
        http::{response::ApiError, router::AppState},
        instances::docker_error,
    },
    databases,
    instances::metadata::InstanceMetadata,
    runtime::docker::{DockerError, ExecRecovery},
    shared::{protocol::Protocol, shell::sh_quote},
};

pub(super) async fn reset_password_in_place(
    context: &InPlaceResetContext<'_>,
    new_verifier: Option<&str>,
    credential_changed: Arc<AtomicBool>,
) -> Result<(), ApiError> {
    if matches!(
        context.metadata.protocol,
        Protocol::Redis | Protocol::Valkey
    ) {
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
    let command = match metadata.protocol {
        Protocol::Redis => {
            "redis-cli -s /run/dbev/redis.sock --user \"$DBE_TENANT_USER\" -a \"$DBE_CURRENT_PASSWORD\" --no-auth-warning ACL LOAD >/dev/null"
        }
        Protocol::Valkey => {
            "valkey-cli -s /run/dbev/valkey.sock --user \"$DBE_TENANT_USER\" -a \"$DBE_CURRENT_PASSWORD\" --no-auth-warning ACL LOAD >/dev/null"
        }
        _ => {
            return Err(ApiError::Runtime(
                "ACL activation requested for a non-RESP database".to_string(),
            ));
        }
    };
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
    let script = match metadata.protocol {
        Protocol::Postgres if target_password.is_some() => {
            postgres_rotation_script(&metadata.database.username, &metadata.database.name)
        }
        Protocol::Postgres => verifier_restore_script(metadata),
        Protocol::Mariadb => mysql_family_rotation_script(
            metadata.protocol,
            &metadata.database.name,
            &metadata.database.username,
            native_password_verifier.ok_or_else(|| {
                ApiError::Runtime("mariadb replacement verifier is missing".to_string())
            })?,
        )?,
        Protocol::Mysql if target_password.is_some() => {
            mysql_rotation_script(&metadata.database.username)?
        }
        Protocol::Mysql => mysql_auth_restore_script(
            &metadata.database.username,
            previous.mysql_auth_plugin.as_deref().ok_or_else(|| {
                ApiError::Runtime(
                    "the previous MySQL authentication plugin was not captured".to_string(),
                )
            })?,
        )?,
        Protocol::Mongodb => {
            if target_password.is_none() {
                return Err(ApiError::Runtime(
                    "the previous MongoDB tenant credential is unavailable for rollback"
                        .to_string(),
                ));
            }
            mongodb_rotation_script(metadata)?
        }
        Protocol::Redis | Protocol::Valkey | Protocol::Clickhouse | Protocol::Qdrant => {
            return Err(ApiError::Runtime(format!(
                "{} credentials are managed through recreated startup configuration, not live SQL",
                metadata.protocol
            )));
        }
    };
    let mysql_password_b64 = if metadata.protocol == Protocol::Mysql {
        target_password.map(|password| {
            SecretString::from(
                base64::engine::general_purpose::STANDARD
                    .encode(password.expose_secret().as_bytes()),
            )
        })
    } else {
        None
    };
    let postgres_admin_password = if metadata.protocol == Protocol::Postgres {
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
            &script,
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
    protocol == Protocol::Postgres && target_password.is_some()
}

pub(super) async fn verify_tenant_credential(
    state: &AppState,
    metadata: &InstanceMetadata,
    new_password: &SecretString,
) -> Result<(), ApiError> {
    let script = match metadata.protocol {
        Protocol::Postgres => format!(
            "PGPASSWORD=\"$DBE_ROTATED_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -Atqc 'SELECT 1' >/dev/null",
            sh_quote(&metadata.database.username),
            sh_quote(&metadata.database.name),
        ),
        Protocol::Redis => format!(
            "test \"$(redis-cli -s /run/dbev/redis.sock --user {} -a \"$DBE_ROTATED_PASSWORD\" --no-auth-warning --raw ping)\" = PONG",
            sh_quote(&metadata.database.username),
        ),
        Protocol::Valkey => format!(
            "test \"$(valkey-cli -s /run/dbev/valkey.sock --user {} -a \"$DBE_ROTATED_PASSWORD\" --no-auth-warning --raw ping)\" = PONG",
            sh_quote(&metadata.database.username),
        ),
        Protocol::Mariadb => format!(
            "MYSQL_PWD=\"$DBE_ROTATED_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u {} {} -N -B -e 'SELECT 1' >/dev/null",
            sh_quote(&metadata.database.username),
            sh_quote(&metadata.database.name),
        ),
        Protocol::Mysql => format!(
            "MYSQL_PWD=\"$DBE_ROTATED_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u {} {} -e 'SELECT 1' >/dev/null",
            sh_quote(&metadata.database.username),
            sh_quote(&metadata.database.name),
        ),
        Protocol::Mongodb => format!(
            "mongosh --quiet --host 127.0.0.1 --username {} --password \"$DBE_ROTATED_PASSWORD\" --authenticationDatabase {} {} --eval 'db.runCommand({{ ping: 1 }}).ok' >/dev/null",
            sh_quote(&metadata.database.username),
            sh_quote(&metadata.database.name),
            sh_quote(&metadata.database.name),
        ),
        Protocol::Clickhouse => format!(
            "clickhouse-client --host 127.0.0.1 --user {} --password \"$DBE_ROTATED_PASSWORD\" --database {} --query 'SELECT 1' >/dev/null",
            sh_quote(&metadata.database.username),
            sh_quote(&metadata.database.name),
        ),
        // Qdrant reads the new API key from its immutable container
        // configuration. Its startup readiness probe confirms the authenticated
        // gRPC listener is accepting connections before metadata is committed.
        Protocol::Qdrant => return Ok(()),
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
    match protocol {
        Protocol::Redis | Protocol::Valkey => {
            databases::resp::write_acl_file(data_path, username, password)
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))
        }
        _ => Err(ApiError::Runtime(
            "ACL rotation requested for a non-RESP database".to_string(),
        )),
    }
}

pub(super) async fn restore_resp_acl(
    protocol: Protocol,
    data_path: &std::path::Path,
    acl: &[u8],
) -> Result<(), ApiError> {
    match protocol {
        Protocol::Redis | Protocol::Valkey => databases::resp::restore_acl_file(data_path, acl)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string())),
        _ => Err(ApiError::Runtime(
            "ACL rollback requested for a non-RESP database".to_string(),
        )),
    }
}

pub(super) async fn capture_maintenance_credential(
    state: &AppState,
    metadata: &InstanceMetadata,
    previous: &mut PreviousCredential,
) -> Result<(), ApiError> {
    if metadata.protocol == Protocol::Postgres {
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
        return Ok(());
    }

    let (keys, persisted, username): (&[&str], Option<&str>, Option<&str>) = match metadata.protocol
    {
        Protocol::Mariadb => (
            &["DBE_MARIADB_ROOT_PASSWORD", "MARIADB_ROOT_PASSWORD"],
            metadata.mariadb_root_password.as_deref(),
            Some("root"),
        ),
        Protocol::Mysql => (
            &["MYSQL_ROOT_PASSWORD"],
            metadata.mysql_root_password.as_deref(),
            Some("root"),
        ),
        Protocol::Mongodb => (
            &["DBE_MONGO_ROOT_PASSWORD"],
            metadata.mongodb_root_password.as_deref(),
            Some("dbe_root"),
        ),
        Protocol::Redis | Protocol::Valkey | Protocol::Clickhouse | Protocol::Qdrant => {
            return Ok(());
        }
        Protocol::Postgres => {
            return Err(ApiError::Runtime(
                "PostgreSQL maintenance credential dispatch was inconsistent".to_string(),
            ));
        }
    };
    previous.maintenance = persisted
        .filter(|value| !value.is_empty())
        .map(|value| SecretString::from(value.to_string()));
    if previous.maintenance.is_none() {
        for key in keys {
            let candidate = state
                .docker
                .container_environment_value(metadata.protocol, &metadata.instance_id, key)
                .await
                .map_err(docker_error)?
                .filter(|value| !value.expose_secret().is_empty());
            if candidate.is_some() {
                previous.maintenance = candidate;
                break;
            }
        }
    }
    if previous.maintenance.is_none() {
        return Err(ApiError::Conflict(format!(
            "the current {} maintenance credential is unavailable; password rotation cannot be authenticated safely",
            metadata.protocol
        )));
    }
    previous.maintenance_username = username.map(str::to_string);
    Ok(())
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
        || verifier.len() > 4_096
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
    if decoded.is_empty() || decoded.len() > 4_096 {
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
    if metadata.protocol == Protocol::Mysql {
        return crate::api::instances::create::verify_mysql_root_auth(
            state,
            &metadata.instance_id,
            maintenance,
        )
        .await;
    }
    if metadata.protocol == Protocol::Postgres {
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
    let command = match metadata.protocol {
        Protocol::Postgres => {
            return Err(ApiError::Runtime(
                "PostgreSQL maintenance authentication dispatch was inconsistent".to_string(),
            ));
        }
        Protocol::Mariadb => "MYSQL_PWD=\"$DBE_ROTATION_ADMIN_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -u root -N -B -e 'SELECT 1' >/dev/null".to_string(),
        Protocol::Mysql => {
            return Err(ApiError::Runtime(
                "MySQL maintenance authentication dispatch was inconsistent".to_string(),
            ));
        }
        Protocol::Mongodb => "mongosh --quiet --host 127.0.0.1 --username dbe_root --password \"$DBE_ROTATION_ADMIN_PASSWORD\" --authenticationDatabase admin admin --eval 'db.adminCommand({ ping: 1 }).ok' >/dev/null".to_string(),
        Protocol::Redis | Protocol::Valkey | Protocol::Clickhouse | Protocol::Qdrant => {
            return Err(ApiError::Runtime(format!(
                "{} does not support live password rotation",
                metadata.protocol
            )));
        }
    };
    let deadline = Instant::now() + ROTATION_READINESS_TIMEOUT;
    let mut last_error = None;
    let environment = [("DBE_ROTATION_ADMIN_PASSWORD", maintenance)];
    while Instant::now() < deadline {
        match state
            .docker
            .exec_secret_readiness_probe(
                metadata.protocol,
                &metadata.instance_id,
                &command,
                &environment,
                Duration::from_secs(5),
            )
            .await
        {
            Ok(_) => {
                let invalid_password =
                    SecretString::from(format!("dbe-invalid-{}", uuid::Uuid::new_v4().simple()));
                match state
                    .docker
                    .exec_secret_readiness_probe(
                        metadata.protocol,
                        &metadata.instance_id,
                        &command,
                        &[("DBE_ROTATION_ADMIN_PASSWORD", &invalid_password)],
                        Duration::from_secs(5),
                    )
                    .await
                {
                    Err(error) if is_password_rejection(metadata.protocol, &error) => {}
                    Err(error) => {
                        return Err(ApiError::Runtime(format!(
                            "incorrect-password enforcement verification failed ambiguously: {error}"
                        )));
                    }
                    Ok(_) => {
                        return Err(ApiError::Conflict(format!(
                            "{} maintenance authentication accepted an incorrect password; refusing to adopt or rotate credentials while password enforcement is bypassed",
                            metadata.protocol
                        )));
                    }
                }
                return match state
                    .docker
                    .exec_secret_readiness_probe(
                        metadata.protocol,
                        &metadata.instance_id,
                        &command,
                        &environment,
                        Duration::from_secs(5),
                    )
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(error) => Err(ApiError::Runtime(format!(
                        "maintenance authentication became unavailable after password-enforcement verification: {error}"
                    ))),
                };
            }
            Err(error) => {
                last_error = Some(error.to_string());
                sleep(Duration::from_secs(1)).await;
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

pub(super) fn is_password_rejection(protocol: Protocol, error: &DockerError) -> bool {
    let DockerError::ExecFailed { failure_output, .. } = error else {
        return false;
    };
    let output = failure_output.to_ascii_lowercase();
    match protocol {
        Protocol::Postgres => output.contains("password authentication failed"),
        Protocol::Mariadb => {
            output.contains("access denied for user") && output.contains("using password: yes")
        }
        Protocol::Mongodb => {
            output.contains("authentication failed") || output.contains("code: 18")
        }
        Protocol::Mysql
        | Protocol::Redis
        | Protocol::Valkey
        | Protocol::Clickhouse
        | Protocol::Qdrant => false,
    }
}

pub(super) fn protected_value_matches(expected: &str, actual: &str) -> bool {
    bool::from(expected.as_bytes().ct_eq(actual.as_bytes()))
}

pub(super) fn postgres_rotation_script(username: &str, database: &str) -> String {
    let sql = databases::postgres::provision::reset_tenant_password_sql(username);
    format!(
        "set -eu\n{{ printf '%s\\n' '\\getenv tenant_password DBE_ROTATED_PASSWORD'; printf '%s\\n' {}; }} | PGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -v ON_ERROR_STOP=1\n",
        sh_quote(&sql),
        sh_quote(databases::postgres::docker::INTERNAL_ADMIN_USERNAME),
        sh_quote(database),
    )
}

fn verifier_restore_script(metadata: &InstanceMetadata) -> String {
    let sql = databases::postgres::provision::restore_verifier_sql(&metadata.database.username);
    format!(
        "set -eu\n{{ printf '%s\\n' '\\getenv tenant_password_verifier DBE_PREVIOUS_PASSWORD_VERIFIER'; printf '%s\\n' {}; }} | PGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -v ON_ERROR_STOP=1\n",
        sh_quote(&sql),
        sh_quote(databases::postgres::docker::INTERNAL_ADMIN_USERNAME),
        sh_quote(&metadata.database.name),
    )
}

fn mysql_family_rotation_script(
    protocol: Protocol,
    database: &str,
    username: &str,
    verifier: &str,
) -> Result<String, ApiError> {
    let sql = match protocol {
        Protocol::Mariadb => {
            databases::mariadb::provision::tenant_user_sql(database, username, verifier)
                .map_err(|error| ApiError::Runtime(error.to_string()))?
        }
        _ => {
            return Err(ApiError::Runtime(
                "invalid mysql-family password rotation protocol".to_string(),
            ));
        }
    };
    Ok(format!(
        "set -eu\nprintf %s {} | MYSQL_PWD=\"$DBE_ROTATION_ADMIN_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -u root\n",
        sh_quote(&sql)
    ))
}

pub(super) fn mysql_rotation_script(username: &str) -> Result<String, ApiError> {
    let sql = databases::mysql::provision::reset_tenant_password_sql(username);
    let (before_password, after_password) =
        databases::mysql::provision::password_sql_fragments(&sql)
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(format!(
        "set -eu\n{{ printf %s {}; printf %s \"$DBE_ROTATED_PASSWORD_B64\"; printf %s {}; }} | MYSQL_PWD=\"$DBE_ROTATION_ADMIN_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -uroot\n",
        sh_quote(before_password),
        sh_quote(after_password),
    ))
}

pub(super) fn mysql_auth_restore_script(username: &str, plugin: &str) -> Result<String, ApiError> {
    let sql = databases::mysql::provision::restore_tenant_auth_sql(username, plugin)
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let (before_auth, after_auth) = databases::mysql::provision::auth_string_sql_fragments(&sql)
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(format!(
        "set -eu\n{{ printf %s {}; printf %s \"$DBE_PREVIOUS_MYSQL_AUTH_B64\"; printf %s {}; }} | MYSQL_PWD=\"$DBE_ROTATION_ADMIN_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -uroot\n",
        sh_quote(before_auth),
        sh_quote(after_auth),
    ))
}

fn mongodb_rotation_script(metadata: &InstanceMetadata) -> Result<String, ApiError> {
    let javascript = databases::mongodb::provision::password_update_script(
        &metadata.database.name,
        &metadata.database.username,
    )
    .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(format!(
        "set -eu\nmongosh --quiet --host 127.0.0.1 --username dbe_root --password \"$DBE_ROTATION_ADMIN_PASSWORD\" --authenticationDatabase admin admin --eval {}\n",
        sh_quote(&javascript)
    ))
}
