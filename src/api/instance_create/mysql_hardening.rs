use std::time::Duration;

use base64::Engine as _;
use futures::StreamExt;
use secrecy::{ExposeSecret, SecretString};
use tokio::time::{Instant, sleep};

use super::fail_runtime;
use crate::{
    api::{api_response::ApiError, routes::AppState},
    constants::MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
    databases,
    instances::metadata::{InstanceMetadata, InstanceStatus},
    runtime::docker::DockerError,
    shared::{protocol::Protocol, shell::sh_quote},
};

const MYSQL_AUTH_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const MYSQL_AUTH_READINESS_TIMEOUT: Duration = Duration::from_secs(120);
const MYSQL_AUTH_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn execute_mysql_protected_sql(
    state: &AppState,
    instance_id: &str,
    sql: &str,
    password: &str,
    root_password: &str,
) -> Result<(), ApiError> {
    let (before_password, after_password) =
        databases::mysql::provision::password_sql_fragments(sql)
            .map_err(|error| fail_runtime(state, instance_id, error))?;
    let script = format!(
        "set -eu\n{{ printf %s {}; printf %s \"$DBE_PASSWORD_B64\"; printf %s {}; }} | MYSQL_PWD=\"$DBE_MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -uroot\n",
        sh_quote(before_password),
        sh_quote(after_password),
    );
    let password_b64 =
        SecretString::from(base64::engine::general_purpose::STANDARD.encode(password.as_bytes()));
    let root_password = SecretString::from(root_password.to_string());
    state
        .docker
        .exec_shell_with_secret_env(
            Protocol::Mysql,
            instance_id,
            &script,
            &[
                ("DBE_PASSWORD_B64", &password_b64),
                ("DBE_MYSQL_ROOT_PASSWORD", &root_password),
            ],
        )
        .await
        .map_err(|error| fail_runtime(state, instance_id, error))?;
    Ok(())
}

pub(crate) async fn harden_mysql_tenant_auth(
    state: &AppState,
    instance_id: &str,
    username: &str,
    password: &str,
    root_password: &str,
) -> Result<(), ApiError> {
    let metadata = state.instances.get(instance_id).await.filter(|metadata| {
        metadata.protocol == Protocol::Mysql
            && metadata.database.username == username
            && metadata.tenant_password.as_deref() == Some(password)
            && metadata.mysql_root_password.as_deref() == Some(root_password)
    });
    if let Some(metadata) = metadata.as_ref() {
        match crate::instances::auth_hardening::attestation_is_current(
            &state.manager,
            &state.docker,
            metadata,
        )
        .await
        {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                event = "audit auth_hardening_attestation_check_failed",
                instance_id,
                protocol = %Protocol::Mysql,
                %error,
                "could not validate the cached hardening attestation; running full MySQL hardening"
            ),
        }
    }
    let root_password = SecretString::from(root_password.to_string());
    verify_mysql_root_auth_with_timeout(
        state,
        instance_id,
        &root_password,
        MYSQL_AUTH_READINESS_TIMEOUT,
    )
    .await?;
    apply_mysql_tenant_auth(
        state,
        instance_id,
        username,
        password,
        root_password.expose_secret(),
    )
    .await?;
    if let Some(metadata) = metadata.as_ref()
        && let Err(error) = crate::instances::auth_hardening::record_attestation(
            &state.manager,
            &state.docker,
            metadata,
        )
        .await
    {
        tracing::warn!(
            event = "audit auth_hardening_attestation_write_failed",
            instance_id,
            protocol = %Protocol::Mysql,
            %error,
            "MySQL hardening succeeded, but its optimization attestation could not be persisted"
        );
    }
    Ok(())
}

async fn apply_mysql_tenant_auth(
    state: &AppState,
    instance_id: &str,
    username: &str,
    password: &str,
    root_password: &str,
) -> Result<(), ApiError> {
    let sql = databases::mysql::provision::reset_tenant_password_sql(username);
    execute_mysql_protected_sql(state, instance_id, &sql, password, root_password).await?;
    verify_mysql_tenant_auth(state, instance_id, username, password).await
}

pub(crate) async fn verify_mysql_root_auth(
    state: &AppState,
    instance_id: &str,
    root_password: &SecretString,
) -> Result<(), ApiError> {
    verify_mysql_root_auth_with_timeout(
        state,
        instance_id,
        root_password,
        MYSQL_AUTH_RECOVERY_TIMEOUT,
    )
    .await
}

pub(super) async fn verify_mysql_root_auth_with_timeout(
    state: &AppState,
    instance_id: &str,
    root_password: &SecretString,
    readiness_timeout: Duration,
) -> Result<(), ApiError> {
    let invalid_password =
        SecretString::from(format!("dbev-invalid-{}", uuid::Uuid::new_v4().simple()));
    let command = "set -eu\ntest \"$(cat /proc/1/comm)\" = mysqld\nMYSQL_PWD=\"$DBE_MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -uroot -N -B -e 'SELECT 1' >/dev/null\n";
    let deadline = Instant::now() + readiness_timeout;
    loop {
        let Some(attempt_timeout) = mysql_auth_attempt_timeout(deadline) else {
            return Err(mysql_auth_readiness_error(state, instance_id, None));
        };
        let first_candidate = state
            .docker
            .exec_readiness_probe_with_secret_env_timeout(
                Protocol::Mysql,
                instance_id,
                command,
                &[("DBE_MYSQL_ROOT_PASSWORD", root_password)],
                attempt_timeout,
            )
            .await;
        if let Err(error) = first_candidate {
            match classify_mysql_candidate_auth_failure(&error) {
                MysqlCandidateAuthFailure::CredentialRejected => {
                    return Err(ApiError::Conflict(
                        "the MySQL maintenance credential was rejected; refusing to retry a known-invalid credential"
                            .to_string(),
                    ));
                }
                MysqlCandidateAuthFailure::Retryable if Instant::now() >= deadline => {
                    return Err(fail_runtime(
                        state,
                        instance_id,
                        format!("MySQL maintenance authentication did not become ready: {error}"),
                    ));
                }
                MysqlCandidateAuthFailure::Retryable => {
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
            }
        }
        let Some(attempt_timeout) = mysql_auth_attempt_timeout(deadline) else {
            return Err(mysql_auth_readiness_error(state, instance_id, None));
        };
        let invalid_result = state
            .docker
            .exec_readiness_probe_with_secret_env_timeout(
                Protocol::Mysql,
                instance_id,
                command,
                &[("DBE_MYSQL_ROOT_PASSWORD", &invalid_password)],
                attempt_timeout,
            )
            .await;
        match invalid_result {
            Ok(_) => {
                return Err(ApiError::Conflict(
                    "MySQL root socket authentication accepted a deliberately invalid password; refusing to adopt an unverifiable maintenance credential"
                        .to_string(),
                ));
            }
            Err(error) if is_definite_mysql_auth_rejection(&error) => {}
            Err(_) if Instant::now() >= deadline => {
                return Err(mysql_auth_readiness_error(state, instance_id, None));
            }
            Err(_) => {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        }
        let Some(attempt_timeout) = mysql_auth_attempt_timeout(deadline) else {
            return Err(mysql_auth_readiness_error(state, instance_id, None));
        };
        match state
            .docker
            .exec_readiness_probe_with_secret_env_timeout(
                Protocol::Mysql,
                instance_id,
                command,
                &[("DBE_MYSQL_ROOT_PASSWORD", root_password)],
                attempt_timeout,
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) if Instant::now() >= deadline => {
                return Err(mysql_auth_readiness_error(
                    state,
                    instance_id,
                    Some(error.to_string()),
                ));
            }
            Err(_) => {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        }
    }
}

fn is_definite_mysql_auth_rejection(error: &DockerError) -> bool {
    let DockerError::ExecFailed { failure_output, .. } = error else {
        return false;
    };
    let output = failure_output.to_ascii_uppercase();
    output.contains("ERROR 1045")
        && (output.contains("(28000)") || output.contains("SQLSTATE[28000]"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MysqlCandidateAuthFailure {
    CredentialRejected,
    Retryable,
}

fn classify_mysql_candidate_auth_failure(error: &DockerError) -> MysqlCandidateAuthFailure {
    if is_definite_mysql_auth_rejection(error) {
        MysqlCandidateAuthFailure::CredentialRejected
    } else {
        MysqlCandidateAuthFailure::Retryable
    }
}

fn mysql_auth_attempt_timeout(deadline: Instant) -> Option<Duration> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    (!remaining.is_zero()).then_some(remaining.min(MYSQL_AUTH_ATTEMPT_TIMEOUT))
}

fn mysql_auth_readiness_error(
    state: &AppState,
    instance_id: &str,
    detail: Option<String>,
) -> ApiError {
    let detail = detail.unwrap_or_else(|| "the verification deadline expired".to_string());
    fail_runtime(
        state,
        instance_id,
        format!("MySQL maintenance authentication did not become ready: {detail}"),
    )
}

async fn verify_mysql_tenant_auth(
    state: &AppState,
    instance_id: &str,
    username: &str,
    password: &str,
) -> Result<(), ApiError> {
    let username = SecretString::from(username.to_string());
    let password = SecretString::from(password.to_string());
    state
        .docker
        .exec_readiness_probe_with_secret_env_timeout(
            Protocol::Mysql,
            instance_id,
            "set -eu\nMYSQL_PWD=\"$DBE_MYSQL_TENANT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u\"$DBE_MYSQL_TENANT_USER\" \"$MYSQL_DATABASE\" -N -B -e 'SELECT 1' >/dev/null\n",
            &[
                ("DBE_MYSQL_TENANT_USER", &username),
                ("DBE_MYSQL_TENANT_PASSWORD", &password),
            ],
            MYSQL_AUTH_ATTEMPT_TIMEOUT,
        )
        .await
        .map_err(|error| fail_runtime(state, instance_id, error))?;
    Ok(())
}

async fn verify_mysql_tenant_auth_for_adoption(
    state: &AppState,
    instance_id: &str,
    username: &str,
    password: &SecretString,
) -> Result<bool, ApiError> {
    let username = SecretString::from(username.to_string());
    let invalid_password =
        SecretString::from(format!("dbev-invalid-{}", uuid::Uuid::new_v4().simple()));
    let command = "set -eu\nMYSQL_PWD=\"$DBE_MYSQL_TENANT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u\"$DBE_MYSQL_TENANT_USER\" \"$MYSQL_DATABASE\" -N -B -e 'SELECT 1' >/dev/null\n";
    let environment = mysql_tenant_probe_environment(&username, password);
    if state
        .docker
        .exec_readiness_probe_with_secret_env_timeout(
            Protocol::Mysql,
            instance_id,
            command,
            &environment,
            MYSQL_AUTH_ATTEMPT_TIMEOUT,
        )
        .await
        .is_err()
    {
        return Ok(false);
    }
    let invalid_environment = mysql_tenant_probe_environment(&username, &invalid_password);
    match state
        .docker
        .exec_readiness_probe_with_secret_env_timeout(
            Protocol::Mysql,
            instance_id,
            command,
            &invalid_environment,
            MYSQL_AUTH_ATTEMPT_TIMEOUT,
        )
        .await
    {
        Err(error) if is_definite_mysql_auth_rejection(&error) => {}
        Ok(_) => {
            return Err(ApiError::Conflict(
                "MySQL tenant authentication accepted a deliberately invalid password; refusing to adopt an unverifiable legacy credential"
                    .to_string(),
            ));
        }
        Err(error) => return Err(fail_runtime(state, instance_id, error)),
    }
    let environment = mysql_tenant_probe_environment(&username, password);
    Ok(state
        .docker
        .exec_readiness_probe_with_secret_env_timeout(
            Protocol::Mysql,
            instance_id,
            command,
            &environment,
            MYSQL_AUTH_ATTEMPT_TIMEOUT,
        )
        .await
        .is_ok())
}

fn mysql_tenant_probe_environment<'a>(
    username: &'a SecretString,
    password: &'a SecretString,
) -> [(&'static str, &'a SecretString); 2] {
    [
        ("DBE_MYSQL_TENANT_USER", username),
        ("DBE_MYSQL_TENANT_PASSWORD", password),
    ]
}

#[derive(Debug, Clone)]
pub(crate) struct MysqlAuthHardeningFailure {
    pub instance_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MysqlAuthHardeningSummary {
    pub checked: usize,
    pub root_credentials_migrated: usize,
    pub verifiers_repaired: usize,
    pub attestations_reused: usize,
    pub failures: Vec<MysqlAuthHardeningFailure>,
}

pub(crate) async fn harden_mysql_accounts_on_boot(state: &AppState) -> MysqlAuthHardeningSummary {
    let instances = state.manager.store().list().await;
    let outcomes = futures::stream::iter(
        instances
            .into_iter()
            .filter(|metadata| metadata.protocol == Protocol::Mysql),
    )
    .map(|snapshot| harden_mysql_account_on_boot(state, snapshot))
    .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;
    aggregate_mysql_auth_hardening_summaries(outcomes)
}

async fn harden_mysql_account_on_boot(
    state: &AppState,
    snapshot: InstanceMetadata,
) -> MysqlAuthHardeningSummary {
    let mut summary = MysqlAuthHardeningSummary::default();
    let _operation = state.instance_locks.lock(&snapshot.instance_id).await;
    let Some(metadata) = state.manager.store().get(&snapshot.instance_id).await else {
        return summary;
    };
    if metadata.protocol != Protocol::Mysql || metadata.status != InstanceStatus::Running {
        return summary;
    }
    match crate::instances::auth_hardening::attestation_is_current(
        &state.manager,
        &state.docker,
        &metadata,
    )
    .await
    {
        Ok(true) => {
            summary.attestations_reused = 1;
            return summary;
        }
        Ok(false) => {}
        Err(error) => tracing::warn!(
            event = "audit auth_hardening_attestation_check_failed",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "could not validate the cached hardening attestation; running full MySQL hardening"
        ),
    }
    summary.checked = 1;
    let mut metadata = metadata;
    let container_root_password = state
        .docker
        .container_environment_value(
            Protocol::Mysql,
            &metadata.instance_id,
            "MYSQL_ROOT_PASSWORD",
        )
        .await
        .ok()
        .flatten()
        .filter(|password| !password.expose_secret().is_empty());
    let persisted_root_password = metadata
        .mysql_root_password
        .as_deref()
        .filter(|password| !password.is_empty())
        .map(|password| SecretString::from(password.to_string()));
    let mut migrate_root_password = false;
    let root_password = if let Some(persisted) = persisted_root_password {
        if verify_mysql_root_auth_with_timeout(
            state,
            &metadata.instance_id,
            &persisted,
            MYSQL_AUTH_READINESS_TIMEOUT,
        )
        .await
        .is_ok()
        {
            persisted
        } else if let Some(container) = container_root_password {
            if container.expose_secret() != persisted.expose_secret()
                && verify_mysql_root_auth_with_timeout(
                    state,
                    &metadata.instance_id,
                    &container,
                    MYSQL_AUTH_READINESS_TIMEOUT,
                )
                .await
                .is_ok()
            {
                migrate_root_password = true;
                container
            } else {
                record_mysql_auth_failure(
                    state,
                    &metadata,
                    "neither the encrypted nor legacy MySQL maintenance credential matches the live database"
                        .to_string(),
                    &mut summary,
                )
                .await;
                return summary;
            }
        } else {
            record_mysql_auth_failure(
                state,
                &metadata,
                "the encrypted MySQL maintenance credential was rejected and no legacy container credential is available"
                    .to_string(),
                &mut summary,
            )
            .await;
            return summary;
        }
    } else if let Some(container) = container_root_password {
        if verify_mysql_root_auth_with_timeout(
            state,
            &metadata.instance_id,
            &container,
            MYSQL_AUTH_READINESS_TIMEOUT,
        )
        .await
        .is_ok()
        {
            migrate_root_password = true;
            container
        } else {
            record_mysql_auth_failure(
                state,
                &metadata,
                "the legacy MySQL maintenance credential could not be verified safely; reset or recreate this instance"
                    .to_string(),
                &mut summary,
            )
            .await;
            return summary;
        }
    } else {
        record_mysql_auth_failure(
            state,
            &metadata,
            "the encrypted MySQL maintenance credential is missing and the managed container does not expose a recoverable root credential; reset or recreate this legacy instance"
                .to_string(),
            &mut summary,
        )
        .await;
        return summary;
    };
    let mut migrate_tenant_password = false;
    let password = match metadata.tenant_password.as_deref() {
        Some(password) if !password.is_empty() => password.to_string(),
        _ => {
            let candidate = match state
                .docker
                .mysql_legacy_tenant_credentials(&metadata.instance_id)
                .await
            {
                Ok(Some((username, password))) if username == metadata.database.username => {
                    password
                }
                Ok(Some(_)) => {
                    record_mysql_auth_failure(
                        state,
                        &metadata,
                        "the legacy MySQL tenant username does not match protected instance metadata; refusing to adopt it"
                            .to_string(),
                        &mut summary,
                    )
                    .await;
                    return summary;
                }
                Ok(None) | Err(_) => {
                    record_mysql_auth_failure(
                        state,
                        &metadata,
                        "the encrypted MySQL tenant credential is missing and no unambiguous legacy container credential is available; reset this legacy instance before opening its gateway"
                            .to_string(),
                        &mut summary,
                    )
                    .await;
                    return summary;
                }
            };
            match verify_mysql_tenant_auth_for_adoption(
                state,
                &metadata.instance_id,
                &metadata.database.username,
                &candidate,
            )
            .await
            {
                Ok(true) => {
                    migrate_tenant_password = true;
                    candidate.expose_secret().to_string()
                }
                _ => {
                    record_mysql_auth_failure(
                        state,
                        &metadata,
                        "the legacy MySQL tenant credential could not be verified against the live database; reset this legacy instance before opening its gateway"
                            .to_string(),
                        &mut summary,
                    )
                    .await;
                    return summary;
                }
            }
        }
    };
    if apply_mysql_tenant_auth(
        state,
        &metadata.instance_id,
        &metadata.database.username,
        &password,
        root_password.expose_secret(),
    )
    .await
    .is_err()
    {
        record_mysql_auth_failure(
            state,
            &metadata,
            "MySQL tenant authentication hardening or verification failed; reset the instance credential before reopening its route"
                .to_string(),
            &mut summary,
        )
        .await;
        return summary;
    }
    let verifier = crate::protocols::mariadb::native_password_sha1_stage2_hex(&password);
    let verifier_changed =
        metadata.mysql_native_password_sha1_stage2.as_deref() != Some(verifier.as_str());
    if verifier_changed {
        metadata.mysql_native_password_sha1_stage2 = Some(verifier);
    }
    metadata.mysql_root_password = Some(root_password.expose_secret().to_string());
    metadata.tenant_password = Some(password);
    if migrate_root_password || migrate_tenant_password || verifier_changed {
        let persistence = if migrate_root_password || migrate_tenant_password {
            state
                .manager
                .upsert_recovered_protected_secrets(metadata.clone())
                .await
        } else {
            state.manager.upsert(metadata.clone()).await
        };
        if let Err(error) = persistence {
            record_mysql_auth_failure(
                state,
                &metadata,
                format!(
                    "verified MySQL credentials or gateway verifier could not be encrypted and persisted: {error}"
                ),
                &mut summary,
            )
            .await;
            return summary;
        }
        summary.root_credentials_migrated = usize::from(migrate_root_password);
        summary.verifiers_repaired = usize::from(verifier_changed);
        tracing::info!(
            event = "audit mysql_credentials_migrated",
            instance_id = %metadata.instance_id,
            maintenance = migrate_root_password,
            tenant = migrate_tenant_password,
            verifier = verifier_changed,
            "verified and encrypted current MySQL credentials"
        );
    }
    if let Err(error) = crate::instances::auth_hardening::record_attestation(
        &state.manager,
        &state.docker,
        &metadata,
    )
    .await
    {
        tracing::warn!(
            event = "audit auth_hardening_attestation_write_failed",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "MySQL hardening succeeded, but its optimization attestation could not be persisted"
        );
    }
    summary
}

fn aggregate_mysql_auth_hardening_summaries(
    outcomes: Vec<MysqlAuthHardeningSummary>,
) -> MysqlAuthHardeningSummary {
    let mut summary = MysqlAuthHardeningSummary::default();
    for mut outcome in outcomes {
        summary.checked += outcome.checked;
        summary.root_credentials_migrated += outcome.root_credentials_migrated;
        summary.verifiers_repaired += outcome.verifiers_repaired;
        summary.attestations_reused += outcome.attestations_reused;
        summary.failures.append(&mut outcome.failures);
    }
    summary.failures.sort_by(|left, right| {
        left.instance_id
            .cmp(&right.instance_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    summary
}

async fn record_mysql_auth_failure(
    state: &AppState,
    metadata: &InstanceMetadata,
    reason: String,
    summary: &mut MysqlAuthHardeningSummary,
) {
    let failed = mysql_auth_failed_metadata(metadata);
    state.instances.upsert(failed.clone()).await;
    let persistence_error = state.manager.upsert(failed).await.err();
    let reason = match persistence_error {
        Some(error) => format!(
            "{reason}; the route was removed in memory, but the failed state could not be persisted: {error}"
        ),
        None => reason,
    };
    tracing::error!(
        event = "audit mysql_auth_hardening_instance_failed",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        %reason,
        "isolated one MySQL instance after authentication hardening failed; other gateway routes remain eligible"
    );
    summary.failures.push(MysqlAuthHardeningFailure {
        instance_id: metadata.instance_id.clone(),
        reason,
    });
}

pub(super) fn mysql_auth_failed_metadata(metadata: &InstanceMetadata) -> InstanceMetadata {
    let mut failed = metadata.clone();
    failed.status = InstanceStatus::Failed;
    failed.updated_at = crate::shared::time::now_rfc3339();
    failed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_mysql_access_denied_is_an_authentication_rejection() {
        let rejected = DockerError::ExecFailed {
            container: "mysql".to_string(),
            operation: "sh [arguments redacted]".to_string(),
            exit_code: 1,
            failure_output:
                "ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)"
                    .to_string(),
        };
        let socket_failure = DockerError::ExecFailed {
            container: "mysql".to_string(),
            operation: "sh [arguments redacted]".to_string(),
            exit_code: 1,
            failure_output: "ERROR 2002 (HY000): Can't connect to local MySQL server".to_string(),
        };
        let timeout = DockerError::ExecTimedOut {
            container: "mysql".to_string(),
            operation: "sh [arguments redacted]".to_string(),
            timeout_seconds: 5,
        };

        assert!(is_definite_mysql_auth_rejection(&rejected));
        assert!(!is_definite_mysql_auth_rejection(&socket_failure));
        assert!(!is_definite_mysql_auth_rejection(&timeout));
        assert_eq!(
            classify_mysql_candidate_auth_failure(&rejected),
            MysqlCandidateAuthFailure::CredentialRejected
        );
        assert_eq!(
            classify_mysql_candidate_auth_failure(&socket_failure),
            MysqlCandidateAuthFailure::Retryable
        );
        assert_eq!(
            classify_mysql_candidate_auth_failure(&timeout),
            MysqlCandidateAuthFailure::Retryable
        );
    }

    #[test]
    fn concurrent_outcomes_are_aggregated_deterministically() {
        let summary = aggregate_mysql_auth_hardening_summaries(vec![
            MysqlAuthHardeningSummary {
                checked: 1,
                root_credentials_migrated: 0,
                verifiers_repaired: 1,
                attestations_reused: 1,
                failures: vec![MysqlAuthHardeningFailure {
                    instance_id: "mysql-z".to_string(),
                    reason: "z failure".to_string(),
                }],
            },
            MysqlAuthHardeningSummary {
                checked: 2,
                root_credentials_migrated: 1,
                verifiers_repaired: 0,
                attestations_reused: 2,
                failures: vec![MysqlAuthHardeningFailure {
                    instance_id: "mysql-a".to_string(),
                    reason: "a failure".to_string(),
                }],
            },
        ]);

        assert_eq!(summary.checked, 3);
        assert_eq!(summary.root_credentials_migrated, 1);
        assert_eq!(summary.verifiers_repaired, 1);
        assert_eq!(summary.attestations_reused, 3);
        assert_eq!(summary.failures.len(), 2);
        assert_eq!(summary.failures[0].instance_id, "mysql-a");
        assert_eq!(summary.failures[1].instance_id, "mysql-z");
    }
}
