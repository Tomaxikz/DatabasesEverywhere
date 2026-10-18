use std::{num::NonZeroU32, time::Duration};

use aws_lc_rs::{hmac, pbkdf2};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::StreamExt;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    databases::{postgres::online_backup::foreign_replication_role_diagnostic, protocol::Protocol},
    runtime::docker::{CommandOutput, DockerError, DockerRuntime, ExecRecovery},
    server::{
        locks::InstanceLocks,
        manager::InstanceManager,
        metadata::{InstanceMetadata, InstanceStatus},
    },
    utils::constants::MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
    utils::shell::sh_quote,
};

const HARDENING_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct PostgresHardeningFailure {
    pub instance_id: String,
    pub reason: String,
}

/// The instance still serves. Online capture stays off until the named role is renamed or dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresReplicationCaptureBlock {
    pub instance_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct PostgresHardeningSummary {
    pub checked: usize,
    pub hardened: usize,
    pub administrator_credentials_migrated: usize,
    pub attestations_reused: usize,
    pub deferred: usize,
    pub failures: Vec<PostgresHardeningFailure>,
    pub replication_capture_blocked: Vec<PostgresReplicationCaptureBlock>,
}

#[derive(Debug)]
struct AuthHardeningOutcome {
    changed: bool,
    replication_capture_blocked: bool,
}

#[derive(Debug)]
enum HardeningStdout {
    Completed(AuthHardeningOutcome),
    LegacyBootstrapSuperuser,
    MissingTenantRole,
    Unexpected,
}

pub async fn provision_tenant_role(
    docker: &DockerRuntime,
    instance_id: &str,
    database: &str,
    tenant_username: &str,
    tenant_password: &SecretString,
    admin_password: &SecretString,
    recovery: ExecRecovery,
) -> Result<(), DockerError> {
    let role = TenantRole {
        database,
        username: tenant_username,
        password: tenant_password,
    };
    provision_role(docker, instance_id, role, admin_password, recovery, false).await
}

pub async fn provision_shared_tenant_role(
    docker: &DockerRuntime,
    instance_id: &str,
    database: &str,
    tenant_username: &str,
    tenant_password: &SecretString,
    admin_password: &SecretString,
    recovery: ExecRecovery,
) -> Result<(), DockerError> {
    let role = TenantRole {
        database,
        username: tenant_username,
        password: tenant_password,
    };
    provision_role(docker, instance_id, role, admin_password, recovery, true).await
}

/// The tenant role a provisioning step creates or repairs.
struct TenantRole<'a> {
    database: &'a str,
    username: &'a str,
    password: &'a SecretString,
}

async fn provision_role(
    docker: &DockerRuntime,
    instance_id: &str,
    role: TenantRole<'_>,
    admin_password: &SecretString,
    recovery: ExecRecovery,
    shared: bool,
) -> Result<(), DockerError> {
    let TenantRole {
        database,
        username: tenant_username,
        password: tenant_password,
    } = role;
    let role_state = super::provision::tenant_role_state_sql(tenant_username);
    let provision = if shared {
        super::provision::provision_shared_tenant_role_sql(database, tenant_username)
    } else {
        super::provision::provision_tenant_role_sql(database, tenant_username)
    };
    let script = format!(
        "set -eu\ntest \"$(cat /proc/1/comm)\" = postgres || {{ printf 'postgres_final_server_unavailable\\n'; exit 40; }}\nadmin_psql() {{ PGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" \"$@\"; }}\nadmin_psql -Atqc 'SELECT 1' >/dev/null 2>&1 || {{ printf 'admin_auth_unavailable\\n'; exit 41; }}\nrole_state=$(admin_psql -Atq -c {})\ncase \"$role_state\" in\n  10:*) printf 'legacy_bootstrap_superuser\\n'; exit 0 ;;\nesac\n{{ printf '%s\\n' '\\getenv tenant_password DBE_TENANT_PASSWORD'; printf '%s\\n' {}; }} | admin_psql -v ON_ERROR_STOP=1\nprintf 'provisioned\\n'\n",
        sh_quote(&role_state),
        sh_quote(&provision),
    );
    let output = run_hardening_command(
        docker,
        instance_id,
        &script,
        &[
            ("DBE_TENANT_PASSWORD", tenant_password),
            ("DBE_POSTGRES_ADMIN_PASSWORD", admin_password),
        ],
        recovery,
    )
    .await?;
    match output.stdout.lines().last() {
        Some("provisioned") => {}
        Some("legacy_bootstrap_superuser") => {
            return Err(DockerError::LegacyPostgresBootstrapSuperuser {
                instance_id: instance_id.to_string(),
                username: tenant_username.to_string(),
            });
        }
        _ => {
            return Err(DockerError::UnexpectedPostgresProvisioningOutput {
                instance_id: instance_id.to_string(),
            });
        }
    }
    harden_instance_auth(
        docker,
        instance_id,
        database,
        tenant_username,
        tenant_password,
        admin_password,
        recovery,
    )
    .await
    .map(|_| ())
}

fn classify_hardening_stdout(stdout: &str) -> HardeningStdout {
    let replication_capture_blocked = stdout
        .lines()
        .any(|line| line == "replication_capture_blocked");
    match stdout.lines().last() {
        Some("hardened") => HardeningStdout::Completed(AuthHardeningOutcome {
            changed: true,
            replication_capture_blocked,
        }),
        Some("already_hardened") => HardeningStdout::Completed(AuthHardeningOutcome {
            changed: false,
            replication_capture_blocked,
        }),
        Some("legacy_bootstrap_superuser") => HardeningStdout::LegacyBootstrapSuperuser,
        Some("missing_tenant_role") => HardeningStdout::MissingTenantRole,
        _ => HardeningStdout::Unexpected,
    }
}

pub async fn harden_instance_auth(
    docker: &DockerRuntime,
    instance_id: &str,
    tenant_database: &str,
    tenant_username: &str,
    tenant_password: &SecretString,
    admin_password: &SecretString,
    recovery: ExecRecovery,
) -> Result<bool, DockerError> {
    Ok(execute_auth_hardening(
        docker,
        instance_id,
        tenant_database,
        tenant_username,
        tenant_password,
        admin_password,
        recovery,
    )
    .await?
    .changed)
}

async fn execute_auth_hardening(
    docker: &DockerRuntime,
    instance_id: &str,
    tenant_database: &str,
    tenant_username: &str,
    tenant_password: &SecretString,
    admin_password: &SecretString,
    recovery: ExecRecovery,
) -> Result<AuthHardeningOutcome, DockerError> {
    let invalid_password = random_invalid_password();
    let tenant_database_secret = SecretString::from(tenant_database.to_string());
    let tenant_username_secret = SecretString::from(tenant_username.to_string());
    let replication_password =
        match super::online_backup::replication_password(admin_password.expose_secret()) {
            Ok(password) => password,
            Err(reason) => {
                return Err(DockerError::PostgresAuthHardeningFailed {
                    instance_id: instance_id.to_string(),
                    reason: reason.to_string(),
                });
            }
        };
    let script = hardening_script(tenant_username);
    let output = run_hardening_command(
        docker,
        instance_id,
        &script,
        &[
            ("DBE_TENANT_PASSWORD", tenant_password),
            ("DBE_POSTGRES_DATABASE", &tenant_database_secret),
            ("DBE_POSTGRES_USER", &tenant_username_secret),
            ("DBE_POSTGRES_ADMIN_PASSWORD", admin_password),
            ("DBE_INVALID_PASSWORD", &invalid_password),
            ("DBE_REPLICATION_PASSWORD", &replication_password),
        ],
        recovery,
    )
    .await?;
    match classify_hardening_stdout(&output.stdout) {
        HardeningStdout::Completed(outcome) => {
            if outcome.replication_capture_blocked {
                let reason = foreign_replication_role_diagnostic();
                tracing::warn!(
                    event = "audit postgres_replication_capture_blocked",
                    instance_id,
                    role = super::online_backup::REPLICATION_ROLE,
                    %reason,
                    "PostgreSQL authentication hardening kept this instance in service"
                );
            }
            Ok(outcome)
        }
        HardeningStdout::LegacyBootstrapSuperuser => {
            Err(DockerError::LegacyPostgresBootstrapSuperuser {
                instance_id: instance_id.to_string(),
                username: tenant_username.to_string(),
            })
        }
        HardeningStdout::MissingTenantRole => Err(DockerError::MissingPostgresTenantRole {
            instance_id: instance_id.to_string(),
            username: tenant_username.to_string(),
        }),
        HardeningStdout::Unexpected => Err(DockerError::UnexpectedPostgresProvisioningOutput {
            instance_id: instance_id.to_string(),
        }),
    }
}

async fn run_hardening_command(
    docker: &DockerRuntime,
    instance_id: &str,
    script: &str,
    environment: &[(&str, &SecretString)],
    recovery: ExecRecovery,
) -> Result<CommandOutput, DockerError> {
    match recovery {
        ExecRecovery::RestartRuntime => {
            docker
                .exec_shell_with_secrets_timeout(
                    Protocol::Postgres,
                    instance_id,
                    script,
                    environment,
                    HARDENING_TIMEOUT,
                )
                .await
        }
        ExecRecovery::CallerHandles => {
            docker
                .exec_tenant_shell(
                    Protocol::Postgres,
                    instance_id,
                    script,
                    environment,
                    HARDENING_TIMEOUT,
                )
                .await
        }
    }
}

pub(crate) async fn verify_admin_password(
    docker: &DockerRuntime,
    instance_id: &str,
    password: &SecretString,
) -> Result<(), DockerError> {
    let output = docker
        .exec_shell_with_secrets_timeout(
            Protocol::Postgres,
            instance_id,
            "set -eu\ntest \"$(cat /proc/1/comm)\" = postgres\nPGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -Atqc \"SELECT rolpassword FROM pg_authid WHERE rolname = current_user\"\n",
            &[("DBE_POSTGRES_ADMIN_PASSWORD", password)],
            HARDENING_TIMEOUT,
        )
        .await?;
    let verifier = output.stdout.trim().to_string();
    let password = password.expose_secret().to_string();
    let verified = tokio::task::spawn_blocking(move || verify_scram_password(&password, &verifier))
        .await
        .map_err(|error| DockerError::PostgresAuthHardeningFailed {
            instance_id: instance_id.to_string(),
            reason: format!("the PostgreSQL SCRAM verification task failed: {error}"),
        })?;
    if !verified {
        return Err(DockerError::PostgresAuthHardeningFailed {
            instance_id: instance_id.to_string(),
            reason: "the PostgreSQL internal administrator credential could not be verified against the database SCRAM secret; refusing to adopt it"
                .to_string(),
        });
    }
    Ok(())
}

async fn verify_tenant_scram(
    docker: &DockerRuntime,
    instance_id: &str,
    tenant_username: &str,
    tenant_password: &SecretString,
    admin_password: &SecretString,
) -> Result<bool, DockerError> {
    let verifier_query = sh_quote(&super::provision::tenant_password_verifier_sql(
        tenant_username,
    ));
    let output = docker
        .exec_shell_with_secrets_timeout(
            Protocol::Postgres,
            instance_id,
            &format!(
                "set -eu\nPGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -Atqc {verifier_query}\n"
            ),
            &[("DBE_POSTGRES_ADMIN_PASSWORD", admin_password)],
            HARDENING_TIMEOUT,
        )
        .await?;
    let verifier = output.stdout.trim().to_string();
    let password = tenant_password.expose_secret().to_string();
    tokio::task::spawn_blocking(move || verify_scram_password(&password, &verifier))
        .await
        .map_err(|error| DockerError::PostgresAuthHardeningFailed {
            instance_id: instance_id.to_string(),
            reason: format!("the PostgreSQL tenant SCRAM verification task failed: {error}"),
        })
}

/// Rotate the DBEV-only administrator to a known protected candidate only when
/// legacy local authentication demonstrably accepts a deliberately invalid
/// password. This is a controlled migration out of `trust`; it never changes
/// a tenant credential and cannot bypass an already enforced password policy.
async fn repair_admin_password(
    docker: &DockerRuntime,
    instance_id: &str,
    replacement: &SecretString,
) -> Result<bool, DockerError> {
    let invalid_password = random_invalid_password();
    let reset = sh_quote(&super::provision::reset_tenant_password_sql(
        super::docker::INTERNAL_ADMIN_USERNAME,
    ));
    let script = format!(
        r#"set -eu
test "$(cat /proc/1/comm)" = postgres
if ! PGPASSWORD="$DBE_INVALID_PASSWORD" psql -X -h /var/run/postgresql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc 'SELECT 1' >/dev/null 2>&1; then
  printf 'password_enforced\n'
  exit 0
fi
{{ printf '%s\n' '\getenv tenant_password DBE_RECOVERY_ADMIN_PASSWORD'; printf '%s\n' {reset}; }} | \
  PGPASSWORD="$DBE_INVALID_PASSWORD" psql -X -h /var/run/postgresql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 >/dev/null
printf 'rotated\n'
"#
    );
    let output = docker
        .exec_shell_with_secrets_timeout(
            Protocol::Postgres,
            instance_id,
            &script,
            &[
                ("DBE_INVALID_PASSWORD", &invalid_password),
                ("DBE_RECOVERY_ADMIN_PASSWORD", replacement),
            ],
            HARDENING_TIMEOUT,
        )
        .await?;
    match output.stdout.lines().last() {
        Some("rotated") => {
            verify_admin_password(docker, instance_id, replacement).await?;
            Ok(true)
        }
        Some("password_enforced") => Ok(false),
        _ => Err(DockerError::PostgresAuthHardeningFailed {
            instance_id: instance_id.to_string(),
            reason:
                "the controlled administrator credential recovery returned an unexpected result"
                    .to_string(),
        }),
    }
}

fn random_invalid_password() -> SecretString {
    SecretString::from(format!("dbev-invalid-{}", uuid::Uuid::new_v4().simple()))
}

fn verify_scram_password(password: &str, verifier: &str) -> bool {
    const MAX_VERIFIER_BYTES: usize = 4_096;
    const MAX_ITERATIONS: u32 = 100_000;
    const MAX_SALT_BYTES: usize = 1_024;

    if !password.is_ascii() || verifier.len() > MAX_VERIFIER_BYTES {
        return false;
    }
    let Some(rest) = verifier.strip_prefix("SCRAM-SHA-256$") else {
        return false;
    };
    let Some((iteration_and_salt, keys)) = rest.split_once('$') else {
        return false;
    };
    let Some((iterations, salt)) = iteration_and_salt.split_once(':') else {
        return false;
    };
    let Some((stored_key, server_key)) = keys.split_once(':') else {
        return false;
    };
    if server_key.contains(':') {
        return false;
    }
    let Ok(iterations) = iterations.parse::<u32>() else {
        return false;
    };
    if iterations > MAX_ITERATIONS {
        return false;
    }
    let Some(iterations) = NonZeroU32::new(iterations) else {
        return false;
    };
    let (Ok(salt), Ok(expected_stored_key), Ok(server_key)) = (
        STANDARD.decode(salt),
        STANDARD.decode(stored_key),
        STANDARD.decode(server_key),
    ) else {
        return false;
    };
    if salt.is_empty()
        || salt.len() > MAX_SALT_BYTES
        || expected_stored_key.len() != 32
        || server_key.len() != 32
    {
        return false;
    }
    let mut salted_password = [0_u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &mut salted_password,
    );
    let client_key = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, &salted_password),
        b"Client Key",
    );
    let actual_stored_key = Sha256::digest(client_key.as_ref());
    bool::from(actual_stored_key[..].ct_eq(expected_stored_key.as_slice()))
}

pub async fn harden_on_boot(
    manager: &InstanceManager,
    docker: &DockerRuntime,
    instance_locks: &InstanceLocks,
) -> PostgresHardeningSummary {
    let instances = manager.store().list().await;
    let outcomes = futures::stream::iter(instances.into_iter().filter(|metadata| {
        metadata.protocol == Protocol::Postgres
            && metadata.deployment_mode == crate::server::placement::DeploymentMode::Dedicated
    }))
    .map(|snapshot| harden_postgres(manager, docker, instance_locks, snapshot))
    .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;
    merge_postgres_hardening(outcomes)
}

async fn harden_postgres(
    manager: &InstanceManager,
    docker: &DockerRuntime,
    instance_locks: &InstanceLocks,
    snapshot: InstanceMetadata,
) -> PostgresHardeningSummary {
    let mut summary = PostgresHardeningSummary::default();
    let _operation = instance_locks.lock(&snapshot.instance_id).await;
    let Some(metadata) = manager.store().get(&snapshot.instance_id).await else {
        return summary;
    };
    if metadata.protocol != Protocol::Postgres || metadata.status == InstanceStatus::Quarantined {
        return summary;
    }
    let attestation = if metadata.status == InstanceStatus::Running {
        match crate::server::auth_hardening::begin_attestation(manager, docker, &metadata).await {
            Ok(check) if check.current => {
                summary.attestations_reused = 1;
                return summary;
            }
            Ok(check) => {
                if let Some(error) = check.cache_warning.as_deref() {
                    tracing::warn!(
                        event = "audit auth_hardening_attestation_check_failed",
                        instance_id = %metadata.instance_id,
                        protocol = %metadata.protocol,
                        %error,
                        "could not validate the cached hardening attestation; running full PostgreSQL hardening"
                    );
                }
                Some(check)
            }
            Err(error) => {
                record_auth_failure(
                    manager,
                    &metadata,
                    format!(
                        "could not bind PostgreSQL hardening to one container generation: {error}"
                    ),
                    &mut summary,
                )
                .await;
                return summary;
            }
        }
    } else {
        None
    };
    let bootstrap_credentials = docker
        .postgres_bootstrap_credentials(&metadata.instance_id)
        .await;
    let (bootstrap_username, bootstrap_password) = match bootstrap_credentials {
        Ok(credentials) => credentials,
        Err(error) if metadata.status != InstanceStatus::Running => {
            summary.deferred = 1;
            tracing::warn!(
                event = "audit postgres_admin_credential_migration_deferred",
                instance_id = %metadata.instance_id,
                %error,
                "could not inspect a non-running PostgreSQL container; credential migration remains pending"
            );
            return summary;
        }
        Err(_) => {
            record_auth_failure(
                manager,
                &metadata,
                "the managed PostgreSQL bootstrap credential could not be inspected safely"
                    .to_string(),
                &mut summary,
            )
            .await;
            return summary;
        }
    };
    if bootstrap_username != super::docker::INTERNAL_ADMIN_USERNAME {
        let error = DockerError::LegacyPostgresBootstrapSuperuser {
            instance_id: metadata.instance_id.clone(),
            username: bootstrap_username,
        };
        if metadata.status != InstanceStatus::Running {
            summary.deferred = 1;
            tracing::warn!(
                event = "audit legacy_postgres_admin_migration_deferred",
                instance_id = %metadata.instance_id,
                %error,
                "non-running legacy PostgreSQL instance requires export and recreation before it can be started"
            );
            return summary;
        }
        record_auth_failure(manager, &metadata, error.to_string(), &mut summary).await;
        return summary;
    }
    if metadata.status != InstanceStatus::Running {
        return summary;
    }
    let persisted_admin = metadata
        .postgres_admin_password
        .as_deref()
        .map(|password| SecretString::from(password.to_string()));
    let resolved_admin = resolve_admin_password(
        docker,
        &metadata.instance_id,
        persisted_admin,
        bootstrap_password,
    )
    .await;
    let Some((admin_password, migrate_admin_password)) = resolved_admin else {
        record_auth_failure(
            manager,
            &metadata,
            "the existing PostgreSQL administrator credential could not be verified or safely repaired against the database SCRAM secret"
                .to_string(),
            &mut summary,
        )
        .await;
        return summary;
    };
    if verify_admin_password(docker, &metadata.instance_id, &admin_password)
        .await
        .is_err()
    {
        record_auth_failure(
            manager,
            &metadata,
            "the existing PostgreSQL administrator credential could not be verified against the database SCRAM secret"
                .to_string(),
            &mut summary,
        )
        .await;
        return summary;
    }
    let mut metadata = metadata;
    if migrate_admin_password {
        metadata.postgres_admin_password = Some(admin_password.expose_secret().to_string());
    }
    let (tenant_password, migrate_tenant_password) =
        match resolve_tenant_password(docker, &metadata, &admin_password).await {
            Ok(resolved) => resolved,
            Err(reason) => {
                record_auth_failure(manager, &metadata, reason.to_string(), &mut summary).await;
                return summary;
            }
        };
    summary.checked = 1;
    let hardening = execute_auth_hardening(
        docker,
        &metadata.instance_id,
        &metadata.database.name,
        &metadata.database.username,
        &tenant_password,
        &admin_password,
        ExecRecovery::RestartRuntime,
    )
    .await;
    let outcome = match hardening {
        Ok(outcome) => outcome,
        Err(_) => {
            record_auth_failure(
                manager,
                &metadata,
                "PostgreSQL local authentication hardening could not be completed safely"
                    .to_string(),
                &mut summary,
            )
            .await;
            return summary;
        }
    };
    if outcome.changed {
        summary.hardened = 1;
    }
    if outcome.replication_capture_blocked {
        summary
            .replication_capture_blocked
            .push(PostgresReplicationCaptureBlock {
                instance_id: metadata.instance_id.clone(),
                reason: foreign_replication_role_diagnostic(),
            });
    }
    if migrate_admin_password || migrate_tenant_password {
        metadata.postgres_admin_password = Some(admin_password.expose_secret().to_string());
        metadata.tenant_password = Some(tenant_password.expose_secret().to_string());
        if let Err(error) = manager.upsert_recovered_secrets(metadata.clone()).await {
            record_auth_failure(
                manager,
                &metadata,
                format!(
                    "verified legacy PostgreSQL credentials could not be encrypted and persisted: {error}"
                ),
                &mut summary,
            )
            .await;
            return summary;
        }
        if migrate_admin_password {
            summary.administrator_credentials_migrated = 1;
        }
        tracing::info!(
            event = "audit postgres_credentials_migrated",
            instance_id = %metadata.instance_id,
            administrator = migrate_admin_password,
            tenant = migrate_tenant_password,
            "verified and encrypted current PostgreSQL credentials"
        );
    }
    if let Some(attestation) = attestation.as_ref()
        && let Err(error) = crate::server::auth_hardening::complete_attestation(
            manager,
            docker,
            &metadata,
            attestation.generation(),
        )
        .await
    {
        if error.is_storage() {
            tracing::warn!(
                event = "audit auth_hardening_attestation_write_failed",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %error,
                "PostgreSQL hardening succeeded, but its optimization attestation could not be persisted"
            );
        } else {
            record_auth_failure(
                manager,
                &metadata,
                format!("PostgreSQL container generation changed during hardening: {error}"),
                &mut summary,
            )
            .await;
            return summary;
        }
    }
    summary
}

async fn resolve_admin_password(
    docker: &DockerRuntime,
    instance_id: &str,
    persisted_admin: Option<SecretString>,
    bootstrap_password: SecretString,
) -> Option<(SecretString, bool)> {
    let Some(persisted) = persisted_admin else {
        if verify_admin_password(docker, instance_id, &bootstrap_password)
            .await
            .is_ok()
        {
            return Some((bootstrap_password, true));
        }
        return match repair_admin_password(docker, instance_id, &bootstrap_password).await {
            Ok(true) => Some((bootstrap_password, true)),
            _ => None,
        };
    };
    if verify_admin_password(docker, instance_id, &persisted)
        .await
        .is_ok()
    {
        return Some((persisted, false));
    }
    if persisted.expose_secret() != bootstrap_password.expose_secret()
        && verify_admin_password(docker, instance_id, &bootstrap_password)
            .await
            .is_ok()
    {
        return Some((bootstrap_password, true));
    }
    match repair_admin_password(docker, instance_id, &persisted).await {
        Ok(true) => Some((persisted, false)),
        _ => None,
    }
}

async fn resolve_tenant_password(
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
    admin_password: &SecretString,
) -> Result<(SecretString, bool), &'static str> {
    if let Some(password) = metadata
        .tenant_password
        .as_deref()
        .filter(|password| !password.is_empty())
    {
        return Ok((SecretString::from(password.to_string()), false));
    }
    let legacy_credentials = docker
        .postgres_legacy_credentials(&metadata.instance_id)
        .await;
    let candidate = match legacy_credentials {
        Ok(Some((username, password))) if username == metadata.database.username => password,
        Ok(Some(_)) => {
            return Err(
                "the legacy PostgreSQL tenant username does not match protected instance metadata; refusing to adopt it",
            );
        }
        Ok(None) | Err(_) => {
            return Err(
                "the encrypted tenant credential is missing and no unambiguous legacy container credential is available; reset this legacy instance before opening its gateway",
            );
        }
    };
    let verified = verify_tenant_scram(
        docker,
        &metadata.instance_id,
        &metadata.database.username,
        &candidate,
        admin_password,
    )
    .await;
    match verified {
        Ok(true) => Ok((candidate, true)),
        _ => Err(
            "the legacy PostgreSQL tenant credential does not match the live database SCRAM verifier; reset this legacy instance before opening its gateway",
        ),
    }
}

fn merge_postgres_hardening(outcomes: Vec<PostgresHardeningSummary>) -> PostgresHardeningSummary {
    let mut summary = PostgresHardeningSummary::default();
    for mut outcome in outcomes {
        summary.checked += outcome.checked;
        summary.hardened += outcome.hardened;
        summary.administrator_credentials_migrated += outcome.administrator_credentials_migrated;
        summary.attestations_reused += outcome.attestations_reused;
        summary.deferred += outcome.deferred;
        summary.failures.append(&mut outcome.failures);
        summary
            .replication_capture_blocked
            .append(&mut outcome.replication_capture_blocked);
    }
    summary.failures.sort_by(|left, right| {
        left.instance_id
            .cmp(&right.instance_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    summary.replication_capture_blocked.sort_by(|left, right| {
        left.instance_id
            .cmp(&right.instance_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    summary
}

async fn record_auth_failure(
    manager: &InstanceManager,
    metadata: &InstanceMetadata,
    reason: String,
    summary: &mut PostgresHardeningSummary,
) {
    let failed = auth_failed_metadata(metadata);
    manager.store().upsert(failed.clone()).await;
    let persistence_error = manager.upsert(failed).await.err();
    let reason = match persistence_error {
        Some(error) => format!(
            "{reason}; the route was removed in memory, but the failed state could not be persisted: {error}"
        ),
        None => reason,
    };
    tracing::error!(
        event = "audit postgres_auth_hardening_instance_failed",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        %reason,
        "isolated one PostgreSQL instance after authentication hardening failed; other gateway routes remain eligible"
    );
    summary.failures.push(PostgresHardeningFailure {
        instance_id: metadata.instance_id.clone(),
        reason,
    });
}

fn auth_failed_metadata(metadata: &InstanceMetadata) -> InstanceMetadata {
    let mut failed = metadata.clone();
    failed.status = InstanceStatus::Failed;
    failed.updated_at = crate::utils::time::now_rfc3339();
    failed
}

pub(super) fn hardening_script(tenant_username: &str) -> String {
    let role_state = sh_quote(&super::provision::tenant_role_state_sql(tenant_username));
    let restrict = sh_quote(&super::provision::restrict_tenant_role_sql(tenant_username));
    let reset = sh_quote(&super::provision::reset_tenant_password_sql(
        tenant_username,
    ));
    let ensure_sql = super::online_backup::ensure_replication_role_sql();
    assert!(
        ensure_sql.contains(&super::online_backup::replication_role_comment_sql()),
        "replication role creation must commit the ownership comment in the same transaction"
    );
    let ensure_replication = sh_quote(&ensure_sql);
    let reset_replication = sh_quote(&super::online_backup::reset_replication_password_sql());
    let replication_state = sh_quote(&super::online_backup::replication_role_state_sql());
    let replication_ownership = sh_quote(&super::online_backup::replication_role_ownership_sql());
    // Longer placeholders first. `@REPLICATION_ROLE@` is not a substring of
    // `@REPLICATION_ROLE_STATE@` (the next character is `_`), and this order
    // keeps that true if a name is extended later.
    HARDENING_SCRIPT
        .replace("@REPLICATION_OWNERSHIP_SQL@", &replication_ownership)
        .replace("@ENSURE_REPLICATION_ROLE_SQL@", &ensure_replication)
        .replace("@RESET_REPLICATION_PASSWORD_SQL@", &reset_replication)
        .replace("@REPLICATION_ROLE_STATE_SQL@", &replication_state)
        .replace(
            "@REPLICATION_ROLE_STATE@",
            super::online_backup::REPLICATION_ROLE_STATE,
        )
        .replace(
            "@REPLICATION_HBA_LINE@",
            super::online_backup::REPLICATION_HBA_LINE,
        )
        .replace(
            "@LOCAL_CLIENT_HBA_LINE@",
            super::online_backup::LOCAL_CLIENT_HBA_LINE,
        )
        .replace("@REPLICATION_ROLE@", super::online_backup::REPLICATION_ROLE)
        .replace("@ROLE_STATE_SQL@", &role_state)
        .replace("@RESTRICT_ROLE_SQL@", &restrict)
        .replace("@RESET_PASSWORD_SQL@", &reset)
}

const HARDENING_SCRIPT: &str = r#"set -eu
test "$(cat /proc/1/comm)" = postgres || { printf 'postgres_final_server_unavailable\n'; exit 40; }
tenant_psql() { PGPASSWORD="$DBE_TENANT_PASSWORD" psql -X -h /var/run/postgresql -U "$DBE_POSTGRES_USER" -d "$DBE_POSTGRES_DATABASE" "$@"; }
admin_psql() { PGPASSWORD="$DBE_POSTGRES_ADMIN_PASSWORD" psql -X -h /var/run/postgresql -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"; }
tenant_available=false
tenant_state=
if tenant_psql -Atqc 'SELECT 1' >/dev/null 2>&1; then
  tenant_available=true
  tenant_state=$(tenant_psql -Atq -c @ROLE_STATE_SQL@)
  case "$tenant_state" in
    10:*) printf 'legacy_bootstrap_superuser\n'; exit 0 ;;
  esac
fi
admin_available=false
if admin_psql -Atqc 'SELECT 1' >/dev/null 2>&1; then admin_available=true; fi
case "${PGDATA:-}" in /var/lib/postgresql/*) ;; *) printf 'unsafe_postgres_auth_path\n'; exit 44 ;; esac
test -d "$PGDATA" && test ! -L "$PGDATA" || { printf 'unsafe_postgres_data_directory\n'; exit 45; }
hba_file="$PGDATA/pg_hba.conf"
test -f "$hba_file" && test ! -L "$hba_file" || { printf 'unsafe_postgres_auth_file\n'; exit 46; }
hba_is_hardened() {
  awk '
    /^[[:space:]]*(#|$)/ { next }
    $1 ~ /^include/ { exit 10 }
    $1 == "local" {
      if ($2 == "all" && $3 == "all" && $4 == "scram-sha-256" && NF == 4) all_scram++
      else if ($2 == "replication" && $3 == "@REPLICATION_ROLE@" && $4 == "scram-sha-256" && NF == 4) replication_scram++
      else exit 11
    }
    END { if (all_scram == 1 && replication_scram == 1) exit 0; exit 12 }
  ' "$hba_file"
}
verify_tenant_auth() {
  tenant_psql -Atqc 'SELECT 1' >/dev/null
  if PGPASSWORD="$DBE_INVALID_PASSWORD" psql -X -h /var/run/postgresql -U "$DBE_POSTGRES_USER" -d "$DBE_POSTGRES_DATABASE" -Atqc 'SELECT 1' >/dev/null 2>&1; then
    printf 'postgres_wrong_password_accepted\n'
    exit 49
  fi
}
changed=false
if ! hba_is_hardened; then
  if test "$admin_available" != true && test "$tenant_available" != true; then
    printf 'postgres_admin_auth_unavailable\n'
    exit 42
  fi
awk '/^[[:space:]]*(include|include_if_exists|include_dir)[[:space:]]/ { exit 1 }' "$hba_file" || { printf 'unsupported_postgres_hba_include\n'; exit 47; }
  umask 077
  hba_tmp=$(mktemp "${hba_file}.dbev.XXXXXX")
  trap 'rm -f "$hba_tmp"' EXIT HUP INT TERM
  awk '$1 == "local" || $2 == "replication" { next } { print }' "$hba_file" >"$hba_tmp"
  printf '%s\n' '@LOCAL_CLIENT_HBA_LINE@' >>"$hba_tmp"
  printf '%s\n' '@REPLICATION_HBA_LINE@' >>"$hba_tmp"
  chmod --reference="$hba_file" "$hba_tmp"
  mv -f "$hba_tmp" "$hba_file"
  trap - EXIT HUP INT TERM
  kill -HUP 1
  sleep 1
  changed=true
fi
admin_psql -Atqc 'SELECT 1' >/dev/null 2>&1 || { printf 'postgres_admin_auth_unavailable\n'; exit 43; }
shown_hba=$(admin_psql -Atqc 'SHOW hba_file')
test "$shown_hba" = "$hba_file" || { printf 'unexpected_postgres_auth_path\n'; exit 48; }
role_state=$(admin_psql -Atq -c @ROLE_STATE_SQL@)
case "$role_state" in
  '') printf 'missing_tenant_role\n'; exit 0 ;;
  10:*) printf 'legacy_bootstrap_superuser\n'; exit 0 ;;
  *:1) printf '%s\n' @RESTRICT_ROLE_SQL@ | admin_psql -v ON_ERROR_STOP=1; changed=true ;;
esac
if ! tenant_psql -Atqc 'SELECT 1' >/dev/null 2>&1; then
  { printf '%s\n' '\getenv tenant_password DBE_TENANT_PASSWORD'; printf '%s\n' @RESET_PASSWORD_SQL@; } | admin_psql -v ON_ERROR_STOP=1
  changed=true
fi
replication_auth_ok() {
  db=$1
  output=$(PGPASSWORD="$DBE_REPLICATION_PASSWORD" psql -X -h /var/run/postgresql -U @REPLICATION_ROLE@ -d "$db" -Atqc 'SELECT 1' 2>&1) && return 0
  case "$output" in
    *'permission denied'*) return 0 ;;
    *'does not exist'*) return 2 ;;
    *) return 1 ;;
  esac
}
replication_login_ok() {
  status=0
  replication_auth_ok postgres || status=$?
  if [ "$status" -eq 0 ]; then return 0; fi
  if [ "$status" -eq 1 ]; then return 1; fi
  status=0
  replication_auth_ok template1 || status=$?
  if [ "$status" -eq 0 ]; then return 0; fi
  if [ "$status" -eq 1 ]; then return 1; fi
  if [ -n "${POSTGRES_DB:-}" ]; then
    status=0
    replication_auth_ok "$POSTGRES_DB" || status=$?
    if [ "$status" -eq 0 ]; then return 0; fi
    if [ "$status" -eq 1 ]; then return 1; fi
  fi
  return 1
}
replication_capture_blocked=false
replication_ownership=$(admin_psql -Atq -c @REPLICATION_OWNERSHIP_SQL@) || replication_ownership=
case "$replication_ownership" in
  missing)
    { printf '%s\n' '\getenv replication_password DBE_REPLICATION_PASSWORD'; printf '%s\n' @ENSURE_REPLICATION_ROLE_SQL@; } | admin_psql -v ON_ERROR_STOP=1
    changed=true
    ;;
  owned)
    replication_role_state=$(admin_psql -Atq -c @REPLICATION_ROLE_STATE_SQL@)
    if [ "$replication_role_state" != "@REPLICATION_ROLE_STATE@" ]; then
      { printf '%s\n' '\getenv replication_password DBE_REPLICATION_PASSWORD'; printf '%s\n' @ENSURE_REPLICATION_ROLE_SQL@; } | admin_psql -v ON_ERROR_STOP=1
      changed=true
    elif ! replication_login_ok; then
      { printf '%s\n' '\getenv replication_password DBE_REPLICATION_PASSWORD'; printf '%s\n' @RESET_REPLICATION_PASSWORD_SQL@; } | admin_psql -v ON_ERROR_STOP=1
      changed=true
      if ! replication_login_ok; then
        printf 'replication_auth_failed\n'
        exit 50
      fi
    fi
    ;;
  candidate)
    # Partial earlier run committed the role before the password and marker.
    # It already has the daemon privilege bits and owns nothing.
    { printf '%s\n' '\getenv replication_password DBE_REPLICATION_PASSWORD'; printf '%s\n' @ENSURE_REPLICATION_ROLE_SQL@; } | admin_psql -v ON_ERROR_STOP=1
    changed=true
    ;;
  foreign)
    replication_capture_blocked=true
    printf 'replication_capture_blocked\n'
    ;;
  *)
    printf 'replication_role_not_owned\n'
    exit 52
    ;;
esac
if [ "$replication_capture_blocked" != true ]; then
  confirmed=$(admin_psql -Atq -c @REPLICATION_ROLE_STATE_SQL@)
  test "$confirmed" = "@REPLICATION_ROLE_STATE@" || { printf 'replication_role_privileges\n'; exit 51; }
fi
verify_tenant_auth
hba_is_hardened
if test "$changed" = true; then printf 'hardened\n'; else printf 'already_hardened\n'; fi
"#;

#[cfg(test)]
mod tests;
