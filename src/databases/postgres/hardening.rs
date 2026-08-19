use std::{num::NonZeroU32, time::Duration};

use aws_lc_rs::{hmac, pbkdf2};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::StreamExt;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    constants::MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
    instances::{
        locks::InstanceLocks,
        manager::InstanceManager,
        metadata::{InstanceMetadata, InstanceStatus},
    },
    runtime::docker::{DockerError, DockerRuntime},
    shared::protocol::Protocol,
};

const HARDENING_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct PostgresHardeningFailure {
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
}

pub async fn provision_tenant_role(
    docker: &DockerRuntime,
    instance_id: &str,
    database: &str,
    tenant_username: &str,
    tenant_password: &SecretString,
    admin_password: &SecretString,
) -> Result<(), DockerError> {
    let role_state = super::provision::tenant_role_state_sql(tenant_username);
    let provision = super::provision::provision_tenant_role_sql(database, tenant_username);
    let script = format!(
        "set -eu\ntest \"$(cat /proc/1/comm)\" = postgres || {{ printf 'postgres_final_server_unavailable\\n'; exit 40; }}\nadmin_psql() {{ PGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" \"$@\"; }}\nadmin_psql -Atqc 'SELECT 1' >/dev/null 2>&1 || {{ printf 'admin_auth_unavailable\\n'; exit 41; }}\nrole_state=$(admin_psql -Atq -c {})\ncase \"$role_state\" in\n  10:*) printf 'legacy_bootstrap_superuser\\n'; exit 0 ;;\nesac\n{{ printf '%s\\n' '\\getenv tenant_password DBE_TENANT_PASSWORD'; printf '%s\\n' {}; }} | admin_psql -v ON_ERROR_STOP=1\nprintf 'provisioned\\n'\n",
        shell_quote(&role_state),
        shell_quote(&provision),
    );
    let output = docker
        .exec_shell_with_secret_env_timeout(
            Protocol::Postgres,
            instance_id,
            &script,
            &[
                ("DBE_TENANT_PASSWORD", tenant_password),
                ("DBE_POSTGRES_ADMIN_PASSWORD", admin_password),
            ],
            HARDENING_TIMEOUT,
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
        tenant_username,
        tenant_password,
        admin_password,
    )
    .await
    .map(|_| ())
}

pub async fn harden_instance_auth(
    docker: &DockerRuntime,
    instance_id: &str,
    tenant_username: &str,
    tenant_password: &SecretString,
    admin_password: &SecretString,
) -> Result<bool, DockerError> {
    let invalid_password =
        SecretString::from(format!("dbev-invalid-{}", uuid::Uuid::new_v4().simple()));
    let script = hardening_script(tenant_username);
    let output = docker
        .exec_shell_with_secret_env_timeout(
            Protocol::Postgres,
            instance_id,
            &script,
            &[
                ("DBE_TENANT_PASSWORD", tenant_password),
                ("DBE_POSTGRES_ADMIN_PASSWORD", admin_password),
                ("DBE_INVALID_PASSWORD", &invalid_password),
            ],
            HARDENING_TIMEOUT,
        )
        .await?;
    match output.stdout.lines().last() {
        Some("hardened") => Ok(true),
        Some("already_hardened") => Ok(false),
        Some("legacy_bootstrap_superuser") => Err(DockerError::LegacyPostgresBootstrapSuperuser {
            instance_id: instance_id.to_string(),
            username: tenant_username.to_string(),
        }),
        Some("missing_tenant_role") => Err(DockerError::MissingPostgresTenantRole {
            instance_id: instance_id.to_string(),
            username: tenant_username.to_string(),
        }),
        _ => Err(DockerError::UnexpectedPostgresProvisioningOutput {
            instance_id: instance_id.to_string(),
        }),
    }
}

pub(crate) async fn verify_internal_admin_password(
    docker: &DockerRuntime,
    instance_id: &str,
    password: &SecretString,
) -> Result<(), DockerError> {
    let output = docker
        .exec_shell_with_secret_env_timeout(
            Protocol::Postgres,
            instance_id,
            "set -eu\ntest \"$(cat /proc/1/comm)\" = postgres\nPGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -Atqc \"SELECT rolpassword FROM pg_authid WHERE rolname = current_user\"\n",
            &[("DBE_POSTGRES_ADMIN_PASSWORD", password)],
            HARDENING_TIMEOUT,
        )
        .await?;
    let verifier = output.stdout.trim().to_string();
    let password = password.expose_secret().to_string();
    let verified =
        tokio::task::spawn_blocking(move || verify_scram_sha256_password(&password, &verifier))
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

async fn verify_tenant_password_against_scram(
    docker: &DockerRuntime,
    instance_id: &str,
    tenant_username: &str,
    tenant_password: &SecretString,
    admin_password: &SecretString,
) -> Result<bool, DockerError> {
    let verifier_query = shell_quote(&super::provision::tenant_password_verifier_sql(
        tenant_username,
    ));
    let output = docker
        .exec_shell_with_secret_env_timeout(
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
    tokio::task::spawn_blocking(move || verify_scram_sha256_password(&password, &verifier))
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
async fn repair_internal_admin_password_under_bypassed_auth(
    docker: &DockerRuntime,
    instance_id: &str,
    replacement: &SecretString,
) -> Result<bool, DockerError> {
    let invalid_password =
        SecretString::from(format!("dbev-invalid-{}", uuid::Uuid::new_v4().simple()));
    let reset = shell_quote(&super::provision::reset_tenant_password_sql(
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
        .exec_shell_with_secret_env_timeout(
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
            verify_internal_admin_password(docker, instance_id, replacement).await?;
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

fn verify_scram_sha256_password(password: &str, verifier: &str) -> bool {
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
    let outcomes = futures::stream::iter(
        instances
            .into_iter()
            .filter(|metadata| metadata.protocol == Protocol::Postgres),
    )
    .map(|snapshot| harden_postgres_instance_on_boot(manager, docker, instance_locks, snapshot))
    .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;
    aggregate_postgres_hardening_summaries(outcomes)
}

async fn harden_postgres_instance_on_boot(
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
    if metadata.status == InstanceStatus::Running {
        match crate::instances::auth_hardening::attestation_is_current(manager, docker, &metadata)
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
                "could not validate the cached hardening attestation; running full PostgreSQL hardening"
            ),
        }
    }
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
            record_running_auth_failure(
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
        record_running_auth_failure(manager, &metadata, error.to_string(), &mut summary).await;
        return summary;
    }
    if metadata.status != InstanceStatus::Running {
        return summary;
    }
    let persisted_admin = metadata
        .postgres_admin_password
        .as_deref()
        .map(|password| SecretString::from(password.to_string()));
    let mut migrate_admin_password = false;
    let admin_password = if let Some(persisted) = persisted_admin {
        if verify_internal_admin_password(docker, &metadata.instance_id, &persisted)
            .await
            .is_ok()
        {
            persisted
        } else if persisted.expose_secret() != bootstrap_password.expose_secret()
            && verify_internal_admin_password(docker, &metadata.instance_id, &bootstrap_password)
                .await
                .is_ok()
        {
            migrate_admin_password = true;
            bootstrap_password
        } else {
            match repair_internal_admin_password_under_bypassed_auth(
                docker,
                &metadata.instance_id,
                &persisted,
            )
            .await
            {
                Ok(true) => persisted,
                _ => {
                    record_running_auth_failure(
                        manager,
                        &metadata,
                        "the existing PostgreSQL administrator credential could not be verified or safely repaired against the database SCRAM secret"
                            .to_string(),
                        &mut summary,
                    )
                    .await;
                    return summary;
                }
            }
        }
    } else if verify_internal_admin_password(docker, &metadata.instance_id, &bootstrap_password)
        .await
        .is_ok()
    {
        migrate_admin_password = true;
        bootstrap_password
    } else {
        match repair_internal_admin_password_under_bypassed_auth(
            docker,
            &metadata.instance_id,
            &bootstrap_password,
        )
        .await
        {
            Ok(true) => {
                migrate_admin_password = true;
                bootstrap_password
            }
            _ => {
                record_running_auth_failure(
                    manager,
                    &metadata,
                    "the existing PostgreSQL administrator credential could not be verified or safely repaired against the database SCRAM secret"
                        .to_string(),
                    &mut summary,
                )
                .await;
                return summary;
            }
        }
    };
    if verify_internal_admin_password(docker, &metadata.instance_id, &admin_password)
        .await
        .is_err()
    {
        record_running_auth_failure(
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
    let mut migrate_tenant_password = false;
    let tenant_password = match metadata.tenant_password.as_deref() {
        Some(password) if !password.is_empty() => SecretString::from(password.to_string()),
        _ => {
            let candidate = match docker
                .postgres_legacy_tenant_credentials(&metadata.instance_id)
                .await
            {
                Ok(Some((username, password))) if username == metadata.database.username => {
                    password
                }
                Ok(Some(_)) => {
                    record_running_auth_failure(
                        manager,
                        &metadata,
                        "the legacy PostgreSQL tenant username does not match protected instance metadata; refusing to adopt it"
                            .to_string(),
                        &mut summary,
                    )
                    .await;
                    return summary;
                }
                Ok(None) | Err(_) => {
                    record_running_auth_failure(
                        manager,
                        &metadata,
                        "the encrypted tenant credential is missing and no unambiguous legacy container credential is available; reset this legacy instance before opening its gateway"
                            .to_string(),
                        &mut summary,
                    )
                    .await;
                    return summary;
                }
            };
            match verify_tenant_password_against_scram(
                docker,
                &metadata.instance_id,
                &metadata.database.username,
                &candidate,
                &admin_password,
            )
            .await
            {
                Ok(true) => {
                    migrate_tenant_password = true;
                    candidate
                }
                _ => {
                    record_running_auth_failure(
                        manager,
                        &metadata,
                        "the legacy PostgreSQL tenant credential does not match the live database SCRAM verifier; reset this legacy instance before opening its gateway"
                            .to_string(),
                        &mut summary,
                    )
                    .await;
                    return summary;
                }
            }
        }
    };
    summary.checked = 1;
    let hardening = harden_instance_auth(
        docker,
        &metadata.instance_id,
        &metadata.database.username,
        &tenant_password,
        &admin_password,
    )
    .await;
    let changed = match hardening {
        Ok(changed) => changed,
        Err(_) => {
            record_running_auth_failure(
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
    if changed {
        summary.hardened = 1;
    }
    if migrate_admin_password || migrate_tenant_password {
        metadata.postgres_admin_password = Some(admin_password.expose_secret().to_string());
        metadata.tenant_password = Some(tenant_password.expose_secret().to_string());
        if let Err(error) = manager
            .upsert_recovered_protected_secrets(metadata.clone())
            .await
        {
            record_running_auth_failure(
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
    if let Err(error) =
        crate::instances::auth_hardening::record_attestation(manager, docker, &metadata).await
    {
        tracing::warn!(
            event = "audit auth_hardening_attestation_write_failed",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "PostgreSQL hardening succeeded, but its optimization attestation could not be persisted"
        );
    }
    summary
}

fn aggregate_postgres_hardening_summaries(
    outcomes: Vec<PostgresHardeningSummary>,
) -> PostgresHardeningSummary {
    let mut summary = PostgresHardeningSummary::default();
    for mut outcome in outcomes {
        summary.checked += outcome.checked;
        summary.hardened += outcome.hardened;
        summary.administrator_credentials_migrated += outcome.administrator_credentials_migrated;
        summary.attestations_reused += outcome.attestations_reused;
        summary.deferred += outcome.deferred;
        summary.failures.append(&mut outcome.failures);
    }
    summary.failures.sort_by(|left, right| {
        left.instance_id
            .cmp(&right.instance_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    summary
}

async fn record_running_auth_failure(
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
    failed.updated_at = crate::shared::time::now_rfc3339();
    failed
}

pub(super) fn hardening_script(tenant_username: &str) -> String {
    let role_state = shell_quote(&super::provision::tenant_role_state_sql(tenant_username));
    let restrict = shell_quote(&super::provision::restrict_tenant_role_sql(tenant_username));
    let reset = shell_quote(&super::provision::reset_tenant_password_sql(
        tenant_username,
    ));
    HARDENING_SCRIPT
        .replace("@ROLE_STATE_SQL@", &role_state)
        .replace("@RESTRICT_ROLE_SQL@", &restrict)
        .replace("@RESET_PASSWORD_SQL@", &reset)
}

const HARDENING_SCRIPT: &str = r#"set -eu
test "$(cat /proc/1/comm)" = postgres || { printf 'postgres_final_server_unavailable\n'; exit 40; }
tenant_psql() { PGPASSWORD="$DBE_TENANT_PASSWORD" psql -X -h /var/run/postgresql -U "$DBE_POSTGRES_USER" -d "$POSTGRES_DB" "$@"; }
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
      else if ($2 == "replication" && $3 == "all" && $4 == "scram-sha-256" && NF == 4) replication_scram++
      else exit 11
    }
    END { if (all_scram == 1 && replication_scram <= 1) exit 0; exit 12 }
  ' "$hba_file"
}
verify_tenant_auth() {
  tenant_psql -Atqc 'SELECT 1' >/dev/null
  if PGPASSWORD="$DBE_INVALID_PASSWORD" psql -X -h /var/run/postgresql -U "$DBE_POSTGRES_USER" -d "$POSTGRES_DB" -Atqc 'SELECT 1' >/dev/null 2>&1; then
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
  awk '$1 != "local" { print }' "$hba_file" >"$hba_tmp"
  printf '%s\n' 'local all all scram-sha-256' >>"$hba_tmp"
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
verify_tenant_auth
hba_is_hardened
if test "$changed" = true; then printf 'hardened\n'; else printf 'already_hardened\n'; fi
"#;

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        instances::{
            metadata::{
                DatabaseIdentity, DesiredInstanceState, PublicEndpoint, RuntimeKind,
                RuntimeMetadata, SCHEMA_VERSION,
            },
            state::InstanceStore,
        },
        shared::{backend::BackendEndpoint, limits::InstanceLimits},
    };

    #[test]
    fn migration_replaces_all_local_authentication_with_scram() {
        let script = hardening_script("tenant_user");

        assert!(script.contains("local all all scram-sha-256"));
        assert!(script.contains("DBE_POSTGRES_ADMIN_PASSWORD"));
        assert!(script.contains("DBE_INVALID_PASSWORD"));
        assert!(script.contains("kill -HUP 1"));
        assert!(!script.contains("peer map="));
        assert!(!script.contains("-v tenant_password="));
        assert!(script.contains("admin_available"));
        assert!(script.contains("tenant_available"));
        assert!(script.contains("mv -f \"$hba_tmp\" \"$hba_file\""));
    }

    #[test]
    fn generated_sql_uses_psql_environment_variables_for_secrets() {
        let script = hardening_script("user-with-dash");

        assert!(script.contains("\\getenv tenant_password DBE_TENANT_PASSWORD"));
        assert!(!script.contains("-v tenant_password="));
        assert!(script.contains("ALTER ROLE \"user-with-dash\" PASSWORD"));
    }

    #[test]
    fn privileged_hardening_queries_always_use_internal_admin() {
        let script = hardening_script("tenant_user");

        assert!(script.contains("role_state=$(admin_psql -Atq -c"));
        assert!(script.contains("shown_hba=$(admin_psql -Atqc 'SHOW hba_file')"));
        assert!(script.contains("hba_file=\"$PGDATA/pg_hba.conf\""));
        assert!(!script.contains("db_psql"));
    }

    #[test]
    fn bootstrap_admin_is_adopted_only_when_its_scram_secret_matches() {
        let verifier = "SCRAM-SHA-256$4096:MDEyMzQ1Njc4OWFiY2RlZg==$6/GDk4+gZMX4iv8Ibw6yXOdLYz3kM7F1as2BGy/hOKo=:Oa1MbaDa29ii1LLBMeTRyDGjXTn6G2q1ZT+GhsnFa2c=";

        assert!(verify_scram_sha256_password("admin-password", verifier));
        assert!(!verify_scram_sha256_password("wrong-password", verifier));
        assert!(!verify_scram_sha256_password(
            "admin-password",
            "md5deadbeef"
        ));
        assert!(!verify_scram_sha256_password(
            "admin-password",
            &verifier.replacen("4096", "100001", 1)
        ));
        assert!(!verify_scram_sha256_password(
            "admin-password",
            &format!("SCRAM-SHA-256$4096:{}$AA==:AA==", "A".repeat(2_000))
        ));
    }

    #[test]
    fn failed_auth_preserves_recovery_intent_and_volume_identity() {
        let metadata = test_metadata("legacy", "legacy_user", "legacy_db");

        let failed = auth_failed_metadata(&metadata);

        assert_eq!(failed.status, InstanceStatus::Failed);
        assert_eq!(failed.desired_state, DesiredInstanceState::Running);
        assert_eq!(failed.backend, metadata.backend);
        assert_eq!(
            failed.runtime.container_name,
            metadata.runtime.container_name
        );
    }

    #[tokio::test]
    async fn one_failed_legacy_route_does_not_remove_a_healthy_route() {
        let store = InstanceStore::default();
        let failed = test_metadata("legacy", "legacy_user", "legacy_db");
        let healthy = test_metadata("healthy", "healthy_user", "healthy_db");
        store.upsert(failed.clone()).await;
        store.upsert(healthy).await;

        store.upsert(auth_failed_metadata(&failed)).await;

        assert!(matches!(
            store
                .resolve_postgres("legacy_user", Some("legacy_db"))
                .await,
            crate::instances::state::DatabaseRouteResolution::NotFound
        ));
        assert!(matches!(
            store
                .resolve_postgres("healthy_user", Some("healthy_db"))
                .await,
            crate::instances::state::DatabaseRouteResolution::Found { .. }
        ));
    }

    #[test]
    fn concurrent_outcomes_are_aggregated_deterministically() {
        let summary = aggregate_postgres_hardening_summaries(vec![
            PostgresHardeningSummary {
                checked: 1,
                hardened: 1,
                administrator_credentials_migrated: 0,
                attestations_reused: 1,
                deferred: 0,
                failures: vec![PostgresHardeningFailure {
                    instance_id: "postgres-z".to_string(),
                    reason: "z failure".to_string(),
                }],
            },
            PostgresHardeningSummary {
                checked: 2,
                hardened: 0,
                administrator_credentials_migrated: 1,
                attestations_reused: 2,
                deferred: 1,
                failures: vec![PostgresHardeningFailure {
                    instance_id: "postgres-a".to_string(),
                    reason: "a failure".to_string(),
                }],
            },
        ]);

        assert_eq!(summary.checked, 3);
        assert_eq!(summary.hardened, 1);
        assert_eq!(summary.administrator_credentials_migrated, 1);
        assert_eq!(summary.attestations_reused, 3);
        assert_eq!(summary.deferred, 1);
        assert_eq!(summary.failures.len(), 2);
        assert_eq!(summary.failures[0].instance_id, "postgres-a");
        assert_eq!(summary.failures[1].instance_id, "postgres-z");
    }

    fn test_metadata(instance_id: &str, username: &str, database: &str) -> InstanceMetadata {
        InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: instance_id.to_string(),
            protocol: Protocol::Postgres,
            status: InstanceStatus::Running,
            desired_state: DesiredInstanceState::Running,
            disk_limit_blocked: false,
            public: PublicEndpoint {
                host: "127.0.0.1".to_string(),
                port: 20_020,
            },
            backend: BackendEndpoint::UnixSocket {
                socket_path: format!("/run/dbev/sockets/{instance_id}/.s.PGSQL.5432"),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: format!("dbe-postgres-{instance_id}"),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: database.to_string(),
                username: username.to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mysql_native_password_sha1_stage2: None,
            mysql_root_password: None,
            mongodb_root_password: None,
            postgres_admin_password: Some("admin-password".to_string()),
            tenant_password: None,
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }
}
