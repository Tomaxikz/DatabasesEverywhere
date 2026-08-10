use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};

use crate::{
    instances::{locks::InstanceLocks, manager::InstanceManager, metadata::InstanceStatus},
    runtime::docker::{DockerError, DockerRuntime},
    shared::protocol::Protocol,
};

const HARDENING_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
pub struct PostgresHardeningSummary {
    pub checked: usize,
    pub hardened: usize,
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

pub async fn harden_on_boot(
    manager: &InstanceManager,
    docker: &DockerRuntime,
    instance_locks: &InstanceLocks,
) -> Result<PostgresHardeningSummary, DockerError> {
    let instances = manager.store().list().await;
    let mut checked = 0;
    let mut hardened = 0;
    for snapshot in instances {
        if snapshot.protocol != Protocol::Postgres {
            continue;
        }
        let _operation = instance_locks.lock(&snapshot.instance_id).await;
        let Some(metadata) = manager.store().get(&snapshot.instance_id).await else {
            continue;
        };
        if metadata.protocol != Protocol::Postgres {
            continue;
        }
        if metadata.status == InstanceStatus::Quarantined {
            continue;
        }
        let bootstrap_credentials = docker
            .postgres_bootstrap_credentials(&metadata.instance_id)
            .await;
        let (bootstrap_username, bootstrap_password) = match bootstrap_credentials {
            Ok(credentials) => credentials,
            Err(error) if metadata.status != InstanceStatus::Running => {
                tracing::warn!(
                    event = "audit postgres_admin_credential_migration_deferred",
                    instance_id = %metadata.instance_id,
                    %error,
                    "could not inspect a non-running PostgreSQL container; credential migration remains pending"
                );
                continue;
            }
            Err(error) => return Err(error),
        };
        if bootstrap_username != super::docker::INTERNAL_ADMIN_USERNAME {
            let error = DockerError::LegacyPostgresBootstrapSuperuser {
                instance_id: metadata.instance_id.clone(),
                username: bootstrap_username,
            };
            if metadata.status != InstanceStatus::Running {
                tracing::warn!(
                    event = "audit legacy_postgres_admin_migration_deferred",
                    instance_id = %metadata.instance_id,
                    %error,
                    "non-running legacy PostgreSQL instance requires export and recreation before it can be started"
                );
                continue;
            }
            return Err(error);
        }
        let admin_password = match metadata.postgres_admin_password.as_deref() {
            Some(persisted) => {
                if persisted != bootstrap_password.expose_secret() {
                    let error = DockerError::PostgresAuthHardeningFailed {
                        instance_id: metadata.instance_id.clone(),
                        reason: "the encrypted internal administrator credential does not match the managed container; refusing to guess or overwrite it".to_string(),
                    };
                    if metadata.status != InstanceStatus::Running {
                        tracing::warn!(
                            event = "audit postgres_admin_credential_mismatch_deferred",
                            instance_id = %metadata.instance_id,
                            %error,
                            "non-running PostgreSQL instance has inconsistent administrator metadata and remains unavailable"
                        );
                        continue;
                    }
                    return Err(error);
                }
                SecretString::from(persisted.to_string())
            }
            None => {
                let mut migrated = metadata.clone();
                migrated.postgres_admin_password =
                    Some(bootstrap_password.expose_secret().to_string());
                manager.upsert(migrated).await.map_err(|error| {
                    DockerError::PostgresAuthHardeningFailed {
                        instance_id: metadata.instance_id.clone(),
                        reason: format!(
                            "failed to persist the encrypted internal administrator credential: {error}"
                        ),
                    }
                })?;
                tracing::info!(
                    event = "audit postgres_admin_credential_migrated",
                    instance_id = %metadata.instance_id,
                    "encrypted the existing PostgreSQL internal administrator credential"
                );
                bootstrap_password
            }
        };
        if metadata.status != InstanceStatus::Running {
            continue;
        }
        let tenant_password = metadata.tenant_password.as_deref().ok_or_else(|| {
            DockerError::PostgresAuthHardeningFailed {
                instance_id: metadata.instance_id.clone(),
                reason: "the encrypted tenant credential is missing; reset or recreate this legacy instance before opening its gateway".to_string(),
            }
        })?;
        checked += 1;
        if harden_instance_auth(
            docker,
            &metadata.instance_id,
            &metadata.database.username,
            &SecretString::from(tenant_password.to_string()),
            &admin_password,
        )
        .await?
        {
            hardened += 1;
        }
    }
    Ok(PostgresHardeningSummary { checked, hardened })
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
}
