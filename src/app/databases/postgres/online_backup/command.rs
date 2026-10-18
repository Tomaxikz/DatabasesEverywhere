//! Command lines, shell wrappers and the replication credential for
//! `pg_basebackup`. The shell text never contains the password.

use aws_lc_rs::hmac;
use secrecy::SecretString;

use crate::{
    databases::postgres::provision::quote_ident, utils::backend::POSTGRES_SOCKET_DIRECTORY,
};

pub(crate) const REPLICATION_ROLE: &str = "dbe_replication";
pub(crate) const REPLICATION_HBA_LINE: &str = "local replication dbe_replication scram-sha-256";
pub(crate) const LOCAL_CLIENT_HBA_LINE: &str = "local all all scram-sha-256";
/// `rolcanlogin:rolreplication:rolsuper:rolcreatedb:rolcreaterole:rolbypassrls:rolinherit`
pub(crate) const REPLICATION_ROLE_STATE: &str = "1:1:0:0:0:0:0";
/// `COMMENT ON ROLE` marker. A role without it is never altered.
pub(crate) const REPLICATION_ROLE_COMMENT: &str = "dbe-managed-replication-v1";
pub(crate) const DATA_ROOT: &str = "pgdata";
pub(crate) const RESTORE_RECIPE_ID: &str = "postgres.basebackup.directory";
pub(crate) const RESTORE_RECIPE_VERSION: u32 = 1;
pub(crate) const PREFLIGHT_HEADER: &str = "DBEV_PG_PREFLIGHT_V1";
pub(crate) const MAX_INVENTORY_DATABASES: u64 = 64;
pub(crate) const DATA_MOUNT: &str = "/var/lib/postgresql";

const REPLICATION_PASSWORD_DOMAIN: &[u8] = b"dbe-postgres-replication-v1";
const TAG_PREFIX: &str = "dbev_bk_";

/// Hex HMAC-SHA256 of the administrator password. Empty input is refused so a
/// missing credential cannot become a predictable replication secret.
pub(crate) fn replication_password(admin_password: &str) -> Result<SecretString, &'static str> {
    if admin_password.is_empty() {
        return Err("PostgreSQL administrator credential is empty");
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, admin_password.as_bytes());
    let tag = hmac::sign(&key, REPLICATION_PASSWORD_DOMAIN);
    Ok(SecretString::from(hex::encode(tag.as_ref())))
}

pub(crate) fn capture_tag(tag: &str) -> bool {
    let Some(hex) = tag.strip_prefix(TAG_PREFIX) else {
        return false;
    };
    hex.len() == 32
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn backup_label_for_tag(tag: &str) -> Option<String> {
    let hex = tag.strip_prefix(TAG_PREFIX)?;
    capture_tag(tag).then(|| format!("dbev-{hex}"))
}

fn replication_attribute_sql(alias: &str) -> String {
    [
        "rolcanlogin",
        "rolreplication",
        "rolsuper",
        "rolcreatedb",
        "rolcreaterole",
        "rolbypassrls",
        "rolinherit",
    ]
    .into_iter()
    .map(|column| format!("{alias}.{column}::int::text"))
    .collect::<Vec<_>>()
    .join(" || ':' || ")
}

pub(crate) fn replication_role_state_sql() -> String {
    format!(
        "SELECT {} FROM pg_roles WHERE rolname = {};",
        replication_attribute_sql("pg_roles"),
        sql_literal(REPLICATION_ROLE)
    )
}

/// Read-only. One of `missing`, `owned`, `candidate`, or `foreign`.
/// `candidate` is an unmarked role with exactly the daemon privilege bits, no
/// memberships, and no database ownership. Anything else that already exists
/// is `foreign` and must not be altered.
pub(crate) fn replication_role_ownership_sql() -> String {
    format!(
        "SELECT CASE WHEN r.oid IS NULL THEN 'missing' WHEN shobj_description(r.oid, 'pg_authid') = {comment} THEN 'owned' WHEN COALESCE(shobj_description(r.oid, 'pg_authid'), '') = '' AND {attributes} = {state} AND NOT EXISTS (SELECT 1 FROM pg_auth_members AS m WHERE m.roleid = r.oid OR m.\"member\" = r.oid) AND NOT EXISTS (SELECT 1 FROM pg_database AS db WHERE db.datdba = r.oid) THEN 'candidate' ELSE 'foreign' END FROM (SELECT 1) AS probe LEFT JOIN pg_roles AS r ON r.rolname = {role};",
        comment = sql_literal(REPLICATION_ROLE_COMMENT),
        attributes = replication_attribute_sql("r"),
        state = sql_literal(REPLICATION_ROLE_STATE),
        role = sql_literal(REPLICATION_ROLE),
    )
}

pub(crate) fn replication_role_comment_sql() -> String {
    format!(
        "COMMENT ON ROLE {} IS {};",
        quote_ident(REPLICATION_ROLE),
        sql_literal(REPLICATION_ROLE_COMMENT)
    )
}

/// Value of [`replication_role_ownership_sql`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplicationRoleOwnership {
    Missing,
    Owned,
    Candidate,
    Foreign,
}

pub(crate) fn parse_replication_role_ownership(value: &str) -> Option<ReplicationRoleOwnership> {
    match value {
        "missing" => Some(ReplicationRoleOwnership::Missing),
        "owned" => Some(ReplicationRoleOwnership::Owned),
        "candidate" => Some(ReplicationRoleOwnership::Candidate),
        "foreign" => Some(ReplicationRoleOwnership::Foreign),
        _ => None,
    }
}

/// Preflight key for [`replication_role_ownership_preflight_sql`].
/// Capture must treat `foreign` as online capture disabled, not as a serving failure.
pub(crate) const REPLICATION_OWNERSHIP_PREFLIGHT_KEY: &str = "role_ownership";

/// `role_ownership=missing|owned|candidate|foreign`. One row, read-only.
pub(crate) fn replication_role_ownership_preflight_sql() -> String {
    let body = replication_role_ownership_sql();
    let body = body.trim_end_matches(';');
    format!("SELECT '{REPLICATION_OWNERSHIP_PREFLIGHT_KEY}=' || ({body});")
}

/// Shown when a tenant already owns `dbe_replication`. Serving continues.
pub(crate) fn foreign_replication_role_diagnostic() -> String {
    format!(
        "online backup capture is disabled because role {REPLICATION_ROLE} exists without ownership marker {REPLICATION_ROLE_COMMENT}; rename or drop that role, then rerun authentication hardening"
    )
}

/// Create or repair the replication role in one transaction.
///
/// `CREATE ROLE`, the SCRAM password and the ownership comment commit together.
/// A crash rolls the role back instead of leaving an unmarked passwordless
/// role. Callers set psql variable `replication_password` with `\getenv` and
/// must not put the password in argv. Do not also pass `--single-transaction`;
/// this script already has `BEGIN`/`COMMIT`. `ON_ERROR_STOP` must be on.
pub(crate) fn ensure_replication_role_sql() -> String {
    let ident = quote_ident(REPLICATION_ROLE);
    format!(
        "BEGIN;\nSET LOCAL log_min_error_statement = PANIC;\nSET LOCAL password_encryption = 'scram-sha-256';\nSELECT 'CREATE ROLE {ident} LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {literal})\n\\gexec\nALTER ROLE {ident} WITH LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'replication_password';\n{comment}\nCOMMIT;\n",
        literal = sql_literal(REPLICATION_ROLE),
        comment = replication_role_comment_sql(),
    )
}

pub(crate) fn reset_replication_password_sql() -> String {
    format!(
        "SET password_encryption = 'scram-sha-256';\nALTER ROLE {} PASSWORD :'replication_password';",
        quote_ident(REPLICATION_ROLE)
    )
}

pub(crate) fn basebackup_argv(pgdata: &str, label: &str) -> Vec<String> {
    vec![
        "pg_basebackup".to_string(),
        "--pgdata".to_string(),
        pgdata.to_string(),
        "--format".to_string(),
        "plain".to_string(),
        "--wal-method".to_string(),
        "stream".to_string(),
        "--checkpoint".to_string(),
        "spread".to_string(),
        "--username".to_string(),
        REPLICATION_ROLE.to_string(),
        "--host".to_string(),
        POSTGRES_SOCKET_DIRECTORY.to_string(),
        "--no-password".to_string(),
        "--label".to_string(),
        label.to_string(),
        "--manifest-checksums".to_string(),
        "SHA256".to_string(),
    ]
}

pub(crate) fn verifybackup_argv(pgdata: &str) -> Vec<String> {
    vec![
        "pg_verifybackup".to_string(),
        "--exit-on-error".to_string(),
        pgdata.to_string(),
    ]
}

pub(crate) fn preflight_script() -> &'static str {
    PREFLIGHT_SCRIPT
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

const PREFLIGHT_SCRIPT: &str = r#"set -eu
printf 'DBEV_PG_PREFLIGHT_V1\n'
tool_basebackup=$(pg_basebackup --version 2>/dev/null | awk 'NR==1 { print; exit }' || true)
tool_verifybackup=$(pg_verifybackup --version 2>/dev/null | awk 'NR==1 { print; exit }' || true)
printf 'tool_basebackup=%s\n' "$tool_basebackup"
printf 'tool_verifybackup=%s\n' "$tool_verifybackup"
admin_psql() { PGPASSWORD="$DBE_POSTGRES_ADMIN_PASSWORD" psql -X -h /var/run/postgresql -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"; }
admin_psql -v ON_ERROR_STOP=1 -Atq <<'SQL'
SELECT 'server_version=' || current_setting('server_version');
SELECT 'server_version_num=' || current_setting('server_version_num');
SELECT 'data_directory=' || current_setting('data_directory');
SELECT 'config_file=' || current_setting('config_file');
SELECT 'hba_file=' || current_setting('hba_file');
SELECT 'ident_file=' || current_setting('ident_file');
SELECT 'database_bytes=' || COALESCE(sum(pg_database_size(oid)), 0)::bigint FROM pg_database;
SELECT 'wal_bytes=' || COALESCE((SELECT sum(size) FROM pg_ls_waldir()), 0)::bigint;
SELECT 'hba_errors=' || count(*) FILTER (WHERE error IS NOT NULL)::bigint FROM pg_hba_file_rules;
SELECT 'hba=' || coalesce(type, '') || '|' || coalesce(array_to_string(database, ','), '') || '|' || coalesce(array_to_string(user_name, ','), '') || '|' || coalesce(auth_method, '')
FROM pg_hba_file_rules
WHERE error IS NULL AND 'replication' = ANY(database);
SELECT 'role=' || COALESCE((
  SELECT rolcanlogin::int::text || ':' || rolreplication::int::text || ':' || rolsuper::int::text || ':' || rolcreatedb::int::text || ':' || rolcreaterole::int::text || ':' || rolbypassrls::int::text || ':' || rolinherit::int::text
  FROM pg_roles WHERE rolname = 'dbe_replication'
), 'missing');
SELECT 'tablespace=' || spcname || '|' || coalesce(pg_tablespace_location(oid), '')
FROM pg_tablespace
WHERE spcname NOT IN ('pg_default', 'pg_global');
SELECT 'connectable=' || count(*) FILTER (WHERE datallowconn AND NOT datistemplate)::bigint || '|' || count(*) FILTER (WHERE datallowconn AND NOT datistemplate AND datname !~ '[[:cntrl:]|=]')::bigint
FROM pg_database;
SQL
safe_count=$(admin_psql -Atqc "SELECT count(*) FROM pg_database WHERE datallowconn AND NOT datistemplate AND datname !~ '[[:cntrl:]|=]'")
total_count=$(admin_psql -Atqc "SELECT count(*) FROM pg_database WHERE datallowconn AND NOT datistemplate")
if [ "$safe_count" != "$total_count" ]; then
  printf 'too_many_databases=blocked\n'
elif [ "$safe_count" -gt 64 ]; then
  printf 'too_many_databases=1\n'
else
  printf 'too_many_databases=0\n'
  dbs=$(admin_psql -Atqc "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate AND datname !~ '[[:cntrl:]|=]' ORDER BY 1")
  db_list=$(mktemp)
  trap 'rm -f "$db_list"' EXIT HUP INT TERM
  printf '%s\n' "$dbs" >"$db_list"
  while IFS= read -r db <&3; do
    [ -n "$db" ] || continue
    PGPASSWORD="$DBE_POSTGRES_ADMIN_PASSWORD" psql -X -h /var/run/postgresql -U "$POSTGRES_USER" -d "$db" -v ON_ERROR_STOP=1 -Atq <<'SQL'
SELECT 'unlogged=' || current_database() || '|' || n.nspname || '.' || c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relpersistence = 'u'
  AND c.relkind IN ('r', 'p', 'm', 'S')
  AND n.nspname <> 'pg_toast'
  AND n.nspname !~ '[[:cntrl:]|=|.]'
  AND c.relname !~ '[[:cntrl:]|=]';
SELECT 'extension=' || current_database() || '|' || extname || '|' || extversion
FROM pg_extension
WHERE extname !~ '[[:cntrl:]|=]' AND extversion !~ '[[:cntrl:]|=]';
SELECT 'inventory_blocked=' || (
  (SELECT count(*) FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relpersistence = 'u'
      AND c.relkind IN ('r', 'p', 'm', 'S')
      AND n.nspname <> 'pg_toast'
      AND (n.nspname ~ '[[:cntrl:]|=|.]' OR c.relname ~ '[[:cntrl:]|=]'))
  +
  (SELECT count(*) FROM pg_extension
    WHERE extname ~ '[[:cntrl:]|=]' OR extversion ~ '[[:cntrl:]|=]')
)::text;
SQL
  done 3<"$db_list"
  rm -f "$db_list"
  trap - EXIT HUP INT TERM
fi
auth=failed
for db in postgres template1 ${POSTGRES_DB:+x}; do
  probe=$db
  if [ "$db" = x ]; then probe="$POSTGRES_DB"; fi
  [ -n "$probe" ] || continue
  output=$(PGPASSWORD="$DBE_REPLICATION_PASSWORD" psql -X -h /var/run/postgresql -U dbe_replication -d "$probe" -Atqc 'SELECT 1' 2>&1) && { auth=ok; break; }
  case "$output" in
    *'permission denied'*) auth=ok; break ;;
    *'does not exist'*) continue ;;
    *) auth=failed; break ;;
  esac
done
printf 'auth=%s\n' "$auth"
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    const TAG: &str = "dbev_bk_0123456789abcdef0123456789abcdef";
    const LABEL: &str = "dbev-0123456789abcdef0123456789abcdef";

    #[test]
    fn replication_password_is_stable_hex_and_rejects_empty_input() {
        let first = replication_password("admin-secret").unwrap();
        let second = replication_password("admin-secret").unwrap();
        let other = replication_password("other-secret").unwrap();
        assert_eq!(first.expose_secret(), second.expose_secret());
        assert_eq!(first.expose_secret().len(), 64);
        assert!(
            first
                .expose_secret()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_ne!(first.expose_secret(), other.expose_secret());
        assert_ne!(first.expose_secret(), "admin-secret");
        assert!(replication_password("").is_err());
    }

    #[test]
    fn capture_tags_reject_traversal_and_the_wrong_shape() {
        assert!(capture_tag(TAG));
        assert_eq!(backup_label_for_tag(TAG).as_deref(), Some(LABEL));
        for tag in [
            "",
            "..",
            "dbev_bk_../etc",
            "dbev_bk_0123456789abcdef0123456789abcde",
            "dbev_bk_0123456789ABCDEF0123456789ABCDEF",
            "dbev_bk_0123456789abcdef0123456789abcdef/pgdata",
            "pgdata",
        ] {
            assert!(!capture_tag(tag), "{tag}");
        }
    }

    #[test]
    fn basebackup_argv_streams_a_spread_plain_backup() {
        let pgdata = format!("{POSTGRES_SOCKET_DIRECTORY}/{TAG}/{DATA_ROOT}");
        let argv = basebackup_argv(&pgdata, LABEL);
        assert!(has_pair(&argv, "--pgdata", &pgdata));
        assert!(has_pair(&argv, "--format", "plain"));
        assert!(has_pair(&argv, "--wal-method", "stream"));
        assert!(has_pair(&argv, "--checkpoint", "spread"));
        assert!(has_pair(&argv, "--username", REPLICATION_ROLE));
        assert!(has_pair(&argv, "--host", POSTGRES_SOCKET_DIRECTORY));
        assert!(has_pair(&argv, "--label", LABEL));
        assert!(has_pair(&argv, "--manifest-checksums", "SHA256"));
        assert!(argv.iter().any(|arg| arg == "--no-password"));
        for forbidden in [
            "--no-slot",
            "--no-sync",
            "--write-recovery-conf",
            "--verbose",
            "--progress",
            "--format=tar",
            "--wal-method=fetch",
            "--checkpoint=fast",
            "-R",
            "tar",
            "fetch",
            "fast",
        ] {
            assert!(!argv.iter().any(|arg| arg == forbidden), "{forbidden}");
        }
    }

    #[test]
    fn replication_role_sql_is_login_replication_without_a_password_literal() {
        let ensure = ensure_replication_role_sql();
        let reset = reset_replication_password_sql();
        let state = replication_role_state_sql();
        assert!(ensure.contains(" REPLICATION "));
        assert!(!ensure.contains("NOREPLICATION"));
        for privilege in [
            "LOGIN",
            "NOSUPERUSER",
            "NOCREATEDB",
            "NOCREATEROLE",
            "NOINHERIT",
            "NOBYPASSRLS",
        ] {
            assert!(ensure.contains(privilege), "{privilege}");
        }
        assert!(ensure.contains("\\gexec"));
        assert!(ensure.contains(":'replication_password'"));
        assert!(reset.contains(":'replication_password'"));
        assert!(!ensure.contains("hunter2"));
        assert!(!reset.contains("hunter2"));
        assert!(ensure.contains("SET LOCAL password_encryption = 'scram-sha-256'"));
        assert!(ensure.contains("SET LOCAL log_min_error_statement = PANIC"));
        let begin = ensure.find("BEGIN;").unwrap();
        let create = ensure.find("CREATE ROLE").unwrap();
        let alter = ensure.find("ALTER ROLE").unwrap();
        let comment_at = ensure.find("COMMENT ON ROLE").unwrap();
        let commit = ensure.find("COMMIT;").unwrap();
        assert!(begin < create && create < alter && alter < comment_at && comment_at < commit);
        assert_eq!(ensure.matches("BEGIN;").count(), 1);
        assert_eq!(ensure.matches("COMMIT;").count(), 1);
        assert!(!ensure.contains("--single-transaction"));
        assert!(state.contains("'dbe_replication'"));
        assert!(ensure.contains("COMMENT ON ROLE"));
        assert!(ensure.contains("dbe-managed-replication-v1"));
        let ownership = replication_role_ownership_sql();
        let comment = replication_role_comment_sql();
        for token in ["missing", "owned", "candidate", "foreign"] {
            assert!(ownership.contains(&format!("'{token}'")), "{token}");
        }
        assert!(ownership.contains("dbe-managed-replication-v1"));
        assert!(ownership.contains(REPLICATION_ROLE_STATE));
        assert!(ownership.contains("pg_auth_members"));
        assert!(ownership.contains("datdba"));
        assert!(ownership.contains(&replication_attribute_sql("r")));
        assert!(state.contains(&replication_attribute_sql("pg_roles")));
        let lowered = ownership.to_ascii_lowercase();
        assert!(!lowered.contains("alter "));
        assert!(!lowered.contains("create role"));
        assert!(!lowered.contains("comment on"));
        assert!(!lowered.contains("password"));
        assert!(comment.starts_with("COMMENT ON ROLE \"dbe_replication\" IS "));
        assert!(!comment.to_ascii_lowercase().contains("alter"));
        assert!(!comment.to_ascii_lowercase().contains("password"));
        assert_eq!(
            parse_replication_role_ownership("missing"),
            Some(ReplicationRoleOwnership::Missing)
        );
        assert_eq!(
            parse_replication_role_ownership("owned"),
            Some(ReplicationRoleOwnership::Owned)
        );
        assert_eq!(
            parse_replication_role_ownership("candidate"),
            Some(ReplicationRoleOwnership::Candidate)
        );
        assert_eq!(
            parse_replication_role_ownership("foreign"),
            Some(ReplicationRoleOwnership::Foreign)
        );
        assert_eq!(parse_replication_role_ownership("nope"), None);
        let preflight = replication_role_ownership_preflight_sql();
        assert!(preflight.starts_with("SELECT 'role_ownership=' || ("));
        assert!(preflight.contains("'foreign'"));
        assert!(preflight.ends_with(");"));
        assert!(!preflight.to_ascii_lowercase().contains("alter "));
        let diagnostic = foreign_replication_role_diagnostic();
        assert!(diagnostic.contains(REPLICATION_ROLE));
        assert!(diagnostic.contains(REPLICATION_ROLE_COMMENT));
        assert!(diagnostic.contains("rename or drop"));
        assert_eq!(MAX_INVENTORY_DATABASES, 64);
        assert!(preflight_script().contains("DBEV_PG_PREFLIGHT_V1"));
        assert!(preflight_script().contains("-gt 64"));
        assert!(preflight_script().contains("pg_ls_waldir"));
        assert!(preflight_script().contains("nspname <> 'pg_toast'"));
        assert!(!preflight_script().contains("hunter2"));
    }

    fn has_pair(argv: &[String], name: &str, value: &str) -> bool {
        argv.windows(2)
            .any(|pair| pair[0] == name && pair[1] == value)
    }
}
