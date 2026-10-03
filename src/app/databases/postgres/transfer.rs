use crate::{
    databases::engine::{
        EngineTransfer, ImportConnection, LogicalCredential, LogicalImportRequest, RemoteDumpFlow,
        SelectionUse, TransferError,
    },
    instance::metadata::InstanceMetadata,
    instance::placement::DeploymentMode,
    subsystems::import_export::{ImportExportSelection, SelectionMode},
    utils::shell::sh_quote,
};

use super::engine::Postgres;

impl EngineTransfer for Postgres {
    fn validate_selection_items(
        &self,
        selection: &ImportExportSelection,
        use_case: SelectionUse,
    ) -> Result<(), TransferError> {
        self.validate_sql_selection_items(selection, use_case)
    }

    fn logical_credential_for_export(&self, _deployment_mode: DeploymentMode) -> LogicalCredential {
        LogicalCredential::Tenant {
            username: "DBE_POSTGRES_USER",
            password: "DBE_POSTGRES_PASSWORD",
        }
    }

    fn logical_credential_for_import(
        &self,
        _deployment_mode: DeploymentMode,
        _database_definition_in_dump: bool,
    ) -> LogicalCredential {
        LogicalCredential::Tenant {
            username: "DBE_POSTGRES_USER",
            password: "DBE_POSTGRES_PASSWORD",
        }
    }

    fn remote_dump_flow(&self) -> RemoteDumpFlow {
        RemoteDumpFlow::Postgres
    }

    fn remote_dump_output_name(&self) -> Option<&'static str> {
        Some("source.postgres.sql")
    }

    fn logical_export_script(
        &self,
        _metadata: &InstanceMetadata,
        output_path: &str,
        selection: &ImportExportSelection,
        _include_database_definition: bool,
    ) -> Result<String, TransferError> {
        let filters = postgres_dump_selection_args(selection)?;
        Ok(format!(
            r#"set -eu
PGPASSWORD="$DBE_POSTGRES_PASSWORD" pg_dump \
  -h /var/run/postgresql \
  -U "$DBE_POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  --clean --if-exists --no-owner --no-privileges{filters} \
  > {output_path}
"#
        ))
    }

    fn logical_wipe_script(
        &self,
        metadata: &InstanceMetadata,
        _database_definition_in_dump: bool,
    ) -> Result<String, TransferError> {
        let script = if metadata.deployment_mode == DeploymentMode::Shared {
            SHARED_WIPE_SCRIPT
        } else {
            DEDICATED_WIPE_SCRIPT
        };
        Ok(script.to_string())
    }

    fn logical_import_script(
        &self,
        request: &LogicalImportRequest<'_>,
    ) -> Result<String, TransferError> {
        let input_path = request.input_path;
        let host = match request.connection {
            ImportConnection::LocalSocket => "/var/run/postgresql",
            ImportConnection::PoolLoopback => "127.0.0.1",
        };
        let restrict_key = format!("dbev{}", uuid::Uuid::new_v4().simple());
        let input = match request.postgres_wrapper_lines {
            Some((restrict_line, unrestrict_line))
                if restrict_line > 0 && unrestrict_line > restrict_line =>
            {
                format!(
                    "command -v sed >/dev/null\nsed -e '{restrict_line}d' -e '{unrestrict_line}d' {input_path}"
                )
            }
            Some(_) => {
                return Err(TransferError::Runtime(
                    "PostgreSQL dump wrapper line numbers are invalid".to_string(),
                ));
            }
            None => format!("cat {input_path}"),
        };
        Ok(format!(
            r#"set -eu
{{ printf '%s\n' '\restrict {restrict_key}'; {input}; }} | \
PGPASSWORD="$DBE_POSTGRES_PASSWORD" psql \
  --no-psqlrc \
  -h {host} \
  -U "$DBE_POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 \
  -f -
"#
        ))
    }
}

fn postgres_dump_selection_args(
    selection: &ImportExportSelection,
) -> Result<String, TransferError> {
    if selection.mode == SelectionMode::Full {
        return Ok(String::new());
    }
    let mut args = String::new();
    for item in &selection.include {
        args.push_str(" --table=");
        args.push_str(&sh_quote(item));
    }
    for item in &selection.exclude {
        args.push_str(" --exclude-table=");
        args.push_str(&sh_quote(item));
    }
    Ok(args)
}

const SHARED_WIPE_SCRIPT: &str = r#"set -eu
PGPASSWORD="$DBE_POSTGRES_PASSWORD" psql \
  -X -h /var/run/postgresql \
  -U "$DBE_POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 <<'DBEV_SQL'
SELECT format('DROP SCHEMA %I CASCADE;', nspname)
FROM pg_namespace
WHERE nspowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
  AND nspname <> 'public'
  AND nspname <> 'information_schema'
  AND nspname NOT LIKE 'pg_%'
ORDER BY nspname
\gexec
SELECT format('DROP %s %I.%I CASCADE;',
  CASE c.relkind
    WHEN 'S' THEN 'SEQUENCE'
    WHEN 'v' THEN 'VIEW'
    WHEN 'm' THEN 'MATERIALIZED VIEW'
    WHEN 'f' THEN 'FOREIGN TABLE'
    ELSE 'TABLE'
  END,
  n.nspname,
  c.relname)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
  AND n.nspname = 'public'
  AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
ORDER BY CASE c.relkind WHEN 'v' THEN 0 WHEN 'm' THEN 0 ELSE 1 END, c.relname
\gexec
SELECT format('DROP ROUTINE %I.%I(%s) CASCADE;',
  n.nspname, p.proname, pg_get_function_identity_arguments(p.oid))
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
  AND n.nspname = 'public'
ORDER BY p.proname
\gexec
SELECT format('DROP %s %I.%I CASCADE;',
  CASE t.typtype WHEN 'd' THEN 'DOMAIN' ELSE 'TYPE' END,
  n.nspname,
  t.typname)
FROM pg_type t
JOIN pg_namespace n ON n.oid = t.typnamespace
WHERE t.typowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
  AND n.nspname = 'public'
  AND t.typtype IN ('d', 'e', 'c', 'r')
  AND NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = t.typrelid)
ORDER BY t.typname
\gexec
DBEV_SQL
"#;

const DEDICATED_WIPE_SCRIPT: &str = r#"set -eu
PGPASSWORD="$DBE_POSTGRES_PASSWORD" psql \
  -h /var/run/postgresql \
  -U "$DBE_POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 <<'DBEV_SQL'
DO $dbev$
DECLARE schema_name text;
BEGIN
  FOR schema_name IN
    SELECT nspname
    FROM pg_namespace
    WHERE nspname <> 'information_schema'
      AND nspname NOT LIKE 'pg_%'
  LOOP
    EXECUTE format('DROP SCHEMA %I CASCADE', schema_name);
  END LOOP;
END
$dbev$;
CREATE SCHEMA public AUTHORIZATION CURRENT_USER;
DBEV_SQL
"#;
