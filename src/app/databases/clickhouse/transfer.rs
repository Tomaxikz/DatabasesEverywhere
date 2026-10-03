use crate::{
    databases::engine::{
        EngineTransfer, LogicalCredential, LogicalImportRequest, RemoteDumpFlow, SelectionUse,
        TransferError,
    },
    instance::metadata::InstanceMetadata,
    instance::placement::DeploymentMode,
    subsystems::import_export::{
        CLICKHOUSE_ENGINE_AWK_PROGRAM, ImportExportSelection, SelectionMode,
    },
    utils::{ids::portable_identifier, shell::sh_quote},
};

use super::engine::Clickhouse;

impl EngineTransfer for Clickhouse {
    fn validate_selection_items(
        &self,
        selection: &ImportExportSelection,
        _use_case: SelectionUse,
    ) -> Result<(), TransferError> {
        for item in selection.include.iter().chain(selection.exclude.iter()) {
            self.validate_simple_identifier("clickhouse table", item)?;
        }
        for (table, fields) in &selection.fields {
            self.validate_simple_identifier("clickhouse table", table)?;
            for field in fields {
                self.validate_simple_identifier("clickhouse column", field)?;
            }
        }
        Ok(())
    }

    fn logical_credential_for_export(&self, _deployment_mode: DeploymentMode) -> LogicalCredential {
        clickhouse_credential()
    }

    fn logical_credential_for_import(
        &self,
        _deployment_mode: DeploymentMode,
        _database_definition_in_dump: bool,
    ) -> LogicalCredential {
        clickhouse_credential()
    }

    fn logical_export_script(
        &self,
        _metadata: &InstanceMetadata,
        output_path: &str,
        selection: &ImportExportSelection,
        _include_database_definition: bool,
    ) -> Result<String, TransferError> {
        let table_source = clickhouse_table_source(selection)?;
        let column_expr = clickhouse_column_expr(selection)?;
        let engine_parser = sh_quote(CLICKHOUSE_ENGINE_AWK_PROGRAM);
        Ok(format!(
            r#"set -eu
out={output_path}
printf '%s\n' '-- DatabasesEverywhere ClickHouse logical dump' > "$out"
{{ {table_source} || printf '\n!DBEV_TABLE_LIST_FAILED\n'; }} | while IFS= read -r table; do
    [ -n "$table" ] || continue
    case "$table" in
      '!DBEV_TABLE_LIST_FAILED') echo 'failed to list ClickHouse tables' >&2; exit 44 ;;
      *[!A-Za-z0-9_-]*)
      echo 'target clickhouse contains a non-portable table name' >&2
      exit 42
    ;; esac
    kind=$(clickhouse-client \
      --host 127.0.0.1 \
      --user "$CLICKHOUSE_USER" \
      --password "$CLICKHOUSE_PASSWORD" \
      --database "$CLICKHOUSE_DB" \
      --query "SELECT engine FROM system.tables WHERE database = currentDatabase() AND name = '$table' FORMAT TSVRaw")
    case "$kind" in
      View)
        create=$(clickhouse-client \
          --host 127.0.0.1 \
          --user "$CLICKHOUSE_USER" \
          --password "$CLICKHOUSE_PASSWORD" \
          --database "$CLICKHOUSE_DB" \
          --query "SHOW CREATE TABLE \`$table\` FORMAT TabSeparatedRaw")
        printf 'DROP VIEW IF EXISTS `%s`;\n' "$table" >> "$out"
        printf '%s\n;\n' "$create" >> "$out"
        continue
      ;;
      MaterializedView|LiveView|WindowView|Dictionary|'')
        echo 'target clickhouse contains an object that cannot be represented by a safe tenant rollback dump' >&2
        exit 43
      ;;
    esac
    create=$(clickhouse-client \
      --host 127.0.0.1 \
      --user "$CLICKHOUSE_USER" \
      --password "$CLICKHOUSE_PASSWORD" \
      --database "$CLICKHOUSE_DB" \
      --query "SHOW CREATE TABLE \`$table\` FORMAT TabSeparatedRaw")
    engine=$(printf '%s\n' "$create" | awk {engine_parser}) || {{
      echo 'target clickhouse SHOW CREATE must contain exactly one valid ENGINE clause' >&2
      exit 43
    }}
    case "$engine" in
      MergeTree|ReplacingMergeTree|SummingMergeTree|AggregatingMergeTree|CollapsingMergeTree|VersionedCollapsingMergeTree|GraphiteMergeTree|CoalescingMergeTree|Log|TinyLog|StripeLog|Memory) ;;
      *)
        echo 'target clickhouse table uses an unsupported or non-portable table engine' >&2
        exit 43
      ;;
    esac
    columns=$({column_expr})
    printf 'DROP TABLE IF EXISTS `%s`;\n' "$table" >> "$out"
    printf '%s\n' "$create" >> "$out"
    printf ';\n' >> "$out"
    clickhouse-client \
      --host 127.0.0.1 \
      --user "$CLICKHOUSE_USER" \
      --password "$CLICKHOUSE_PASSWORD" \
      --database "$CLICKHOUSE_DB" \
      --output_format_sql_insert_table_name="$table" \
      --query "SELECT $columns FROM \`$table\` FORMAT SQLInsert" >> "$out"
    printf '\n' >> "$out"
  done
"#
        ))
    }

    fn logical_wipe_script(
        &self,
        _metadata: &InstanceMetadata,
        _database_definition_in_dump: bool,
    ) -> Result<String, TransferError> {
        Ok(WIPE_SCRIPT.to_string())
    }

    fn logical_import_script(
        &self,
        request: &LogicalImportRequest<'_>,
    ) -> Result<String, TransferError> {
        let input_path = request.input_path;
        Ok(format!(
            r#"set -eu
clickhouse-client \
  --host 127.0.0.1 \
  --user "$CLICKHOUSE_USER" \
  --password "$CLICKHOUSE_PASSWORD" \
  --database "$CLICKHOUSE_DB" \
  --multiquery \
  < {input_path}
"#
        ))
    }

    fn shared_wipe_uses_admin_runtime(&self) -> bool {
        true
    }

    fn validate_remote_database_name(&self, database: Option<&str>) -> Result<(), TransferError> {
        if !database.is_some_and(|value| portable_identifier(value, 128)) {
            return Err(TransferError::BadRequest(
                "clickhouse source.database must be at most 128 bytes and use only ascii letters, digits, underscore, or dash"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn remote_dump_flow(&self) -> RemoteDumpFlow {
        RemoteDumpFlow::Clickhouse
    }

    fn remote_dump_output_name(&self) -> Option<&'static str> {
        Some("source.clickhouse.sql")
    }
}

fn clickhouse_credential() -> LogicalCredential {
    LogicalCredential::Tenant {
        username: "CLICKHOUSE_USER",
        password: "CLICKHOUSE_PASSWORD",
    }
}

fn clickhouse_table_source(selection: &ImportExportSelection) -> Result<String, TransferError> {
    if selection.mode == SelectionMode::Full {
        return Ok(r#"clickhouse-client \
  --host 127.0.0.1 \
  --user "$CLICKHOUSE_USER" \
  --password "$CLICKHOUSE_PASSWORD" \
  --database "$CLICKHOUSE_DB" \
  --query "SELECT name FROM system.tables WHERE database = currentDatabase() ORDER BY engine = 'View', name FORMAT TSVRaw""#
            .to_string());
    }
    Ok(format!(
        "printf '%s\\n' {}",
        sh_quote(&selection.include.join("\n"))
    ))
}

fn clickhouse_column_expr(selection: &ImportExportSelection) -> Result<String, TransferError> {
    if selection.fields.is_empty() {
        return Ok(r#"printf '*'"#.to_string());
    }
    let mut cases = String::from("case \"$table\" in\n");
    for (table, fields) in &selection.fields {
        let columns = fields
            .iter()
            .map(|field| format!("`{field}`"))
            .collect::<Vec<_>>()
            .join(", ");
        cases.push_str(&format!(
            "  {}) printf '%s' {} ;;\n",
            sh_quote(table),
            sh_quote(&columns)
        ));
    }
    cases.push_str("  *) printf '*' ;;\nesac");
    Ok(cases)
}

const WIPE_SCRIPT: &str = r#"set -eu
{
clickhouse-client \
  --host 127.0.0.1 \
  --user "$CLICKHOUSE_USER" \
  --password "$CLICKHOUSE_PASSWORD" \
  --database "$CLICKHOUSE_DB" \
  --query "SELECT name FROM system.tables WHERE database = currentDatabase() ORDER BY engine != 'View', name FORMAT TSVRaw" || printf '\n!DBEV_TABLE_LIST_FAILED\n'
} | while IFS= read -r table; do
  [ -n "$table" ] || continue
  case "$table" in
    '!DBEV_TABLE_LIST_FAILED') echo 'failed to list ClickHouse tables' >&2; exit 44 ;;
    *[!A-Za-z0-9_-]*)
    echo 'target clickhouse contains a non-portable table name' >&2
    exit 42
  ;; esac
  kind=$(clickhouse-client \
    --host 127.0.0.1 \
    --user "$CLICKHOUSE_USER" \
    --password "$CLICKHOUSE_PASSWORD" \
    --database "$CLICKHOUSE_DB" \
    --query "SELECT engine FROM system.tables WHERE database = currentDatabase() AND name = '$table' FORMAT TSVRaw")
  case "$kind" in
    View) drop='DROP VIEW' ;;
    MaterializedView|LiveView|WindowView|Dictionary|'')
      echo 'target clickhouse contains an object that cannot be wiped by the safe tenant restore path' >&2
      exit 43
    ;;
    *) drop='DROP TABLE' ;;
  esac
  clickhouse-client \
    --host 127.0.0.1 \
    --user "$CLICKHOUSE_USER" \
    --password "$CLICKHOUSE_PASSWORD" \
    --database "$CLICKHOUSE_DB" \
    --query "$drop IF EXISTS \`$table\` SYNC"
done
"#;
