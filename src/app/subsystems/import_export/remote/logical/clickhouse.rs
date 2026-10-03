use super::*;

pub(super) async fn prepare_clickhouse(
    source: &RemoteImportSource,
    selection: &ImportExportSelection,
    work_dir: &Path,
    connect_timeout_seconds: u64,
) -> Result<String, ApiError> {
    let database = required(source.database.as_deref(), "source.database")?;
    let username = required(source.username.as_deref(), "source.username")?;
    let password = required_secret(source.password.as_ref(), "source.password")?;
    if !portable_identifier(database, 128) {
        return Err(ApiError::BadRequest(
            "clickhouse source.database must use ascii letters, digits, underscore, or dash"
                .to_string(),
        ));
    }
    let secure = if source.endpoint.tls { "true" } else { "false" };
    let tls_validation = if source.endpoint.tls {
        r#"<openSSL><client><loadDefaultCAFile>true</loadDefaultCAFile><verificationMode>strict</verificationMode><invalidCertificateHandler><name>RejectCertificateHandler</name></invalidCertificateHandler></client></openSSL>"#
    } else {
        ""
    };
    let config = format!(
        "<clickhouse><host>{}</host><port>{}</port><user>{}</user><password>{}</password><database>{}</database><secure>{secure}</secure><connect_timeout>{connect_timeout_seconds}</connect_timeout>{tls_validation}</clickhouse>\n",
        xml_escape(&source.endpoint.host),
        source.endpoint.port,
        xml_escape(username),
        xml_escape(password),
        xml_escape(database),
    );
    write_private_file(&work_dir.join("clickhouse-client.xml"), config.as_bytes()).await?;

    let (table_source, exclude_case) = clickhouse_table_selection(selection);
    let column_case = clickhouse_column_selection(selection);
    let database_shell = sh_quote(database);
    let rebase_create = CLICKHOUSE_REBASE_CREATE_SCRIPT;
    let engine_parser = sh_quote(CLICKHOUSE_ENGINE_AWK_PROGRAM);
    Ok(format!(
        r#"set -eu
umask 077
client='clickhouse-client --config-file=/work/clickhouse-client.xml'
database={database_shell}
$client --query 'SELECT version()' >/work/source-version
printf '%s\n' '-- DatabasesEverywhere ClickHouse logical dump' > /work/source.clickhouse.sql
{{ {table_source} || printf '\n!DBEV_TABLE_LIST_FAILED\n'; }} | while IFS= read -r table; do
  [ -n "$table" ] || continue
  case "$table" in
    '!DBEV_TABLE_LIST_FAILED') echo 'failed to list ClickHouse tables' >&2; exit 44 ;;
    *[!A-Za-z0-9_-]*)
    echo 'remote clickhouse contains a non-portable table name' >&2
    exit 40
  ;; esac
  {exclude_case}
  create=$($client --query "SHOW CREATE TABLE \`$table\` FORMAT TabSeparatedRaw")
  engine=$(printf '%s\n' "$create" | awk {engine_parser}) || {{
    echo 'remote clickhouse SHOW CREATE must contain exactly one valid ENGINE clause' >&2
    exit 41
  }}
  case "$engine" in
    MergeTree|ReplacingMergeTree|SummingMergeTree|AggregatingMergeTree|CollapsingMergeTree|VersionedCollapsingMergeTree|GraphiteMergeTree|CoalescingMergeTree|Log|TinyLog|StripeLog|Memory) ;;
    *)
      echo 'remote clickhouse table uses an unsupported or non-portable table engine' >&2
      exit 41
    ;;
  esac
  columns=$({column_case})
  printf 'DROP TABLE IF EXISTS `%s`;\n' "$table" >> /work/source.clickhouse.sql
  {rebase_create} >> /work/source.clickhouse.sql
  printf ';\n' >> /work/source.clickhouse.sql
  $client \
    --output_format_sql_insert_table_name="$table" \
    --query "SELECT $columns FROM \`$table\` FORMAT SQLInsert" >> /work/source.clickhouse.sql
  printf '\n' >> /work/source.clickhouse.sql
done
"#
    ))
}

pub(super) const CLICKHOUSE_REBASE_CREATE_SCRIPT: &str = r#"quoted_qualified="CREATE TABLE \`$database\`.\`$table\`"
plain_qualified="CREATE TABLE $database.$table"
quoted_local="CREATE TABLE \`$table\`"
plain_local="CREATE TABLE $table"
case "$create" in
  "$quoted_qualified"*) suffix=${create#"$quoted_qualified"} ;;
  "$plain_qualified"*)  suffix=${create#"$plain_qualified"} ;;
  "$quoted_local"*)     suffix=${create#"$quoted_local"} ;;
  "$plain_local"*)      suffix=${create#"$plain_local"} ;;
  *)
    echo 'remote clickhouse SHOW CREATE returned an unexpected table identifier' >&2
    exit 42
  ;;
esac
case "$suffix" in
  ''|[[:space:]]*|'('*) ;;
  *)
    echo 'remote clickhouse SHOW CREATE table identifier was ambiguous' >&2
    exit 43
  ;;
esac
printf 'CREATE TABLE `%s`%s\n' "$table" "$suffix""#;

pub(super) fn clickhouse_table_selection(selection: &ImportExportSelection) -> (String, String) {
    let source = if selection.mode == SelectionMode::Full {
        "$client --query 'SHOW TABLES FORMAT TSVRaw'".to_string()
    } else {
        format!("printf '%s\\n' {}", sh_quote(&selection.include.join("\n")))
    };
    if selection.exclude.is_empty() {
        return (source, ":".to_string());
    }
    let patterns = selection
        .exclude
        .iter()
        .map(|table| sh_quote(table))
        .collect::<Vec<_>>()
        .join("|");
    (
        source,
        format!("case \"$table\" in {patterns}) continue ;; esac"),
    )
}

pub(super) fn clickhouse_column_selection(selection: &ImportExportSelection) -> String {
    if selection.fields.is_empty() {
        return "printf '*'".to_string();
    }
    let mut cases = String::from("case \"$table\" in ");
    for (table, fields) in &selection.fields {
        let fields = fields
            .iter()
            .map(|field| format!("`{field}`"))
            .collect::<Vec<_>>()
            .join(", ");
        cases.push_str(&format!(
            "{}) printf '%s' {} ;; ",
            sh_quote(table),
            sh_quote(&fields)
        ));
    }
    cases.push_str("*) printf '*' ;; esac");
    cases
}
