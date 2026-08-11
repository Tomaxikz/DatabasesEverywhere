//! Protocol-specific selection validation and native dump/restore scripts.

use super::{files::*, *};
use crate::instances::credentials::logical_import_environment;

pub(super) async fn validate_import_source(
    _state: &AppState,
    target_protocol: Protocol,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    match &options.source {
        ImportSourceOptions::Artifact(path) => {
            if path.as_os_str().is_empty() {
                return Err(ApiError::BadRequest(
                    "artifact import requires source.artifact_id".to_string(),
                ));
            }
            validate_logical_artifact_selection(target_protocol, &options.selection)?;
            if matches!(
                target_protocol,
                Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
            ) && options.archive_format.is_some()
            {
                return Err(ApiError::BadRequest(format!(
                    "{} artifact imports consume their physical archive directly; omit archive_format",
                    target_protocol.as_str()
                )));
            }
        }
        ImportSourceOptions::Upload { upload_id, .. } => {
            if upload_id.is_empty() {
                return Err(ApiError::BadRequest(
                    "upload import requires source.upload_id".to_string(),
                ));
            }
            validate_logical_artifact_selection(target_protocol, &options.selection)?;
            if options.archive_format.is_some() {
                return Err(ApiError::BadRequest(
                    "upload imports detect their format from the uploaded file; omit archive_format"
                        .to_string(),
                ));
            }
        }
        ImportSourceOptions::RemoteRequest(_) | ImportSourceOptions::Remote(_) => {
            if options.archive_format.is_some() {
                return Err(ApiError::BadRequest(
                    "remote imports create their own native dump; omit archive_format".to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_upload_source_database(
    target_protocol: Protocol,
    options: &ImportOptions,
) -> Result<(), ApiError> {
    if !matches!(&options.source, ImportSourceOptions::Upload { .. }) {
        if options.source_database.is_some() {
            return Err(ApiError::BadRequest(
                "source.source_database is supported only for temporary uploads".to_string(),
            ));
        }
        return Ok(());
    }
    match (target_protocol, options.source_database.as_deref()) {
        (Protocol::Mongodb, Some(source_database)) => {
            crate::api::remote_import::validate_mongodb_database_name(
                "source.source_database",
                source_database,
                false,
            )
        }
        (Protocol::Mongodb, None) => Ok(()),
        (_, Some(_)) => Err(ApiError::BadRequest(
            "source.source_database is supported only for mongodb upload imports".to_string(),
        )),
        (_, None) => Ok(()),
    }
}

pub(super) async fn harden_import_options(
    state: &AppState,
    instance_id: &str,
    target_protocol: Protocol,
    mut options: ImportOptions,
) -> Result<ImportOptions, ApiError> {
    validate_import_source(state, target_protocol, &options).await?;
    validate_upload_source_database(target_protocol, &options)?;
    let source = std::mem::take(&mut options.source);
    options.source = match source {
        ImportSourceOptions::Artifact(path) => {
            ImportSourceOptions::Artifact(validate_artifact_path(state, instance_id, &path).await?)
        }
        ImportSourceOptions::Upload { upload_id, .. } => {
            let (source, archive_format) = super::uploads::harden_upload_source(
                state,
                instance_id,
                target_protocol,
                upload_id,
            )
            .await?;
            options.archive_format = archive_format;
            source
        }
        ImportSourceOptions::RemoteRequest(request) => ImportSourceOptions::Remote(
            validate_remote_source(state, target_protocol, request).await?,
        ),
        ImportSourceOptions::Remote(source) => ImportSourceOptions::Remote(source),
    };
    Ok(options)
}

#[derive(Debug, Clone, Copy)]
pub(super) enum SelectionUse {
    Export,
    Import,
}

pub(super) fn validate_selection(
    protocol: Protocol,
    selection: &ImportExportSelection,
    use_case: SelectionUse,
) -> Result<(), ApiError> {
    if selection.include.len() > MAX_SELECTION_ITEMS
        || selection.exclude.len() > MAX_SELECTION_ITEMS
    {
        return Err(ApiError::BadRequest(format!(
            "selection include/exclude may contain at most {MAX_SELECTION_ITEMS} items"
        )));
    }
    if selection.fields.len() > MAX_SELECTION_ITEMS {
        return Err(ApiError::BadRequest(format!(
            "selection fields may contain at most {MAX_SELECTION_ITEMS} objects"
        )));
    }
    for fields in selection.fields.values() {
        if fields.len() > MAX_SELECTION_FIELDS_PER_ITEM {
            return Err(ApiError::BadRequest(format!(
                "selection fields for one object may contain at most {MAX_SELECTION_FIELDS_PER_ITEM} fields"
            )));
        }
    }

    if selection.mode == SelectionMode::Full {
        if !selection.include.is_empty()
            || !selection.exclude.is_empty()
            || !selection.fields.is_empty()
        {
            return Err(ApiError::BadRequest(
                "selection.mode=full must not include include/exclude/fields".to_string(),
            ));
        }
        return Ok(());
    }

    if selection.include.is_empty() {
        return Err(ApiError::BadRequest(
            "selection.mode=selective requires at least one include item".to_string(),
        ));
    }
    if let Some(overlap) = selection
        .include
        .iter()
        .find(|item| selection.exclude.contains(*item))
    {
        return Err(ApiError::BadRequest(format!(
            "selection cannot both include and exclude {overlap}"
        )));
    }

    match protocol {
        Protocol::Postgres | Protocol::Mariadb | Protocol::Mysql => {
            for item in selection.include.iter().chain(selection.exclude.iter()) {
                validate_sql_object_name(protocol, item)?;
            }
            if !selection.fields.is_empty() {
                return Err(ApiError::NotImplemented(format!(
                    "{} column-level selective {} is not implemented yet; use table-level selection",
                    protocol.as_str(),
                    selection_use_name(use_case)
                )));
            }
        }
        Protocol::Mongodb => {
            for item in selection.include.iter().chain(selection.exclude.iter()) {
                validate_simple_identifier("mongodb collection", item)?;
            }
            let mut included_collections = HashSet::with_capacity(selection.include.len());
            if let Some(duplicate) = selection
                .include
                .iter()
                .find(|collection| !included_collections.insert(collection.as_str()))
            {
                return Err(ApiError::BadRequest(format!(
                    "mongodb selection includes collection {duplicate} more than once"
                )));
            }
            if matches!(use_case, SelectionUse::Export) && selection.include.len() != 1 {
                return Err(ApiError::NotImplemented(format!(
                    "mongodb selective {} currently supports exactly one included collection",
                    selection_use_name(use_case)
                )));
            }
            if !selection.fields.is_empty() {
                return Err(ApiError::NotImplemented(
                    "mongodb field projection is not implemented yet; use collection-level selection".to_string(),
                ));
            }
        }
        Protocol::Clickhouse => {
            for item in selection.include.iter().chain(selection.exclude.iter()) {
                validate_simple_identifier("clickhouse table", item)?;
            }
            for (table, fields) in &selection.fields {
                validate_simple_identifier("clickhouse table", table)?;
                for field in fields {
                    validate_simple_identifier("clickhouse column", field)?;
                }
            }
        }
        Protocol::Redis => {
            return Err(ApiError::NotImplemented(
                "redis selective import/export requires a logical key dump format and is not implemented yet".to_string(),
            ));
        }
        Protocol::Valkey => {
            return Err(ApiError::NotImplemented(
                "valkey selective import/export requires a logical key dump format and is not implemented yet".to_string(),
            ));
        }
        Protocol::Qdrant => {
            for item in selection.include.iter().chain(selection.exclude.iter()) {
                validate_simple_identifier("qdrant collection", item)?;
            }
            if !selection.fields.is_empty() {
                return Err(ApiError::NotImplemented(
                    "qdrant field-level selection is not implemented; use collection-level selection"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn selection_use_name(use_case: SelectionUse) -> &'static str {
    match use_case {
        SelectionUse::Export => "export",
        SelectionUse::Import => "import",
    }
}

pub(super) fn ensure_full_selection(
    protocol: Protocol,
    selection: &ImportExportSelection,
) -> Result<(), ApiError> {
    if selection.mode == SelectionMode::Full
        && selection.include.is_empty()
        && selection.exclude.is_empty()
        && selection.fields.is_empty()
    {
        return Ok(());
    }
    Err(ApiError::BadRequest(format!(
        "{} artifact import/export path only accepts selection.mode=full; create a selective export artifact or use remote selective import",
        protocol.as_str()
    )))
}

pub(super) fn validate_sql_object_name(protocol: Protocol, value: &str) -> Result<(), ApiError> {
    let parts: Vec<_> = value.split('.').collect();
    let valid = match protocol {
        Protocol::Postgres => (1..=2).contains(&parts.len()),
        Protocol::Mariadb => (1..=2).contains(&parts.len()),
        Protocol::Mysql => (1..=2).contains(&parts.len()),
        _ => false,
    } && parts
        .iter()
        .all(|part| !part.is_empty() && simple_identifier(part));
    if valid {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "invalid {} object name {value}; use ascii identifiers like table or schema.table",
            protocol.as_str()
        )))
    }
}

pub(super) fn validate_simple_identifier(kind: &str, value: &str) -> Result<(), ApiError> {
    if simple_identifier(value) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "invalid {kind} {value}; use ascii letters, digits, underscore, or dash"
        )))
    }
}

pub(super) fn simple_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(super) fn postgres_dump_selection_args(
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
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

pub(super) fn mariadb_local_dump_selection_args(
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(" -- \"$MARIADB_DATABASE\"".to_string());
    }
    let mut args = String::new();
    for item in &selection.exclude {
        let table = item
            .rsplit_once('.')
            .map(|(_, table)| table)
            .unwrap_or(item);
        args.push_str(&format!(" --ignore-table=\"$MARIADB_DATABASE.{table}\""));
    }
    args.push_str(" -- \"$MARIADB_DATABASE\"");
    for item in &selection.include {
        let table = item
            .rsplit_once('.')
            .map(|(_, table)| table)
            .unwrap_or(item);
        args.push(' ');
        args.push_str(&sh_quote(table));
    }
    Ok(args)
}

pub(super) fn mysql_local_dump_selection_args(
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(" -- \"$MYSQL_DATABASE\"".to_string());
    }
    let mut args = String::new();
    for item in &selection.exclude {
        let table = item
            .rsplit_once('.')
            .map(|(_, table)| table)
            .unwrap_or(item);
        args.push_str(&format!(" --ignore-table=\"$MYSQL_DATABASE.{table}\""));
    }
    args.push_str(" -- \"$MYSQL_DATABASE\"");
    for item in &selection.include {
        let table = item
            .rsplit_once('.')
            .map(|(_, table)| table)
            .unwrap_or(item);
        args.push(' ');
        args.push_str(&sh_quote(table));
    }
    Ok(args)
}

pub(super) fn mongodb_dump_selection_args(
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(String::new());
    }
    let mut args = String::new();
    let collection = selection.include.first().ok_or_else(|| {
        ApiError::BadRequest(
            "mongodb selective export requires one included collection".to_string(),
        )
    })?;
    args.push_str(" --collection=");
    args.push_str(&sh_quote(collection));
    Ok(args)
}

pub(super) fn clickhouse_table_source(
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(r#"clickhouse-client \
  --host 127.0.0.1 \
  --user "$CLICKHOUSE_USER" \
  --password "$CLICKHOUSE_PASSWORD" \
  --database "$CLICKHOUSE_DB" \
  --query "SHOW TABLES FORMAT TSV""#
            .to_string());
    }
    Ok(format!(
        "printf '%s\\n' {}",
        sh_quote(&selection.include.join("\n"))
    ))
}

pub(super) fn validate_logical_artifact_selection(
    protocol: Protocol,
    selection: &ImportExportSelection,
) -> Result<(), ApiError> {
    if protocol == Protocol::Mongodb {
        validate_selection(protocol, selection, SelectionUse::Import)
    } else {
        ensure_full_selection(protocol, selection)
    }
}

pub(super) fn clickhouse_column_expr_function(
    selection: &ImportExportSelection,
) -> Result<String, ApiError> {
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

pub(super) fn ensure_mongodb_root_password(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if metadata.protocol == Protocol::Mongodb && metadata.mongodb_root_password.is_none() {
        return Err(ApiError::BadRequest(
            "mongodb internal root password is missing; this instance was created before DBE stored MongoDB maintenance credentials, so DBE cannot export/import protected internal collections such as time-series buckets. Recreate the instance or use a manual admin dump.".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_mysql_root_password(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if metadata.protocol == Protocol::Mysql && metadata.mysql_root_password.is_none() {
        return Err(ApiError::BadRequest(
            "mysql internal root password is missing; recreate or repair this instance before exporting or importing"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) fn export_script(
    metadata: &InstanceMetadata,
    output_path: &str,
    selection: &ImportExportSelection,
    include_database_definition: bool,
) -> Result<String, ApiError> {
    let protocol = metadata.protocol;
    let script = match protocol {
        Protocol::Postgres => {
            let filters = postgres_dump_selection_args(selection)?;
            format!(
                r#"set -eu
PGPASSWORD="$DBE_POSTGRES_PASSWORD" pg_dump \
  -h /var/run/postgresql \
  -U "$DBE_POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  --clean --if-exists --no-owner --no-privileges{filters} \
  > {output_path}
"#
            )
        }
        Protocol::Mariadb => {
            let filters = mariadb_local_dump_selection_args(selection)?;
            let database_definition = if include_database_definition {
                " --databases"
            } else {
                ""
            };
            format!(
                r#"set -eu
mariadb-dump \
  --protocol=socket \
  --socket=/run/mysqld/mysqld.sock \
  -u "$MARIADB_USER" \
  -p"$DBE_MARIADB_PASSWORD" \
  --single-transaction --quick --routines --events --triggers \
  --hex-blob --add-drop-table{database_definition}{filters} \
  > {output_path}
"#
            )
        }
        Protocol::Mysql => {
            ensure_mysql_root_password(metadata)?;
            let filters = mysql_local_dump_selection_args(selection)?;
            let database_definition = if include_database_definition {
                " --databases"
            } else {
                ""
            };
            format!(
                r#"set -eu
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump \
  --protocol=socket \
  --socket=/var/run/mysqld/mysqld.sock \
  -u root \
  --single-transaction --quick --routines --events --triggers \
  --hex-blob --add-drop-table --no-tablespaces --set-gtid-purged=OFF{database_definition}{filters} \
  > {output_path}
"#
            )
        }
        Protocol::Mongodb => {
            ensure_mongodb_root_password(metadata)?;
            let filters = mongodb_dump_selection_args(selection)?;
            format!(
                r#"set -eu
mongodump \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_ROOT_USER" \
  --password "$DBE_MONGO_ROOT_PASSWORD" \
  --authenticationDatabase "admin" \
  --db "$DBE_MONGO_DATABASE" \
  {filters} \
  --archive={output_path} \
  --gzip
"#
            )
        }
        Protocol::Clickhouse => {
            let table_source = clickhouse_table_source(selection)?;
            let column_expr = clickhouse_column_expr_function(selection)?;
            let engine_parser = sh_quote(CLICKHOUSE_ENGINE_AWK_PROGRAM);
            format!(
                r#"set -eu
out={output_path}
printf '%s\n' '-- DatabasesEverywhere ClickHouse logical dump' > "$out"
{table_source} | while IFS= read -r table; do
    [ -n "$table" ] || continue
    case "$table" in *[!A-Za-z0-9_-]*)
      echo 'target clickhouse contains a non-portable table name' >&2
      exit 42
    ;; esac
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
            )
        }
        Protocol::Redis => {
            return Err(ApiError::BadRequest(
                "redis uses physical archive export".to_string(),
            ));
        }
        Protocol::Valkey => {
            return Err(ApiError::BadRequest(
                "valkey uses physical archive export".to_string(),
            ));
        }
        Protocol::Qdrant => {
            return Err(ApiError::NotImplemented(
                "qdrant snapshot export is not implemented yet".to_string(),
            ));
        }
    };
    Ok(script)
}

pub(super) fn wipe_logical_script(
    metadata: &InstanceMetadata,
    database_definition_in_dump: bool,
) -> Result<String, ApiError> {
    let script = match metadata.protocol {
        Protocol::Postgres => r#"set -eu
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
"#
        .to_string(),
        Protocol::Mariadb if database_definition_in_dump => r#"set -eu
mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock \
  -u root -p"$DBE_MARIADB_ROOT_PASSWORD" \
  -e "DROP DATABASE IF EXISTS \`$MARIADB_DATABASE\`;"
"#
        .to_string(),
        Protocol::Mariadb => r#"set -eu
settings=$(mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock \
  -u root -p"$DBE_MARIADB_ROOT_PASSWORD" \
  --batch --skip-column-names "$MARIADB_DATABASE" \
  -e 'SELECT @@character_set_database, @@collation_database')
set -- $settings
[ "$#" -eq 2 ] || {
  echo 'failed to read the target database charset and collation' >&2
  exit 43
}
case "$1" in ''|*[!A-Za-z0-9_]*)
  echo 'target database returned an invalid character set name' >&2
  exit 43
;; esac
case "$2" in ''|*[!A-Za-z0-9_]*)
  echo 'target database returned an invalid collation name' >&2
  exit 43
;; esac
mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock \
  -u root -p"$DBE_MARIADB_ROOT_PASSWORD" \
  -e "DROP DATABASE IF EXISTS \`$MARIADB_DATABASE\`; CREATE DATABASE \`$MARIADB_DATABASE\` CHARACTER SET $1 COLLATE $2;"
"#
        .to_string(),
        Protocol::Mysql if database_definition_in_dump => {
            ensure_mysql_root_password(metadata)?;
            r#"set -eu
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql \
  --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root \
  -e "DROP DATABASE IF EXISTS \`$MYSQL_DATABASE\`;"
"#
            .to_string()
        }
        Protocol::Mysql => {
            logical_import_environment(metadata, false)
                .map_err(|error| ApiError::Conflict(error.to_string()))?;
            r#"set -eu
settings=$(MYSQL_PWD="$DBE_IMPORT_PASSWORD" mysql \
  --protocol=socket --socket=/var/run/mysqld/mysqld.sock \
  -u "$DBE_IMPORT_USER" \
  --batch --skip-column-names "$MYSQL_DATABASE" \
  -e 'SELECT @@character_set_database, @@collation_database')
set -- $settings
[ "$#" -eq 2 ] || {
  echo 'failed to read the target database charset and collation' >&2
  exit 43
}
case "$1" in ''|*[!A-Za-z0-9_]*)
  echo 'target database returned an invalid character set name' >&2
  exit 43
;; esac
case "$2" in ''|*[!A-Za-z0-9_]*)
  echo 'target database returned an invalid collation name' >&2
  exit 43
;; esac
MYSQL_PWD="$DBE_IMPORT_PASSWORD" mysql \
  --protocol=socket --socket=/var/run/mysqld/mysqld.sock \
  -u "$DBE_IMPORT_USER" \
  -e "DROP DATABASE IF EXISTS \`$MYSQL_DATABASE\`; CREATE DATABASE \`$MYSQL_DATABASE\` CHARACTER SET $1 COLLATE $2;"
"#
            .to_string()
        }
        Protocol::Mongodb => {
            ensure_mongodb_root_password(metadata)?;
            r#"set -eu
mongosh --quiet \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_ROOT_USER" \
  --password "$DBE_MONGO_ROOT_PASSWORD" \
  --authenticationDatabase admin \
  "$DBE_MONGO_DATABASE" \
  --eval 'db.dropDatabase()'
"#
            .to_string()
        }
        Protocol::Clickhouse => r#"set -eu
clickhouse-client \
  --host 127.0.0.1 \
  --user "$CLICKHOUSE_USER" \
  --password "$CLICKHOUSE_PASSWORD" \
  --database "$CLICKHOUSE_DB" \
  --query 'SHOW TABLES FORMAT TSVRaw' | while IFS= read -r table; do
  [ -n "$table" ] || continue
  case "$table" in *[!A-Za-z0-9_-]*)
    echo 'target clickhouse contains a non-portable table name' >&2
    exit 42
  ;; esac
  clickhouse-client \
    --host 127.0.0.1 \
    --user "$CLICKHOUSE_USER" \
    --password "$CLICKHOUSE_PASSWORD" \
    --database "$CLICKHOUSE_DB" \
    --query "DROP TABLE IF EXISTS \`$table\` SYNC"
done
"#
        .to_string(),
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => {
            return Err(ApiError::BadRequest(format!(
                "{} does not use the logical wipe path",
                metadata.protocol.as_str()
            )));
        }
    };
    Ok(script)
}

pub(super) async fn wipe_logical_target(
    state: &AppState,
    metadata: &InstanceMetadata,
    exec_timeout: Option<Duration>,
    database_definition_in_dump: bool,
) -> Result<(), ApiError> {
    let script = wipe_logical_script(metadata, database_definition_in_dump)?;
    let credentials = logical_import_environment(metadata, database_definition_in_dump)
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    let environment = credentials.references();
    let result = match exec_timeout {
        Some(timeout) => {
            state
                .docker
                .exec_shell_with_secret_env_timeout(
                    metadata.protocol,
                    &metadata.instance_id,
                    &script,
                    &environment,
                    timeout,
                )
                .await
        }
        None => {
            state
                .docker
                .exec_shell_with_secret_env(
                    metadata.protocol,
                    &metadata.instance_id,
                    &script,
                    &environment,
                )
                .await
        }
    };
    result.map_err(|error| {
        ApiError::Runtime(format!(
            "failed to wipe {} target before import: {error}",
            metadata.protocol.as_str()
        ))
    })?;
    Ok(())
}

pub(super) fn mongodb_namespace_pattern(database: &str) -> String {
    let mut pattern = String::with_capacity(database.len() + 2);
    for character in database.chars() {
        match character {
            '\\' => pattern.push_str(r"\\"),
            '*' => pattern.push_str(r"\*"),
            _ => pattern.push(character),
        }
    }
    pattern.push_str(".*");
    pattern
}

fn mongodb_collection_namespace_pattern(database: &str, collection: &str) -> String {
    let mut pattern = mongodb_namespace_pattern(database);
    pattern.pop();
    pattern.push_str(collection);
    pattern
}

pub(super) fn mongodb_restore_namespace_args(
    selection: &ImportExportSelection,
    source_database: Option<&str>,
) -> Result<String, ApiError> {
    validate_selection(Protocol::Mongodb, selection, SelectionUse::Import)?;

    let mut filters = Vec::new();
    match source_database {
        Some(source_database) => {
            if selection.mode == SelectionMode::Full {
                filters.push(format!(
                    "--nsInclude {}",
                    sh_quote(&mongodb_namespace_pattern(source_database))
                ));
            } else {
                for collection in &selection.include {
                    filters.push(format!(
                        "--nsInclude {}",
                        sh_quote(&mongodb_collection_namespace_pattern(
                            source_database,
                            collection
                        ))
                    ));
                }
                for collection in &selection.exclude {
                    filters.push(format!(
                        "--nsExclude {}",
                        sh_quote(&mongodb_collection_namespace_pattern(
                            source_database,
                            collection
                        ))
                    ));
                }
            }
            let source_pattern = mongodb_namespace_pattern(source_database);
            filters.push(format!("--nsFrom {}", sh_quote(&source_pattern)));
            filters.push("--nsTo \"$DBE_MONGO_DATABASE.*\"".to_string());
        }
        None if selection.mode == SelectionMode::Full => {
            filters.push("--nsInclude \"$DBE_MONGO_DATABASE.*\"".to_string());
        }
        None => {
            // Local archives have no trusted source database to remap. Collection filters
            // therefore apply only to namespaces already matching the target database.
            for collection in &selection.include {
                filters.push(format!(
                    "--nsInclude \"$DBE_MONGO_DATABASE\".{}",
                    sh_quote(collection)
                ));
            }
            for collection in &selection.exclude {
                filters.push(format!(
                    "--nsExclude \"$DBE_MONGO_DATABASE\".{}",
                    sh_quote(collection)
                ));
            }
        }
    }
    Ok(filters.join(" \\\n  "))
}

#[cfg(test)]
pub(super) fn import_script(
    metadata: &InstanceMetadata,
    input_path: &str,
    source_database: Option<&str>,
    selection: &ImportExportSelection,
    database_definition_in_dump: bool,
) -> Result<String, ApiError> {
    import_script_with_postgres_wrapper(
        metadata,
        input_path,
        source_database,
        selection,
        database_definition_in_dump,
        None,
    )
}

pub(super) fn import_script_with_postgres_wrapper(
    metadata: &InstanceMetadata,
    input_path: &str,
    source_database: Option<&str>,
    selection: &ImportExportSelection,
    database_definition_in_dump: bool,
    postgres_wrapper_lines: Option<(u64, u64)>,
) -> Result<String, ApiError> {
    let protocol = metadata.protocol;
    let script = match protocol {
        Protocol::Postgres => {
            let restrict_key = format!("dbev{}", uuid::Uuid::new_v4().simple());
            let input = match postgres_wrapper_lines {
                Some((restrict_line, unrestrict_line))
                    if restrict_line > 0 && unrestrict_line > restrict_line =>
                {
                    format!(
                        "command -v sed >/dev/null\nsed -e '{restrict_line}d' -e '{unrestrict_line}d' {input_path}"
                    )
                }
                Some(_) => {
                    return Err(ApiError::Runtime(
                        "PostgreSQL dump wrapper line numbers are invalid".to_string(),
                    ));
                }
                None => format!("cat {input_path}"),
            };
            format!(
                r#"set -eu
{{ printf '%s\n' '\restrict {restrict_key}'; {input}; }} | \
PGPASSWORD="$DBE_POSTGRES_PASSWORD" psql \
  --no-psqlrc \
  -h /var/run/postgresql \
  -U "$DBE_POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 \
  -f -
"#
            )
        }
        Protocol::Mariadb if database_definition_in_dump => format!(
            r#"set -eu
mariadb \
  --binary-mode \
  --protocol=socket \
  --socket=/run/mysqld/mysqld.sock \
  -u root \
  -p"$DBE_MARIADB_ROOT_PASSWORD" \
  < {input_path}
"#
        ),
        Protocol::Mariadb => format!(
            r#"set -eu
mariadb \
  --binary-mode \
  --protocol=socket \
  --socket=/run/mysqld/mysqld.sock \
  -u "$MARIADB_USER" \
  -p"$DBE_MARIADB_PASSWORD" \
  "$MARIADB_DATABASE" \
  < {input_path}
"#
        ),
        Protocol::Mysql if database_definition_in_dump => {
            ensure_mysql_root_password(metadata)?;
            format!(
                r#"set -eu
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql \
  --binary-mode \
  --protocol=socket \
  --socket=/var/run/mysqld/mysqld.sock \
  -u root \
  < {input_path}
"#
            )
        }
        Protocol::Mysql => {
            logical_import_environment(metadata, false)
                .map_err(|error| ApiError::Conflict(error.to_string()))?;
            format!(
                r#"set -eu
MYSQL_PWD="$DBE_IMPORT_PASSWORD" mysql \
  --binary-mode \
  --protocol=socket \
  --socket=/var/run/mysqld/mysqld.sock \
  -u "$DBE_IMPORT_USER" \
  "$MYSQL_DATABASE" \
  < {input_path}
"#
            )
        }
        Protocol::Mongodb => {
            ensure_mongodb_root_password(metadata)?;
            let namespaces = mongodb_restore_namespace_args(selection, source_database)?;
            format!(
                r#"set -eu
mongorestore \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_ROOT_USER" \
  --password "$DBE_MONGO_ROOT_PASSWORD" \
  --authenticationDatabase "admin" \
  --drop \
  {namespaces} \
  --archive={input_path} \
  --gzip
"#
            )
        }
        Protocol::Clickhouse => format!(
            r#"set -eu
clickhouse-client \
  --host 127.0.0.1 \
  --user "$CLICKHOUSE_USER" \
  --password "$CLICKHOUSE_PASSWORD" \
  --database "$CLICKHOUSE_DB" \
  --multiquery \
  < {input_path}
"#
        ),
        Protocol::Redis => {
            return Err(ApiError::BadRequest(
                "redis uses physical archive import".to_string(),
            ));
        }
        Protocol::Valkey => {
            return Err(ApiError::BadRequest(
                "valkey uses physical archive import".to_string(),
            ));
        }
        Protocol::Qdrant => {
            return Err(ApiError::NotImplemented(
                "qdrant snapshot import is not implemented yet".to_string(),
            ));
        }
    };
    Ok(script)
}
