use super::{
    ManifestError,
    model::{
        CollectedManifest, DataRecord, MultisetAccumulator, MultisetDigest, SchemaRecord,
        object_key,
    },
    normalize::normalize_qualified_sql,
    query::{ManifestContext, decode_base64, decode_utf8, validate_identifier},
};
use crate::{
    databases::{quote_mysql_ident as quote_mysql, quote_mysql_string},
    shared::protocol::Protocol,
};

const PAGE_SIZE: usize = 128;

#[derive(Debug)]
struct Table {
    name: String,
    kind: TableKind,
    engine: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableKind {
    Base,
    View,
    Sequence,
}

#[derive(Debug)]
struct Column {
    name: String,
    data_type: String,
}

pub(super) async fn collect(
    context: &ManifestContext<'_>,
) -> Result<CollectedManifest, ManifestError> {
    context.check_scan_bytes(data_size_sql()).await?;
    let mut collected = CollectedManifest::default();
    let tables = table_catalog(context).await?;
    for table in &tables {
        match table.kind {
            TableKind::Base => {
                if !table
                    .engine
                    .as_deref()
                    .is_some_and(|engine| engine.eq_ignore_ascii_case("InnoDB"))
                {
                    return Err(ManifestError::UnsupportedFeature(format!(
                        "{} table {} uses non-transactional engine {}; the logical export cannot provide a consistent snapshot",
                        context.runtime.protocol.as_str(),
                        table.name,
                        table.engine.as_deref().unwrap_or("unknown")
                    )));
                }
                let definition = show_create(context, "TABLE", &table.name).await?;
                collected.push_schema(SchemaRecord::new(
                    object_key("table", &[&table.name]),
                    normalize_qualified_sql(&definition, context.target.database),
                )?)?;
                let columns = table_columns(context, &table.name).await?;
                let digest = table_digest(context, &table.name, &columns).await?;
                collected.push_data(DataRecord::new(
                    object_key("table-data", &[&table.name]),
                    digest,
                )?)?;
            }
            TableKind::View => {
                let definition = view_definition(context, &table.name).await?;
                collected.push_schema(SchemaRecord::new(
                    object_key("view", &[&table.name]),
                    normalize_qualified_sql(&definition, context.target.database),
                )?)?;
            }
            TableKind::Sequence => {
                if context.runtime.protocol != Protocol::Mariadb {
                    return Err(ManifestError::UnsupportedFeature(format!(
                        "unexpected sequence {} in {}",
                        table.name,
                        context.runtime.protocol.as_str()
                    )));
                }
                let definition = show_create(context, "SEQUENCE", &table.name).await?;
                collected.push_schema(SchemaRecord::new(
                    object_key("sequence", &[&table.name]),
                    normalize_qualified_sql(&definition, context.target.database),
                )?)?;
                let digest = sequence_digest(context, &table.name).await?;
                collected.push_data(DataRecord::new(
                    object_key("sequence-state", &[&table.name]),
                    digest,
                )?)?;
            }
        }
    }
    collect_auxiliary_schema(context, &mut collected).await?;
    Ok(collected)
}

fn data_size_sql() -> &'static str {
    r#"SELECT CAST(COALESCE(SUM(COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0)), 0) AS UNSIGNED)
FROM information_schema.TABLES
WHERE BINARY TABLE_SCHEMA = BINARY DATABASE();"#
}

async fn table_catalog(context: &ManifestContext<'_>) -> Result<Vec<Table>, ManifestError> {
    let mut tables = Vec::new();
    let mut offset = 0;
    loop {
        let sql = format!(
            r#"SELECT
  REPLACE(TO_BASE64(TABLE_NAME), '\n', ''),
  REPLACE(TO_BASE64(TABLE_TYPE), '\n', ''),
  REPLACE(TO_BASE64(COALESCE(ENGINE, '')), '\n', '')
FROM information_schema.TABLES
WHERE BINARY TABLE_SCHEMA = BINARY DATABASE()
ORDER BY TABLE_NAME
LIMIT {PAGE_SIZE} OFFSET {offset};"#,
        );
        let output = context.query(&sql).await?;
        let mut rows = 0;
        for line in output.lines().filter(|line| !line.trim().is_empty()) {
            rows += 1;
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != 3 {
                return Err(ManifestError::InvalidCatalog(
                    "invalid MySQL table catalog row",
                ));
            }
            let name = decode_utf8(fields[0])?;
            let table_type = decode_utf8(fields[1])?;
            let engine = decode_utf8(fields[2])?;
            validate_identifier(&name)?;
            let kind = match table_type.as_str() {
                "BASE TABLE" | "SYSTEM VERSIONED" => TableKind::Base,
                "VIEW" => TableKind::View,
                "SEQUENCE" => TableKind::Sequence,
                other => {
                    return Err(ManifestError::UnsupportedFeature(format!(
                        "{} table type {other} is not covered",
                        context.runtime.protocol.as_str()
                    )));
                }
            };
            tables.push(Table {
                name,
                kind,
                engine: (!engine.is_empty()).then_some(engine),
            });
        }
        if rows < PAGE_SIZE {
            return Ok(tables);
        }
        offset += PAGE_SIZE;
    }
}

async fn show_create(
    context: &ManifestContext<'_>,
    kind: &str,
    name: &str,
) -> Result<String, ManifestError> {
    let output = context
        .query(&format!("SHOW CREATE {kind} {};", quote_mysql(name)))
        .await?;
    let (_, definition) = output
        .split_once('\t')
        .ok_or(ManifestError::InvalidCatalog("invalid SHOW CREATE output"))?;
    let definition = definition.trim_end_matches(['\r', '\n']);
    if definition.is_empty() {
        return Err(ManifestError::InvalidCatalog(
            "empty SHOW CREATE definition",
        ));
    }
    Ok(definition.to_string())
}

async fn view_definition(
    context: &ManifestContext<'_>,
    name: &str,
) -> Result<String, ManifestError> {
    let sql = format!(
        r#"SELECT REPLACE(TO_BASE64(CONCAT(
  {definition}, {check_option}, {updatable}, {security},
  {client_charset}, {connection_collation}
)), '\n', '')
FROM information_schema.VIEWS
WHERE BINARY TABLE_SCHEMA = BINARY DATABASE()
  AND BINARY TABLE_NAME = BINARY {name};"#,
        definition = frame("VIEW_DEFINITION"),
        check_option = frame("CHECK_OPTION"),
        updatable = frame("IS_UPDATABLE"),
        security = frame("SECURITY_TYPE"),
        client_charset = frame("CHARACTER_SET_CLIENT"),
        connection_collation = frame("COLLATION_CONNECTION"),
        name = quote_mysql_string(name),
    );
    one_base64_value(&context.query(&sql).await?, "missing MySQL view definition")
}

async fn table_columns(
    context: &ManifestContext<'_>,
    table: &str,
) -> Result<Vec<Column>, ManifestError> {
    let sql = format!(
        r#"SELECT
  REPLACE(TO_BASE64(COLUMN_NAME), '\n', ''),
  REPLACE(TO_BASE64(LOWER(DATA_TYPE)), '\n', '')
FROM information_schema.COLUMNS
WHERE BINARY TABLE_SCHEMA = BINARY DATABASE()
  AND BINARY TABLE_NAME = BINARY {}
ORDER BY ORDINAL_POSITION;"#,
        quote_mysql_string(table),
    );
    let output = context.query(&sql).await?;
    let mut columns = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 2 {
            return Err(ManifestError::InvalidCatalog(
                "invalid MySQL column catalog row",
            ));
        }
        let name = decode_utf8(fields[0])?;
        let data_type = decode_utf8(fields[1])?;
        validate_identifier(&name)?;
        if !supported_data_type(&data_type) {
            return Err(ManifestError::UnsupportedFeature(format!(
                "{} column {}.{} uses unsupported type {data_type}",
                context.runtime.protocol.as_str(),
                table,
                name
            )));
        }
        columns.push(Column { name, data_type });
    }
    if columns.is_empty() {
        return Err(ManifestError::InvalidCatalog(
            "MySQL table has no visible columns",
        ));
    }
    Ok(columns)
}

async fn table_digest(
    context: &ManifestContext<'_>,
    table: &str,
    columns: &[Column],
) -> Result<MultisetDigest, ManifestError> {
    let cell_hashes = columns
        .iter()
        .map(cell_hash_expression)
        .collect::<Vec<_>>()
        .join(", ");
    let timeout = context.engine_timeout()?;
    let timeout_setting = match context.runtime.protocol {
        Protocol::Mysql => format!("SET SESSION MAX_EXECUTION_TIME={};", timeout.as_millis()),
        Protocol::Mariadb => format!("SET SESSION max_statement_time={};", timeout.as_secs_f64()),
        protocol => return Err(ManifestError::Unsupported(protocol)),
    };
    let sql = format!(
        r#"SET SESSION time_zone = '+00:00';
{timeout_setting}
WITH row_hash AS (
  SELECT SHA2(CONCAT(UNHEX('{challenge}'), {cell_hashes}), 256) AS hash
  FROM {table}
), words AS (
  SELECT
    CAST(CONV(SUBSTRING(hash, 1, 16), 16, 10) AS DECIMAL(20, 0)) AS w0,
    CAST(CONV(SUBSTRING(hash, 17, 16), 16, 10) AS DECIMAL(20, 0)) AS w1,
    CAST(CONV(SUBSTRING(hash, 33, 16), 16, 10) AS DECIMAL(20, 0)) AS w2,
    CAST(CONV(SUBSTRING(hash, 49, 16), 16, 10) AS DECIMAL(20, 0)) AS w3
  FROM row_hash
)
SELECT COUNT(*),
  CAST(MOD(COALESCE(SUM(w0), 0), 18446744073709551616) AS UNSIGNED),
  CAST(MOD(COALESCE(SUM(w1), 0), 18446744073709551616) AS UNSIGNED),
  CAST(MOD(COALESCE(SUM(w2), 0), 18446744073709551616) AS UNSIGNED),
  CAST(MOD(COALESCE(SUM(w3), 0), 18446744073709551616) AS UNSIGNED),
  CAST(COALESCE(BIT_XOR(CAST(w0 AS UNSIGNED)), 0) AS UNSIGNED),
  CAST(COALESCE(BIT_XOR(CAST(w1 AS UNSIGNED)), 0) AS UNSIGNED),
  CAST(COALESCE(BIT_XOR(CAST(w2 AS UNSIGNED)), 0) AS UNSIGNED),
  CAST(COALESCE(BIT_XOR(CAST(w3 AS UNSIGNED)), 0) AS UNSIGNED)
FROM words;"#,
        challenge = context.challenge.hex(),
        table = quote_mysql(table),
    );
    MultisetDigest::parse_tsv(&context.query(&sql).await?)
}

fn cell_hash_expression(column: &Column) -> String {
    let column_name = quote_mysql(&column.name);
    let value = if geometry_type(&column.data_type) {
        format!("CONCAT(UNHEX(LPAD(HEX(ST_SRID({column_name})), 8, '0')), ST_AsWKB({column_name}))")
    } else if column.data_type == "bit" {
        format!("UNHEX(LPAD(HEX(CAST({column_name} AS UNSIGNED)), 16, '0'))")
    } else {
        format!("CAST({column_name} AS BINARY)")
    };
    format!(
        "UNHEX(SHA2(CASE WHEN {column_name} IS NULL THEN UNHEX('00') ELSE CONCAT(UNHEX('01'), UNHEX(LPAD(HEX(OCTET_LENGTH({value})), 16, '0')), {value}) END, 256))"
    )
}

async fn sequence_digest(
    context: &ManifestContext<'_>,
    name: &str,
) -> Result<MultisetDigest, ManifestError> {
    let output = context
        .query(&format!("SELECT * FROM {} LIMIT 1;", quote_mysql(name)))
        .await?;
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let value = lines.next().ok_or(ManifestError::InvalidCatalog(
        "missing MariaDB sequence state",
    ))?;
    if lines.next().is_some() {
        return Err(ManifestError::InvalidCatalog(
            "multiple MariaDB sequence states returned",
        ));
    }
    let key = object_key("sequence-state", &[name]);
    let mut digest = MultisetAccumulator::new();
    digest.add(context.challenge, &key, value.as_bytes())?;
    Ok(digest.finish())
}

async fn collect_auxiliary_schema(
    context: &ManifestContext<'_>,
    collected: &mut CollectedManifest,
) -> Result<(), ManifestError> {
    let mut offset = 0;
    loop {
        let output = context.query(&auxiliary_catalog_sql(offset)).await?;
        let mut rows = 0;
        for line in output.lines().filter(|line| !line.trim().is_empty()) {
            rows += 1;
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != 3 {
                return Err(ManifestError::InvalidCatalog(
                    "invalid MySQL executable object catalog row",
                ));
            }
            let kind = fields[0];
            if !matches!(kind, "routine" | "trigger" | "event" | "parameter") {
                return Err(ManifestError::InvalidCatalog(
                    "invalid MySQL executable object kind",
                ));
            }
            let name = decode_utf8(fields[1])?;
            validate_identifier(&name)?;
            let definition = decode_base64(fields[2])?;
            if definition.is_empty() {
                return Err(ManifestError::UnsupportedFeature(format!(
                    "{kind} {name} is not visible under the tenant credential"
                )));
            }
            collected.push_schema(SchemaRecord::new(
                object_key(kind, &[&name]),
                normalize_qualified_sql(
                    &String::from_utf8(definition).map_err(|_| {
                        ManifestError::InvalidCatalog("MySQL definition is not UTF-8")
                    })?,
                    context.target.database,
                ),
            )?)?;
        }
        if rows < PAGE_SIZE {
            return Ok(());
        }
        offset += PAGE_SIZE;
    }
}

fn auxiliary_catalog_sql(offset: usize) -> String {
    let routine = concat_frames(&[
        "ROUTINE_TYPE",
        "DATA_TYPE",
        "DTD_IDENTIFIER",
        "ROUTINE_BODY",
        "ROUTINE_DEFINITION",
        "IS_DETERMINISTIC",
        "SQL_DATA_ACCESS",
        "SECURITY_TYPE",
        "SQL_MODE",
        "CHARACTER_SET_CLIENT",
        "COLLATION_CONNECTION",
        "DATABASE_COLLATION",
    ]);
    let trigger = concat_frames(&[
        "EVENT_MANIPULATION",
        "EVENT_OBJECT_TABLE",
        "ACTION_ORDER",
        "ACTION_CONDITION",
        "ACTION_STATEMENT",
        "ACTION_ORIENTATION",
        "ACTION_TIMING",
        "SQL_MODE",
        "CHARACTER_SET_CLIENT",
        "COLLATION_CONNECTION",
        "DATABASE_COLLATION",
    ]);
    let event = concat_frames(&[
        "EVENT_DEFINITION",
        "EVENT_TYPE",
        "EXECUTE_AT",
        "INTERVAL_VALUE",
        "INTERVAL_FIELD",
        "SQL_MODE",
        "STARTS",
        "ENDS",
        "STATUS",
        "ON_COMPLETION",
        "EVENT_COMMENT",
        "TIME_ZONE",
        "CHARACTER_SET_CLIENT",
        "COLLATION_CONNECTION",
        "DATABASE_COLLATION",
    ]);
    let parameter = concat_frames(&[
        "SPECIFIC_NAME",
        "ORDINAL_POSITION",
        "PARAMETER_MODE",
        "PARAMETER_NAME",
        "DATA_TYPE",
        "DTD_IDENTIFIER",
        "CHARACTER_SET_NAME",
        "COLLATION_NAME",
        "ROUTINE_TYPE",
    ]);
    format!(
        r#"SELECT kind, REPLACE(TO_BASE64(name), '\n', ''), REPLACE(TO_BASE64(definition), '\n', '')
FROM (
  SELECT 'routine' AS kind,
    CONCAT(SPECIFIC_NAME, '/', ROUTINE_TYPE) AS name,
    CASE WHEN ROUTINE_DEFINITION IS NULL THEN NULL ELSE {routine} END AS definition
  FROM information_schema.ROUTINES
  WHERE BINARY ROUTINE_SCHEMA = BINARY DATABASE()
  UNION ALL
  SELECT 'trigger', TRIGGER_NAME, {trigger}
  FROM information_schema.TRIGGERS
  WHERE BINARY TRIGGER_SCHEMA = BINARY DATABASE()
  UNION ALL
  SELECT 'event', EVENT_NAME, {event}
  FROM information_schema.EVENTS
  WHERE BINARY EVENT_SCHEMA = BINARY DATABASE()
  UNION ALL
  SELECT 'parameter', CONCAT(SPECIFIC_NAME, '/', LPAD(ORDINAL_POSITION, 10, '0')), {parameter}
  FROM information_schema.PARAMETERS
  WHERE BINARY SPECIFIC_SCHEMA = BINARY DATABASE()
) objects
ORDER BY kind, name
LIMIT {PAGE_SIZE} OFFSET {offset};"#,
    )
}

fn frame(expression: &str) -> String {
    format!(
        "IF({expression} IS NULL, 'N', CONCAT('V', LPAD(OCTET_LENGTH({expression}), 20, '0'), ':', {expression}))"
    )
}

fn concat_frames(expressions: &[&str]) -> String {
    format!(
        "CONCAT({})",
        expressions
            .iter()
            .map(|expression| frame(expression))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn one_base64_value(output: &str, missing: &'static str) -> Result<String, ManifestError> {
    let mut values = output.lines().filter(|line| !line.trim().is_empty());
    let value = values
        .next()
        .ok_or(ManifestError::InvalidCatalog(missing))?;
    if values.next().is_some() {
        return Err(ManifestError::InvalidCatalog(
            "multiple catalog definitions returned",
        ));
    }
    String::from_utf8(decode_base64(value)?)
        .map_err(|_| ManifestError::InvalidCatalog("catalog definition is not UTF-8"))
}

fn geometry_type(data_type: &str) -> bool {
    matches!(
        data_type,
        "geometry"
            | "point"
            | "linestring"
            | "polygon"
            | "multipoint"
            | "multilinestring"
            | "multipolygon"
            | "geometrycollection"
    )
}

fn supported_data_type(data_type: &str) -> bool {
    geometry_type(data_type)
        || matches!(
            data_type,
            "tinyint"
                | "smallint"
                | "mediumint"
                | "int"
                | "integer"
                | "bigint"
                | "decimal"
                | "numeric"
                | "float"
                | "double"
                | "real"
                | "bit"
                | "bool"
                | "boolean"
                | "date"
                | "datetime"
                | "timestamp"
                | "time"
                | "year"
                | "char"
                | "varchar"
                | "binary"
                | "varbinary"
                | "tinyblob"
                | "blob"
                | "mediumblob"
                | "longblob"
                | "tinytext"
                | "text"
                | "mediumtext"
                | "longtext"
                | "enum"
                | "set"
                | "json"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_hashes_are_null_and_length_framed() {
        let expression = cell_hash_expression(&Column {
            name: "payload".to_string(),
            data_type: "blob".to_string(),
        });
        assert!(expression.contains("IS NULL"));
        assert!(expression.contains("OCTET_LENGTH"));
        assert!(expression.contains("SHA2"));
    }

    #[test]
    fn unsupported_new_types_fail_closed() {
        assert!(supported_data_type("json"));
        assert!(!supported_data_type("vector"));
        assert!(!supported_data_type("unknown_future_type"));
    }

    #[test]
    fn auxiliary_schema_covers_bodies_and_parameter_types() {
        let query = auxiliary_catalog_sql(0);
        assert!(query.contains("ROUTINE_DEFINITION"));
        assert!(query.contains("ACTION_STATEMENT"));
        assert!(query.contains("EVENT_DEFINITION"));
        assert!(query.contains("DTD_IDENTIFIER"));
        assert!(data_size_sql().contains("DATA_LENGTH"));
    }
}
