use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    config::BackupBrowsingConfig, instances::metadata::InstanceMetadata,
    runtime::docker::DockerRuntime, shared::protocol::Protocol,
};

pub const BACKUP_CATALOG_SCHEMA_VERSION: u32 = 1;
const CATALOG_QUERY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCatalog {
    pub schema_version: u32,
    pub backup_id: String,
    pub instance_id: String,
    pub protocol: Protocol,
    pub database_name: String,
    pub captured_at: String,
    pub consistency: String,
    pub truncated: bool,
    pub warnings: Vec<String>,
    pub objects: Vec<BackupCatalogObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCatalogObject {
    pub id: String,
    pub namespace: String,
    pub name: String,
    pub kind: String,
    pub estimated_rows: Option<u64>,
    pub columns: Vec<BackupCatalogColumn>,
    pub preview_rows: Vec<Value>,
    pub preview_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCatalogColumn {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub ordinal: usize,
}

impl BackupCatalog {
    pub async fn capture(
        docker: &DockerRuntime,
        metadata: &InstanceMetadata,
        backup_id: &str,
        policy: &BackupBrowsingConfig,
    ) -> Self {
        let mut catalog = Self {
            schema_version: BACKUP_CATALOG_SCHEMA_VERSION,
            backup_id: backup_id.to_string(),
            instance_id: metadata.instance_id.clone(),
            protocol: metadata.protocol,
            database_name: metadata.database.name.clone(),
            captured_at: crate::jobs::import_export::now_rfc3339(),
            consistency: "captured_immediately_before_physical_archive".to_string(),
            truncated: false,
            warnings: Vec::new(),
            objects: Vec::new(),
        };

        match capture_schema(docker, metadata, policy.max_objects.saturating_add(1)).await {
            Ok(mut objects) => {
                if objects.len() > policy.max_objects {
                    catalog.truncated = true;
                    catalog.warnings.push(format!(
                        "schema catalog reached the configured {}-object limit",
                        policy.max_objects
                    ));
                }
                objects.truncate(policy.max_objects);
                catalog.objects = objects;
            }
            Err(error) => {
                tracing::warn!(
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    %error,
                    "backup schema catalog capture failed"
                );
                catalog.warnings.push(format!(
                    "{} schema introspection was unavailable; the physical backup is still restorable",
                    metadata.protocol.as_str()
                ));
            }
        }

        if policy.preview_rows_per_object > 0 && policy.max_preview_objects > 0 {
            capture_previews(docker, metadata, policy, &mut catalog).await;
        }
        if matches!(
            metadata.protocol,
            Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
        ) {
            catalog.warnings.push(format!(
                "{} uses a physical, schema-less store; this catalog describes the backup but does not expose record previews",
                metadata.protocol.as_str()
            ));
        }
        catalog
    }

    pub fn encode_bounded(mut self, max_bytes: u64) -> Result<Vec<u8>, serde_json::Error> {
        let mut encoded = serde_json::to_vec(&self)?;
        if encoded.len() as u64 <= max_bytes {
            return Ok(encoded);
        }

        self.truncated = true;
        // Preview data is optional and can dominate the catalog. Remove it in
        // one pass instead of repeatedly serializing a large document per row.
        for object in &mut self.objects {
            if !object.preview_rows.is_empty() {
                object.preview_rows.clear();
                object.preview_truncated = true;
            }
        }
        encoded = serde_json::to_vec(&self)?;

        // Preserve complete schema for a leading subset of objects. Estimate
        // a proportional batch on each pass so a very large catalog requires
        // only a handful of serializations rather than one per column/object.
        while encoded.len() as u64 > max_bytes && !self.objects.is_empty() {
            if self.objects.len() == 1 && !self.objects[0].columns.is_empty() {
                self.objects[0].columns.clear();
            } else {
                let current = self.objects.len();
                let excess = encoded.len().saturating_sub(max_bytes as usize);
                let estimated = current
                    .saturating_mul(excess)
                    .div_ceil(encoded.len().max(1));
                let remove = estimated.clamp(1, current);
                self.objects.truncate(current - remove);
            }
            encoded = serde_json::to_vec(&self)?;
        }
        if encoded.len() as u64 > max_bytes {
            self.warnings.clear();
            encoded = serde_json::to_vec(&self)?;
        }
        Ok(encoded)
    }

    pub fn decode_and_validate(
        bytes: &[u8],
        instance_id: &str,
        backup_id: &str,
    ) -> Result<Self, String> {
        let catalog: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid backup catalog JSON: {error}"))?;
        if catalog.schema_version != BACKUP_CATALOG_SCHEMA_VERSION
            || catalog.instance_id != instance_id
            || catalog.backup_id != backup_id
        {
            return Err("backup catalog identity does not match the requested backup".to_string());
        }
        Ok(catalog)
    }
}

async fn capture_schema(
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
    max_objects: usize,
) -> Result<Vec<BackupCatalogObject>, String> {
    match metadata.protocol {
        Protocol::Postgres => {
            let output = execute(docker, metadata, &postgres_schema_script(max_objects)).await?;
            parse_postgres_schema(&output)
        }
        Protocol::Mariadb => {
            let output =
                execute(docker, metadata, &mysql_schema_script(false, max_objects)).await?;
            parse_mysql_schema(&output)
        }
        Protocol::Mysql => {
            let output = execute(docker, metadata, &mysql_schema_script(true, max_objects)).await?;
            parse_mysql_schema(&output)
        }
        Protocol::Mongodb => {
            let output = execute(docker, metadata, &mongodb_schema_script(max_objects)).await?;
            parse_mongodb_schema(&output)
        }
        Protocol::Clickhouse => {
            let output = execute(docker, metadata, &clickhouse_schema_script(max_objects)).await?;
            parse_clickhouse_schema(&output)
        }
        Protocol::Redis => Ok(vec![schema_less_object(metadata, "keyspace")]),
        Protocol::Valkey => Ok(vec![schema_less_object(metadata, "keyspace")]),
        Protocol::Qdrant => Ok(vec![schema_less_object(metadata, "collection_store")]),
    }
}

async fn capture_previews(
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
    policy: &BackupBrowsingConfig,
    catalog: &mut BackupCatalog,
) {
    if matches!(
        metadata.protocol,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    ) {
        return;
    }
    let mut failures = 0_usize;
    let previewable_objects = catalog
        .objects
        .iter()
        .filter(|object| object.kind == "table" || object.kind == "collection")
        .count();
    let eligible = catalog
        .objects
        .iter()
        .enumerate()
        .filter(|(_, object)| object.kind == "table" || object.kind == "collection")
        .take(policy.max_preview_objects)
        .map(|(index, object)| (index, object.clone()))
        .collect::<Vec<_>>();
    if eligible.len() < previewable_objects {
        catalog.truncated = true;
    }
    for (index, object) in eligible {
        // Read one bounded sentinel row so callers can distinguish a complete
        // small object from a preview that stopped at the configured limit.
        let capture_rows = policy.preview_rows_per_object.saturating_add(1);
        let script = preview_script(
            metadata.protocol,
            &object,
            capture_rows,
            policy.max_row_bytes,
        );
        let Some(script) = script else {
            failures += 1;
            catalog.objects[index].preview_truncated = true;
            continue;
        };
        match execute(docker, metadata, &script).await {
            Ok(output) => {
                let (rows, truncated) = parse_preview_rows(
                    metadata.protocol,
                    &output,
                    policy.preview_rows_per_object,
                    policy.max_row_bytes,
                );
                let target = &mut catalog.objects[index];
                target.preview_rows = rows;
                target.preview_truncated = truncated;
                if metadata.protocol == Protocol::Mongodb {
                    infer_mongodb_columns(target);
                }
            }
            Err(error) => {
                failures += 1;
                tracing::debug!(
                    instance_id = %metadata.instance_id,
                    object = %object.id,
                    %error,
                    "backup content preview capture failed"
                );
            }
        }
    }
    if failures > 0 {
        catalog.warnings.push(format!(
            "content previews were unavailable for {failures} database objects"
        ));
    }
}

async fn execute(
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
    script: &str,
) -> Result<String, String> {
    docker
        .exec_shell_with_timeout(
            metadata.protocol,
            &metadata.instance_id,
            script,
            CATALOG_QUERY_TIMEOUT,
        )
        .await
        .map(|output| output.stdout)
        .map_err(|error| error.to_string())
}

fn postgres_schema_script(max_objects: usize) -> String {
    format!(
        r#"set -eu
PGPASSWORD="${{DBE_POSTGRES_PASSWORD:-$POSTGRES_PASSWORD}}" psql \
  -X -qAt -F '|' -v ON_ERROR_STOP=1 \
  -h /var/run/postgresql \
  -U "${{DBE_POSTGRES_USER:-$POSTGRES_USER}}" \
  -d "$POSTGRES_DB" <<'DBEV_SQL'
WITH objects AS (
  SELECT c.oid, n.nspname, c.relname, c.relkind,
         GREATEST(c.reltuples, 0)::bigint AS estimated_rows
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
    AND n.nspname <> 'information_schema'
    AND n.nspname NOT LIKE 'pg_%'
  ORDER BY n.nspname, c.relname
  LIMIT {max_objects}
)
SELECT encode(convert_to(o.nspname, 'UTF8'), 'hex'),
       encode(convert_to(o.relname, 'UTF8'), 'hex'),
       o.relkind,
       o.estimated_rows,
       a.attnum,
       encode(convert_to(a.attname, 'UTF8'), 'hex'),
       encode(convert_to(format_type(a.atttypid, a.atttypmod), 'UTF8'), 'hex'),
       CASE WHEN a.attnotnull THEN 'NO' ELSE 'YES' END
FROM objects o
JOIN pg_attribute a ON a.attrelid = o.oid
WHERE a.attnum > 0 AND NOT a.attisdropped
ORDER BY o.nspname, o.relname, a.attnum;
DBEV_SQL
"#
    )
}

fn mysql_schema_script(mysql: bool, max_objects: usize) -> String {
    let command = if mysql {
        "MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root --database=\"$MYSQL_DATABASE\""
    } else {
        "mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" -p\"$MARIADB_PASSWORD\" --database=\"$MARIADB_DATABASE\""
    };
    format!(
        r#"set -eu
{command} --batch --raw --skip-column-names <<'DBEV_SQL'
SELECT HEX(c.TABLE_SCHEMA), HEX(c.TABLE_NAME), HEX(t.TABLE_TYPE),
       COALESCE(t.TABLE_ROWS, 0), c.ORDINAL_POSITION,
       HEX(c.COLUMN_NAME), HEX(c.COLUMN_TYPE), c.IS_NULLABLE
FROM information_schema.COLUMNS c
JOIN (
  SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, TABLE_ROWS
  FROM information_schema.TABLES
  WHERE TABLE_SCHEMA = DATABASE()
  ORDER BY TABLE_NAME
  LIMIT {max_objects}
) t ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME
ORDER BY c.TABLE_SCHEMA, c.TABLE_NAME, c.ORDINAL_POSITION;
DBEV_SQL
"#
    )
}

fn clickhouse_schema_script(max_objects: usize) -> String {
    let query = format!(
        "SELECT hex(c.database), hex(c.table), hex(t.engine), ifNull(t.total_rows, 0), c.position, hex(c.name), hex(c.type), toUInt8(startsWith(c.type, 'Nullable(')) FROM system.columns c INNER JOIN (SELECT database, name, engine, total_rows FROM system.tables WHERE database = currentDatabase() ORDER BY name LIMIT {max_objects}) t ON t.database = c.database AND t.name = c.table ORDER BY c.database, c.table, c.position FORMAT TSVRaw"
    );
    format!(
        "set -eu\nclickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query {}\n",
        shell_quote(&query)
    )
}

fn mongodb_schema_script(max_objects: usize) -> String {
    let javascript = format!(
        r#"const infos = db.getCollectionInfos().sort((a,b) => a.name.localeCompare(b.name)).slice(0, {max_objects});
for (const info of infos) {{
  let count = null;
  try {{ count = db.getCollection(info.name).estimatedDocumentCount(); }} catch (_) {{}}
  print(EJSON.stringify({{
    namespace: db.getName(),
    name: info.name,
    kind: info.type === 'collection' ? 'collection' : info.type,
    estimated_rows: count,
    columns: []
  }}));
}}"#
    );
    format!(
        "set -eu\nmongosh --quiet --host 127.0.0.1 --username \"$DBE_MONGO_ROOT_USER\" --password \"$DBE_MONGO_ROOT_PASSWORD\" --authenticationDatabase admin \"$DBE_MONGO_DATABASE\" --eval {}\n",
        shell_quote(&javascript)
    )
}

fn preview_script(
    protocol: Protocol,
    object: &BackupCatalogObject,
    rows: usize,
    max_row_bytes: usize,
) -> Option<String> {
    match protocol {
        Protocol::Postgres => {
            let qualified = format!(
                "{}.{}",
                postgres_identifier(&object.namespace),
                postgres_identifier(&object.name)
            );
            let query = format!(
                "SELECT left(row_to_json(dbev_row)::text, {max_row_bytes}) FROM (SELECT * FROM {qualified} LIMIT {rows}) AS dbev_row"
            );
            Some(format!(
                "set -eu\nPGPASSWORD=\"${{DBE_POSTGRES_PASSWORD:-$POSTGRES_PASSWORD}}\" psql -X -qAt -v ON_ERROR_STOP=1 -h /var/run/postgresql -U \"${{DBE_POSTGRES_USER:-$POSTGRES_USER}}\" -d \"$POSTGRES_DB\" -c {}\n",
                shell_quote(&query)
            ))
        }
        Protocol::Mariadb | Protocol::Mysql => {
            if object.columns.is_empty() || object.columns.len() > 128 {
                return None;
            }
            let fields = object
                .columns
                .iter()
                .flat_map(|column| [mysql_string(&column.name), mysql_identifier(&column.name)])
                .collect::<Vec<_>>()
                .join(", ");
            let query = format!(
                "SELECT LEFT(JSON_OBJECT({fields}), {max_row_bytes}) FROM {} LIMIT {rows}",
                mysql_identifier(&object.name)
            );
            let command = if protocol == Protocol::Mysql {
                "MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root \"$MYSQL_DATABASE\""
            } else {
                "mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" -p\"$MARIADB_PASSWORD\" \"$MARIADB_DATABASE\""
            };
            Some(format!(
                "set -eu\n{command} --batch --raw --skip-column-names -e {}\n",
                shell_quote(&query)
            ))
        }
        Protocol::Mongodb => {
            let collection = serde_json::to_string(&object.name).ok()?;
            let javascript = format!(
                "const out=[]; for (const value of db.getCollection({collection}).find({{}}).limit({rows}).toArray()) {{ out.push(EJSON.stringify(value).slice(0,{max_row_bytes})); }} print(JSON.stringify(out));"
            );
            Some(format!(
                "set -eu\nmongosh --quiet --host 127.0.0.1 --username \"$DBE_MONGO_ROOT_USER\" --password \"$DBE_MONGO_ROOT_PASSWORD\" --authenticationDatabase admin \"$DBE_MONGO_DATABASE\" --eval {}\n",
                shell_quote(&javascript)
            ))
        }
        Protocol::Clickhouse => {
            let query = format!(
                "SELECT substring(toJSONString(tuple(*)), 1, {max_row_bytes}) FROM {} LIMIT {rows} FORMAT TSVRaw",
                clickhouse_identifier(&object.name)
            );
            Some(format!(
                "set -eu\nclickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query {}\n",
                shell_quote(&query)
            ))
        }
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => None,
    }
}

fn parse_postgres_schema(output: &str) -> Result<Vec<BackupCatalogObject>, String> {
    parse_relational_schema(output, '|', |fields| {
        let kind = match fields[2] {
            "r" | "p" => "table",
            "v" | "m" => "view",
            "f" => "foreign_table",
            _ => "object",
        };
        Ok(ParsedColumn {
            namespace: decode_hex(fields[0])?,
            object: decode_hex(fields[1])?,
            kind: kind.to_string(),
            estimated_rows: fields[3].parse().ok(),
            ordinal: fields[4].parse().map_err(|_| "invalid column ordinal")?,
            column: decode_hex(fields[5])?,
            data_type: decode_hex(fields[6])?,
            nullable: fields[7] == "YES",
        })
    })
}

fn parse_mysql_schema(output: &str) -> Result<Vec<BackupCatalogObject>, String> {
    parse_relational_schema(output, '\t', |fields| {
        let table_type = decode_hex(fields[2])?;
        Ok(ParsedColumn {
            namespace: decode_hex(fields[0])?,
            object: decode_hex(fields[1])?,
            kind: if table_type.eq_ignore_ascii_case("BASE TABLE") {
                "table".to_string()
            } else {
                "view".to_string()
            },
            estimated_rows: fields[3].parse().ok(),
            ordinal: fields[4].parse().map_err(|_| "invalid column ordinal")?,
            column: decode_hex(fields[5])?,
            data_type: decode_hex(fields[6])?,
            nullable: fields[7] == "YES",
        })
    })
}

fn parse_clickhouse_schema(output: &str) -> Result<Vec<BackupCatalogObject>, String> {
    parse_relational_schema(output, '\t', |fields| {
        let engine = decode_hex(fields[2])?;
        Ok(ParsedColumn {
            namespace: decode_hex(fields[0])?,
            object: decode_hex(fields[1])?,
            kind: if engine.to_ascii_lowercase().contains("view") {
                "view".to_string()
            } else {
                "table".to_string()
            },
            estimated_rows: fields[3].parse().ok(),
            ordinal: fields[4].parse().map_err(|_| "invalid column ordinal")?,
            column: decode_hex(fields[5])?,
            data_type: decode_hex(fields[6])?,
            nullable: fields[7] == "1",
        })
    })
}

fn parse_mongodb_schema(output: &str) -> Result<Vec<BackupCatalogObject>, String> {
    let mut objects = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        #[derive(Deserialize)]
        struct MongoObject {
            namespace: String,
            name: String,
            kind: String,
            estimated_rows: Option<u64>,
        }
        let object: MongoObject = serde_json::from_str(line)
            .map_err(|error| format!("invalid MongoDB catalog JSON: {error}"))?;
        objects.push(BackupCatalogObject {
            id: object_id(&object.namespace, &object.name),
            namespace: object.namespace,
            name: object.name,
            kind: object.kind,
            estimated_rows: object.estimated_rows,
            columns: Vec::new(),
            preview_rows: Vec::new(),
            preview_truncated: false,
        });
    }
    Ok(objects)
}

struct ParsedColumn {
    namespace: String,
    object: String,
    kind: String,
    estimated_rows: Option<u64>,
    ordinal: usize,
    column: String,
    data_type: String,
    nullable: bool,
}

fn parse_relational_schema<F>(
    output: &str,
    separator: char,
    mut parse: F,
) -> Result<Vec<BackupCatalogObject>, String>
where
    F: FnMut(&[&str]) -> Result<ParsedColumn, &'static str>,
{
    let mut objects = BTreeMap::<(String, String), BackupCatalogObject>::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split(separator).collect::<Vec<_>>();
        if fields.len() != 8 {
            return Err("database schema output contained an invalid field count".to_string());
        }
        let column = parse(&fields).map_err(str::to_string)?;
        let key = (column.namespace.clone(), column.object.clone());
        let object = objects.entry(key).or_insert_with(|| BackupCatalogObject {
            id: object_id(&column.namespace, &column.object),
            namespace: column.namespace.clone(),
            name: column.object.clone(),
            kind: column.kind.clone(),
            estimated_rows: column.estimated_rows,
            columns: Vec::new(),
            preview_rows: Vec::new(),
            preview_truncated: false,
        });
        object.columns.push(BackupCatalogColumn {
            name: column.column,
            data_type: column.data_type,
            nullable: column.nullable,
            ordinal: column.ordinal,
        });
    }
    Ok(objects.into_values().collect())
}

fn parse_preview_rows(
    protocol: Protocol,
    output: &str,
    max_rows: usize,
    max_row_bytes: usize,
) -> (Vec<Value>, bool) {
    let lines = if protocol == Protocol::Mongodb {
        serde_json::from_str::<Vec<String>>(output.trim()).unwrap_or_default()
    } else {
        output.lines().map(str::to_string).collect()
    };
    let mut truncated = lines.len() > max_rows;
    let mut rows = Vec::new();
    for line in lines.into_iter().take(max_rows) {
        let (line, was_truncated) = truncate_utf8(&line, max_row_bytes);
        truncated |= was_truncated;
        match serde_json::from_str::<Value>(line) {
            Ok(value) => rows.push(value),
            Err(_) => {
                truncated = true;
                rows.push(serde_json::json!({
                    "truncated": true,
                    "json_prefix": line,
                }));
            }
        }
    }
    (rows, truncated)
}

fn infer_mongodb_columns(object: &mut BackupCatalogObject) {
    let mut columns = BTreeMap::<String, String>::new();
    for row in &object.preview_rows {
        let Some(row) = row.as_object() else {
            continue;
        };
        for (name, value) in row {
            columns
                .entry(name.clone())
                .or_insert_with(|| json_type(value).to_string());
        }
    }
    object.columns = columns
        .into_iter()
        .enumerate()
        .map(|(index, (name, data_type))| BackupCatalogColumn {
            name,
            data_type,
            nullable: true,
            ordinal: index + 1,
        })
        .collect();
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn schema_less_object(metadata: &InstanceMetadata, kind: &str) -> BackupCatalogObject {
    BackupCatalogObject {
        id: object_id(&metadata.database.name, kind),
        namespace: metadata.database.name.clone(),
        name: kind.to_string(),
        kind: kind.to_string(),
        estimated_rows: None,
        columns: Vec::new(),
        preview_rows: Vec::new(),
        preview_truncated: false,
    }
}

fn object_id(namespace: &str, name: &str) -> String {
    fn escape(value: &str) -> String {
        value.replace('\\', "\\\\").replace('.', "\\.")
    }
    format!("{}.{}", escape(namespace), escape(name))
}

fn decode_hex(value: &str) -> Result<String, &'static str> {
    if !value.len().is_multiple_of(2) {
        return Err("invalid hex field length");
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0]).ok_or("invalid hex field")?;
        let low = hex_digit(pair[1]).ok_or("invalid hex field")?;
        bytes.push((high << 4) | low);
    }
    String::from_utf8(bytes).map_err(|_| "database identifier was not UTF-8")
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> (&str, bool) {
    if value.len() <= max_bytes {
        return (value, false);
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (&value[..end], true)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn postgres_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn mysql_identifier(value: &str) -> String {
    format!("`{}`", value.replace('`', "``"))
}

fn mysql_string(value: &str) -> String {
    let hex = value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    format!("CONVERT(0x{hex} USING utf8mb4)")
}

fn clickhouse_identifier(value: &str) -> String {
    format!("`{}`", value.replace('`', "``"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_schema_parser_groups_columns_by_object() {
        let output = "7075626c6963|7573657273|r|12|1|6964|626967696e74|NO\n7075626c6963|7573657273|r|12|2|6e616d65|74657874|YES\n";
        let objects = parse_postgres_schema(output).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].id, "public.users");
        assert_eq!(objects[0].columns.len(), 2);
        assert_eq!(objects[0].estimated_rows, Some(12));
    }

    #[test]
    fn bounded_catalog_drops_previews_before_schema() {
        let mut catalog = BackupCatalog {
            schema_version: BACKUP_CATALOG_SCHEMA_VERSION,
            backup_id: "one.physical.tar.gz".to_string(),
            instance_id: "inst_one".to_string(),
            protocol: Protocol::Postgres,
            database_name: "app".to_string(),
            captured_at: "2024-01-01T00:00:00Z".to_string(),
            consistency: "test".to_string(),
            truncated: false,
            warnings: Vec::new(),
            objects: vec![BackupCatalogObject {
                id: "public.users".to_string(),
                namespace: "public".to_string(),
                name: "users".to_string(),
                kind: "table".to_string(),
                estimated_rows: Some(1),
                columns: vec![BackupCatalogColumn {
                    name: "id".to_string(),
                    data_type: "bigint".to_string(),
                    nullable: false,
                    ordinal: 1,
                }],
                preview_rows: vec![serde_json::json!({"large": "x".repeat(1024)})],
                preview_truncated: false,
            }],
        };
        let bytes = catalog.clone().encode_bounded(700).unwrap();
        catalog = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(catalog.objects.len(), 1);
        assert!(catalog.objects[0].preview_rows.is_empty());
        assert!(catalog.truncated);
    }

    #[test]
    fn identifier_quoting_never_turns_names_into_commands() {
        assert_eq!(postgres_identifier("a\"b"), "\"a\"\"b\"");
        assert_eq!(mysql_identifier("a`b"), "`a``b`");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn object_ids_escape_dots_and_backslashes_without_changing_normal_ids() {
        assert_eq!(object_id("public", "users"), "public.users");
        assert_ne!(object_id("a.b", "c"), object_id("a", "b.c"));
        assert_ne!(object_id("a\\b", "c"), object_id("a", "b\\c"));
    }

    #[test]
    fn mysql_json_keys_use_hex_literals() {
        assert_eq!(
            mysql_string("odd'\\name"),
            "CONVERT(0x6F6464275C6E616D65 USING utf8mb4)"
        );
    }

    #[test]
    fn preview_parser_uses_an_extra_row_as_a_truncation_sentinel() {
        let (rows, truncated) = parse_preview_rows(
            Protocol::Postgres,
            "{\"id\":1}\n{\"id\":2}\n{\"id\":3}\n",
            2,
            1024,
        );

        assert_eq!(rows.len(), 2);
        assert!(truncated);
    }
}
