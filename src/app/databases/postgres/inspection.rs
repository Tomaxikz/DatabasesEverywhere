use crate::{
    databases::engine::EngineInspection,
    instance::backup::catalog::{
        BackupCatalogObject, ParsedColumn, decode_hex, parse_relational_schema,
    },
    instance::metadata::InstanceMetadata,
    utils::shell::sh_quote,
};

use super::engine::Postgres;

impl EngineInspection for Postgres {
    fn catalog_schema_script(
        &self,
        _metadata: &InstanceMetadata,
        max_objects: usize,
    ) -> Option<String> {
        Some(schema_script(max_objects))
    }

    fn parse_catalog_schema(&self, output: &str) -> Result<Vec<BackupCatalogObject>, String> {
        parse_postgres_schema(output)
    }

    fn catalog_preview_script(
        &self,
        _metadata: &InstanceMetadata,
        object: &BackupCatalogObject,
        rows: usize,
        max_row_bytes: usize,
    ) -> Option<String> {
        let qualified = format!(
            "{}.{}",
            postgres_identifier(&object.namespace),
            postgres_identifier(&object.name)
        );
        let query = format!(
            "SELECT left(row_to_json(dbev_row)::text, {max_row_bytes}) FROM (SELECT * FROM {qualified} LIMIT {rows}) AS dbev_row"
        );
        Some(format!(
            "set -eu\nPGPASSWORD=\"$DBE_POSTGRES_PASSWORD\" psql -X -qAt -v ON_ERROR_STOP=1 -h /var/run/postgresql -U \"$DBE_POSTGRES_USER\" -d \"$POSTGRES_DB\" -c {}\n",
            sh_quote(&query)
        ))
    }
}

fn schema_script(max_objects: usize) -> String {
    format!(
        r#"set -eu
PGPASSWORD="$DBE_POSTGRES_PASSWORD" psql \
  -X -qAt -F '|' -v ON_ERROR_STOP=1 \
  -h /var/run/postgresql \
  -U "$DBE_POSTGRES_USER" \
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

pub(crate) fn parse_postgres_schema(output: &str) -> Result<Vec<BackupCatalogObject>, String> {
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

pub(crate) fn postgres_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
