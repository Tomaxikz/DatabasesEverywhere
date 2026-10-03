use crate::{
    databases::engine::EngineInspection,
    server::backup::catalog::{
        BackupCatalogObject, ParsedColumn, decode_hex, parse_relational_schema,
    },
    server::metadata::InstanceMetadata,
    server::placement::DeploymentMode,
    utils::shell::sh_quote,
};

use super::engine::Mysql;

const MAX_MYSQL_PREVIEW_COLUMNS: usize = 128;

impl EngineInspection for Mysql {
    fn catalog_schema_script(
        &self,
        metadata: &InstanceMetadata,
        max_objects: usize,
    ) -> Option<String> {
        let command = if metadata.deployment_mode == DeploymentMode::Shared {
            "MYSQL_PWD=\"$DBE_MYSQL_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u \"$MYSQL_USER\" --database=\"$MYSQL_DATABASE\""
        } else {
            "MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root --database=\"$MYSQL_DATABASE\""
        };
        Some(schema_script(command, max_objects))
    }

    fn parse_catalog_schema(&self, output: &str) -> Result<Vec<BackupCatalogObject>, String> {
        parse_mysql_schema(output)
    }

    fn catalog_preview_script(
        &self,
        metadata: &InstanceMetadata,
        object: &BackupCatalogObject,
        rows: usize,
        max_row_bytes: usize,
    ) -> Option<String> {
        let command = if metadata.deployment_mode == DeploymentMode::Shared {
            "MYSQL_PWD=\"$DBE_MYSQL_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u \"$MYSQL_USER\" \"$MYSQL_DATABASE\""
        } else {
            "MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root \"$MYSQL_DATABASE\""
        };
        preview_script(command, object, rows, max_row_bytes)
    }
}

pub(crate) fn schema_script(command: &str, max_objects: usize) -> String {
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

pub(crate) fn preview_script(
    command: &str,
    object: &BackupCatalogObject,
    rows: usize,
    max_row_bytes: usize,
) -> Option<String> {
    if object.columns.is_empty() || object.columns.len() > MAX_MYSQL_PREVIEW_COLUMNS {
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
    Some(format!(
        "set -eu\n{command} --batch --raw --skip-column-names -e {}\n",
        sh_quote(&query)
    ))
}

pub(crate) fn parse_mysql_schema(output: &str) -> Result<Vec<BackupCatalogObject>, String> {
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

pub(crate) fn mysql_identifier(value: &str) -> String {
    format!("`{}`", value.replace('`', "``"))
}

pub(crate) fn mysql_string(value: &str) -> String {
    let hex = value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    format!("CONVERT(0x{hex} USING utf8mb4)")
}
