use crate::{
    databases::engine::EngineInspection,
    instance::backup::catalog::{
        BackupCatalogObject, ParsedColumn, decode_hex, parse_relational_schema,
    },
    instance::metadata::InstanceMetadata,
    utils::shell::sh_quote,
};

use super::engine::Clickhouse;

impl EngineInspection for Clickhouse {
    fn catalog_schema_script(
        &self,
        _metadata: &InstanceMetadata,
        max_objects: usize,
    ) -> Option<String> {
        Some(schema_script(max_objects))
    }

    fn parse_catalog_schema(&self, output: &str) -> Result<Vec<BackupCatalogObject>, String> {
        parse_clickhouse_schema(output)
    }

    fn catalog_preview_script(
        &self,
        _metadata: &InstanceMetadata,
        object: &BackupCatalogObject,
        rows: usize,
        max_row_bytes: usize,
    ) -> Option<String> {
        let query = format!(
            "SELECT substring(toJSONString(tuple(*)), 1, {max_row_bytes}) FROM {} LIMIT {rows} FORMAT TSVRaw",
            clickhouse_identifier(&object.name)
        );
        Some(format!(
            "set -eu\nclickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query {}\n",
            sh_quote(&query)
        ))
    }
}

fn schema_script(max_objects: usize) -> String {
    let query = format!(
        "SELECT hex(c.database), hex(c.table), hex(t.engine), ifNull(t.total_rows, 0), c.position, hex(c.name), hex(c.type), toUInt8(startsWith(c.type, 'Nullable(')) FROM system.columns c INNER JOIN (SELECT database, name, engine, total_rows FROM system.tables WHERE database = currentDatabase() ORDER BY name LIMIT {max_objects}) t ON t.database = c.database AND t.name = c.table ORDER BY c.database, c.table, c.position FORMAT TSVRaw"
    );
    format!(
        "set -eu\nclickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query {}\n",
        sh_quote(&query)
    )
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

fn clickhouse_identifier(value: &str) -> String {
    format!("`{}`", value.replace('`', "``"))
}
