use super::{
    ManifestError,
    model::{CollectedManifest, DataRecord, MultisetDigest, SchemaRecord, object_key},
    normalize::normalize_clickhouse_ddl,
    query::{ManifestContext, decode_base64, decode_utf8, validate_identifier},
};
use crate::{
    databases::clickhouse::provision::quote_ident as quote_clickhouse,
    shared::ids::portable_identifier,
};

const PAGE_SIZE: usize = 128;

#[derive(Debug)]
struct Table {
    name: String,
    engine: String,
    definition: Vec<u8>,
}

pub(super) async fn collect(
    context: &ManifestContext<'_>,
) -> Result<CollectedManifest, ManifestError> {
    context.check_scan_bytes(data_size_sql()).await?;
    let tables = table_catalog(context).await?;
    let mut collected = CollectedManifest::default();
    for table in tables {
        if !portable_engine(&table.engine) {
            return Err(ManifestError::UnsupportedFeature(format!(
                "ClickHouse table {} uses unsupported logical-migration engine {}",
                table.name, table.engine
            )));
        }
        reject_unstable_types(context, &table.name).await?;
        collected.push_schema(SchemaRecord::new(
            object_key("table", &[&table.name]),
            table.definition,
        )?)?;
        collected.push_data(DataRecord::new(
            object_key("table-data", &[&table.name]),
            table_digest(context, &table.name).await?,
        )?)?;
    }
    Ok(collected)
}

fn data_size_sql() -> &'static str {
    r#"SELECT toString(sum(toUInt64(total_bytes)))
FROM system.tables
WHERE database = currentDatabase() AND is_temporary = 0
FORMAT TSVRaw;"#
}

async fn table_catalog(context: &ManifestContext<'_>) -> Result<Vec<Table>, ManifestError> {
    let mut tables = Vec::new();
    let mut offset = 0;
    loop {
        let sql = format!(
            r#"SELECT
  base64Encode(name),
  base64Encode(engine),
  base64Encode(create_table_query)
FROM system.tables
WHERE database = currentDatabase() AND is_temporary = 0
ORDER BY name
LIMIT {PAGE_SIZE} OFFSET {offset}
FORMAT TSVRaw;"#,
        );
        let output = context.query(&sql).await?;
        let mut rows = 0;
        for line in output.lines().filter(|line| !line.trim().is_empty()) {
            rows += 1;
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != 3 {
                return Err(ManifestError::InvalidCatalog(
                    "invalid ClickHouse table catalog row",
                ));
            }
            let name = decode_utf8(fields[0])?;
            let engine = decode_utf8(fields[1])?;
            let definition = String::from_utf8(decode_base64(fields[2])?)
                .map_err(|_| ManifestError::InvalidCatalog("ClickHouse definition is not UTF-8"))?;
            validate_identifier(&name)?;
            validate_identifier(&engine)?;
            if !portable_identifier(&name, 128) {
                return Err(ManifestError::UnsupportedFeature(format!(
                    "ClickHouse table {name} has a name the logical exporter cannot preserve"
                )));
            }
            tables.push(Table {
                name,
                engine,
                definition: normalize_clickhouse_ddl(&definition, context.target.database)
                    .into_bytes(),
            });
        }
        if rows < PAGE_SIZE {
            return Ok(tables);
        }
        offset += PAGE_SIZE;
    }
}

async fn reject_unstable_types(
    context: &ManifestContext<'_>,
    table: &str,
) -> Result<(), ManifestError> {
    let sql = format!(
        r#"SELECT base64Encode(name), base64Encode(type)
FROM system.columns
WHERE database = currentDatabase() AND table = {}
ORDER BY position
FORMAT TSVRaw;"#,
        clickhouse_string(table),
    );
    let output = context.query(&sql).await?;
    let mut columns = 0;
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        columns += 1;
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 2 {
            return Err(ManifestError::InvalidCatalog(
                "invalid ClickHouse column catalog row",
            ));
        }
        let name = decode_utf8(fields[0])?;
        let data_type = decode_utf8(fields[1])?;
        if unstable_type(&data_type) {
            return Err(ManifestError::UnsupportedFeature(format!(
                "ClickHouse column {table}.{name} uses {data_type}, whose portable RowBinary representation is not stable enough for cutover validation"
            )));
        }
    }
    if columns == 0 {
        return Err(ManifestError::InvalidCatalog(
            "ClickHouse table has no visible columns",
        ));
    }
    Ok(())
}

async fn table_digest(
    context: &ManifestContext<'_>,
    table: &str,
) -> Result<MultisetDigest, ManifestError> {
    let timeout = context.engine_timeout()?.as_secs().max(1);
    let sql = format!(
        r#"WITH SHA256(concat(unhex('{challenge}'), formatRow('RowBinary', *))) AS hash
SELECT
  count(),
  toString(sumWithOverflow(reinterpretAsUInt64(substring(hash, 1, 8)))),
  toString(sumWithOverflow(reinterpretAsUInt64(substring(hash, 9, 8)))),
  toString(sumWithOverflow(reinterpretAsUInt64(substring(hash, 17, 8)))),
  toString(sumWithOverflow(reinterpretAsUInt64(substring(hash, 25, 8)))),
  toString(groupBitXor(reinterpretAsUInt64(substring(hash, 1, 8)))),
  toString(groupBitXor(reinterpretAsUInt64(substring(hash, 9, 8)))),
  toString(groupBitXor(reinterpretAsUInt64(substring(hash, 17, 8)))),
  toString(groupBitXor(reinterpretAsUInt64(substring(hash, 25, 8))))
FROM {table}
SETTINGS max_execution_time = {timeout}, max_bytes_to_read = {max_bytes}
FORMAT TSVRaw;"#,
        challenge = context.challenge.hex(),
        table = quote_clickhouse(table),
        max_bytes = context.max_data_bytes,
    );
    MultisetDigest::parse_tsv(&context.query(&sql).await?)
}

fn portable_engine(engine: &str) -> bool {
    matches!(
        engine,
        "MergeTree"
            | "ReplacingMergeTree"
            | "SummingMergeTree"
            | "AggregatingMergeTree"
            | "CollapsingMergeTree"
            | "VersionedCollapsingMergeTree"
            | "GraphiteMergeTree"
            | "CoalescingMergeTree"
            | "Log"
            | "TinyLog"
            | "StripeLog"
            | "Memory"
    )
}

fn unstable_type(data_type: &str) -> bool {
    let compact = data_type.replace(' ', "").to_ascii_lowercase();
    compact == "json"
        || compact.starts_with("json(")
        || compact.starts_with("object(")
        || compact == "dynamic"
        || compact.starts_with("dynamic(")
        || compact.starts_with("aggregatefunction(")
        || compact.starts_with("variant(")
}

fn clickhouse_string(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unstable_cross_version_types_fail_closed() {
        for data_type in [
            "JSON",
            "Object('json')",
            "Dynamic",
            "AggregateFunction(sum, UInt64)",
            "Variant(UInt64, String)",
        ] {
            assert!(unstable_type(data_type), "{data_type}");
        }
        assert!(!unstable_type("Array(Nullable(Tuple(UInt64, String)))"));
    }

    #[test]
    fn engine_allowlist_matches_the_portable_exporter() {
        assert!(portable_engine("MergeTree"));
        assert!(portable_engine("Memory"));
        assert!(!portable_engine("Distributed"));
        assert!(!portable_engine("MaterializedView"));
        assert!(data_size_sql().contains("total_bytes"));
    }
}
