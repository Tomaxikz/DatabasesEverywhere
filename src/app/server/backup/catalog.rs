use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    config::BackupBrowsingConfig, databases::protocol::Protocol, runtime::docker::DockerRuntime,
    server::credentials::logical_export_env, server::metadata::InstanceMetadata,
    server::placement::DeploymentMode, utils::hex::nibble,
};

#[cfg(test)]
use crate::{
    databases::{
        mysql::inspection::{mysql_identifier, mysql_string},
        postgres::inspection::{parse_postgres_schema, postgres_identifier},
    },
    utils::shell::sh_quote,
};

pub const BACKUP_CATALOG_SCHEMA_VERSION: u32 = 1;
const CATALOG_QUERY_TIMEOUT: Duration = Duration::from_secs(60);
const RELATIONAL_SCHEMA_FIELD_COUNT: usize = 8;

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
            captured_at: crate::server::jobs::import_export::now_rfc3339(),
            consistency: consistency_label(metadata.deployment_mode).to_string(),
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
                let layout = if metadata.deployment_mode == DeploymentMode::Shared {
                    "logical"
                } else {
                    "physical"
                };
                catalog.warnings.push(format!(
                    "{} schema introspection was unavailable; the {layout} backup is still restorable",
                    metadata.protocol.as_str()
                ));
            }
        }

        if policy.preview_rows_per_object > 0 && policy.max_preview_objects > 0 {
            capture_previews(docker, metadata, policy, &mut catalog).await;
        }
        if is_schema_less(metadata.protocol) {
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

    pub fn decode(bytes: &[u8], instance_id: &str, backup_id: &str) -> Result<Self, String> {
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

fn consistency_label(mode: DeploymentMode) -> &'static str {
    match mode {
        DeploymentMode::Dedicated => "captured_immediately_before_physical_archive",
        DeploymentMode::Shared => "captured_immediately_before_tenant_logical_dump",
    }
}

fn is_schema_less(protocol: Protocol) -> bool {
    protocol.engine().is_physical()
}

fn is_previewable(object: &BackupCatalogObject) -> bool {
    object.kind == "table" || object.kind == "collection"
}

async fn capture_schema(
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
    max_objects: usize,
) -> Result<Vec<BackupCatalogObject>, String> {
    let engine = metadata.protocol.engine();
    if let Some(kind) = engine.schema_less_catalog_kind() {
        return Ok(vec![schema_less_object(metadata, kind)]);
    }
    let Some(script) = engine.catalog_schema_script(metadata, max_objects) else {
        return Ok(Vec::new());
    };
    let output = run_query(docker, metadata, &script).await?;
    engine.parse_catalog_schema(&output)
}

async fn capture_previews(
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
    policy: &BackupBrowsingConfig,
    catalog: &mut BackupCatalog,
) {
    if is_schema_less(metadata.protocol) {
        return;
    }
    let mut failures = 0_usize;
    let previewable_objects = catalog
        .objects
        .iter()
        .filter(|object| is_previewable(object))
        .count();
    let eligible = catalog
        .objects
        .iter()
        .enumerate()
        .filter(|(_, object)| is_previewable(object))
        .take(policy.max_preview_objects)
        .map(|(index, object)| (index, object.clone()))
        .collect::<Vec<_>>();
    if eligible.len() < previewable_objects {
        catalog.truncated = true;
    }
    // Read one bounded sentinel row so callers can distinguish a complete
    // small object from a preview that stopped at the configured limit.
    let capture_rows = policy.preview_rows_per_object.saturating_add(1);
    for (index, object) in eligible {
        let script = metadata.protocol.engine().catalog_preview_script(
            metadata,
            &object,
            capture_rows,
            policy.max_row_bytes,
        );
        let Some(script) = script else {
            failures += 1;
            catalog.objects[index].preview_truncated = true;
            continue;
        };
        match run_query(docker, metadata, &script).await {
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
                metadata.protocol.engine().infer_preview_columns(target);
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

async fn run_query(
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
    script: &str,
) -> Result<String, String> {
    let credentials = logical_export_env(metadata).map_err(|error| error.to_string())?;
    let environment = credentials.references();
    let result = match metadata.deployment_mode {
        DeploymentMode::Dedicated => {
            docker
                .exec_shell_with_secrets_timeout(
                    metadata.protocol,
                    metadata.runtime_id(),
                    script,
                    &environment,
                    CATALOG_QUERY_TIMEOUT,
                )
                .await
        }
        DeploymentMode::Shared => {
            docker
                .exec_tenant_shell(
                    metadata.protocol,
                    metadata.runtime_id(),
                    script,
                    &environment,
                    CATALOG_QUERY_TIMEOUT,
                )
                .await
        }
    };
    result
        .map(|output| output.stdout)
        .map_err(|error| error.to_string())
}

pub(crate) struct ParsedColumn {
    pub(crate) namespace: String,
    pub(crate) object: String,
    pub(crate) kind: String,
    pub(crate) estimated_rows: Option<u64>,
    pub(crate) ordinal: usize,
    pub(crate) column: String,
    pub(crate) data_type: String,
    pub(crate) nullable: bool,
}

pub(crate) fn parse_relational_schema<F>(
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
        if fields.len() != RELATIONAL_SCHEMA_FIELD_COUNT {
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
    let lines = protocol.engine().preview_output_lines(output);
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

pub(crate) fn object_id(namespace: &str, name: &str) -> String {
    fn escape(value: &str) -> String {
        value.replace('\\', "\\\\").replace('.', "\\.")
    }
    format!("{}.{}", escape(namespace), escape(name))
}

pub(crate) fn decode_hex(value: &str) -> Result<String, &'static str> {
    if !value.len().is_multiple_of(2) {
        return Err("invalid hex field length");
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().as_chunks::<2>().0 {
        let high = nibble(pair[0]).ok_or("invalid hex field")?;
        let low = nibble(pair[1]).ok_or("invalid hex field")?;
        bytes.push((high << 4) | low);
    }
    String::from_utf8(bytes).map_err(|_| "database identifier was not UTF-8")
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
        assert_eq!(sh_quote("a'b"), "'a'\"'\"'b'");
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
