use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::{
    databases::engine::EngineInspection,
    server::backup::catalog::{BackupCatalogColumn, BackupCatalogObject, object_id},
    server::metadata::InstanceMetadata,
    server::placement::DeploymentMode,
    utils::shell::sh_quote,
};

use super::engine::Mongodb;

impl EngineInspection for Mongodb {
    fn catalog_schema_script(
        &self,
        metadata: &InstanceMetadata,
        max_objects: usize,
    ) -> Option<String> {
        Some(schema_script(
            metadata.deployment_mode == DeploymentMode::Shared,
            max_objects,
        ))
    }

    fn parse_catalog_schema(&self, output: &str) -> Result<Vec<BackupCatalogObject>, String> {
        parse_mongodb_schema(output)
    }

    fn catalog_preview_script(
        &self,
        metadata: &InstanceMetadata,
        object: &BackupCatalogObject,
        rows: usize,
        max_row_bytes: usize,
    ) -> Option<String> {
        let collection = serde_json::to_string(&object.name).ok()?;
        let javascript = format!(
            "const out=[]; for (const value of db.getCollection({collection}).find({{}}).limit({rows}).toArray()) {{ out.push(EJSON.stringify(value).slice(0,{max_row_bytes})); }} print(JSON.stringify(out));"
        );
        let auth = auth_arguments(metadata.deployment_mode == DeploymentMode::Shared);
        Some(format!(
            "set -eu\nmongosh --quiet --host 127.0.0.1 {auth} \"$DBE_MONGO_DATABASE\" --eval {}\n",
            sh_quote(&javascript)
        ))
    }

    fn preview_output_lines(&self, output: &str) -> Vec<String> {
        serde_json::from_str::<Vec<String>>(output.trim()).unwrap_or_default()
    }

    fn infer_preview_columns(&self, object: &mut BackupCatalogObject) {
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
}

fn schema_script(shared: bool, max_objects: usize) -> String {
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
    let auth = auth_arguments(shared);
    format!(
        "set -eu\nmongosh --quiet --host 127.0.0.1 {auth} \"$DBE_MONGO_DATABASE\" --eval {}\n",
        sh_quote(&javascript)
    )
}

fn auth_arguments(shared: bool) -> &'static str {
    if shared {
        "--username \"$DBE_MONGO_USER\" --password \"$DBE_MONGO_PASSWORD\" --authenticationDatabase \"$DBE_MONGO_DATABASE\""
    } else {
        "--username \"$DBE_MONGO_ROOT_USER\" --password \"$DBE_MONGO_ROOT_PASSWORD\" --authenticationDatabase admin"
    }
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
