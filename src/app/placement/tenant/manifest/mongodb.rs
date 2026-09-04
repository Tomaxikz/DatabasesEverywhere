use std::path::PathBuf;

use bson::{raw::RawBsonRef, raw::RawDocument};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, BufReader};
use uuid::Uuid;

use super::{
    MAX_OBJECTS, ManifestError,
    model::{CollectedManifest, DataRecord, MultisetAccumulator, SchemaRecord, object_key},
    query::{ManifestContext, validate_identifier},
};
use crate::runtime::docker::DockerError;

const PAGE_SIZE: usize = 64;
const MAX_BSON_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_BSON_NESTING_DEPTH: usize = 128;

#[derive(Debug, Deserialize)]
struct CollectionRecord {
    name: String,
    kind: String,
    data_bearing: bool,
    schema: String,
}

pub(super) async fn collect(
    context: &ManifestContext<'_>,
) -> Result<CollectedManifest, ManifestError> {
    let collections = collection_catalog(context).await?;
    let mut collected = CollectedManifest::default();
    let mut scanned_bytes = 0_u64;
    for collection in collections {
        collected.push_schema(SchemaRecord::new(
            object_key("collection", &[&collection.name, &collection.kind]),
            collection.schema,
        )?)?;
        if !collection.data_bearing {
            continue;
        }
        let remaining = context.max_data_bytes.saturating_sub(scanned_bytes);
        let path = temp_path();
        let guard = TempFileGuard(path.clone());
        let result = match context
            .mongo_to_file(&collection.name, &path, remaining)
            .await
        {
            Ok(result) => result,
            Err(ManifestError::Docker(DockerError::ExecStreamOutputTooLarge { .. })) => {
                return Err(ManifestError::DataLimit(context.max_data_bytes));
            }
            Err(error) => return Err(error),
        };
        scanned_bytes = scanned_bytes
            .checked_add(result.transferred_bytes)
            .ok_or(ManifestError::DataLimit(context.max_data_bytes))?;
        if scanned_bytes > context.max_data_bytes {
            return Err(ManifestError::DataLimit(context.max_data_bytes));
        }
        let key = object_key("collection-data", &[&collection.name]);
        let digest = digest_bson_file(context, &path, &key).await?;
        drop(guard);
        collected.push_data(DataRecord::new(key, digest)?)?;
    }
    Ok(collected)
}

async fn collection_catalog(
    context: &ManifestContext<'_>,
) -> Result<Vec<CollectionRecord>, ManifestError> {
    let mut collections = Vec::new();
    let mut offset = 0;
    loop {
        let script = collection_catalog_script(offset, context.engine_timeout()?.as_millis());
        let output = context.query(&script).await?;
        let mut rows = 0;
        for line in output.lines().filter(|line| !line.trim().is_empty()) {
            rows += 1;
            let record: CollectionRecord = serde_json::from_str(line).map_err(|_| {
                ManifestError::InvalidCatalog("invalid MongoDB collection catalog row")
            })?;
            validate_identifier(&record.name)?;
            if !matches!(record.kind.as_str(), "collection" | "timeseries" | "view") {
                return Err(ManifestError::UnsupportedFeature(format!(
                    "MongoDB collection {} has unsupported type {}",
                    record.name, record.kind
                )));
            }
            if record.schema.len() > 1024 * 1024 {
                return Err(ManifestError::SchemaLimit(1024 * 1024));
            }
            collections.push(record);
            if collections.len() > MAX_OBJECTS {
                return Err(ManifestError::ObjectLimit(MAX_OBJECTS));
            }
        }
        if rows < PAGE_SIZE {
            return Ok(collections);
        }
        offset += PAGE_SIZE;
    }
}

fn collection_catalog_script(offset: usize, _max_time_ms: u128) -> String {
    format!(
        r#"const offset = {offset};
const limit = {PAGE_SIZE};
const infos = db.getCollectionInfos()
  .filter(info => info.name === 'system.js' || !info.name.startsWith('system.'))
  .sort((left, right) => left.name.localeCompare(right.name))
  .slice(offset, offset + limit);
function cleanIndex(source) {{
  const value = Object.assign({{}}, source || {{}});
  delete value.v;
  delete value.ns;
  delete value.background;
  delete value.buildUUID;
  return value;
}}
for (const info of infos) {{
  const kind = info.type === 'collection' && info.options && info.options.timeseries
    ? 'timeseries'
    : info.type;
  const dataBearing = kind === 'collection' || kind === 'timeseries';
  const options = Object.assign({{}}, info.options || {{}});
  delete options.uuid;
  let indexes = [];
  if (dataBearing) {{
    indexes = db.getCollection(info.name).getIndexes()
      .map(cleanIndex)
      .sort((left, right) => left.name.localeCompare(right.name));
  }}
  const schema = EJSON.stringify({{
    kind,
    options,
    idIndex: cleanIndex(info.idIndex),
    indexes
  }});
  print(JSON.stringify({{
    name: info.name,
    kind,
    data_bearing: dataBearing,
    schema
  }}));
}}"#,
    )
}

async fn digest_bson_file(
    context: &ManifestContext<'_>,
    path: &PathBuf,
    key: &[u8],
) -> Result<super::model::MultisetDigest, ManifestError> {
    let file = tokio::fs::File::open(path).await?;
    let mut reader = BufReader::new(file);
    let mut digest = MultisetAccumulator::new();
    loop {
        let Some(prefix) = read_prefix(&mut reader).await? else {
            break;
        };
        let length = i32::from_le_bytes(prefix);
        if !(5..=MAX_BSON_DOCUMENT_BYTES as i32).contains(&length) {
            return Err(ManifestError::InvalidCatalog(
                "MongoDB dump contains an invalid BSON document length",
            ));
        }
        let mut document = vec![0_u8; length as usize];
        document[..4].copy_from_slice(&prefix);
        reader.read_exact(&mut document[4..]).await?;
        validate_bson(&document)?;
        digest.add(context.challenge, key, &document)?;
    }
    Ok(digest.finish())
}

async fn read_prefix<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<[u8; 4]>, ManifestError> {
    let mut prefix = [0_u8; 4];
    let mut filled = 0;
    while filled < prefix.len() {
        let read = reader.read(&mut prefix[filled..]).await?;
        if read == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(ManifestError::InvalidCatalog(
                "MongoDB dump ended in a BSON length prefix",
            ));
        }
        filled += read;
    }
    Ok(Some(prefix))
}

fn validate_bson(bytes: &[u8]) -> Result<(), ManifestError> {
    let root = RawDocument::from_bytes(bytes)
        .map_err(|_| ManifestError::InvalidCatalog("MongoDB dump contains malformed BSON"))?;
    let mut pending = vec![(root.iter_elements(), 0_usize)];
    while let Some((elements, depth)) = pending.last_mut() {
        let Some(element) = elements.next() else {
            pending.pop();
            continue;
        };
        let value = element
            .and_then(|element| element.value())
            .map_err(|_| ManifestError::InvalidCatalog("MongoDB dump contains malformed BSON"))?;
        let nested = match value {
            RawBsonRef::Document(document) => Some(document),
            RawBsonRef::Array(array) => {
                Some(RawDocument::from_bytes(array.as_bytes()).map_err(|_| {
                    ManifestError::InvalidCatalog("MongoDB dump contains malformed BSON")
                })?)
            }
            RawBsonRef::JavaScriptCodeWithScope(code) => Some(code.scope),
            _ => None,
        };
        if let Some(document) = nested {
            let next_depth = *depth + 1;
            if next_depth > MAX_BSON_NESTING_DEPTH {
                return Err(ManifestError::UnsupportedFeature(
                    "MongoDB BSON nesting exceeds the manifest depth limit".to_string(),
                ));
            }
            pending.push((document.iter_elements(), next_depth));
        }
    }
    Ok(())
}

fn temp_path() -> PathBuf {
    std::env::temp_dir().join(format!("dbev-manifest-{}.bson", Uuid::new_v4()))
}

struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                path = %self.0.display(),
                %error,
                "failed to remove temporary MongoDB manifest stream"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use bson::doc;

    use super::*;

    #[test]
    fn catalog_schema_strips_runtime_index_fields_and_keeps_index_semantics() {
        let script = collection_catalog_script(0, 1000);
        assert!(script.contains("delete value.v"));
        assert!(script.contains("delete value.buildUUID"));
        assert!(script.contains("getIndexes"));
        assert!(script.contains("options"));
    }

    #[test]
    fn raw_bson_validation_accepts_nested_values_and_rejects_truncation() {
        let bytes = bson::to_vec(&doc! { "nested": { "value": 1 }, "items": [1, 2] }).unwrap();
        validate_bson(&bytes).unwrap();
        assert!(validate_bson(&bytes[..bytes.len() - 1]).is_err());
    }
}
