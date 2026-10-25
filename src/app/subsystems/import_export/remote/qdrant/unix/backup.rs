//! Online Qdrant backups through the snapshot API.
//!
//! Capture snapshots every collection over the instance's always-on HTTP
//! socket, downloads each one and deletes it from the instance before the next
//! starts. A `collections.json` manifest records the Qdrant version, every
//! collection's file, size and SHA-256, and the aliases. Each collection is
//! consistent on its own; there is no common point across collections.
//!
//! Restore wipes the running instance and uploads the snapshots through the
//! same path a remote import takes, rollback snapshots and quarantine
//! included.
//!
//! Qdrant names its snapshots itself, so they cannot carry the backup job's
//! ownership tag. A daemon crash between creating and deleting one leaves
//! that single snapshot in the instance, listed by Qdrant's snapshot API.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    databases::protocol::Protocol,
    routes::http::{response::ApiError, router::AppState},
    server::metadata::InstanceMetadata,
    utils::backend::{BackendEndpoint, qdrant_http_socket_path},
};

use super::{
    super::super::{ImportMode, prepare_private_dir, staging_directory},
    MAX_QDRANT_ALIASES, MAX_QDRANT_COLLECTIONS, QdrantHttp,
    apply::{ApplyBudget, StagedSource, apply_staged_source},
    cleanup_staging, cleanup_target_snapshots,
    compat::version_triplet,
    selected_aliases,
    selection::{QdrantAlias, valid_qdrant_name},
};

pub(crate) const MANIFEST_FILE: &str = "collections.json";
const MANIFEST_SCHEMA: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const API_KEY_ENV: &str = "QDRANT__SERVICE__API_KEY";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CollectionsSummary {
    pub qdrant_version: String,
    pub collections: usize,
    pub aliases: usize,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CollectionsManifest {
    schema_version: u32,
    qdrant_version: String,
    collections: Vec<CapturedCollection>,
    aliases: Vec<QdrantAlias>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CapturedCollection {
    name: String,
    file: String,
    bytes: u64,
    sha256: String,
}

fn snapshot_file(index: usize) -> String {
    format!("collection-{index}.snapshot")
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl CollectionsManifest {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != MANIFEST_SCHEMA {
            return Err(format!(
                "the qdrant collection manifest uses schema {}, which this daemon cannot read",
                self.schema_version
            ));
        }
        if version_triplet(&self.qdrant_version).is_none() {
            return Err("the qdrant collection manifest has an invalid version".to_string());
        }
        if self.collections.len() > MAX_QDRANT_COLLECTIONS
            || self.aliases.len() > MAX_QDRANT_ALIASES
        {
            return Err("the qdrant collection manifest lists too many entries".to_string());
        }
        let mut names = HashSet::new();
        for (index, collection) in self.collections.iter().enumerate() {
            if !valid_qdrant_name(&collection.name) || !names.insert(collection.name.as_str()) {
                return Err("the qdrant collection manifest has an invalid collection".to_string());
            }
            if collection.file != snapshot_file(index)
                || collection.bytes == 0
                || !is_sha256(&collection.sha256)
            {
                return Err(format!(
                    "the qdrant collection manifest entry for {} is invalid",
                    collection.name
                ));
            }
        }
        let mut alias_names = HashSet::new();
        for alias in &self.aliases {
            if !valid_qdrant_name(&alias.alias_name)
                || !alias_names.insert(alias.alias_name.as_str())
                || names.contains(alias.alias_name.as_str())
                || !names.contains(alias.collection_name.as_str())
            {
                return Err(format!(
                    "the qdrant collection manifest alias {} is invalid",
                    alias.alias_name
                ));
            }
        }
        Ok(())
    }

    fn summary(&self) -> CollectionsSummary {
        CollectionsSummary {
            qdrant_version: self.qdrant_version.clone(),
            collections: self.collections.len(),
            aliases: self.aliases.len(),
            bytes: self.collections.iter().fold(0, |total, collection| {
                total.saturating_add(collection.bytes)
            }),
        }
    }
}

/// The instance's always-on HTTP socket, next to its gRPC socket.
fn managed_http_socket(metadata: &InstanceMetadata) -> Result<PathBuf, ApiError> {
    let BackendEndpoint::UnixSocket { socket_path } = &metadata.backend else {
        return Err(ApiError::Conflict(
            "this qdrant instance has no unix socket backend; restart it once to upgrade its runtime"
                .to_string(),
        ));
    };
    qdrant_http_socket_path(Path::new(socket_path))
        .ok_or_else(|| ApiError::Runtime("invalid qdrant backend socket path".to_string()))
}

/// Snapshots every collection into `output` (created here) within
/// `max_bytes` and `deadline`. Leaves no snapshot in the instance unless the
/// daemon itself stops mid-collection.
pub(crate) async fn capture_collections(
    state: &AppState,
    metadata: &InstanceMetadata,
    output: &Path,
    max_bytes: u64,
    deadline: tokio::time::Instant,
) -> Result<CollectionsSummary, ApiError> {
    let socket = managed_http_socket(metadata)?;
    let key = state
        .docker
        .container_environment_value(Protocol::Qdrant, metadata.runtime_id(), API_KEY_ENV)
        .await
        .map_err(ApiError::runtime_context(
            "failed to read the managed qdrant API key",
        ))?
        .ok_or_else(|| {
            ApiError::Runtime("the managed qdrant API key is unavailable".to_string())
        })?;
    let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
    if timeout.is_zero() {
        return Err(capture_timeout());
    }
    let client = QdrantHttp::target_socket(&socket, &key, timeout)?;
    let mut pending = None;
    let result = tokio::time::timeout_at(
        deadline,
        capture_into(&client, output, max_bytes, &mut pending),
    )
    .await
    .unwrap_or_else(|_| Err(capture_timeout()));
    if result.is_err()
        && let Some(snapshot) = pending
    {
        cleanup_target_snapshots(&client, &[snapshot]).await;
    }
    result
}

fn capture_timeout() -> ApiError {
    ApiError::ServiceUnavailable(
        "qdrant snapshot capture exceeded the online backup deadline".to_string(),
    )
}

async fn capture_into(
    client: &QdrantHttp,
    output: &Path,
    max_bytes: u64,
    pending: &mut Option<(String, String)>,
) -> Result<CollectionsSummary, ApiError> {
    let qdrant_version = client.version().await?;
    client.check_standalone().await?;
    let mut names = client.collections().await?;
    names.sort();
    prepare_private_dir(output).await?;
    let mut collections = Vec::with_capacity(names.len());
    let mut total = 0_u64;
    for (index, name) in names.iter().enumerate() {
        let (snapshot, reported) = client.create_snapshot_with_checksum(name).await?;
        *pending = Some((name.clone(), snapshot.clone()));
        let file = snapshot_file(index);
        let path = output.join(&file);
        let bytes = client
            .download_snapshot(name, &snapshot, &path, max_bytes.saturating_sub(total))
            .await?;
        client.delete_snapshot(name, &snapshot).await?;
        *pending = None;
        total = total.saturating_add(bytes);
        let sha256 = hash_file(path).await?;
        if reported.is_some_and(|reported| reported != sha256) {
            return Err(ApiError::Runtime(format!(
                "the snapshot of qdrant collection {name} does not match the checksum qdrant reported"
            )));
        }
        collections.push(CapturedCollection {
            name: name.clone(),
            file,
            bytes,
            sha256,
        });
    }
    // Aliases read last, limited to the collections captured.
    let captured = names.into_iter().collect::<HashSet<_>>();
    let aliases = selected_aliases(client.aliases().await?, &captured);
    let manifest = CollectionsManifest {
        schema_version: MANIFEST_SCHEMA,
        qdrant_version,
        collections,
        aliases,
    };
    manifest.validate().map_err(ApiError::Runtime)?;
    let contents = serde_json::to_vec_pretty(&manifest).map_err(ApiError::runtime_context(
        "failed to encode the qdrant collection manifest",
    ))?;
    let path = output.join(MANIFEST_FILE);
    crate::routes::http::response::run_blocking(
        "failed to write the qdrant collection manifest",
        move || crate::io::files::atomic_write_private(&path, &contents),
    )
    .await?;
    Ok(manifest.summary())
}

async fn hash_file(path: PathBuf) -> Result<String, ApiError> {
    crate::routes::http::response::run_blocking("failed to hash a qdrant snapshot", move || {
        crate::utils::hash::sha256_reader(std::fs::File::open(&path)?)
    })
    .await
}

fn read_manifest(dir: &Path) -> Result<CollectionsManifest, String> {
    let path = dir.join(MANIFEST_FILE);
    crate::io::files::require_regular_file(&path)?;
    let size = std::fs::metadata(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?
        .len();
    if size > MAX_MANIFEST_BYTES {
        return Err("the qdrant collection manifest is too large".to_string());
    }
    let contents = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let manifest: CollectionsManifest = serde_json::from_slice(&contents)
        .map_err(|error| format!("the qdrant collection manifest is invalid: {error}"))?;
    manifest.validate()?;
    Ok(manifest)
}

/// Checks the manifest and that every snapshot file is present with its
/// recorded size and SHA-256. Blocking.
fn check_collections(dir: &Path) -> Result<CollectionsManifest, String> {
    let manifest = read_manifest(dir)?;
    for collection in &manifest.collections {
        let path = dir.join(&collection.file);
        crate::io::files::require_regular_file(&path)?;
        let file =
            std::fs::File::open(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let size = file
            .metadata()
            .map_err(|error| format!("{}: {error}", path.display()))?
            .len();
        if size != collection.bytes {
            return Err(format!(
                "the snapshot of qdrant collection {} has {size} bytes, not the recorded {}",
                collection.name, collection.bytes
            ));
        }
        let sha256 = crate::utils::hash::sha256_reader(file)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if sha256 != collection.sha256 {
            return Err(format!(
                "the snapshot of qdrant collection {} does not match its recorded checksum",
                collection.name
            ));
        }
    }
    Ok(manifest)
}

/// Blocking verification of a captured collection directory.
pub(crate) fn verify_collections(dir: &Path) -> Result<CollectionsSummary, String> {
    check_collections(dir).map(|manifest| manifest.summary())
}

/// Moves the checked snapshots into the import staging layout.
fn stage_snapshots(
    payload: &Path,
    staging: &Path,
    manifest: &CollectionsManifest,
) -> Result<(), String> {
    for (index, collection) in manifest.collections.iter().enumerate() {
        let source = payload.join(&collection.file);
        let target = staging.join(format!("source-{index}.snapshot"));
        if std::fs::rename(&source, &target).is_err() {
            std::fs::copy(&source, &target)
                .map_err(|error| format!("stage {}: {error}", collection.file))?;
        }
    }
    Ok(())
}

/// Replaces every collection and alias of the running instance with the
/// captured ones in `payload`, rolling back on failure.
pub(crate) async fn restore_collections(
    state: &AppState,
    metadata: &InstanceMetadata,
    payload: &Path,
    timeout: Duration,
) -> Result<(), ApiError> {
    let dir = payload.to_path_buf();
    let manifest = tokio::task::spawn_blocking(move || check_collections(&dir))
        .await
        .map_err(ApiError::runtime)?
        .map_err(ApiError::Conflict)?;
    let rollback_bytes =
        crate::subsystems::import_export::jobs::measure_export_bytes(state, metadata).await?;
    let _capacity = state
        .import_uploads
        .reserve_output_capacity(Path::new(&state.config.paths.tmp_root()), rollback_bytes)
        .await?;
    let staging = staging_directory(state).await?;
    let summary = manifest.summary();
    let staged = {
        let (payload, staging) = (payload.to_path_buf(), staging.clone());
        tokio::task::spawn_blocking(move || {
            stage_snapshots(&payload, &staging, &manifest).map(|()| manifest)
        })
        .await
    };
    let manifest = match staged {
        Ok(Ok(manifest)) => manifest,
        Ok(Err(error)) => {
            cleanup_staging(&staging).await;
            return Err(ApiError::Runtime(error));
        }
        Err(error) => {
            cleanup_staging(&staging).await;
            return Err(ApiError::runtime(error));
        }
    };
    let started = tokio::time::Instant::now();
    apply_staged_source(
        state,
        &metadata.instance_id,
        StagedSource {
            staging,
            version: manifest.qdrant_version,
            collections: manifest
                .collections
                .into_iter()
                .map(|collection| collection.name)
                .collect(),
            aliases: manifest.aliases,
            staged_bytes: summary.bytes,
            operation: "backup restore",
        },
        ImportMode::Wipe,
        ApplyBudget {
            request_timeout: timeout,
            work_deadline: started + timeout - timeout / 4,
            operation_deadline: started + timeout,
            max_staged_bytes: summary.bytes.saturating_add(rollback_bytes),
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn manifest() -> CollectionsManifest {
        CollectionsManifest {
            schema_version: MANIFEST_SCHEMA,
            qdrant_version: "1.13.2".to_string(),
            collections: vec![
                CapturedCollection {
                    name: "docs".to_string(),
                    file: snapshot_file(0),
                    bytes: 4,
                    sha256: HASH.to_string(),
                },
                CapturedCollection {
                    name: "images".to_string(),
                    file: snapshot_file(1),
                    bytes: 4,
                    sha256: HASH.to_string(),
                },
            ],
            aliases: vec![QdrantAlias {
                alias_name: "current".to_string(),
                collection_name: "docs".to_string(),
            }],
        }
    }

    #[test]
    fn manifests_must_be_self_consistent() {
        assert!(manifest().validate().is_ok());
        let mut renamed = manifest();
        renamed.collections[1].file = "../escape".to_string();
        assert!(renamed.validate().is_err());
        let mut duplicate = manifest();
        duplicate.collections[1].name = "docs".to_string();
        assert!(duplicate.validate().is_err());
        let mut dangling = manifest();
        dangling.aliases[0].collection_name = "missing".to_string();
        assert!(dangling.validate().is_err());
        let mut shadowing = manifest();
        shadowing.aliases[0].alias_name = "images".to_string();
        assert!(shadowing.validate().is_err());
        let mut uppercase = manifest();
        uppercase.collections[0].sha256 = HASH.to_ascii_uppercase();
        assert!(uppercase.validate().is_err());
        let mut future = manifest();
        future.schema_version = 2;
        assert!(future.validate().is_err());
    }

    #[test]
    fn verification_checks_sizes_and_checksums() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(snapshot_file(0)), b"test").unwrap();
        std::fs::write(dir.path().join(snapshot_file(1)), b"test").unwrap();
        std::fs::write(
            dir.path().join(MANIFEST_FILE),
            serde_json::to_vec(&manifest()).unwrap(),
        )
        .unwrap();
        let summary = verify_collections(dir.path()).unwrap();
        assert_eq!(
            (summary.collections, summary.aliases, summary.bytes),
            (2, 1, 8)
        );

        std::fs::write(dir.path().join(snapshot_file(1)), b"tess").unwrap();
        assert!(
            verify_collections(dir.path())
                .unwrap_err()
                .contains("checksum")
        );
        std::fs::write(dir.path().join(snapshot_file(1)), b"tests").unwrap();
        assert!(
            verify_collections(dir.path())
                .unwrap_err()
                .contains("bytes")
        );
        std::fs::remove_file(dir.path().join(snapshot_file(1))).unwrap();
        assert!(verify_collections(dir.path()).is_err());
    }

    #[test]
    fn staging_moves_snapshots_into_the_import_layout() {
        let payload = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(payload.path().join(snapshot_file(0)), b"a").unwrap();
        std::fs::write(payload.path().join(snapshot_file(1)), b"b").unwrap();
        stage_snapshots(payload.path(), staging.path(), &manifest()).unwrap();
        assert_eq!(
            std::fs::read(staging.path().join("source-1.snapshot")).unwrap(),
            b"b"
        );
        assert!(!payload.path().join(snapshot_file(0)).exists());
    }
}
