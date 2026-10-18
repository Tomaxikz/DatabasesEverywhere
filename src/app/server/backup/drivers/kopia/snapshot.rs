//! Kopia command arguments, snapshot listing parsing and manifest tags.

use super::*;

pub(super) fn restore_arguments(object_path: &str, destination: &Path) -> Vec<OsString> {
    vec![
        OsString::from("snapshot"),
        OsString::from("restore"),
        OsString::from(object_path),
        destination.as_os_str().to_owned(),
        OsString::from("--write-files-atomically"),
        OsString::from("--no-ignore-errors"),
    ]
}

pub(super) fn create_arguments(
    source_path: &str,
    manifest: &StoredBackup,
    tags: Vec<String>,
) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("snapshot"),
        OsString::from("create"),
        OsString::from(source_path),
        OsString::from("--json"),
        OsString::from("--description"),
        OsString::from(format!("DatabasesEverywhere backup {}", manifest.backup_id)),
        // DBEV owns retention for these snapshots. Pinning prevents an
        // unrelated Kopia source policy from expiring them behind DBEV.
        // `--pin` takes a value; without one the CLI rejects the command.
        OsString::from("--pin"),
        OsString::from(DBEV_PIN),
    ];
    for tag in tags {
        arguments.push(OsString::from("--tags"));
        arguments.push(OsString::from(tag));
    }
    arguments
}

pub(super) fn source_manifest_arguments(path: &str) -> Vec<OsString> {
    vec![
        OsString::from("manifest"),
        OsString::from("list"),
        OsString::from("--json"),
        OsString::from("--filter"),
        OsString::from("type:snapshot"),
        // Kopia splits a filter at its first ':', so the path keeps its own.
        OsString::from("--filter"),
        OsString::from(format!("path:{path}")),
    ]
}

/// The source path Kopia records for `directory`: `filepath.Clean` of the
/// absolute path, without resolving symlinks.
pub(super) fn snapshot_source_path(directory: &Path) -> Result<String, BackupStoreError> {
    use std::path::Component;

    let mut clean = PathBuf::new();
    for component in directory.components() {
        match component {
            Component::RootDir | Component::Normal(_) => clean.push(component),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(BackupStoreError::InvalidConfiguration(format!(
                    "Kopia source {} must be a plain absolute path",
                    directory.display()
                )));
            }
        }
    }
    match clean.to_str() {
        Some(path) if clean.is_absolute() && clean.parent().is_some() => Ok(path.to_string()),
        _ => Err(BackupStoreError::InvalidConfiguration(format!(
            "Kopia source {} must be an absolute UTF-8 path below the root",
            directory.display()
        ))),
    }
}

pub(super) fn parse_snapshot_list(stdout: &[u8]) -> Result<Vec<KopiaManifest>, BackupStoreError> {
    serde_json::from_slice::<Vec<KopiaManifest>>(stdout)
        .map_err(|error| {
            BackupStoreError::Corrupt(format!(
                "Kopia returned invalid snapshot list JSON: {error}"
            ))
        })?
        .into_iter()
        .map(normalize_tags)
        .collect()
}

/// The filter is evaluated by Kopia; a manifest is deleted only when its
/// labels prove it is a snapshot of exactly `path`.
pub(super) fn source_entry_id(
    entry: KopiaManifestEntry,
    path: &str,
) -> Result<String, BackupStoreError> {
    let label = |name: &str| entry.labels.get(name).map(String::as_str);
    if label("type") == Some("snapshot") && label("path") == Some(path) && !entry.id.is_empty() {
        Ok(entry.id)
    } else {
        Err(BackupStoreError::Corrupt(format!(
            "Kopia returned manifest {} outside source {path}",
            entry.id
        )))
    }
}

pub(super) fn parse_manifest_entries(
    stdout: &[u8],
) -> Result<Vec<KopiaManifestEntry>, BackupStoreError> {
    serde_json::from_slice(stdout).map_err(|error| {
        BackupStoreError::Corrupt(format!(
            "Kopia returned invalid manifest list JSON: {error}"
        ))
    })
}

/// Strips the stored `tag:` prefix. An unprefixed key is accepted as the
/// same tag; one present in both forms with different values is ambiguous.
pub(super) fn normalize_tags(
    mut snapshot: KopiaManifest,
) -> Result<KopiaManifest, BackupStoreError> {
    let mut tags = HashMap::with_capacity(snapshot.tags.len());
    for (key, value) in std::mem::take(&mut snapshot.tags) {
        let key = key
            .strip_prefix(STORED_TAG_PREFIX)
            .map(str::to_string)
            .unwrap_or(key);
        if let Some(previous) = tags.insert(key.clone(), value)
            && tags.get(&key) != Some(&previous)
        {
            return Err(BackupStoreError::Corrupt(format!(
                "Kopia snapshot {} has conflicting values for tag {key}",
                snapshot.id
            )));
        }
    }
    snapshot.tags = tags;
    Ok(snapshot)
}

pub(super) fn instance_tag(instance_id: &str) -> String {
    format!("{TAG_INSTANCE}:{instance_id}")
}

pub(super) fn layout_tag_value(layout: BackupLayout) -> &'static str {
    match layout {
        BackupLayout::Physical => "physical",
        BackupLayout::Logical => "logical",
    }
}

pub(super) fn legacy_manifest_tags(manifest: &StoredBackup) -> Vec<String> {
    vec![
        instance_tag(&manifest.instance_id),
        format!("{TAG_BACKUP}:{}", manifest.backup_id),
        format!("{TAG_SIZE}:{}", manifest.size_bytes),
        format!("{TAG_SHA256}:{}", manifest.sha256),
        format!("{TAG_CREATED}:{}", manifest.created_at_unix),
        format!("{TAG_CREATED_AT}:{}", manifest.created_at.replace(':', "_")),
        format!("{TAG_PROTOCOL}:{}", manifest.protocol.as_str()),
        format!("{TAG_CATALOG}:{}", manifest.catalog_available),
        format!("{TAG_LAYOUT}:{}", layout_tag_value(manifest.layout)),
    ]
}

pub(super) fn v2_manifest_tags(
    manifest: &StoredBackup,
    manifest_sha256: &str,
) -> Result<Vec<String>, BackupStoreError> {
    let details = manifest.details.as_ref().ok_or_else(|| {
        BackupStoreError::Corrupt("schema 2 projection requires manifest details".to_string())
    })?;
    Ok(vec![
        instance_tag(&manifest.instance_id),
        format!("{TAG_BACKUP}:{}", manifest.backup_id),
        format!("{TAG_MANIFEST_VERSION}:{}", manifest.schema_version),
        format!("{TAG_MANIFEST_SHA256}:{manifest_sha256}"),
        format!("{TAG_V2_SIZE}:{}", manifest.size_bytes),
        format!("{TAG_V2_SHA256}:{}", manifest.sha256),
        format!("{TAG_V2_CREATED}:{}", manifest.created_at_unix),
        format!("{TAG_V2_FORMAT}:{}", format_tag_value(details.format)),
        format!("{TAG_V2_RECIPE}:{}", details.restore_recipe.tag_value()),
    ])
}

pub(super) fn format_tag_value(format: ArtifactFormat) -> &'static str {
    match format {
        ArtifactFormat::DataDirectoryArchive => "data_directory_archive",
        ArtifactFormat::LogicalDump => "logical_dump",
        ArtifactFormat::OnlineCapture => "online_capture",
    }
}

/// Schema 2 tag projection: enough to locate and authenticate the canonical
/// manifest and to cross-check it, never enough to reconstruct a recipe.
pub(super) struct V2Projection {
    pub(super) backup_id: String,
    pub(super) manifest_sha256: String,
    pub(super) size_bytes: u64,
    pub(super) sha256: String,
    pub(super) created_at_unix: i64,
    pub(super) format: String,
    pub(super) recipe: String,
}

impl V2Projection {
    pub(super) fn from_snapshot(
        instance_id: &str,
        snapshot: &KopiaManifest,
    ) -> Result<Self, BackupStoreError> {
        let tag = |name: &str| {
            snapshot.tags.get(name).cloned().ok_or_else(|| {
                BackupStoreError::Corrupt(format!("Kopia snapshot omitted tag {name}"))
            })
        };
        if tag(TAG_INSTANCE)? != instance_id {
            return Err(BackupStoreError::Corrupt(
                "Kopia snapshot instance tag does not match".to_string(),
            ));
        }
        let backup_id = tag(TAG_BACKUP)?;
        validate_backup_id(&backup_id)?;
        let manifest_sha256 = tag(TAG_MANIFEST_SHA256)?;
        if !crate::server::backup::is_sha256(&manifest_sha256) {
            return Err(BackupStoreError::Corrupt(
                "Kopia snapshot has an invalid manifest checksum tag".to_string(),
            ));
        }
        let invalid =
            |name: &str| BackupStoreError::Corrupt(format!("Kopia snapshot has invalid {name}"));
        Ok(Self {
            backup_id,
            manifest_sha256,
            size_bytes: tag(TAG_V2_SIZE)?
                .parse()
                .map_err(|_| invalid(TAG_V2_SIZE))?,
            sha256: tag(TAG_V2_SHA256)?,
            created_at_unix: tag(TAG_V2_CREATED)?
                .parse()
                .map_err(|_| invalid(TAG_V2_CREATED))?,
            format: tag(TAG_V2_FORMAT)?,
            recipe: tag(TAG_V2_RECIPE)?,
        })
    }

    pub(super) fn check(&self, manifest: &StoredBackup) -> Result<(), BackupStoreError> {
        let details = manifest.details.as_ref();
        let matches = manifest.backup_id == self.backup_id
            && manifest.size_bytes == self.size_bytes
            && manifest.sha256 == self.sha256
            && manifest.created_at_unix == self.created_at_unix
            && details.is_some_and(|details| {
                format_tag_value(details.format) == self.format
                    && details.restore_recipe.tag_value() == self.recipe
            });
        if matches {
            Ok(())
        } else {
            Err(BackupStoreError::Corrupt(format!(
                "Kopia snapshot tags disagree with the canonical manifest for {}",
                self.backup_id
            )))
        }
    }
}

pub(super) async fn read_metadata_file(path: PathBuf) -> Result<Vec<u8>, BackupStoreError> {
    tokio::task::spawn_blocking(move || read_bounded_private_file(&path, MAX_METADATA_BYTES))
        .await
        .map_err(|error| BackupStoreError::Runtime(format!("metadata read task failed: {error}")))?
        .map_err(|source| io_error("read backup metadata", source))
}

pub(super) fn record_from_snapshot(
    instance_id: &str,
    snapshot: &KopiaManifest,
) -> Result<StoredBackup, BackupStoreError> {
    let tag =
        |name: &str| {
            snapshot.tags.get(name).map(String::as_str).ok_or_else(|| {
                BackupStoreError::Corrupt(format!("Kopia snapshot omitted tag {name}"))
            })
        };
    if tag(TAG_INSTANCE)? != instance_id {
        return Err(BackupStoreError::Corrupt(
            "Kopia snapshot instance tag does not match".to_string(),
        ));
    }
    let backup_id = tag(TAG_BACKUP)?.to_string();
    validate_backup_id(&backup_id)?;
    let size_bytes = tag(TAG_SIZE)?.parse::<u64>().map_err(|_| {
        BackupStoreError::Corrupt("Kopia snapshot has invalid size tag".to_string())
    })?;
    let sha256 = tag(TAG_SHA256)?.to_string();
    let created_at_unix = tag(TAG_CREATED)?.parse::<i64>().map_err(|_| {
        BackupStoreError::Corrupt("Kopia snapshot has invalid creation timestamp".to_string())
    })?;
    let created_at = tag(TAG_CREATED_AT)?.replace('_', ":");
    let protocol = tag(TAG_PROTOCOL)?.parse::<Protocol>().map_err(|error| {
        BackupStoreError::Corrupt(format!("Kopia snapshot has invalid protocol: {error}"))
    })?;
    let catalog_available = tag(TAG_CATALOG)? == "true";
    let layout = match snapshot.tags.get(TAG_LAYOUT).map(String::as_str) {
        None | Some("physical") => BackupLayout::Physical,
        Some("logical") => BackupLayout::Logical,
        Some(_) => {
            return Err(BackupStoreError::Corrupt(
                "Kopia snapshot has invalid backup layout".to_string(),
            ));
        }
    };
    let manifest = StoredBackup {
        schema_version: crate::server::backup::manifest::LEGACY_MANIFEST_SCHEMA_VERSION,
        backup_id,
        instance_id: instance_id.to_string(),
        protocol,
        layout,
        size_bytes,
        created_at,
        created_at_unix,
        sha256,
        catalog_available,
        details: None,
    };
    manifest.validate(instance_id)?;
    Ok(manifest)
}
