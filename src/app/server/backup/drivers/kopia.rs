use std::{
    collections::HashMap,
    ffi::OsString,
    fmt,
    path::{Path, PathBuf},
    process::ExitStatus,
    time::Duration,
};

use futures::future::BoxFuture;
use serde::Deserialize;
use tokio::io::AsyncReadExt;

use crate::{
    config::BackupKopiaConfig,
    databases::protocol::Protocol,
    io::files::read_bounded_private_file,
    server::backup::{
        BackupBundle, BackupInventory, BackupLayout, BackupStoreError, MAX_METADATA_BYTES,
        StoredBackup, UnsupportedBackup, catalog_file_name, check_instance_id,
        drivers::{PublicationJournal, PublicationResource},
        io_error,
        manifest::ArtifactFormat,
        metadata_file_name, prepare_private_dir, remove_file_if_exists, validate_backup_id,
    },
};

// `--tags key:value` arguments name tags without a prefix; the CLI stores
// them on the manifest under `tag:<key>`, which is what `snapshot list
// --json` returns. See kopia v0.22 cli/command_snapshot_create.go getTags.
const STORED_TAG_PREFIX: &str = "tag:";
/// Pin that keeps Kopia policy retention away from DBEV-owned snapshots.
const DBEV_PIN: &str = "dbev";
const TAG_INSTANCE: &str = "dbev-instance";
const TAG_BACKUP: &str = "dbev-backup";
const TAG_SIZE: &str = "dbev-size";
const TAG_SHA256: &str = "dbev-sha256";
const TAG_CREATED: &str = "dbev-created";
const TAG_CREATED_AT: &str = "dbev-created-at";
const TAG_PROTOCOL: &str = "dbev-protocol";
const TAG_CATALOG: &str = "dbev-catalog";
const TAG_LAYOUT: &str = "dbev-layout";
// Schema 2 projection. Legacy summary tags are deliberately absent from these
// snapshots so a schema 1 daemon rejects them instead of reconstructing a
// schema 1 manifest; the complete canonical manifest travels inside the
// snapshot and is authenticated by its tagged SHA-256.
const TAG_MANIFEST_VERSION: &str = "dbev-manifest-version";
const TAG_MANIFEST_SHA256: &str = "dbev-manifest-sha256";
const TAG_V2_SIZE: &str = "dbev-v2-size";
const TAG_V2_SHA256: &str = "dbev-v2-sha256";
const TAG_V2_CREATED: &str = "dbev-v2-created";
const TAG_V2_FORMAT: &str = "dbev-v2-format";
const TAG_V2_RECIPE: &str = "dbev-v2-recipe";
const MAX_COMMAND_STDOUT: u64 = 8 * 1024 * 1024;
const MAX_COMMAND_STDERR: u64 = 128 * 1024;
const MAX_QUIET_COMMAND_STDOUT: u64 = 64 * 1024;
const MAX_LISTED_SNAPSHOTS: usize = 10_000;
const GROUP_OR_OTHER_WRITE_BITS: u32 = 0o022;
const ANY_EXECUTE_BITS: u32 = 0o111;
const STICKY_BIT: u32 = 0o1000;

#[derive(Clone)]
pub struct KopiaBackupDriver {
    config: BackupKopiaConfig,
    config_file: PathBuf,
    /// Scratch space for canonical manifest retrieval. It lives under backup
    /// staging, which daemon startup removes.
    scratch_root: PathBuf,
}

impl fmt::Debug for KopiaBackupDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KopiaBackupDriver")
            .field("executable", &self.config.executable)
            .field("config_file", &self.config_file)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KopiaManifest {
    id: String,
    source: KopiaSource,
    root_entry: KopiaRootEntry,
    #[serde(default)]
    incomplete: String,
    /// Tag keys without the stored `tag:` prefix once [`normalize_tags`] ran.
    #[serde(default)]
    tags: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KopiaSource {
    path: String,
}

/// One `kopia manifest list --json` entry.
#[derive(Debug, Deserialize)]
struct KopiaManifestEntry {
    id: String,
    #[serde(default)]
    labels: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KopiaRootEntry {
    #[serde(rename = "obj")]
    object_id: String,
}

struct CommandResult {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl super::BackupPreflight for KopiaBackupDriver {
    fn preflight(&self) -> BoxFuture<'_, Result<(), BackupStoreError>> {
        Box::pin(Self::preflight(self))
    }
}

impl super::BackupCommit for KopiaBackupDriver {
    fn commit<'a>(
        &'a self,
        bundle: &'a BackupBundle,
        manifest: &'a StoredBackup,
        journal: &'a dyn PublicationJournal,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(Self::commit(self, bundle, manifest, journal))
    }
}

impl super::BackupListing for KopiaBackupDriver {
    fn inventory<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<BackupInventory, BackupStoreError>> {
        Box::pin(Self::inventory(self, instance_id))
    }

    fn find<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
    ) -> BoxFuture<'a, Result<StoredBackup, BackupStoreError>> {
        Box::pin(Self::find(self, instance_id, backup_id))
    }
}

impl super::BackupDelete for KopiaBackupDriver {
    fn delete<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(Self::delete(self, instance_id, backup_id))
    }

    fn purge_unpublished<'a>(
        &'a self,
        instance_id: &'a str,
        backup_id: &'a str,
        resources: &'a [PublicationResource],
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(Self::purge_unpublished(
            self,
            instance_id,
            backup_id,
            resources,
        ))
    }
}

impl KopiaBackupDriver {
    pub fn new(config: BackupKopiaConfig, backups_root: PathBuf) -> Result<Self, BackupStoreError> {
        let executable = Path::new(config.executable.trim());
        if !executable.is_absolute() {
            return Err(BackupStoreError::InvalidConfiguration(
                "Kopia executable must be an absolute path".to_string(),
            ));
        }
        let config_file = if config.config_file.trim().is_empty() {
            backups_root.join(".kopia").join("repository.config")
        } else {
            PathBuf::from(config.config_file.trim())
        };
        if !config_file.is_absolute() {
            return Err(BackupStoreError::InvalidConfiguration(
                "Kopia config_file must be an absolute path".to_string(),
            ));
        }
        Ok(Self {
            config,
            config_file,
            scratch_root: backups_root.join(".staging").join(".kopia-manifests"),
        })
    }

    pub async fn preflight(&self) -> Result<(), BackupStoreError> {
        let executable = PathBuf::from(self.config.executable.trim());
        let config_file = self.config_file.clone();
        tokio::task::spawn_blocking(move || {
            validate_trusted_file(&executable, true, "Kopia executable")?;
            validate_trusted_file(&config_file, false, "Kopia repository config")
        })
        .await
        .map_err(|error| {
            BackupStoreError::Runtime(format!("Kopia preflight task failed: {error}"))
        })?
    }

    pub async fn commit(
        &self,
        bundle: &BackupBundle,
        manifest: &StoredBackup,
        journal: &dyn PublicationJournal,
    ) -> Result<(), BackupStoreError> {
        manifest.validate(&manifest.instance_id)?;
        self.preflight().await?;
        let tags = self.commit_tags(bundle, manifest).await?;
        // Periodic checkpoints are saved untagged while the upload runs, so
        // the bundle's unique path is journaled before Kopia can save one.
        let source_path = snapshot_source_path(&bundle.directory)?;
        journal
            .record(&PublicationResource::KopiaSourcePath(source_path.clone()))
            .await?;
        let output = self
            .run(
                create_arguments(&source_path, manifest, tags),
                MAX_COMMAND_STDOUT,
            )
            .await?;
        ensure_success("create snapshot", &output)?;
        let snapshot = serde_json::from_slice::<KopiaManifest>(&output.stdout)
            .map_err(|error| {
                BackupStoreError::Corrupt(format!(
                    "Kopia returned invalid snapshot metadata: {error}"
                ))
            })
            .and_then(normalize_tags)?;
        if snapshot.source.path != source_path {
            return Err(BackupStoreError::Corrupt(format!(
                "Kopia recorded snapshot source {} instead of {source_path}",
                snapshot.source.path
            )));
        }
        if snapshot.id.trim().is_empty()
            || snapshot.root_entry.object_id.trim().is_empty()
            || !snapshot.incomplete.trim().is_empty()
        {
            return Err(BackupStoreError::Corrupt(
                "Kopia returned an incomplete snapshot or omitted its manifest/root object id"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn identity(&self) -> String {
        format!("kopia:{}", self.config_file.display())
    }

    pub async fn list(&self, instance_id: &str) -> Result<Vec<StoredBackup>, BackupStoreError> {
        Ok(self.inventory(instance_id).await?.backups)
    }

    pub async fn inventory(&self, instance_id: &str) -> Result<BackupInventory, BackupStoreError> {
        check_instance_id(instance_id)?;
        let snapshots = self
            .list_manifests(&[instance_tag(instance_id)], false)
            .await?;
        let mut inventory = BackupInventory::default();
        for snapshot in snapshots {
            match self.load_record(instance_id, &snapshot).await {
                Ok(manifest) => inventory.backups.push(manifest),
                // Newer formats are listed opaquely; retention keeps them.
                Err(BackupStoreError::UnsupportedFormat(reason)) => {
                    match snapshot
                        .tags
                        .get(TAG_BACKUP)
                        .filter(|backup_id| validate_backup_id(backup_id).is_ok())
                    {
                        Some(backup_id) => inventory.unsupported.push(UnsupportedBackup {
                            backup_id: backup_id.clone(),
                            diagnostic: reason,
                        }),
                        None => tracing::warn!(
                            instance_id,
                            %reason,
                            "skipped unsupported Kopia snapshot without a valid backup tag"
                        ),
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(inventory)
    }

    /// Deletes every snapshot tagged with the backup id, whether or not its
    /// canonical manifest exists, and every snapshot of the journaled source
    /// paths, which includes untagged checkpoints. Succeeds only once a
    /// relisting finds none of them.
    pub async fn purge_unpublished(
        &self,
        instance_id: &str,
        backup_id: &str,
        resources: &[PublicationResource],
    ) -> Result<(), BackupStoreError> {
        check_instance_id(instance_id)?;
        validate_backup_id(backup_id)?;
        let sources = resources
            .iter()
            .map(|resource| match resource {
                PublicationResource::KopiaSourcePath(path) => Ok(path.as_str()),
                other => Err(BackupStoreError::Corrupt(format!(
                    "publication journal holds {other:?}, which is not a Kopia resource"
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let tags = [
            instance_tag(instance_id),
            format!("{TAG_BACKUP}:{backup_id}"),
        ];
        for snapshot in self.list_manifests(&tags, true).await? {
            self.delete_snapshot(snapshot.id).await?;
        }
        for path in &sources {
            for id in self.source_snapshot_ids(path).await? {
                self.delete_snapshot(id).await?;
            }
        }
        let mut remaining = self.list_manifests(&tags, true).await?.len();
        for path in &sources {
            remaining += self.source_snapshot_ids(path).await?.len();
        }
        if remaining > 0 {
            return Err(BackupStoreError::Remote(format!(
                "Kopia still lists {remaining} snapshot(s) of unpublished backup {backup_id}"
            )));
        }
        Ok(())
    }

    /// Ids of every snapshot manifest, complete or not, whose source path is
    /// exactly `path`. Kopia saves each checkpoint with the source labels, so
    /// the path label finds them without tags or the client's user@host.
    async fn source_snapshot_ids(&self, path: &str) -> Result<Vec<String>, BackupStoreError> {
        self.preflight().await?;
        let output = self
            .run(source_manifest_arguments(path), MAX_COMMAND_STDOUT)
            .await?;
        ensure_success("list source snapshots", &output)?;
        let entries = parse_manifest_entries(&output.stdout)?;
        if entries.len() >= MAX_LISTED_SNAPSHOTS {
            return Err(BackupStoreError::Remote(format!(
                "Kopia lists {MAX_LISTED_SNAPSHOTS} or more snapshots of source {path}"
            )));
        }
        entries
            .into_iter()
            .map(|entry| source_entry_id(entry, path))
            .collect()
    }

    pub async fn find(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<StoredBackup, BackupStoreError> {
        let snapshot = self.find_manifest(instance_id, backup_id).await?;
        self.load_record(instance_id, &snapshot).await
    }

    pub async fn delete(&self, instance_id: &str, backup_id: &str) -> Result<(), BackupStoreError> {
        let snapshot = self.find_manifest(instance_id, backup_id).await?;
        self.delete_snapshot(snapshot.id).await
    }

    pub async fn delete_instance(&self, instance_id: &str) -> Result<usize, BackupStoreError> {
        check_instance_id(instance_id)?;
        let snapshots = self
            .list_manifests(&[instance_tag(instance_id)], true)
            .await?;
        let count = snapshots.len();
        for snapshot in snapshots {
            self.delete_snapshot(snapshot.id).await?;
        }
        Ok(count)
    }

    async fn delete_snapshot(&self, snapshot_id: String) -> Result<(), BackupStoreError> {
        let output = self
            .run(
                vec![
                    OsString::from("snapshot"),
                    OsString::from("delete"),
                    OsString::from(snapshot_id),
                    OsString::from("--delete"),
                ],
                MAX_QUIET_COMMAND_STDOUT,
            )
            .await?;
        ensure_success("delete snapshot", &output)
    }

    pub async fn materialize(
        &self,
        instance_id: &str,
        backup_id: &str,
        destination: &Path,
    ) -> Result<(), BackupStoreError> {
        let snapshot = self.find_manifest(instance_id, backup_id).await?;
        let manifest = self.load_record(instance_id, &snapshot).await?;
        self.restore_object(
            &format!("{}/{}", snapshot.root_entry.object_id, backup_id),
            destination,
        )
        .await?;
        if let Err(error) = manifest.verify_archive(destination, "Kopia backup").await {
            remove_file_if_exists(destination).await;
            return Err(error);
        }
        Ok(())
    }

    pub async fn read_catalog(
        &self,
        instance_id: &str,
        backup_id: &str,
        max_bytes: u64,
        tmp_root: &Path,
    ) -> Result<Option<Vec<u8>>, BackupStoreError> {
        let snapshot = self.find_manifest(instance_id, backup_id).await?;
        let manifest = self.load_record(instance_id, &snapshot).await?;
        if !manifest.catalog_available {
            return Ok(None);
        }
        let root = tmp_root.join("backup-catalogs").join(instance_id);
        prepare_private_dir(&root, "backup catalog materialization directory").await?;
        let destination = root.join(format!("{}.json", uuid::Uuid::new_v4()));
        self.restore_object(
            &format!(
                "{}/{}",
                snapshot.root_entry.object_id,
                catalog_file_name(backup_id)
            ),
            &destination,
        )
        .await?;
        let read_path = destination.clone();
        let read_task =
            tokio::task::spawn_blocking(move || read_bounded_private_file(&read_path, max_bytes))
                .await;
        remove_file_if_exists(&destination).await;
        let read_result = read_task.map_err(|error| {
            BackupStoreError::Runtime(format!("catalog read task failed: {error}"))
        })?;
        read_result
            .map(Some)
            .map_err(|source| io_error("read restored Kopia catalog", source))
    }

    /// Tags for a new snapshot. Schema 2 manifests are projected onto
    /// versioned tags and bound to the canonical sidecar by its SHA-256.
    async fn commit_tags(
        &self,
        bundle: &BackupBundle,
        manifest: &StoredBackup,
    ) -> Result<Vec<String>, BackupStoreError> {
        if manifest.details.is_none() {
            return Ok(legacy_manifest_tags(manifest));
        }
        let bytes = read_metadata_file(bundle.metadata.clone()).await?;
        let canonical =
            StoredBackup::from_json(&bytes, &manifest.instance_id, "staged backup metadata")?;
        if canonical.backup_id != manifest.backup_id
            || canonical.sha256 != manifest.sha256
            || canonical.size_bytes != manifest.size_bytes
            || canonical.details != manifest.details
        {
            return Err(BackupStoreError::Corrupt(
                "staged backup metadata does not match the committed manifest".to_string(),
            ));
        }
        v2_manifest_tags(manifest, &crate::server::backup::sha256_bytes(&bytes))
    }

    /// Reads one snapshot's manifest. Snapshots without a version tag are
    /// legacy schema 1 records reconstructed from tags; schema 2 snapshots
    /// are read only from their canonical sidecar.
    async fn load_record(
        &self,
        instance_id: &str,
        snapshot: &KopiaManifest,
    ) -> Result<StoredBackup, BackupStoreError> {
        match snapshot.tags.get(TAG_MANIFEST_VERSION).map(String::as_str) {
            None => record_from_snapshot(instance_id, snapshot),
            Some("2") => self.canonical_record(instance_id, snapshot).await,
            Some(version) => Err(BackupStoreError::UnsupportedFormat(format!(
                "Kopia snapshot {} uses manifest schema {version}, which this daemon cannot read",
                snapshot.id
            ))),
        }
    }

    async fn canonical_record(
        &self,
        instance_id: &str,
        snapshot: &KopiaManifest,
    ) -> Result<StoredBackup, BackupStoreError> {
        let projection = V2Projection::from_snapshot(instance_id, snapshot)?;
        prepare_private_dir(&self.scratch_root, "Kopia manifest scratch directory").await?;
        let destination = self
            .scratch_root
            .join(format!("{}.json", uuid::Uuid::new_v4()));
        self.restore_object(
            &format!(
                "{}/{}",
                snapshot.root_entry.object_id,
                metadata_file_name(&projection.backup_id)
            ),
            &destination,
        )
        .await?;
        let read = read_metadata_file(destination.clone()).await;
        remove_file_if_exists(&destination).await;
        let bytes = read?;
        if crate::server::backup::sha256_bytes(&bytes) != projection.manifest_sha256 {
            return Err(BackupStoreError::Corrupt(format!(
                "Kopia snapshot {} manifest does not match its tagged checksum",
                snapshot.id
            )));
        }
        let manifest = StoredBackup::from_json(&bytes, instance_id, "Kopia backup metadata")?;
        projection.check(&manifest)?;
        Ok(manifest)
    }

    async fn find_manifest(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<KopiaManifest, BackupStoreError> {
        check_instance_id(instance_id)?;
        validate_backup_id(backup_id)?;
        let mut snapshots = self
            .list_manifests(
                &[
                    instance_tag(instance_id),
                    format!("{TAG_BACKUP}:{backup_id}"),
                ],
                false,
            )
            .await?;
        match snapshots.len() {
            0 => Err(BackupStoreError::NotFound),
            1 => Ok(snapshots.remove(0)),
            _ => Err(BackupStoreError::Corrupt(format!(
                "Kopia contains multiple snapshots for backup {backup_id}"
            ))),
        }
    }

    async fn list_manifests(
        &self,
        tags: &[String],
        include_incomplete: bool,
    ) -> Result<Vec<KopiaManifest>, BackupStoreError> {
        self.preflight().await?;
        let mut arguments = vec![
            OsString::from("snapshot"),
            OsString::from("list"),
            OsString::from("--json"),
            OsString::from("--all"),
            OsString::from("--show-identical"),
            OsString::from("--max-results"),
            OsString::from(MAX_LISTED_SNAPSHOTS.to_string()),
        ];
        if include_incomplete {
            arguments.push(OsString::from("--incomplete"));
        }
        for tag in tags {
            arguments.push(OsString::from("--tags"));
            arguments.push(OsString::from(tag));
        }
        let output = self.run(arguments, MAX_COMMAND_STDOUT).await?;
        ensure_success("list snapshots", &output)?;
        let snapshots = parse_snapshot_list(&output.stdout)?;
        if snapshots.len() >= MAX_LISTED_SNAPSHOTS {
            return Err(BackupStoreError::Remote(format!(
                "Kopia returned {MAX_LISTED_SNAPSHOTS} snapshots; narrow the repository or prune old DBEV backups"
            )));
        }
        // `--incomplete` filters only the text listing; JSON always includes
        // incomplete snapshots. A canceled upload keeps its tags and must
        // never be read as a published backup.
        Ok(snapshots
            .into_iter()
            .filter(|snapshot| include_incomplete || snapshot.incomplete.trim().is_empty())
            .collect())
    }

    async fn restore_object(
        &self,
        object_path: &str,
        destination: &Path,
    ) -> Result<(), BackupStoreError> {
        let restored = self
            .run(
                restore_arguments(object_path, destination),
                MAX_QUIET_COMMAND_STDOUT,
            )
            .await
            .and_then(|output| ensure_success("restore object", &output));
        if let Err(error) = restored {
            remove_file_if_exists(destination).await;
            return Err(error);
        }
        Ok(())
    }

    async fn run(
        &self,
        arguments: Vec<OsString>,
        max_stdout: u64,
    ) -> Result<CommandResult, BackupStoreError> {
        let mut command = tokio::process::Command::new(self.config.executable.trim());
        command
            .kill_on_drop(true)
            .env("TZ", "UTC")
            .arg("--config-file")
            .arg(&self.config_file)
            .args(arguments)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if !self.config.repository_password.expose().is_empty() {
            command.env("KOPIA_PASSWORD", self.config.repository_password.expose());
        }
        let mut child = command
            .spawn()
            .map_err(|source| io_error("start Kopia", source))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            BackupStoreError::Runtime("Kopia stdout pipe was not available".to_string())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            BackupStoreError::Runtime("Kopia stderr pipe was not available".to_string())
        })?;
        let operation = async {
            let (status, stdout, stderr) = tokio::join!(
                child.wait(),
                read_bounded(stdout, max_stdout),
                read_bounded(stderr, MAX_COMMAND_STDERR),
            );
            Ok::<_, std::io::Error>(CommandResult {
                status: status?,
                stdout: stdout?,
                stderr: stderr?,
            })
        };
        match tokio::time::timeout(
            Duration::from_secs(self.config.operation_timeout_seconds),
            operation,
        )
        .await
        {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(source)) => Err(io_error("run Kopia", source)),
            Err(_) => {
                let _ = child.kill().await;
                Err(BackupStoreError::Remote(format!(
                    "Kopia exceeded its {}-second operation deadline",
                    self.config.operation_timeout_seconds
                )))
            }
        }
    }
}

fn restore_arguments(object_path: &str, destination: &Path) -> Vec<OsString> {
    vec![
        OsString::from("snapshot"),
        OsString::from("restore"),
        OsString::from(object_path),
        destination.as_os_str().to_owned(),
        OsString::from("--write-files-atomically"),
        OsString::from("--no-ignore-errors"),
    ]
}

fn create_arguments(
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

fn source_manifest_arguments(path: &str) -> Vec<OsString> {
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
fn snapshot_source_path(directory: &Path) -> Result<String, BackupStoreError> {
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

fn parse_snapshot_list(stdout: &[u8]) -> Result<Vec<KopiaManifest>, BackupStoreError> {
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
fn source_entry_id(entry: KopiaManifestEntry, path: &str) -> Result<String, BackupStoreError> {
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

fn parse_manifest_entries(stdout: &[u8]) -> Result<Vec<KopiaManifestEntry>, BackupStoreError> {
    serde_json::from_slice(stdout).map_err(|error| {
        BackupStoreError::Corrupt(format!(
            "Kopia returned invalid manifest list JSON: {error}"
        ))
    })
}

/// Strips the stored `tag:` prefix. An unprefixed key is accepted as the
/// same tag; one present in both forms with different values is ambiguous.
fn normalize_tags(mut snapshot: KopiaManifest) -> Result<KopiaManifest, BackupStoreError> {
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

fn instance_tag(instance_id: &str) -> String {
    format!("{TAG_INSTANCE}:{instance_id}")
}

fn layout_tag_value(layout: BackupLayout) -> &'static str {
    match layout {
        BackupLayout::Physical => "physical",
        BackupLayout::Logical => "logical",
    }
}

fn legacy_manifest_tags(manifest: &StoredBackup) -> Vec<String> {
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

fn v2_manifest_tags(
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

fn format_tag_value(format: ArtifactFormat) -> &'static str {
    match format {
        ArtifactFormat::DataDirectoryArchive => "data_directory_archive",
        ArtifactFormat::LogicalDump => "logical_dump",
        ArtifactFormat::OnlineCapture => "online_capture",
    }
}

/// Schema 2 tag projection: enough to locate and authenticate the canonical
/// manifest and to cross-check it, never enough to reconstruct a recipe.
struct V2Projection {
    backup_id: String,
    manifest_sha256: String,
    size_bytes: u64,
    sha256: String,
    created_at_unix: i64,
    format: String,
    recipe: String,
}

impl V2Projection {
    fn from_snapshot(
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

    fn check(&self, manifest: &StoredBackup) -> Result<(), BackupStoreError> {
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

async fn read_metadata_file(path: PathBuf) -> Result<Vec<u8>, BackupStoreError> {
    tokio::task::spawn_blocking(move || read_bounded_private_file(&path, MAX_METADATA_BYTES))
        .await
        .map_err(|error| BackupStoreError::Runtime(format!("metadata read task failed: {error}")))?
        .map_err(|source| io_error("read backup metadata", source))
}

fn record_from_snapshot(
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

async fn read_bounded<R>(reader: R, max_bytes: u64) -> Result<Vec<u8>, std::io::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Kopia command output exceeds {max_bytes} bytes"),
        ));
    }
    Ok(bytes)
}

fn ensure_success(operation: &str, output: &CommandResult) -> Result<(), BackupStoreError> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = crate::utils::redaction::redact_connection_url(stderr.trim());
    Err(BackupStoreError::Remote(format!(
        "Kopia failed to {operation} (status {}): {}",
        output.status,
        if stderr.is_empty() {
            "no diagnostic output"
        } else {
            &stderr
        }
    )))
}

fn validate_trusted_file(
    path: &Path,
    executable: bool,
    label: &str,
) -> Result<(), BackupStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|source| io_error(format!("inspect {label}"), source))?;
    let expected_uid = rustix::process::geteuid().as_raw();
    let is_trusted_owner = |uid: u32| uid == 0 || uid == expected_uid;
    let mode = metadata.permissions().mode();
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || !is_trusted_owner(metadata.uid())
        || mode & GROUP_OR_OTHER_WRITE_BITS != 0
        || (executable && mode & ANY_EXECUTE_BITS == 0)
    {
        return Err(BackupStoreError::InvalidConfiguration(format!(
            "{label} {} must be a root/daemon-owned real file not writable by group or others{}",
            path.display(),
            if executable {
                " and must be executable"
            } else {
                ""
            }
        )));
    }
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|source| io_error(format!("inspect {label} ancestor"), source))?;
        let mode = metadata.permissions().mode();
        let sticky_root = metadata.uid() == 0 && mode & STICKY_BIT != 0;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !is_trusted_owner(metadata.uid())
            || (mode & GROUP_OR_OTHER_WRITE_BITS != 0 && !sticky_root)
        {
            return Err(BackupStoreError::InvalidConfiguration(format!(
                "{label} ancestor {} is not trusted",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "/var/lib/dbev/backups/.staging/inst_one/.0d9c.bundle";

    /// `kopia snapshot list --json` output (v0.22): user tags are stored
    /// under `tag:<key>`, and an untagged checkpoint of the same source is
    /// listed alongside the final snapshot.
    fn authentic_snapshot_list() -> String {
        format!(
            r#"[
  {{
    "id": "8f3a2c9d0e1b4f5a6b7c8d9e0f1a2b3c",
    "source": {{ "host": "node-a", "userName": "root", "path": "{SOURCE}" }},
    "description": "",
    "startTime": "2026-10-11T09:00:00.123456789Z",
    "endTime": "2026-10-11T09:45:00.123456789Z",
    "stats": {{ "totalSize": 1048576, "excludedTotalSize": 0, "fileCount": 1, "cachedFiles": 0, "nonCachedFiles": 1, "dirCount": 1, "excludedFileCount": 0, "excludedDirCount": 0, "ignoredErrorCount": 0, "errorCount": 0 }},
    "incomplete": "checkpoint",
    "rootEntry": {{ "name": ".0d9c.bundle", "type": "d", "mode": "0700", "mtime": "2026-10-11T09:00:00Z", "obj": "kc0ffee" }},
    "retentionReason": []
  }},
  {{
    "id": "1b2c3d4e5f60718293a4b5c6d7e8f901",
    "source": {{ "host": "node-a", "userName": "root", "path": "{SOURCE}" }},
    "description": "DatabasesEverywhere backup one.physical.tar.gz",
    "startTime": "2026-10-11T09:00:00.123456789Z",
    "endTime": "2026-10-11T10:00:00.123456789Z",
    "stats": {{ "totalSize": 2097152, "excludedTotalSize": 0, "fileCount": 3, "cachedFiles": 0, "nonCachedFiles": 3, "dirCount": 1, "excludedFileCount": 0, "excludedDirCount": 0, "ignoredErrorCount": 0, "errorCount": 0 }},
    "rootEntry": {{ "name": ".0d9c.bundle", "type": "d", "mode": "0700", "mtime": "2026-10-11T09:00:00Z", "obj": "k123", "summ": {{ "size": 2097152, "files": 3, "symlinks": 0, "dirs": 1, "maxTime": "2026-10-11T09:00:00Z", "numFailed": 0 }} }},
    "tags": {{
      "tag:dbev-instance": "inst_one",
      "tag:dbev-backup": "one.physical.tar.gz",
      "tag:dbev-size": "42",
      "tag:dbev-sha256": "{sha}",
      "tag:dbev-created": "1700000000",
      "tag:dbev-created-at": "2023-11-14T22_13_20Z",
      "tag:dbev-protocol": "postgres",
      "tag:dbev-catalog": "true",
      "tag:dbev-layout": "physical"
    }},
    "pins": ["dbev"],
    "retentionReason": ["latest-1", "hourly-1", "daily-1"]
  }}
]"#,
            sha = "a".repeat(64)
        )
    }

    #[test]
    fn authentic_cli_snapshot_lists_are_read_through_stored_tag_keys() {
        let snapshots = parse_snapshot_list(authentic_snapshot_list().as_bytes()).unwrap();
        assert_eq!(snapshots.len(), 2);
        let checkpoint = &snapshots[0];
        assert_eq!(checkpoint.incomplete, "checkpoint");
        assert!(checkpoint.tags.is_empty());
        assert_eq!(checkpoint.source.path, SOURCE);

        let record = record_from_snapshot("inst_one", &snapshots[1]).unwrap();
        assert_eq!(record.backup_id, "one.physical.tar.gz");
        assert_eq!(record.protocol, Protocol::Postgres);
        assert_eq!(record.layout, BackupLayout::Physical);
        assert!(record.catalog_available);
    }

    #[test]
    fn unprefixed_tags_are_accepted_but_conflicting_forms_are_not() {
        let snapshot = |tags: serde_json::Value| -> KopiaManifest {
            serde_json::from_value(serde_json::json!({
                "id": "m1",
                "source": { "host": "h", "userName": "u", "path": SOURCE },
                "rootEntry": { "obj": "k1" },
                "tags": tags,
            }))
            .unwrap()
        };
        let plain = normalize_tags(snapshot(serde_json::json!({ "dbev-backup": "a" }))).unwrap();
        assert_eq!(plain.tags.get(TAG_BACKUP).map(String::as_str), Some("a"));
        let same = serde_json::json!({ "dbev-backup": "a", "tag:dbev-backup": "a" });
        assert!(normalize_tags(snapshot(same)).is_ok());
        let conflict = serde_json::json!({ "dbev-backup": "a", "tag:dbev-backup": "b" });
        assert!(matches!(
            normalize_tags(snapshot(conflict)),
            Err(BackupStoreError::Corrupt(_))
        ));
    }

    #[tokio::test]
    async fn create_passes_unprefixed_tags_and_a_pin_value() {
        let manifest = v2_manifest().await;
        let arguments = create_arguments(SOURCE, &manifest, legacy_manifest_tags(&manifest));
        let position = |flag: &str| arguments.iter().position(|arg| arg == flag).unwrap();
        assert_eq!(arguments[2], SOURCE);
        // kingpin rejects `--pin --tags ...`: the next token must be a value.
        assert_eq!(arguments[position("--pin") + 1], DBEV_PIN);
        let tag = &arguments[position("--tags") + 1];
        assert!(tag.to_str().unwrap().starts_with("dbev-instance:"));
        assert!(
            !arguments
                .iter()
                .any(|arg| arg.to_str().unwrap().starts_with("tag:"))
        );
    }

    #[test]
    fn source_paths_match_kopia_clean_without_resolving_links() {
        assert_eq!(
            snapshot_source_path(Path::new("/var/lib/dbev/./backups//.staging/i/.x.bundle/"))
                .unwrap(),
            "/var/lib/dbev/backups/.staging/i/.x.bundle"
        );
        for path in ["relative/bundle", "/var/../etc", "/"] {
            assert!(snapshot_source_path(Path::new(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn checkpoints_are_found_by_their_source_path_label() {
        let arguments = source_manifest_arguments(SOURCE);
        assert_eq!(
            arguments[..2],
            [OsString::from("manifest"), OsString::from("list")]
        );
        assert!(arguments.contains(&OsString::from("type:snapshot")));
        assert!(arguments.contains(&OsString::from(format!("path:{SOURCE}"))));

        // `kopia manifest list --json` output (v0.22 manifest.EntryMetadata).
        let stdout = format!(
            r#"[
  {{ "id": "8f3a2c9d0e1b4f5a6b7c8d9e0f1a2b3c", "length": 812, "labels": {{ "hostname": "node-a", "path": "{SOURCE}", "type": "snapshot", "username": "root" }}, "mtime": "2026-10-11T09:45:00.1Z" }},
  {{ "id": "1b2c3d4e5f60718293a4b5c6d7e8f901", "length": 1204, "labels": {{ "hostname": "node-a", "path": "{SOURCE}", "tag:dbev-backup": "one.physical.tar.gz", "type": "snapshot", "username": "root" }}, "mtime": "2026-10-11T10:00:00.1Z" }}
]"#
        );
        let ids = parse_manifest_entries(stdout.as_bytes())
            .unwrap()
            .into_iter()
            .map(|entry| source_entry_id(entry, SOURCE))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(ids.len(), 2);

        for labels in [
            serde_json::json!({ "type": "snapshot", "path": "/other" }),
            serde_json::json!({ "type": "policy", "path": SOURCE }),
        ] {
            let entry: KopiaManifestEntry =
                serde_json::from_value(serde_json::json!({ "id": "m", "labels": labels })).unwrap();
            assert!(source_entry_id(entry, SOURCE).is_err());
        }
    }

    #[test]
    fn restore_uses_the_snapshot_restore_command() {
        let arguments = restore_arguments("k123/archive", Path::new("/tmp/archive"));
        assert_eq!(arguments[0], "snapshot");
        assert_eq!(arguments[1], "restore");
        assert_eq!(arguments[2], "k123/archive");
    }

    /// A snapshot as `snapshot list --json` returns it after `snapshot create
    /// --tags <tag>...`: each `key:value` argument stored as `tag:key`.
    fn snapshot_with_tags(tags: Vec<String>) -> KopiaManifest {
        normalize_tags(KopiaManifest {
            id: "m456".to_string(),
            source: KopiaSource {
                path: SOURCE.to_string(),
            },
            root_entry: KopiaRootEntry {
                object_id: "k456".to_string(),
            },
            incomplete: String::new(),
            tags: tags
                .into_iter()
                .map(|tag| {
                    let (key, value) = tag.split_once(':').unwrap();
                    (format!("{STORED_TAG_PREFIX}{key}"), value.to_string())
                })
                .collect(),
        })
        .unwrap()
    }

    async fn v2_manifest() -> StoredBackup {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("archive");
        tokio::fs::write(&archive, b"archive").await.unwrap();
        crate::server::backup::build_manifest(
            "two.physical.tar.gz".to_string(),
            "inst_one".to_string(),
            Protocol::Postgres,
            BackupLayout::Physical,
            &archive,
            false,
            crate::server::backup::test_details(BackupLayout::Physical),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn schema_two_tags_bind_the_canonical_manifest_and_starve_legacy_readers() {
        let manifest = v2_manifest().await;
        let bytes = manifest.to_json().unwrap();
        let checksum = crate::server::backup::sha256_bytes(&bytes);
        let snapshot = snapshot_with_tags(v2_manifest_tags(&manifest, &checksum).unwrap());

        let projection = V2Projection::from_snapshot("inst_one", &snapshot).unwrap();
        assert_eq!(projection.manifest_sha256, checksum);
        projection.check(&manifest).unwrap();
        // A schema 1 reader must not reconstruct a manifest from these tags.
        assert!(matches!(
            record_from_snapshot("inst_one", &snapshot),
            Err(BackupStoreError::Corrupt(_))
        ));

        let mut altered = manifest.clone();
        altered.details.as_mut().unwrap().restore_recipe.version = 9;
        assert!(projection.check(&altered).is_err());
    }

    #[tokio::test]
    async fn unknown_kopia_manifest_versions_are_unsupported() {
        let driver = KopiaBackupDriver::new(
            BackupKopiaConfig {
                executable: "/usr/bin/kopia".to_string(),
                ..Default::default()
            },
            PathBuf::from("/var/lib/dbev/backups"),
        )
        .unwrap();
        let mut tags = v2_manifest_tags(&v2_manifest().await, &"a".repeat(64)).unwrap();
        tags.retain(|tag| !tag.starts_with(TAG_MANIFEST_VERSION));
        tags.push(format!("{TAG_MANIFEST_VERSION}:3"));
        assert!(matches!(
            driver
                .load_record("inst_one", &snapshot_with_tags(tags))
                .await,
            Err(BackupStoreError::UnsupportedFormat(_))
        ));
    }
}
