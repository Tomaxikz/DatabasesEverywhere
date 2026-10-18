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
use snapshot::*;

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

mod snapshot;
#[cfg(test)]
mod tests;
