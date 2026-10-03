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
    instance::backup::{
        BackupBundle, BackupLayout, BackupStoreError, StoredBackup, catalog_file_name,
        check_instance_id, io_error, prepare_private_dir, remove_file_if_exists,
        validate_backup_id,
    },
    io::files::read_bounded_private_file,
    utils::protocol::Protocol,
};

const TAG_INSTANCE: &str = "dbev-instance";
const TAG_BACKUP: &str = "dbev-backup";
const TAG_SIZE: &str = "dbev-size";
const TAG_SHA256: &str = "dbev-sha256";
const TAG_CREATED: &str = "dbev-created";
const TAG_CREATED_AT: &str = "dbev-created-at";
const TAG_PROTOCOL: &str = "dbev-protocol";
const TAG_CATALOG: &str = "dbev-catalog";
const TAG_LAYOUT: &str = "dbev-layout";
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
    root_entry: KopiaRootEntry,
    #[serde(default)]
    incomplete: String,
    #[serde(default)]
    tags: HashMap<String, String>,
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
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(Self::commit(self, bundle, manifest))
    }
}

impl super::BackupInventory for KopiaBackupDriver {
    fn list<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<StoredBackup>, BackupStoreError>> {
        Box::pin(Self::list(self, instance_id))
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
    ) -> Result<(), BackupStoreError> {
        manifest.validate(&manifest.instance_id)?;
        self.preflight().await?;
        let mut arguments = vec![
            OsString::from("snapshot"),
            OsString::from("create"),
            bundle.directory.as_os_str().to_owned(),
            OsString::from("--json"),
            OsString::from("--description"),
            OsString::from(format!("DatabasesEverywhere backup {}", manifest.backup_id)),
            // DBEV owns retention for these snapshots. Pinning prevents an
            // unrelated Kopia source policy from expiring them behind DBEV.
            OsString::from("--pin"),
        ];
        for tag in manifest_tags(manifest) {
            arguments.push(OsString::from("--tags"));
            arguments.push(OsString::from(tag));
        }
        let output = self.run(arguments, MAX_COMMAND_STDOUT).await?;
        ensure_success("create snapshot", &output)?;
        let snapshot: KopiaManifest = serde_json::from_slice(&output.stdout).map_err(|error| {
            BackupStoreError::Corrupt(format!("Kopia returned invalid snapshot metadata: {error}"))
        })?;
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

    pub async fn list(&self, instance_id: &str) -> Result<Vec<StoredBackup>, BackupStoreError> {
        check_instance_id(instance_id)?;
        let snapshots = self
            .list_manifests(&[instance_tag(instance_id)], false)
            .await?;
        snapshots
            .into_iter()
            .map(|snapshot| record_from_snapshot(instance_id, &snapshot))
            .collect()
    }

    pub async fn find(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<StoredBackup, BackupStoreError> {
        let snapshot = self.find_manifest(instance_id, backup_id).await?;
        record_from_snapshot(instance_id, &snapshot)
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
        let manifest = record_from_snapshot(instance_id, &snapshot)?;
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
        let manifest = record_from_snapshot(instance_id, &snapshot)?;
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
        let snapshots: Vec<KopiaManifest> =
            serde_json::from_slice(&output.stdout).map_err(|error| {
                BackupStoreError::Corrupt(format!(
                    "Kopia returned invalid snapshot list JSON: {error}"
                ))
            })?;
        if snapshots.len() >= MAX_LISTED_SNAPSHOTS {
            return Err(BackupStoreError::Remote(format!(
                "Kopia returned {MAX_LISTED_SNAPSHOTS} snapshots; narrow the repository or prune old DBEV backups"
            )));
        }
        Ok(snapshots)
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

fn instance_tag(instance_id: &str) -> String {
    format!("{TAG_INSTANCE}:{instance_id}")
}

fn layout_tag_value(layout: BackupLayout) -> &'static str {
    match layout {
        BackupLayout::Physical => "physical",
        BackupLayout::Logical => "logical",
    }
}

fn manifest_tags(manifest: &StoredBackup) -> Vec<String> {
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
        schema_version: crate::instance::backup::BACKUP_MANIFEST_SCHEMA_VERSION,
        backup_id,
        instance_id: instance_id.to_string(),
        protocol,
        layout,
        size_bytes,
        created_at,
        created_at_unix,
        sha256,
        catalog_available,
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

    #[test]
    fn parses_wings_compatible_kopia_manifest_shape() {
        let snapshot: KopiaManifest = serde_json::from_value(serde_json::json!({
            "id": "m123",
            "rootEntry": { "obj": "k123" },
            "incomplete": "",
            "tags": {
                (TAG_INSTANCE): "inst_one",
                (TAG_BACKUP): "one.physical.tar.gz",
                (TAG_SIZE): "42",
                (TAG_SHA256): "a".repeat(64),
                (TAG_CREATED): "1700000000",
                (TAG_CREATED_AT): "2023-11-14T22_13_20Z",
                (TAG_PROTOCOL): "postgres",
                (TAG_CATALOG): "true"
            }
        }))
        .unwrap();

        let record = record_from_snapshot("inst_one", &snapshot).unwrap();
        assert_eq!(record.backup_id, "one.physical.tar.gz");
        assert_eq!(record.protocol, Protocol::Postgres);
        assert!(record.catalog_available);
    }

    #[test]
    fn restore_uses_the_snapshot_restore_command() {
        let arguments = restore_arguments("k123/archive", Path::new("/tmp/archive"));
        assert_eq!(arguments[0], "snapshot");
        assert_eq!(arguments[1], "restore");
        assert_eq!(arguments[2], "k123/archive");
    }
}
