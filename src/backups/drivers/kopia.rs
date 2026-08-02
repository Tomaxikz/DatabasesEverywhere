use std::{
    collections::HashMap,
    ffi::OsString,
    fmt,
    path::{Path, PathBuf},
    process::ExitStatus,
    time::Duration,
};

use serde::Deserialize;
use tokio::io::AsyncReadExt;

use crate::{
    backups::{
        BackupBundle, BackupStoreError, StoredBackup, catalog_file_name, ensure_private_directory,
        io_error, is_sha256, remove_file_if_exists, sha256_file, validate_backup_id,
    },
    config::BackupKopiaConfig,
    shared::{
        files::read_private_regular_file_bounded, ids::validate_instance_id, protocol::Protocol,
    },
};

const TAG_INSTANCE: &str = "dbev-instance";
const TAG_BACKUP: &str = "dbev-backup";
const TAG_SIZE: &str = "dbev-size";
const TAG_SHA256: &str = "dbev-sha256";
const TAG_CREATED: &str = "dbev-created";
const TAG_CREATED_AT: &str = "dbev-created-at";
const TAG_PROTOCOL: &str = "dbev-protocol";
const TAG_CATALOG: &str = "dbev-catalog";
const MAX_COMMAND_STDOUT: u64 = 8 * 1024 * 1024;
const MAX_COMMAND_STDERR: u64 = 128 * 1024;
const MAX_LISTED_SNAPSHOTS: usize = 10_000;

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
        validate_instance_id(instance_id)
            .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        let snapshots = self
            .list_manifests(&[format!("{TAG_INSTANCE}:{instance_id}")], false)
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
        validate_instance_id(instance_id)
            .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        let snapshots = self
            .list_manifests(&[format!("{TAG_INSTANCE}:{instance_id}")], true)
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
                64 * 1024,
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
        let metadata = match tokio::fs::symlink_metadata(destination).await {
            Ok(metadata) => metadata,
            Err(source) => {
                remove_file_if_exists(destination).await;
                return Err(io_error("inspect restored Kopia backup", source));
            }
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != manifest.size_bytes
        {
            remove_file_if_exists(destination).await;
            return Err(BackupStoreError::Corrupt(
                "Kopia restored a backup with unexpected type or size".to_string(),
            ));
        }
        let hash = match sha256_file(destination).await {
            Ok(hash) => hash,
            Err(error) => {
                remove_file_if_exists(destination).await;
                return Err(error);
            }
        };
        if hash != manifest.sha256 {
            remove_file_if_exists(destination).await;
            return Err(BackupStoreError::Corrupt(
                "Kopia backup SHA-256 does not match its metadata".to_string(),
            ));
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
        ensure_private_directory(&root, "backup catalog materialization directory").await?;
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
        let result = tokio::task::spawn_blocking(move || {
            read_private_regular_file_bounded(&read_path, max_bytes)
        })
        .await;
        remove_file_if_exists(&destination).await;
        let result = result.map_err(|error| {
            BackupStoreError::Runtime(format!("catalog read task failed: {error}"))
        })?;
        result
            .map(Some)
            .map_err(|source| io_error("read restored Kopia catalog", source))
    }

    async fn find_manifest(
        &self,
        instance_id: &str,
        backup_id: &str,
    ) -> Result<KopiaManifest, BackupStoreError> {
        validate_instance_id(instance_id)
            .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        validate_backup_id(backup_id)?;
        let mut snapshots = self
            .list_manifests(
                &[
                    format!("{TAG_INSTANCE}:{instance_id}"),
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
        let output = match self
            .run(restore_arguments(object_path, destination), 64 * 1024)
            .await
        {
            Ok(output) => output,
            Err(error) => {
                remove_file_if_exists(destination).await;
                return Err(error);
            }
        };
        if let Err(error) = ensure_success("restore object", &output) {
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

fn manifest_tags(manifest: &StoredBackup) -> Vec<String> {
    vec![
        format!("{TAG_INSTANCE}:{}", manifest.instance_id),
        format!("{TAG_BACKUP}:{}", manifest.backup_id),
        format!("{TAG_SIZE}:{}", manifest.size_bytes),
        format!("{TAG_SHA256}:{}", manifest.sha256),
        format!("{TAG_CREATED}:{}", manifest.created_at_unix),
        format!("{TAG_CREATED_AT}:{}", manifest.created_at.replace(':', "_")),
        format!(
            "{TAG_PROTOCOL}:{}",
            manifest.protocol.map_or("unknown", Protocol::as_str)
        ),
        format!("{TAG_CATALOG}:{}", manifest.catalog_available),
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
    if !is_sha256(&sha256) {
        return Err(BackupStoreError::Corrupt(
            "Kopia snapshot has invalid SHA-256 tag".to_string(),
        ));
    }
    let created_at_unix = tag(TAG_CREATED)?.parse::<i64>().map_err(|_| {
        BackupStoreError::Corrupt("Kopia snapshot has invalid creation timestamp".to_string())
    })?;
    let created_at = tag(TAG_CREATED_AT)?.replace('_', ":");
    let protocol = match tag(TAG_PROTOCOL)? {
        "unknown" => None,
        value => Some(value.parse::<Protocol>().map_err(|error| {
            BackupStoreError::Corrupt(format!("Kopia snapshot has invalid protocol: {error}"))
        })?),
    };
    let catalog_available = tag(TAG_CATALOG)? == "true";
    let manifest = StoredBackup {
        schema_version: crate::backups::BACKUP_MANIFEST_SCHEMA_VERSION,
        backup_id,
        instance_id: instance_id.to_string(),
        protocol,
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
    let stderr = crate::shared::redaction::redact_connection_url(stderr.trim());
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

#[cfg(unix)]
fn validate_trusted_file(
    path: &Path,
    executable: bool,
    label: &str,
) -> Result<(), BackupStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|source| io_error(format!("inspect {label}"), source))?;
    let expected_uid = rustix::process::geteuid().as_raw();
    let mode = metadata.permissions().mode();
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || (metadata.uid() != 0 && metadata.uid() != expected_uid)
        || mode & 0o022 != 0
        || (executable && mode & 0o111 == 0)
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
        let sticky_root = metadata.uid() == 0 && mode & 0o1000 != 0;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != expected_uid)
            || (mode & 0o022 != 0 && !sticky_root)
        {
            return Err(BackupStoreError::InvalidConfiguration(format!(
                "{label} ancestor {} is not trusted",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_trusted_file(
    _path: &Path,
    _executable: bool,
    _label: &str,
) -> Result<(), BackupStoreError> {
    Err(BackupStoreError::InvalidConfiguration(
        "Kopia backups require a Unix host".to_string(),
    ))
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
        assert_eq!(record.protocol, Some(Protocol::Postgres));
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
