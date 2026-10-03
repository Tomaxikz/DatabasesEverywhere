mod qdrant;
mod redis;
pub mod redis_resp;
pub mod security;

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex as StdMutex},
};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};

use crate::{
    databases::engine::RemoteDumpFlow,
    io::files::ensure_private_dir,
    routes::http::{response::ApiError, router::AppState},
    subsystems::import_export::ImportExportSelection,
    utils::protocol::Protocol,
};

pub(crate) use qdrant::{cleanup_stale_bridge, import_qdrant};
pub(crate) use redis::import_resp;
pub use security::RemoteEndpointRequest;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImportMode {
    #[default]
    Merge,
    Wipe,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteImportRequest {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<SecretString>,
    #[serde(default)]
    pub authentication_database: Option<String>,
    #[serde(default)]
    pub database_index: Option<u32>,
    #[serde(default)]
    pub api_key: Option<SecretString>,
}

impl std::fmt::Debug for RemoteImportRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteImportRequest")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("authentication_database", &self.authentication_database)
            .field("database_index", &self.database_index)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct RemoteImportSource {
    pub endpoint: security::ResolvedRemoteEndpoint,
    pub database: Option<String>,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub authentication_database: Option<String>,
    pub database_index: u32,
    pub api_key: Option<SecretString>,
}

impl std::fmt::Debug for RemoteImportSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteImportSource")
            .field("endpoint", &self.endpoint)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("authentication_database", &self.authentication_database)
            .field("database_index", &self.database_index)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

pub(crate) async fn validate_remote_source(
    state: &AppState,
    protocol: Protocol,
    request: RemoteImportRequest,
) -> Result<RemoteImportSource, ApiError> {
    let policy = &state.config.security.remote_import;
    if !policy.enabled {
        return Err(ApiError::BadRequest(
            "remote database imports are disabled by node policy".to_string(),
        ));
    }
    validate_secret_size("source.password", request.password.as_ref())?;
    validate_secret_size("source.api_key", request.api_key.as_ref())?;

    let database = normalize_optional("source.database", request.database, 256)?;
    let username = normalize_optional("source.username", request.username, 256)?;
    let authentication_database = normalize_optional(
        "source.authentication_database",
        request.authentication_database,
        256,
    )?;

    protocol.engine().validate_remote_source_fields(
        database.as_deref(),
        username.as_deref(),
        request.password.as_ref(),
        authentication_database.as_deref(),
        request.database_index,
        request.api_key.as_ref(),
    )?;

    let endpoint_request = RemoteEndpointRequest {
        host: request.host,
        port: request.port,
        tls: request.tls,
    };
    let endpoint = security::resolve_endpoint(
        &endpoint_request,
        protocol.engine().default_remote_port(endpoint_request.tls),
        policy,
    )
    .await?;

    Ok(RemoteImportSource {
        endpoint,
        database,
        username,
        password: request.password,
        authentication_database,
        database_index: request.database_index.unwrap_or_default(),
        api_key: request.api_key,
    })
}

fn validate_secret_size(field: &str, value: Option<&SecretString>) -> Result<(), ApiError> {
    if value.is_some_and(|value| value.expose_secret().len() > MAX_REMOTE_SECRET_BYTES) {
        return Err(ApiError::BadRequest(format!(
            "{field} exceeds the {MAX_REMOTE_SECRET_BYTES}-byte limit"
        )));
    }
    Ok(())
}

fn normalize_optional(
    field: &str,
    value: Option<String>,
    max_len: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().to_string();
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field} must be between 1 and {max_len} bytes and contain no control characters"
        )));
    }
    Ok(Some(value))
}

pub(crate) fn validate_mongodb_database_name(
    field: &str,
    value: &str,
    allow_external: bool,
) -> Result<(), ApiError> {
    crate::databases::mongodb::transfer::validate_mongodb_database_name(
        field,
        value,
        allow_external,
    )
    .map_err(ApiError::from)
}

const fn default_true() -> bool {
    true
}

const REMOTE_CREDENTIAL_FILES: &[&str] = &[
    "pg_service.conf",
    "pgpass",
    "client.cnf",
    "mongodump.yml",
    "clickhouse-client.xml",
];
const MAX_REMOTE_SECRET_BYTES: usize = 4096;
const MAX_STALE_REMOTE_IMPORT_ENTRIES: usize = 4096;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StaleRemoteCredentialCleanup {
    pub scanned_entries: usize,
    pub job_directories: usize,
    pub removed_files: usize,
    pub removed_directories: usize,
    pub skipped_entries: usize,
    pub errors: usize,
    pub limit_reached: bool,
}

#[derive(Debug)]
pub(crate) struct StagedRemoteDump {
    pub paths: Vec<PathBuf>,
    pub source_database: Option<String>,
    staging: RemoteStagingGuard,
    _permit: RemoteImportPermit,
}

impl StagedRemoteDump {
    pub(crate) async fn cleanup(mut self) {
        self.staging.cleanup().await;
    }
}

pub(crate) async fn acquire_logical_dump(
    state: &AppState,
    protocol: Protocol,
    source: &RemoteImportSource,
    selection: &ImportExportSelection,
    target_username: &str,
    target_database: &str,
) -> Result<StagedRemoteDump, ApiError> {
    if protocol.engine().is_physical() {
        return Err(ApiError::BadRequest(format!(
            "{} does not use the logical remote dump path",
            protocol.as_str()
        )));
    }
    let permit = REMOTE_IMPORT_LIMITER
        .acquire(state.config.security.remote_import.max_concurrent_jobs)
        .await;
    let root = staging_directory(state).await?;
    let mut staging = RemoteStagingGuard::new(root.clone());
    let output_names = logical::output_names(protocol, selection)?;
    let outputs = output_names
        .iter()
        .map(|output_name| root.join(output_name))
        .collect::<Vec<_>>();
    let helper = LogicalDumpHelper {
        state,
        protocol,
        source,
        selection,
        target_username,
        target_database,
    };
    if let Err(error) = helper.stage(&root, &output_names, &outputs).await {
        staging.cleanup().await;
        return Err(error);
    }
    Ok(StagedRemoteDump {
        paths: outputs,
        source_database: source.database.clone(),
        staging,
        _permit: permit,
    })
}

struct LogicalDumpHelper<'a> {
    state: &'a AppState,
    protocol: Protocol,
    source: &'a RemoteImportSource,
    selection: &'a ImportExportSelection,
    target_username: &'a str,
    target_database: &'a str,
}

impl LogicalDumpHelper<'_> {
    async fn stage(
        &self,
        root: &Path,
        output_names: &[String],
        outputs: &[PathBuf],
    ) -> Result<(), ApiError> {
        let helper_result = logical::run_helper(
            self.state,
            self.protocol,
            self.source,
            self.selection,
            self.target_username,
            root,
            output_names,
        )
        .await;
        let credential_cleanup = remove_credential_files(root).await;
        if let Err(error) = helper_result {
            if let Err(cleanup_error) = credential_cleanup {
                tracing::warn!(
                    path = %root.display(),
                    error = %cleanup_error,
                    "failed to remove remote import credentials after helper failure"
                );
            }
            return Err(error);
        }
        credential_cleanup?;
        self.rewrite_schema_qualifiers(outputs).await?;
        validate_total_staged_size(
            outputs,
            self.state.config.security.remote_import.max_staged_bytes,
        )
        .await
    }

    async fn rewrite_schema_qualifiers(&self, outputs: &[PathBuf]) -> Result<(), ApiError> {
        let remote_import = &self.state.config.security.remote_import;
        let timeout = std::time::Duration::from_secs(remote_import.operation_timeout_seconds);
        match self.protocol.engine().remote_dump_flow() {
            RemoteDumpFlow::Mariadb | RemoteDumpFlow::Mysql => {
                let Some(source_database) = self.source.database.as_deref() else {
                    return Err(ApiError::BadRequest(format!(
                        "{} remote import requires a source database",
                        self.protocol.as_str()
                    )));
                };
                mysql_sql::rewrite_mysql_schema_qualifiers(
                    &outputs[0],
                    source_database,
                    self.target_database,
                    remote_import.max_staged_bytes,
                    timeout,
                )
                .await
            }
            RemoteDumpFlow::Clickhouse => {
                let Some(source_database) = self.source.database.as_deref() else {
                    return Err(ApiError::BadRequest(
                        "clickhouse remote import requires a source database".to_string(),
                    ));
                };
                mysql_sql::rewrite_clickhouse_schema(
                    &outputs[0],
                    source_database,
                    self.target_database,
                    remote_import.max_staged_bytes,
                    timeout,
                )
                .await
            }
            RemoteDumpFlow::Postgres | RemoteDumpFlow::Mongodb | RemoteDumpFlow::Unsupported => {
                Ok(())
            }
        }
    }
}

async fn validate_total_staged_size(
    outputs: &[PathBuf],
    max_staged_bytes: u64,
) -> Result<(), ApiError> {
    let mut total_staged_bytes = 0_u64;
    for output in outputs {
        let staged_bytes = validate_staged_file(output, max_staged_bytes).await?;
        total_staged_bytes = match total_staged_bytes.checked_add(staged_bytes) {
            Some(total) if total <= max_staged_bytes => total,
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "remote database dumps exceed the node staging limit of {max_staged_bytes} bytes"
                )));
            }
        };
    }
    Ok(())
}

mod logical;
mod mysql_sql;

async fn remove_credential_files(root: &Path) -> Result<(), ApiError> {
    for name in REMOTE_CREDENTIAL_FILES {
        let path = root.join(name);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ApiError::Runtime(format!(
                    "failed to remove protected remote import credential file {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

/// Removes known logical-import credential files left behind by a process
/// crash. Once stale acquisition helpers have been confirmed removed, it also
/// removes generated staging directories that have no recovery manifest.
/// Manifest-backed snapshot and rollback artifacts are deliberately retained
/// so interrupted imports can still be quarantined and recovered.
///
/// The walk is limited to immediate UUID-named job directories beneath the
/// configured remote-import staging root. Symlinks and special files are never
/// followed or removed.
pub(crate) async fn cleanup_stale_import_secrets(
    tmp_root: &Path,
    remove_orphaned_staging: bool,
) -> StaleRemoteCredentialCleanup {
    let mut summary = StaleRemoteCredentialCleanup::default();
    let staging_root = tmp_root.join("remote-import");
    let root_metadata = match tokio::fs::symlink_metadata(&staging_root).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return summary,
        Err(error) => {
            summary.errors += 1;
            tracing::warn!(
                path = %staging_root.display(),
                %error,
                "failed to inspect stale remote import credential staging root"
            );
            return summary;
        }
    };
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        summary.skipped_entries += 1;
        tracing::warn!(
            path = %staging_root.display(),
            "refusing to scan a symlinked or non-directory remote import staging root"
        );
        return summary;
    }

    let mut entries = match tokio::fs::read_dir(&staging_root).await {
        Ok(entries) => entries,
        Err(error) => {
            summary.errors += 1;
            tracing::warn!(
                path = %staging_root.display(),
                %error,
                "failed to enumerate stale remote import credential staging root"
            );
            return summary;
        }
    };
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(error) => {
                summary.errors += 1;
                tracing::warn!(
                    path = %staging_root.display(),
                    %error,
                    "failed while enumerating stale remote import staging entries"
                );
                break;
            }
        };
        summary.scanned_entries += 1;
        if summary.scanned_entries > MAX_STALE_REMOTE_IMPORT_ENTRIES {
            summary.errors += 1;
            summary.limit_reached = true;
            tracing::warn!(
                path = %staging_root.display(),
                max_entries = MAX_STALE_REMOTE_IMPORT_ENTRIES,
                "stopped stale remote import credential cleanup at the safety entry limit"
            );
            break;
        }

        if !is_generated_import_job(&entry.file_name()) {
            summary.skipped_entries += 1;
            continue;
        }
        cleanup_stale_job_directory(&entry.path(), remove_orphaned_staging, &mut summary).await;
    }
    summary
}

async fn cleanup_stale_job_directory(
    job_path: &Path,
    remove_orphaned_staging: bool,
    summary: &mut StaleRemoteCredentialCleanup,
) {
    let metadata = match tokio::fs::symlink_metadata(job_path).await {
        Ok(metadata) => metadata,
        Err(error) => {
            summary.errors += 1;
            tracing::warn!(
                path = %job_path.display(),
                %error,
                "failed to inspect stale remote import job directory"
            );
            return;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        summary.skipped_entries += 1;
        tracing::warn!(
            path = %job_path.display(),
            "skipping a symlinked or non-directory remote import job entry"
        );
        return;
    }
    summary.job_directories += 1;

    let has_recovery_manifest = inspect_recovery_manifest(job_path, summary).await;
    if remove_orphaned_staging && !has_recovery_manifest {
        remove_orphaned_staging_directory(job_path, summary).await;
        return;
    }

    for name in REMOTE_CREDENTIAL_FILES {
        remove_stale_credential_file(&job_path.join(name), summary).await;
    }
}

async fn inspect_recovery_manifest(
    job_path: &Path,
    summary: &mut StaleRemoteCredentialCleanup,
) -> bool {
    let manifest_path = job_path.join("recovery-manifest.json");
    match tokio::fs::symlink_metadata(&manifest_path).await {
        Ok(manifest_metadata)
            if manifest_metadata.is_file() && !manifest_metadata.file_type().is_symlink() =>
        {
            true
        }
        Ok(_) => {
            summary.errors += 1;
            summary.skipped_entries += 1;
            tracing::warn!(
                path = %manifest_path.display(),
                "refusing to remove a remote import staging directory with a non-regular recovery manifest"
            );
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            summary.errors += 1;
            tracing::warn!(
                path = %manifest_path.display(),
                %error,
                "failed to inspect a remote import recovery manifest"
            );
            true
        }
    }
}

async fn remove_orphaned_staging_directory(
    job_path: &Path,
    summary: &mut StaleRemoteCredentialCleanup,
) {
    match tokio::fs::remove_dir_all(job_path).await {
        Ok(()) => summary.removed_directories += 1,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            summary.errors += 1;
            tracing::warn!(
                path = %job_path.display(),
                %error,
                "failed to remove orphaned remote import staging directory"
            );
        }
    }
}

async fn remove_stale_credential_file(
    credential_path: &Path,
    summary: &mut StaleRemoteCredentialCleanup,
) {
    let credential_metadata = match tokio::fs::symlink_metadata(credential_path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            summary.errors += 1;
            tracing::warn!(
                path = %credential_path.display(),
                %error,
                "failed to inspect a stale remote import credential file"
            );
            return;
        }
    };
    if credential_metadata.file_type().is_symlink() || !credential_metadata.is_file() {
        summary.skipped_entries += 1;
        tracing::warn!(
            path = %credential_path.display(),
            "skipping a symlinked or non-regular remote import credential entry"
        );
        return;
    }
    match tokio::fs::remove_file(credential_path).await {
        Ok(()) => summary.removed_files += 1,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            summary.errors += 1;
            tracing::warn!(
                path = %credential_path.display(),
                %error,
                "failed to remove a stale remote import credential file"
            );
        }
    }
}

fn is_generated_import_job(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name.len() == 36
        && uuid::Uuid::parse_str(name).is_ok_and(|parsed| parsed.hyphenated().to_string() == name)
}

#[derive(Debug)]
struct RemoteStagingGuard {
    root: PathBuf,
    armed: bool,
}

impl RemoteStagingGuard {
    fn new(root: PathBuf) -> Self {
        Self { root, armed: true }
    }

    async fn cleanup(&mut self) {
        if !self.armed {
            return;
        }
        match tokio::fs::remove_dir_all(&self.root).await {
            Ok(()) => self.armed = false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => self.armed = false,
            Err(error) => {
                tracing::warn!(
                    path = %self.root.display(),
                    %error,
                    "failed to remove remote import staging directory"
                );
            }
        }
    }
}

impl Drop for RemoteStagingGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let root = self.root.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = tokio::fs::remove_dir_all(&root).await
                    && error.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::warn!(
                        path = %root.display(),
                        %error,
                        "failed to remove cancelled remote import staging directory"
                    );
                }
            });
        } else if let Err(error) = std::fs::remove_dir_all(&root)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %root.display(),
                %error,
                "failed to remove remote import staging directory without an async runtime"
            );
        }
    }
}

async fn staging_directory(state: &AppState) -> Result<PathBuf, ApiError> {
    let root = PathBuf::from(state.config.paths.tmp_root())
        .join("remote-import")
        .join(uuid::Uuid::new_v4().to_string());
    prepare_private_dir(&root).await?;
    Ok(root)
}

async fn prepare_private_dir(path: &Path) -> Result<(), ApiError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || ensure_private_dir(&path))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("failed to secure import staging area: {error}"))
        })?
        .map_err(|error| {
            ApiError::Runtime(format!("failed to secure import staging area: {error}"))
        })
}

pub(crate) async fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), ApiError> {
    use tokio::io::AsyncWriteExt;

    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).await.map_err(|error| {
        ApiError::Runtime(format!(
            "failed to create protected import credential file: {error}"
        ))
    })?;
    file.write_all(contents).await.map_err(|error| {
        ApiError::Runtime(format!(
            "failed to write protected import credential file: {error}"
        ))
    })?;
    file.sync_all().await.map_err(|error| {
        ApiError::Runtime(format!(
            "failed to sync protected import credential file: {error}"
        ))
    })
}

async fn commit_recovery_manifest(path: &Path) -> Result<(), ApiError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::io::files::remove_private_file_durable(&path))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to commit import recovery metadata: {error}"
            ))
        })?
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to commit import recovery metadata: {error}"
            ))
        })
}

async fn sync_recovery_file(path: &Path) -> Result<(), ApiError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::io::files::sync_private_file(&path))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to sync recovery data: {error}")))?
        .map_err(|error| ApiError::Runtime(format!("failed to sync recovery data: {error}")))
}

async fn validate_staged_file(path: &Path, max_bytes: u64) -> Result<u64, ApiError> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        ApiError::Runtime(format!(
            "remote database dump did not produce a readable artifact: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ApiError::Runtime(
            "remote database dump produced an invalid artifact".to_string(),
        ));
    }
    if metadata.len() == 0 {
        return Err(ApiError::BadRequest(
            "remote database dump was empty".to_string(),
        ));
    }
    if metadata.len() > max_bytes {
        return Err(ApiError::BadRequest(format!(
            "remote database dump is {} bytes; node limit is {max_bytes} bytes",
            metadata.len()
        )));
    }
    Ok(metadata.len())
}

#[derive(Debug)]
struct RemoteImportLimiter {
    active: Mutex<usize>,
    notify: Notify,
}

#[derive(Debug, Default)]
struct RemoteJobAdmission {
    state: Arc<StdMutex<RemoteJobAdmissionState>>,
}

#[derive(Debug, Default)]
struct RemoteJobAdmissionState {
    active: usize,
    instances: HashSet<String>,
}

impl RemoteJobAdmission {
    fn try_acquire(&self, instance_id: &str, maximum: usize) -> Option<RemoteJobAdmissionPermit> {
        let maximum = maximum.max(1);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active >= maximum || state.instances.contains(instance_id) {
            return None;
        }
        state.active += 1;
        state.instances.insert(instance_id.to_string());
        Some(RemoteJobAdmissionPermit {
            state: Arc::clone(&self.state),
            instance_id: instance_id.to_string(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct RemoteJobAdmissionPermit {
    state: Arc<StdMutex<RemoteJobAdmissionState>>,
    instance_id: String,
}

impl Drop for RemoteJobAdmissionPermit {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removed = state.instances.remove(&self.instance_id);
        debug_assert!(removed, "remote job admission instance was missing");
        state.active = state.active.saturating_sub(usize::from(removed));
    }
}

pub(crate) fn try_admit_remote_job(
    instance_id: &str,
    maximum: usize,
) -> Option<RemoteJobAdmissionPermit> {
    REMOTE_JOB_ADMISSION.try_acquire(instance_id, maximum)
}

impl RemoteImportLimiter {
    async fn acquire(&'static self, max: usize) -> RemoteImportPermit {
        let max = max.max(1);
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut active = self.active.lock().await;
                if *active < max {
                    *active += 1;
                    return RemoteImportPermit { limiter: self };
                }
            }
            notified.await;
        }
    }
}

#[derive(Debug)]
struct RemoteImportPermit {
    limiter: &'static RemoteImportLimiter,
}

impl Drop for RemoteImportPermit {
    fn drop(&mut self) {
        let limiter = self.limiter;
        tokio::spawn(async move {
            let mut active = limiter.active.lock().await;
            *active = active.saturating_sub(1);
            limiter.notify.notify_one();
        });
    }
}

static REMOTE_IMPORT_LIMITER: LazyLock<RemoteImportLimiter> =
    LazyLock::new(|| RemoteImportLimiter {
        active: Mutex::new(0),
        notify: Notify::new(),
    });
static REMOTE_JOB_ADMISSION: LazyLock<RemoteJobAdmission> =
    LazyLock::new(RemoteJobAdmission::default);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::engine::{validate_header_safe_secret, validate_line_safe_secret};
    use crate::databases::mongodb::transfer::validate_mongodb_credentials;

    #[test]
    fn remote_secrets_have_a_small_utf8_byte_limit() {
        let exact = SecretString::from("x".repeat(MAX_REMOTE_SECRET_BYTES));
        let oversized = SecretString::from("é".repeat(MAX_REMOTE_SECRET_BYTES / 2 + 1));
        assert!(validate_secret_size("source.password", Some(&exact)).is_ok());
        assert!(validate_secret_size("source.api_key", Some(&oversized)).is_err());
        assert!(validate_secret_size("source.password", None).is_ok());
    }

    #[test]
    fn remote_job_admission_is_nonblocking_bounded_and_releases() {
        let admission = RemoteJobAdmission::default();
        let first = admission.try_acquire("instance-a", 4).unwrap();
        assert!(admission.try_acquire("instance-a", 4).is_none());
        let second = admission.try_acquire("instance-b", 4).unwrap();
        let third = admission.try_acquire("instance-c", 4).unwrap();
        let fourth = admission.try_acquire("instance-d", 4).unwrap();
        assert!(admission.try_acquire("instance-e", 4).is_none());
        drop(first);
        let replacement = admission.try_acquire("instance-e", 4).unwrap();
        drop((second, third, fourth, replacement));
        let state = admission
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.active, 0);
        assert!(state.instances.is_empty());
    }

    #[test]
    fn mongodb_authentication_database_requires_complete_credentials() {
        let password = SecretString::from("secret".to_string());

        assert!(validate_mongodb_credentials(None, None, Some("admin")).is_err());
        assert!(validate_mongodb_credentials(Some("user"), None, Some("admin")).is_err());
        assert!(validate_mongodb_credentials(None, Some(&password), Some("admin")).is_err());
        assert!(validate_mongodb_credentials(Some("user"), Some(&password), Some("admin")).is_ok());
        assert!(validate_mongodb_credentials(None, None, None).is_ok());
    }

    #[test]
    fn mongodb_database_names_follow_linux_server_rules() {
        assert!(validate_mongodb_database_name("source.database", "analytics", false).is_ok());
        assert!(validate_mongodb_database_name("source.database", "tenant*archive", false).is_ok());
        assert!(validate_mongodb_database_name("source.database", &"界".repeat(21), false).is_ok());
        assert!(validate_mongodb_database_name("source.database", &"a".repeat(63), false).is_ok());

        assert!(validate_mongodb_database_name("source.database", "", false).is_err());
        assert!(
            validate_mongodb_database_name("source.database", &"界".repeat(22), false).is_err()
        );
        assert!(validate_mongodb_database_name("source.database", &"a".repeat(64), false).is_err());
        for character in ['\0', '/', '\\', '.', ' ', '"', '$'] {
            let value = format!("invalid{character}name");
            assert!(
                validate_mongodb_database_name("source.database", &value, false).is_err(),
                "{value:?} should be rejected"
            );
        }
    }

    #[test]
    fn mongodb_authentication_database_allows_only_the_external_special_name() {
        assert!(
            validate_mongodb_database_name("source.authentication_database", "$external", true)
                .is_ok()
        );
        assert!(
            validate_mongodb_database_name(
                "source.authentication_database",
                "tenant$external",
                true
            )
            .is_err()
        );
        assert!(validate_mongodb_database_name("source.database", "$external", false).is_err());
    }

    #[test]
    fn sql_password_rejects_config_file_line_injection() {
        for password in ["nul\0byte", "new\nline", "carriage\rreturn"] {
            let password = SecretString::from(password.to_string());
            assert!(validate_line_safe_secret("source.password", &password).is_err());
        }
        let password = SecretString::from("spaces and ! punctuation are allowed".to_string());
        assert!(validate_line_safe_secret("source.password", &password).is_ok());
    }

    #[test]
    fn mysql_family_database_names_follow_the_server_identifier_limit() {
        assert!(crate::databases::mysql::transfer::mysql_database_name(
            &"é".repeat(64)
        ));
        assert!(!crate::databases::mysql::transfer::mysql_database_name(
            &"é".repeat(65)
        ));
    }

    #[test]
    fn qdrant_api_key_must_be_a_valid_http_header_value() {
        let valid = SecretString::from("opaque-api-key_123".to_string());
        let invalid = SecretString::from("header\r\ninjection".to_string());

        assert!(validate_header_safe_secret("source.api_key", &valid).is_ok());
        let error = validate_header_safe_secret("source.api_key", &invalid).unwrap_err();
        assert!(!error.to_string().contains("header\r\ninjection"));
    }

    #[tokio::test]
    async fn credential_cleanup_preserves_the_staged_dump() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let dump = root.join("source.postgres.sql");
        tokio::fs::write(&dump, b"select 1;").await.unwrap();
        for name in REMOTE_CREDENTIAL_FILES {
            tokio::fs::write(root.join(name), b"secret").await.unwrap();
        }

        remove_credential_files(root).await.unwrap();

        assert!(dump.is_file());
        for name in REMOTE_CREDENTIAL_FILES {
            assert!(!root.join(name).exists());
        }
    }

    #[tokio::test]
    async fn startup_cleanup_preserves_manifest_backed_recovery_staging() {
        let directory = tempfile::tempdir().unwrap();
        let staging_root = directory.path().join("remote-import");
        let job = staging_root.join("01234567-89ab-4def-8123-456789abcdef");
        let unrelated_job = staging_root.join("not-a-generated-job");
        tokio::fs::create_dir_all(job.join("nested")).await.unwrap();
        tokio::fs::create_dir_all(&unrelated_job).await.unwrap();
        for name in REMOTE_CREDENTIAL_FILES {
            tokio::fs::write(job.join(name), b"secret").await.unwrap();
        }
        let preserved = [
            "source.postgres.sql",
            "source-0.snapshot",
            "rollback-0.snapshot",
            "rollback.redis.tar.gz",
            "rollback.valkey.tar.gz",
        ];
        for name in preserved {
            tokio::fs::write(job.join(name), b"recovery data")
                .await
                .unwrap();
        }
        tokio::fs::write(job.join("nested").join("pgpass"), b"nested secret")
            .await
            .unwrap();
        tokio::fs::write(job.join("recovery-manifest.json"), b"retained manifest")
            .await
            .unwrap();
        tokio::fs::write(unrelated_job.join("pgpass"), b"unrelated")
            .await
            .unwrap();

        let summary = cleanup_stale_import_secrets(directory.path(), true).await;

        assert_eq!(summary.job_directories, 1);
        assert_eq!(summary.removed_files, REMOTE_CREDENTIAL_FILES.len());
        assert_eq!(summary.removed_directories, 0);
        assert_eq!(summary.errors, 0);
        for name in REMOTE_CREDENTIAL_FILES {
            assert!(!job.join(name).exists());
        }
        for name in preserved {
            assert!(job.join(name).is_file());
        }
        assert!(job.join("nested").join("pgpass").is_file());
        assert!(unrelated_job.join("pgpass").is_file());
    }

    #[tokio::test]
    async fn startup_credential_cleanup_never_follows_job_or_file_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let staging_root = directory.path().join("remote-import");
        tokio::fs::create_dir_all(&staging_root).await.unwrap();

        let outside_job = outside.path().join("job");
        tokio::fs::create_dir(&outside_job).await.unwrap();
        tokio::fs::write(outside_job.join("pgpass"), b"outside secret")
            .await
            .unwrap();
        symlink(
            &outside_job,
            staging_root.join("01234567-89ab-4def-8123-456789abcdef"),
        )
        .unwrap();

        let real_job = staging_root.join("11234567-89ab-4def-8123-456789abcdef");
        tokio::fs::create_dir(&real_job).await.unwrap();
        tokio::fs::write(
            real_job.join("recovery-manifest.json"),
            b"retained manifest",
        )
        .await
        .unwrap();
        let outside_file = outside.path().join("credential");
        tokio::fs::write(&outside_file, b"outside file secret")
            .await
            .unwrap();
        symlink(&outside_file, real_job.join("pgpass")).unwrap();

        let summary = cleanup_stale_import_secrets(directory.path(), true).await;

        assert_eq!(summary.removed_files, 0);
        assert_eq!(summary.errors, 0);
        assert!(summary.skipped_entries >= 2);
        assert!(outside_job.join("pgpass").is_file());
        assert!(outside_file.is_file());
        assert!(real_job.join("pgpass").is_symlink());
    }

    #[tokio::test]
    async fn startup_cleanup_removes_only_orphaned_generated_staging_when_authorized() {
        let directory = tempfile::tempdir().unwrap();
        let staging_root = directory.path().join("remote-import");
        let orphan = staging_root.join("01234567-89ab-4def-8123-456789abcdef");
        tokio::fs::create_dir_all(&orphan).await.unwrap();
        tokio::fs::write(orphan.join("source.mysql.sql"), b"customer dump")
            .await
            .unwrap();

        let deferred = cleanup_stale_import_secrets(directory.path(), false).await;
        assert_eq!(deferred.removed_directories, 0);
        assert!(orphan.is_dir());

        let removed = cleanup_stale_import_secrets(directory.path(), true).await;
        assert_eq!(removed.removed_directories, 1);
        assert!(!orphan.exists());
    }

    #[tokio::test]
    async fn dropped_staging_guard_schedules_cancellation_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("cancelled");
        tokio::fs::create_dir(&root).await.unwrap();
        tokio::fs::write(root.join("credential"), b"secret")
            .await
            .unwrap();
        {
            let _guard = RemoteStagingGuard::new(root.clone());
        }

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while root.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
