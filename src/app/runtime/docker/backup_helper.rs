//! Short-lived backup helper containers.
//!
//! A helper runs an engine-native tool from the instance's own immutable
//! image, so its binaries match the server version. It mounts only the
//! instance socket directory (read-only, for the Unix-socket connection),
//! optionally the instance data directory (read-only, for tools that copy
//! live data files next to a server session), and one
//! coordinator-reserved, disk-backed staging directory. It has no
//! network, CPU, memory and pid limits of its own, a read-only root
//! filesystem, no capabilities and `no-new-privileges`. Native output never
//! lands on the socket mount, which is commonly tmpfs charged to the
//! database's memory cgroup.
//!
//! The caller journals the helper name before [`DockerRuntime::run_backup_helper`]
//! creates it. A supervisor task owns the container: dropping the caller's
//! future cancels it, and the supervisor force-removes the container and
//! confirms it no longer exists before it exits. Staging is measured while
//! the helper runs and the helper is removed once it exceeds its budget.
//! [`DockerRuntime::remove_backup_helper`] waits for a live supervisor, then
//! force-removes and confirms absence, so journal cleanup never races a
//! container that is still being created.

use std::{
    collections::HashMap,
    io::{Error as IoError, ErrorKind},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex as StdMutex, PoisonError},
    time::Duration,
};

use bollard::{
    container::{AttachContainerResults, LogOutput},
    errors::Error as BollardError,
    models::{ContainerCreateBody, HostConfig, HostConfigLogConfig},
    query_parameters::{
        AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, InspectContainerOptions,
        RemoveContainerOptions, StartContainerOptions, WaitContainerOptions,
    },
};
use futures::StreamExt;
use secrecy::ExposeSecret;
use tokio::{
    sync::{Mutex as AsyncMutex, OwnedMutexGuard, oneshot},
    time::{Instant, MissedTickBehavior},
};

use super::{
    DockerEnv, DockerRuntime,
    command::CommandOutput,
    container_config::{bind_mount, cpu_to_nano, disabled_healthcheck, mib_to_bytes},
    error::DockerError,
    security::DockerSecurityPolicy,
    transfer::CappedExecOutput,
};
use crate::{
    io::ownership::{HostOwner, chown_recursive},
    utils::{
        constants::docker::{MANAGED_LABEL, NODE_LABEL},
        logs::truncate_log_tail,
        redaction,
    },
};

/// Where the job's staging directory appears inside a helper.
pub const BACKUP_HELPER_STAGING: &str = "/dbev/staging";
const HELPER_LABEL: &str = "databases-everywhere.backup-helper";
const INSTANCE_LABEL: &str = "databases-everywhere.backup-instance";
const NAME_PREFIX: &str = "dbev_bk_";
const NAME_HEX_LEN: usize = 32;
const MAX_NAME_SUFFIX_LEN: usize = 16;
const HELPER_CPU_CORES: f64 = 1.0;
const HELPER_MEMORY_MIB: u64 = 512;
const HELPER_PIDS_LIMIT: i64 = 64;
const HELPER_TMPFS: &str = "rw,noexec,nosuid,nodev,size=16m,mode=1777";
const HELPER_STOP_TIMEOUT_SECONDS: i64 = 10;
const REMOVE_TIMEOUT: Duration = Duration::from_secs(30);
const SUPERVISOR_WAIT: Duration = Duration::from_secs(120);
const STAGING_POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_STAGING_ENTRIES: usize = 2_000_000;
const MAX_STAGING_DEPTH: usize = 64;
const FAILURE_TAIL_CHARS: usize = 4_000;
const OUTPUT_TAIL_CHARS: usize = 16 * 1024;
const MAX_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 16;

/// Supervisors of helpers started by this process, keyed by container name.
/// A supervisor holds its lock until the container is confirmed gone.
static SUPERVISORS: LazyLock<StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>> =
    LazyLock::new(Default::default);

#[derive(Clone)]
pub struct BackupHelperSpec {
    /// The job tag `dbev_bk_<32 hex>`, optionally followed by `_<suffix>`.
    pub name: String,
    pub instance_id: String,
    /// Immutable image id of the running instance.
    pub image: String,
    pub socket: Option<BackupHelperSocket>,
    /// Instance data directory, mounted read-only.
    pub data: Option<BackupHelperSocket>,
    pub staging_dir: PathBuf,
    pub staging_read_only: bool,
    /// Shell script. It is stored in the container configuration and must
    /// never contain a secret; pass those through `environment`.
    pub script: String,
    pub environment: Vec<DockerEnv>,
    pub timeout: Duration,
    /// The helper is removed once staging holds more than this many bytes.
    pub max_staging_bytes: u64,
}

/// An instance directory (socket or data), mounted read-only.
#[derive(Clone, Debug)]
pub struct BackupHelperSocket {
    pub source: PathBuf,
    pub target: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BackupHelperError {
    #[error("invalid backup helper: {0}")]
    Invalid(String),
    #[error(transparent)]
    Docker(#[from] DockerError),
    #[error("backup helper staging {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: IoError,
    },
    #[error("backup helper exited {exit_code}: {output}")]
    Failed { exit_code: i64, output: String },
    #[error("backup helper exceeded its {seconds}-second deadline and was removed")]
    TimedOut { seconds: u64 },
    #[error(
        "backup staging reached {size} bytes, over its {max_bytes}-byte budget; the helper was removed"
    )]
    OverBudget { size: u64, max_bytes: u64 },
    #[error("backup helper was cancelled and removed")]
    Cancelled,
    #[error("backup helper {name} removal could not be confirmed: {reason}")]
    RemovalUnconfirmed { name: String, reason: String },
}

impl BackupHelperError {
    /// False only when the helper container may still exist.
    pub fn removal_confirmed(&self) -> bool {
        !matches!(self, Self::RemovalUnconfirmed { .. })
    }
}

impl DockerRuntime {
    /// Runs one helper to completion and removes it. Errors other than
    /// [`BackupHelperError::RemovalUnconfirmed`] guarantee the container no
    /// longer exists.
    pub async fn run_backup_helper(
        &self,
        spec: &BackupHelperSpec,
    ) -> Result<CommandOutput, BackupHelperError> {
        validate_spec(spec)?;
        let lock = Arc::new(AsyncMutex::new(()));
        let guard = Arc::clone(&lock)
            .try_lock_owned()
            .map_err(|_| BackupHelperError::Invalid("helper lock is contended".to_string()))?;
        {
            let mut supervisors = SUPERVISORS.lock().unwrap_or_else(PoisonError::into_inner);
            if supervisors.contains_key(&spec.name) {
                return Err(BackupHelperError::Invalid(format!(
                    "helper {} is already supervised",
                    spec.name
                )));
            }
            supervisors.insert(spec.name.clone(), lock);
        }
        // Dropping this future drops `cancel`, which the supervisor observes.
        let (cancel, cancelled) = oneshot::channel::<()>();
        let runtime = self.clone();
        let owned = spec.clone();
        let supervisor =
            tokio::spawn(async move { runtime.supervise(owned, cancelled, guard).await });
        let joined = supervisor.await;
        drop(cancel);
        joined.map_err(|error| BackupHelperError::RemovalUnconfirmed {
            name: spec.name.clone(),
            reason: format!("supervisor ended before cleanup was confirmed: {error}"),
        })?
    }

    /// Force-removes a journaled helper and confirms it no longer exists.
    /// Waits for this process's supervisor first. Refuses a container with
    /// the same name that is not a backup helper of this node.
    pub async fn remove_backup_helper(&self, name: &str) -> Result<(), BackupHelperError> {
        if !is_helper_name(name) {
            return Err(BackupHelperError::Invalid(format!(
                "{name} is not a backup helper name"
            )));
        }
        let supervisor = SUPERVISORS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned();
        let _settled = match supervisor {
            Some(lock) => Some(
                tokio::time::timeout(SUPERVISOR_WAIT, lock.lock_owned())
                    .await
                    .map_err(|_| BackupHelperError::RemovalUnconfirmed {
                        name: name.to_string(),
                        reason: "its supervisor is still running".to_string(),
                    })?,
            ),
            None => None,
        };
        self.remove_helper_container(name).await.map_err(|reason| {
            BackupHelperError::RemovalUnconfirmed {
                name: name.to_string(),
                reason,
            }
        })?;
        forget_supervisor(name);
        Ok(())
    }

    async fn supervise(
        &self,
        spec: BackupHelperSpec,
        mut cancelled: oneshot::Receiver<()>,
        _guard: OwnedMutexGuard<()>,
    ) -> Result<CommandOutput, BackupHelperError> {
        let result = self.execute(&spec, &mut cancelled).await;
        match (result, self.remove_helper_container(&spec.name).await) {
            (result, Ok(())) => {
                forget_supervisor(&spec.name);
                result
            }
            (Ok(_), Err(reason)) => Err(BackupHelperError::RemovalUnconfirmed {
                name: spec.name,
                reason,
            }),
            (Err(error), Err(reason)) => Err(BackupHelperError::RemovalUnconfirmed {
                name: spec.name,
                reason: format!("{error}; {reason}"),
            }),
        }
    }

    async fn execute(
        &self,
        spec: &BackupHelperSpec,
        cancelled: &mut oneshot::Receiver<()>,
    ) -> Result<CommandOutput, BackupHelperError> {
        let node_id = self
            .node_id
            .as_deref()
            .ok_or(DockerError::RuntimeNodeIdUnavailable)?;
        let deadline = Instant::now()
            .checked_add(spec.timeout)
            .ok_or_else(|| BackupHelperError::Invalid("timeout is too large".to_string()))?;
        let user = self.helper_user(spec).await?;
        let secrets: Vec<String> = spec
            .environment
            .iter()
            .map(|entry| entry.value.expose_secret().to_string())
            .filter(|value| !value.is_empty())
            .collect();
        let environment = spec
            .environment
            .iter()
            .map(|entry| format!("{}={}", entry.key, entry.value.expose_secret()))
            .collect();
        if is_cancelled(cancelled) {
            return Err(BackupHelperError::Cancelled);
        }
        let body = helper_body(HelperBody {
            spec,
            user,
            environment,
            security: &self.security,
            rootless_podman: self.uses_rootless_podman(),
            node_id,
        });
        // Let the create call finish: dropping it could race removal with a
        // late server-side creation. Cancellation is observed right after.
        self.docker
            .create_container(
                Some(
                    CreateContainerOptionsBuilder::default()
                        .name(&spec.name)
                        .build(),
                ),
                body,
            )
            .await
            .map_err(DockerError::from)?;
        if is_cancelled(cancelled) {
            return Err(BackupHelperError::Cancelled);
        }
        self.attach_and_wait(spec, deadline, cancelled, &secrets)
            .await
    }

    async fn attach_and_wait(
        &self,
        spec: &BackupHelperSpec,
        deadline: Instant,
        cancelled: &mut oneshot::Receiver<()>,
        secrets: &[String],
    ) -> Result<CommandOutput, BackupHelperError> {
        let timed_out = || BackupHelperError::TimedOut {
            seconds: spec.timeout.as_secs().max(1),
        };
        let AttachContainerResults { mut output, .. } = tokio::time::timeout_at(
            deadline,
            self.docker.attach_container(
                &spec.name,
                Some(
                    AttachContainerOptionsBuilder::default()
                        .stream(true)
                        .stdin(false)
                        .stdout(true)
                        .stderr(true)
                        .build(),
                ),
            ),
        )
        .await
        .map_err(|_| timed_out())?
        .map_err(DockerError::from)?;
        tokio::time::timeout_at(
            deadline,
            self.docker
                .start_container(&spec.name, None::<StartContainerOptions>),
        )
        .await
        .map_err(|_| timed_out())?
        .map_err(DockerError::from)?;

        let mut wait = Box::pin(
            self.docker
                .wait_container(&spec.name, None::<WaitContainerOptions>),
        );
        let mut poll = tokio::time::interval(STAGING_POLL_INTERVAL);
        poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let timeout = tokio::time::sleep_until(deadline);
        tokio::pin!(timeout);
        let mut stdout = CappedExecOutput::default();
        let mut stderr = CappedExecOutput::default();
        let mut exit_code = None;
        let mut output_closed = false;
        while !(output_closed && exit_code.is_some()) {
            tokio::select! {
                _ = &mut *cancelled => return Err(BackupHelperError::Cancelled),
                chunk = output.next(), if !output_closed => match chunk {
                    Some(Ok(LogOutput::StdOut { message } | LogOutput::Console { message })) => {
                        stdout.append(&message);
                    }
                    Some(Ok(LogOutput::StdErr { message })) => stderr.append(&message),
                    Some(Ok(LogOutput::StdIn { .. })) => {}
                    Some(Err(error)) => return Err(DockerError::from(error).into()),
                    None => output_closed = true,
                },
                waited = wait.next(), if exit_code.is_none() => match waited {
                    Some(Ok(response)) => exit_code = Some(response.status_code),
                    Some(Err(BollardError::DockerContainerWaitError { code, error })) => {
                        stderr.append(error.as_bytes());
                        exit_code = Some(code);
                    }
                    Some(Err(error)) => return Err(DockerError::from(error).into()),
                    None => {
                        return Err(BackupHelperError::Invalid(
                            "helper wait stream ended without an exit code".to_string(),
                        ));
                    }
                },
                // The walk is awaited to completion, never abandoned.
                _ = poll.tick() => check_budget(spec).await?,
                _ = &mut timeout => return Err(timed_out()),
            }
        }
        check_budget(spec).await?;
        let stdout = redaction::redact_exact_secrets(&stdout.into_string(), secrets);
        let stderr = redaction::redact_exact_secrets(&stderr.into_string(), secrets);
        let exit_code = exit_code.unwrap_or_default();
        if exit_code != 0 {
            let failure = if stderr.trim().is_empty() {
                &stdout
            } else {
                &stderr
            };
            return Err(BackupHelperError::Failed {
                exit_code,
                output: truncate_log_tail(failure, FAILURE_TAIL_CHARS),
            });
        }
        Ok(CommandOutput {
            stdout: truncate_log_tail(&stdout, OUTPUT_TAIL_CHARS),
            stderr: truncate_log_tail(&stderr, OUTPUT_TAIL_CHARS),
        })
    }

    /// Rootless Podman maps container uid 0 to the service account, which
    /// owns the socket directory; staging is handed to that account. Other
    /// engines run the helper as the owner of the instance socket directory
    /// (the database's own uid), which needs no capability to reach the
    /// private socket mount, and staging is handed to the same owner.
    async fn helper_user(&self, spec: &BackupHelperSpec) -> Result<String, BackupHelperError> {
        if let Some((uid, gid)) = self.rootless_podman_host_owner() {
            if !spec.staging_read_only {
                chown_staging(&spec.staging_dir, HostOwner { uid, gid }).await?;
            }
            return Ok("0:0".to_string());
        }
        let reference = spec
            .socket
            .as_ref()
            .map_or(spec.staging_dir.as_path(), |socket| socket.source.as_path());
        let stat = rustix::fs::stat(reference).map_err(|error| BackupHelperError::Io {
            path: reference.display().to_string(),
            source: error.into(),
        })?;
        let owner = HostOwner {
            uid: stat.st_uid,
            gid: stat.st_gid,
        };
        if !spec.staging_read_only {
            chown_staging(&spec.staging_dir, owner).await?;
        }
        Ok(format!("{}:{}", owner.uid, owner.gid))
    }

    /// Removes a helper by name and confirms it is gone. A container with the
    /// name but without this node's helper labels is never touched.
    async fn remove_helper_container(&self, name: &str) -> Result<(), String> {
        let node_id = self
            .node_id
            .as_deref()
            .ok_or_else(|| "runtime node id is unavailable".to_string())?;
        match self.inspect_helper(name).await? {
            None => return Ok(()),
            Some(labels) if !is_owned_helper(&labels, node_id) => {
                return Err(format!(
                    "container {name} exists but is not a backup helper of this node"
                ));
            }
            Some(_) => {}
        }
        let remove = self.docker.remove_container(
            name,
            Some(RemoveContainerOptions {
                v: true,
                force: true,
                ..Default::default()
            }),
        );
        match tokio::time::timeout(REMOVE_TIMEOUT, remove).await {
            Ok(Ok(()))
            | Ok(Err(BollardError::DockerResponseServerError {
                status_code: 404, ..
            })) => {}
            Ok(Err(error)) => return Err(format!("force removal failed: {error}")),
            Err(_) => {
                return Err(format!(
                    "force removal exceeded {} seconds",
                    REMOVE_TIMEOUT.as_secs()
                ));
            }
        }
        match self.inspect_helper(name).await? {
            None => Ok(()),
            Some(_) => Err("the container still exists after force removal".to_string()),
        }
    }

    async fn inspect_helper(&self, name: &str) -> Result<Option<HashMap<String, String>>, String> {
        let inspect = self
            .docker
            .inspect_container(name, None::<InspectContainerOptions>);
        match tokio::time::timeout(REMOVE_TIMEOUT, inspect).await {
            Ok(Ok(response)) => Ok(Some(
                response
                    .config
                    .and_then(|config| config.labels)
                    .unwrap_or_default(),
            )),
            Ok(Err(BollardError::DockerResponseServerError {
                status_code: 404, ..
            })) => Ok(None),
            Ok(Err(error)) => Err(format!("inspect failed: {error}")),
            Err(_) => Err(format!(
                "inspect exceeded {} seconds",
                REMOVE_TIMEOUT.as_secs()
            )),
        }
    }
}

struct HelperBody<'a> {
    spec: &'a BackupHelperSpec,
    user: String,
    environment: Vec<String>,
    security: &'a DockerSecurityPolicy,
    rootless_podman: bool,
    node_id: &'a str,
}

fn helper_body(options: HelperBody<'_>) -> ContainerCreateBody {
    let HelperBody {
        spec,
        user,
        environment,
        security,
        rootless_podman,
        node_id,
    } = options;
    let mut mounts = vec![bind_mount(
        &spec.staging_dir,
        BACKUP_HELPER_STAGING,
        spec.staging_read_only,
    )];
    for mount in spec.socket.iter().chain(&spec.data) {
        mounts.push(bind_mount(&mount.source, &mount.target, true));
    }
    let mut host_config = HostConfig::default();
    security.apply(&mut host_config);
    if rootless_podman {
        host_config.userns_mode = Some("host".to_string());
    }
    // Helper limits are independent of, and stricter than, the database's.
    host_config.network_mode = Some("none".to_string());
    host_config.nano_cpus = cpu_to_nano(HELPER_CPU_CORES);
    host_config.memory = mib_to_bytes(HELPER_MEMORY_MIB);
    host_config.memory_swap = mib_to_bytes(HELPER_MEMORY_MIB);
    host_config.pids_limit = Some(HELPER_PIDS_LIMIT);
    host_config.readonly_rootfs = Some(true);
    host_config.mounts = Some(mounts);
    host_config.tmpfs = Some(HashMap::from([(
        "/tmp".to_string(),
        HELPER_TMPFS.to_string(),
    )]));
    host_config.log_config = Some(HostConfigLogConfig {
        typ: Some("none".to_string()),
        config: None,
    });
    // Removal is explicit so it can be confirmed.
    host_config.auto_remove = Some(false);
    host_config.port_bindings = None;
    host_config.privileged = Some(false);
    host_config.cap_add = None;
    host_config.cap_drop = Some(vec!["ALL".to_string()]);
    host_config.devices = Some(Vec::new());
    let security_opts = host_config.security_opt.get_or_insert_default();
    if !security_opts
        .iter()
        .any(|option| option == "no-new-privileges")
    {
        security_opts.push("no-new-privileges".to_string());
    }

    ContainerCreateBody {
        image: Some(spec.image.clone()),
        user: Some(user),
        working_dir: Some("/tmp".to_string()),
        entrypoint: Some(vec!["/bin/sh".to_string()]),
        cmd: Some(vec!["-c".to_string(), spec.script.clone()]),
        env: Some(
            std::iter::once("HOME=/tmp".to_string())
                .chain(environment)
                .collect(),
        ),
        labels: Some(HashMap::from([
            (HELPER_LABEL.to_string(), "true".to_string()),
            (MANAGED_LABEL.to_string(), "false".to_string()),
            (NODE_LABEL.to_string(), node_id.to_string()),
            (INSTANCE_LABEL.to_string(), spec.instance_id.clone()),
        ])),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        attach_stdin: Some(false),
        open_stdin: Some(false),
        stdin_once: Some(false),
        tty: Some(false),
        network_disabled: Some(true),
        stop_timeout: Some(HELPER_STOP_TIMEOUT_SECONDS),
        healthcheck: Some(disabled_healthcheck()),
        host_config: Some(host_config),
        exposed_ports: None,
        ..Default::default()
    }
}

fn validate_spec(spec: &BackupHelperSpec) -> Result<(), BackupHelperError> {
    let invalid = |reason: &str| Err(BackupHelperError::Invalid(reason.to_string()));
    if !is_helper_name(&spec.name) {
        return invalid("name is not a backup job tag");
    }
    if spec.image.trim().is_empty() {
        return invalid("image must not be empty");
    }
    if !spec.staging_dir.is_absolute()
        || spec
            .socket
            .iter()
            .chain(&spec.data)
            .any(|mount| !mount.source.is_absolute() || !mount.target.starts_with('/'))
    {
        return invalid("mount paths must be absolute");
    }
    if spec.script.is_empty() || spec.script.len() > MAX_SCRIPT_BYTES || spec.script.contains('\0')
    {
        return invalid("script is empty, too large or contains NUL");
    }
    if spec.environment.len() > MAX_ENVIRONMENT_ENTRIES
        || spec.environment.iter().any(|entry| {
            entry.key.is_empty()
                || !entry
                    .key
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
                || entry.value.expose_secret().contains('\0')
        })
    {
        return invalid("environment entries are malformed");
    }
    if spec.timeout.is_zero() || spec.max_staging_bytes == 0 {
        return invalid("timeout and staging budget must be positive");
    }
    Ok(())
}

/// `dbev_bk_<32 lowercase hex>` with an optional `_<lowercase suffix>`.
fn is_helper_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(NAME_PREFIX) else {
        return false;
    };
    let (hex, suffix) = match rest.split_once('_') {
        Some((hex, suffix)) => (hex, Some(suffix)),
        None => (rest, None),
    };
    hex.len() == NAME_HEX_LEN
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && suffix.is_none_or(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= MAX_NAME_SUFFIX_LEN
                && suffix.bytes().all(|byte| byte.is_ascii_lowercase())
        })
}

fn is_owned_helper(labels: &HashMap<String, String>, node_id: &str) -> bool {
    labels.get(HELPER_LABEL).map(String::as_str) == Some("true")
        && labels.get(NODE_LABEL).map(String::as_str) == Some(node_id)
}

fn is_cancelled(cancelled: &mut oneshot::Receiver<()>) -> bool {
    matches!(
        cancelled.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    )
}

fn forget_supervisor(name: &str) {
    SUPERVISORS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(name);
}

async fn chown_staging(path: &Path, owner: HostOwner) -> Result<(), BackupHelperError> {
    let target = path.to_path_buf();
    tokio::task::spawn_blocking(move || chown_recursive(&target, owner))
        .await
        .map_err(|error| BackupHelperError::Invalid(format!("staging ownership task: {error}")))?
        .map_err(|source| BackupHelperError::Io {
            path: path.display().to_string(),
            source,
        })
}

async fn check_budget(spec: &BackupHelperSpec) -> Result<(), BackupHelperError> {
    let root = spec.staging_dir.clone();
    let max_bytes = spec.max_staging_bytes;
    let size = tokio::task::spawn_blocking(move || staging_bytes(&root, max_bytes))
        .await
        .map_err(|error| BackupHelperError::Invalid(format!("staging measurement task: {error}")))?
        .map_err(|source| BackupHelperError::Io {
            path: spec.staging_dir.display().to_string(),
            source,
        })?;
    if size > max_bytes {
        return Err(BackupHelperError::OverBudget { size, max_bytes });
    }
    Ok(())
}

/// Apparent size of regular files below `root`, stopping once it exceeds
/// `stop_after`. Symbolic links are not followed; entries that disappear
/// while the tool runs (temporary names) are skipped.
fn staging_bytes(root: &Path, stop_after: u64) -> Result<u64, IoError> {
    let mut total = 0_u64;
    for (index, entry) in walkdir::WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .enumerate()
    {
        if index >= MAX_STAGING_ENTRIES {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "backup staging has too many entries",
            ));
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.io_error().map(IoError::kind) == Some(ErrorKind::NotFound) => {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if entry.depth() > MAX_STAGING_DEPTH + 1 {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "backup staging nesting is too deep",
            ));
        }
        if entry.file_type().is_file() {
            let size = match entry.metadata() {
                Ok(metadata) => metadata.len(),
                Err(error) if error.io_error().map(IoError::kind) == Some(ErrorKind::NotFound) => {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            total = total.saturating_add(size);
            if total > stop_after {
                return Ok(total);
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: &str = "dbev_bk_0123456789abcdef0123456789abcdef";

    fn spec(staging: &Path) -> BackupHelperSpec {
        BackupHelperSpec {
            name: TAG.to_string(),
            instance_id: "inst_one".to_string(),
            image: "sha256:abc".to_string(),
            socket: Some(BackupHelperSocket {
                source: PathBuf::from("/run/dbev/sockets/inst_one"),
                target: "/var/run/postgresql".to_string(),
            }),
            data: None,
            staging_dir: staging.to_path_buf(),
            staging_read_only: false,
            script: "set -eu\nexec pg_basebackup\n".to_string(),
            environment: vec![DockerEnv::plain("PGPASSWORD", "hunter2")],
            timeout: Duration::from_secs(60),
            max_staging_bytes: 1024,
        }
    }

    #[test]
    fn helper_names_are_job_tags_with_optional_suffixes() {
        assert!(is_helper_name(TAG));
        assert!(is_helper_name(&format!("{TAG}_verify")));
        for name in [
            "",
            "dbev_bk_",
            "dbev_bk_0123456789ABCDEF0123456789ABCDEF",
            "dbev_bk_0123456789abcdef0123456789abcde",
            "dbe-postgres-inst_one",
            &format!("{TAG}_"),
            &format!("{TAG}_Verify"),
            &format!("{TAG}_../x"),
            &format!("{TAG}_abcdefghijklmnopq"),
        ] {
            assert!(!is_helper_name(name), "{name}");
        }
    }

    #[test]
    fn helper_body_is_isolated_and_limited_independently_of_the_database() {
        let staging = Path::new("/backups/.staging/inst_one/.job.capture");
        let spec = spec(staging);
        let body = helper_body(HelperBody {
            spec: &spec,
            user: "999:999".to_string(),
            environment: vec!["PGPASSWORD=hunter2".to_string()],
            security: &DockerSecurityPolicy::default(),
            rootless_podman: false,
            node_id: "node-a",
        });
        let host = body.host_config.as_ref().unwrap();
        assert_eq!(host.network_mode.as_deref(), Some("none"));
        assert_eq!(body.network_disabled, Some(true));
        assert_eq!(host.readonly_rootfs, Some(true));
        assert_eq!(host.privileged, Some(false));
        assert_eq!(host.cap_drop.as_deref(), Some(&["ALL".to_string()][..]));
        assert!(
            host.security_opt
                .as_ref()
                .unwrap()
                .contains(&"no-new-privileges".to_string())
        );
        assert_eq!(host.memory, mib_to_bytes(HELPER_MEMORY_MIB));
        assert_eq!(host.memory_swap, host.memory);
        assert_eq!(host.pids_limit, Some(HELPER_PIDS_LIMIT));
        assert_eq!(host.auto_remove, Some(false));
        let mounts = host.mounts.as_ref().unwrap();
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].target.as_deref(), Some(BACKUP_HELPER_STAGING));
        assert_eq!(mounts[0].read_only, Some(false));
        assert_eq!(mounts[1].target.as_deref(), Some("/var/run/postgresql"));
        assert_eq!(mounts[1].read_only, Some(true));
        assert_eq!(body.user.as_deref(), Some("999:999"));
        assert_eq!(body.image.as_deref(), Some("sha256:abc"));
        let labels = body.labels.as_ref().unwrap();
        assert!(is_owned_helper(labels, "node-a"));
        assert!(!is_owned_helper(labels, "node-b"));
        assert!(!body.cmd.as_ref().unwrap()[1].contains("hunter2"));
    }

    #[test]
    fn specs_reject_unsafe_names_paths_and_environment() {
        let staging = Path::new("/backups/.staging/inst_one/.job.capture");
        assert!(validate_spec(&spec(staging)).is_ok());
        let mut foreign = spec(staging);
        foreign.name = "dbe-postgres-inst_one".to_string();
        assert!(validate_spec(&foreign).is_err());
        let relative = spec(Path::new("staging"));
        assert!(validate_spec(&relative).is_err());
        let mut env = spec(staging);
        env.environment[0].key = "PG PASSWORD".to_string();
        assert!(validate_spec(&env).is_err());
        let mut unbounded = spec(staging);
        unbounded.max_staging_bytes = 0;
        assert!(validate_spec(&unbounded).is_err());
        let mut data = spec(staging);
        data.data = Some(BackupHelperSocket {
            source: PathBuf::from("volumes/inst_one"),
            target: "/var/lib/mysql".to_string(),
        });
        assert!(validate_spec(&data).is_err());
    }

    #[test]
    fn staging_measurement_stops_past_the_budget_and_skips_links() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(staging_bytes(&root.path().join("missing"), 10).unwrap(), 0);
        std::fs::create_dir_all(root.path().join("pgdata/pg_wal")).unwrap();
        std::fs::write(root.path().join("pgdata/PG_VERSION"), b"18\n").unwrap();
        std::fs::write(root.path().join("pgdata/pg_wal/segment"), vec![0_u8; 100]).unwrap();
        std::os::unix::fs::symlink("/etc", root.path().join("pgdata/link")).unwrap();
        assert_eq!(staging_bytes(root.path(), 1024).unwrap(), 103);
        assert!(staging_bytes(root.path(), 50).unwrap() > 50);
    }

    #[test]
    fn only_unconfirmed_removal_leaves_a_container_behind() {
        assert!(BackupHelperError::Cancelled.removal_confirmed());
        assert!(BackupHelperError::TimedOut { seconds: 1 }.removal_confirmed());
        assert!(
            !BackupHelperError::RemovalUnconfirmed {
                name: TAG.to_string(),
                reason: "inspect failed".to_string(),
            }
            .removal_confirmed()
        );
    }
}
