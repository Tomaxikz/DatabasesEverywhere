use std::{
    collections::HashMap,
    future::Future,
    io::{Error as IoError, ErrorKind},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bollard::{
    Docker,
    container::{AttachContainerResults, LogOutput},
    errors::Error as BollardError,
    models::{ContainerCreateBody, HostConfig, HostConfigLogConfig},
    query_parameters::{
        AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, ListContainersOptionsBuilder,
        RemoveContainerOptions, StartContainerOptions, WaitContainerOptions,
    },
};
use futures::StreamExt;
use tokio::{
    sync::Notify,
    time::{Instant, MissedTickBehavior},
};

use super::{
    CappedExecOutput, CommandOutput, DockerError, DockerRuntime,
    container_config::{bind_mount, cpu_to_nano, disabled_healthcheck, mib_to_bytes},
    security::DockerSecurityPolicy,
};
use crate::{
    constants::docker::MANAGED_LABEL,
    shared::{logs::truncate_log_tail, redaction},
};

const HELPER_LABEL: &str = "databases-everywhere.remote-import-helper";
const HELPER_NAME_PREFIX: &str = "dbe-remote-import-";
const HELPER_WORK_DIR: &str = "/work";
const HELPER_TMPFS: &str = "rw,noexec,nosuid,nodev,size=64m,mode=1777";
const HELPER_CPU_CORES: f64 = 1.0;
const HELPER_MEMORY_MIB: u64 = 1024;
const HELPER_PIDS_LIMIT: i64 = 128;
const HELPER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const HELPER_LOG_TAIL_CHARS: usize = 16 * 1024;
const HELPER_FAILURE_TAIL_CHARS: usize = 4_000;
const OUTPUT_SIZE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_WORK_DIRECTORY_ENTRIES: usize = 4096;
const MAX_WORK_DIRECTORY_DEPTH: usize = 32;
const MAX_HELPER_SCRIPT_BYTES: usize = 256 * 1024;
const MAX_EXTRA_HOSTS: usize = 64;

/// Description of a one-shot, outbound-network helper used to stage a remote
/// database dump. The caller must choose a configured/trusted database image
/// and must keep credentials in private files under `work_dir`; `script` is
/// stored in Docker's container configuration and therefore must not contain
/// secrets.
#[derive(Clone)]
pub struct RemoteImportHelperSpec {
    pub image: String,
    pub work_dir: PathBuf,
    pub script: String,
    pub extra_hosts: Vec<String>,
    pub timeout: Duration,
    pub max_output_bytes: u64,
}

#[derive(Default)]
struct HelperCancellation {
    cancelled: AtomicBool,
    notified: Notify,
}

impl HelperCancellation {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notified.notify_waiters();
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.notified.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

struct CancelHelperOnDrop {
    cancellation: Arc<HelperCancellation>,
    armed: bool,
}

impl CancelHelperOnDrop {
    fn new(cancellation: Arc<HelperCancellation>) -> Self {
        Self {
            cancellation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelHelperOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.cancel();
        }
    }
}

struct RemoteImportHelperCleanupGuard {
    docker: Docker,
    name: String,
    armed: bool,
}

impl RemoteImportHelperCleanupGuard {
    fn new(docker: Docker, name: String) -> Self {
        Self {
            docker,
            name,
            armed: true,
        }
    }

    async fn cleanup(&mut self) -> Result<(), DockerError> {
        let result = force_remove_remote_import_helper(&self.docker, &self.name).await;
        if result.is_ok() {
            self.armed = false;
        }
        result
    }
}

impl Drop for RemoteImportHelperCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let docker = self.docker.clone();
        let name = self.name.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::error!(
                helper = %name,
                "remote import helper cleanup could not be scheduled; startup reconciliation will retry it"
            );
            return;
        };
        runtime.spawn(async move {
            if let Err(error) = force_remove_remote_import_helper(&docker, &name).await {
                tracing::error!(
                    helper = %name,
                    error = %error,
                    "remote import helper cleanup failed; startup reconciliation will retry it"
                );
            }
        });
    }
}

impl DockerRuntime {
    pub async fn ensure_remote_import_image(&self, image: &str) -> Result<(), DockerError> {
        if image.trim().is_empty() {
            return Err(invalid_helper_spec("image must not be empty"));
        }
        self.ensure_image_with_progress(image, None).await
    }

    pub async fn run_remote_import_helper(
        &self,
        spec: &RemoteImportHelperSpec,
    ) -> Result<CommandOutput, DockerError> {
        // The supervisor owns the helper lifecycle. Dropping the caller's
        // future signals cancellation instead of detaching an unmonitored
        // container, and the supervisor remains alive long enough to remove
        // any container it may already have created.
        let cancellation = Arc::new(HelperCancellation::default());
        let mut cancel_on_drop = CancelHelperOnDrop::new(cancellation.clone());
        let runtime = self.clone();
        let spec = spec.clone();
        let supervisor = tokio::spawn(async move {
            runtime
                .run_remote_import_helper_supervised(spec, cancellation)
                .await
        });
        let joined = supervisor.await;
        cancel_on_drop.disarm();
        joined.map_err(|_| {
            DockerError::RemoteImportHelperTask(
                "remote import helper lifecycle supervisor terminated unexpectedly".to_string(),
            )
        })?
    }

    async fn run_remote_import_helper_supervised(
        &self,
        spec: RemoteImportHelperSpec,
        cancellation: Arc<HelperCancellation>,
    ) -> Result<CommandOutput, DockerError> {
        let work_dir = run_unless_cancelled(&cancellation, validate_helper_spec(&spec)).await?;
        if let Some((uid, gid)) = self.rootless_podman_host_owner() {
            let owned_work_dir = work_dir.clone();
            run_unless_cancelled(&cancellation, async move {
                tokio::task::spawn_blocking(move || {
                    crate::shared::ownership::chown_directory_recursive(
                        &owned_work_dir,
                        crate::shared::ownership::HostOwner { uid, gid },
                    )
                    .map_err(|source| DockerError::RemoteImportHelperIo {
                        path: owned_work_dir.display().to_string(),
                        source,
                    })
                })
                .await
                .map_err(|error| DockerError::RemoteImportHelperTask(error.to_string()))?
            })
            .await?;
        }
        let initial_size = run_unless_cancelled(
            &cancellation,
            measure_work_directory(&work_dir, spec.max_output_bytes),
        )
        .await?;
        if initial_size > spec.max_output_bytes {
            return Err(DockerError::RemoteImportHelperOutputTooLarge {
                size: initial_size,
                max_bytes: spec.max_output_bytes,
            });
        }

        // Resolve/pull the trusted caller-selected image before creating any
        // helper container. Remote-import API code writes secrets only after
        // it has selected this configured image.
        run_unless_cancelled(&cancellation, self.ensure_remote_import_image(&spec.image)).await?;
        if cancellation.is_cancelled() {
            return Err(DockerError::RemoteImportHelperCancelled);
        }

        let name = format!("{HELPER_NAME_PREFIX}{}", uuid::Uuid::new_v4().simple());
        let mut cleanup = RemoteImportHelperCleanupGuard::new(self.docker.clone(), name.clone());
        let body = remote_import_helper_body(&spec, &work_dir, &self.security);
        // Once submitted, let the short Docker create call finish. Dropping an
        // in-flight request could race a 404 cleanup with a late server-side
        // creation and leave an unstarted orphan. Cancellation is observed
        // immediately after creation and then takes the guarded cleanup path.
        let response = match self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(&name).build()),
                body,
            )
            .await
        {
            Ok(response) => response,
            Err(source) => {
                if let Err(cleanup_error) = cleanup.cleanup().await {
                    tracing::error!(
                        helper = %name,
                        error = %cleanup_error,
                        "failed to force-remove a possibly-created remote import helper"
                    );
                }
                return Err(source.into());
            }
        };
        if !response.warnings.is_empty() {
            tracing::warn!(
                helper = %name,
                warnings = %truncate_log_tail(
                    &redaction::redact_connection_url(&response.warnings.join("\n")),
                    HELPER_FAILURE_TAIL_CHARS,
                ),
                "remote import helper container was created with warnings"
            );
        }

        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(DockerError::RemoteImportHelperCancelled),
            result = self.run_created_remote_import_helper(&name, &spec, &work_dir) => result,
        };
        let cleanup_result = cleanup.cleanup().await;
        match (result, cleanup_result) {
            (Ok(output), Ok(())) => Ok(output),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
            (Err(error), Err(cleanup_error)) => {
                tracing::error!(
                    helper = %name,
                    error = %cleanup_error,
                    "failed to force-remove remote import helper after an operation error"
                );
                Err(error)
            }
        }
    }

    /// Removes helper containers left behind by an interrupted daemon process.
    ///
    /// Both the exact helper label and the generated name format must match.
    /// This prevents reconciliation from touching managed database containers
    /// or unrelated containers that happen to use a similar label or name.
    pub async fn reconcile_remote_import_helpers(&self) -> Result<usize, DockerError> {
        let filters = HashMap::from([("label".to_string(), vec![format!("{HELPER_LABEL}=true")])]);
        let containers = self
            .docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default()
                    .all(true)
                    .filters(&filters)
                    .build(),
            ))
            .await?;

        let mut removed = 0;
        let mut first_error = None;
        for container in containers {
            if !is_owned_remote_import_helper(container.labels.as_ref(), container.names.as_deref())
            {
                continue;
            }
            let Some(id) = container.id else {
                continue;
            };
            match force_remove_remote_import_helper(&self.docker, &id).await {
                Ok(()) => removed += 1,
                Err(error) => {
                    tracing::error!(
                        helper = %id,
                        error = %error,
                        "failed to reconcile stale remote import helper"
                    );
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(removed)
        }
    }

    async fn run_created_remote_import_helper(
        &self,
        name: &str,
        spec: &RemoteImportHelperSpec,
        work_dir: &Path,
    ) -> Result<CommandOutput, DockerError> {
        let deadline = Instant::now()
            .checked_add(spec.timeout)
            .ok_or_else(|| invalid_helper_spec("timeout is too large"))?;
        let AttachContainerResults {
            mut output,
            input: _,
        } = tokio::time::timeout_at(
            deadline,
            self.docker.attach_container(
                name,
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
        .map_err(|_| helper_timeout(spec.timeout))??;

        tokio::time::timeout_at(
            deadline,
            self.docker
                .start_container(name, None::<StartContainerOptions>),
        )
        .await
        .map_err(|_| helper_timeout(spec.timeout))??;

        let mut wait = Box::pin(
            self.docker
                .wait_container(name, None::<WaitContainerOptions>),
        );
        let mut size_interval = tokio::time::interval(OUTPUT_SIZE_POLL_INTERVAL);
        size_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let timeout = tokio::time::sleep_until(deadline);
        tokio::pin!(timeout);

        let mut stdout = CappedExecOutput::default();
        let mut stderr = CappedExecOutput::default();
        let mut exit_code = None;
        let mut output_closed = false;

        loop {
            tokio::select! {
                chunk = output.next(), if !output_closed => {
                    match chunk {
                        Some(Ok(LogOutput::StdOut { message } | LogOutput::Console { message })) => {
                            stdout.append(&message);
                        }
                        Some(Ok(LogOutput::StdErr { message })) => {
                            stderr.append(&message);
                        }
                        Some(Ok(LogOutput::StdIn { .. })) => {}
                        Some(Err(error)) => return Err(error.into()),
                        None => output_closed = true,
                    }
                }
                wait_result = wait.next(), if exit_code.is_none() => {
                    match wait_result {
                        Some(Ok(response)) => exit_code = Some(response.status_code),
                        Some(Err(BollardError::DockerContainerWaitError { code, error })) => {
                            stderr.append(error.as_bytes());
                            exit_code = Some(code);
                        }
                        Some(Err(error)) => return Err(error.into()),
                        None => return Err(DockerError::RemoteImportHelperWaitEnded),
                    }
                }
                _ = size_interval.tick() => {
                    let size =
                        measure_work_directory(work_dir, spec.max_output_bytes).await?;
                    if size > spec.max_output_bytes {
                        return Err(DockerError::RemoteImportHelperOutputTooLarge {
                            size,
                            max_bytes: spec.max_output_bytes,
                        });
                    }
                }
                _ = &mut timeout => return Err(helper_timeout(spec.timeout)),
            }

            if output_closed && exit_code.is_some() {
                break;
            }
        }

        let final_size = measure_work_directory(work_dir, spec.max_output_bytes).await?;
        if final_size > spec.max_output_bytes {
            return Err(DockerError::RemoteImportHelperOutputTooLarge {
                size: final_size,
                max_bytes: spec.max_output_bytes,
            });
        }

        let output = sanitized_helper_output(stdout, stderr);
        let exit_code = exit_code.unwrap_or_default();
        if exit_code == 0 {
            Ok(output)
        } else {
            let failure_output = if output.stderr.trim().is_empty() {
                output.stdout.trim()
            } else {
                output.stderr.trim()
            };
            Err(DockerError::RemoteImportHelperFailed {
                exit_code,
                failure_output: truncate_log_tail(failure_output, HELPER_FAILURE_TAIL_CHARS),
            })
        }
    }
}

async fn run_unless_cancelled<T>(
    cancellation: &HelperCancellation,
    operation: impl Future<Output = Result<T, DockerError>>,
) -> Result<T, DockerError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(DockerError::RemoteImportHelperCancelled),
        result = operation => result,
    }
}

async fn force_remove_remote_import_helper(
    docker: &Docker,
    name_or_id: &str,
) -> Result<(), DockerError> {
    let remove = docker.remove_container(
        name_or_id,
        Some(RemoveContainerOptions {
            v: true,
            force: true,
            ..Default::default()
        }),
    );
    match tokio::time::timeout(HELPER_CLEANUP_TIMEOUT, remove).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        })) => Ok(()),
        Ok(Err(source)) => Err(DockerError::RemoteImportHelperCleanupFailed {
            container: name_or_id.to_string(),
            source,
        }),
        Err(_) => Err(DockerError::RemoteImportHelperCleanupTimedOut {
            container: name_or_id.to_string(),
            timeout_seconds: HELPER_CLEANUP_TIMEOUT.as_secs(),
        }),
    }
}

fn is_owned_remote_import_helper(
    labels: Option<&HashMap<String, String>>,
    names: Option<&[String]>,
) -> bool {
    labels.and_then(|labels| labels.get(HELPER_LABEL).map(String::as_str)) == Some("true")
        && names.is_some_and(|names| names.iter().any(|name| is_remote_import_helper_name(name)))
}

fn is_remote_import_helper_name(name: &str) -> bool {
    let normalized = name.strip_prefix('/').unwrap_or(name);
    let Some(suffix) = normalized.strip_prefix(HELPER_NAME_PREFIX) else {
        return false;
    };
    suffix.len() == 32
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn remote_import_helper_body(
    spec: &RemoteImportHelperSpec,
    work_dir: &Path,
    security: &DockerSecurityPolicy,
) -> ContainerCreateBody {
    let mut host_config = HostConfig {
        network_mode: Some("bridge".to_string()),
        nano_cpus: cpu_to_nano(HELPER_CPU_CORES),
        memory: mib_to_bytes(HELPER_MEMORY_MIB),
        memory_swap: mib_to_bytes(HELPER_MEMORY_MIB),
        pids_limit: Some(HELPER_PIDS_LIMIT),
        mounts: Some(vec![bind_mount(work_dir, HELPER_WORK_DIR, false)]),
        tmpfs: Some(HashMap::from([(
            "/tmp".to_string(),
            HELPER_TMPFS.to_string(),
        )])),
        extra_hosts: (!spec.extra_hosts.is_empty()).then(|| spec.extra_hosts.clone()),
        log_config: Some(HostConfigLogConfig {
            typ: Some("none".to_string()),
            config: None,
        }),
        auto_remove: Some(true),
        port_bindings: None,
        ..Default::default()
    };
    security.apply(&mut host_config);

    // These helper-specific limits are deliberately stricter than configurable
    // managed-database defaults.
    host_config.network_mode = Some("bridge".to_string());
    host_config.nano_cpus = cpu_to_nano(HELPER_CPU_CORES);
    host_config.memory = mib_to_bytes(HELPER_MEMORY_MIB);
    host_config.memory_swap = mib_to_bytes(HELPER_MEMORY_MIB);
    host_config.pids_limit = Some(HELPER_PIDS_LIMIT);
    host_config.readonly_rootfs = Some(true);
    host_config.mounts = Some(vec![bind_mount(work_dir, HELPER_WORK_DIR, false)]);
    host_config.tmpfs = Some(HashMap::from([(
        "/tmp".to_string(),
        HELPER_TMPFS.to_string(),
    )]));
    host_config.extra_hosts = (!spec.extra_hosts.is_empty()).then(|| spec.extra_hosts.clone());
    host_config.log_config = Some(HostConfigLogConfig {
        typ: Some("none".to_string()),
        config: None,
    });
    host_config.auto_remove = Some(true);
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
        user: Some("0:0".to_string()),
        working_dir: Some(HELPER_WORK_DIR.to_string()),
        entrypoint: Some(vec!["/bin/sh".to_string()]),
        cmd: Some(vec!["-c".to_string(), spec.script.clone()]),
        env: Some(vec!["HOME=/tmp".to_string()]),
        labels: Some(HashMap::from([
            (HELPER_LABEL.to_string(), "true".to_string()),
            (MANAGED_LABEL.to_string(), "false".to_string()),
        ])),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        attach_stdin: Some(false),
        open_stdin: Some(false),
        stdin_once: Some(false),
        tty: Some(false),
        stop_timeout: Some(10),
        healthcheck: Some(disabled_healthcheck()),
        host_config: Some(host_config),
        exposed_ports: None,
        ..Default::default()
    }
}

async fn validate_helper_spec(spec: &RemoteImportHelperSpec) -> Result<PathBuf, DockerError> {
    if spec.image.trim().is_empty() {
        return Err(invalid_helper_spec("image must not be empty"));
    }
    if spec.script.trim().is_empty() {
        return Err(invalid_helper_spec("script must not be empty"));
    }
    if spec.script.len() > MAX_HELPER_SCRIPT_BYTES {
        return Err(invalid_helper_spec(format!(
            "script exceeds {MAX_HELPER_SCRIPT_BYTES} bytes"
        )));
    }
    if spec.script.contains('\0') {
        return Err(invalid_helper_spec("script must not contain NUL"));
    }
    if spec.timeout.is_zero() {
        return Err(invalid_helper_spec("timeout must be greater than zero"));
    }
    if spec.max_output_bytes == 0 {
        return Err(invalid_helper_spec(
            "max_output_bytes must be greater than zero",
        ));
    }
    if spec.extra_hosts.len() > MAX_EXTRA_HOSTS {
        return Err(invalid_helper_spec(format!(
            "extra_hosts may contain at most {MAX_EXTRA_HOSTS} entries"
        )));
    }
    for entry in &spec.extra_hosts {
        if entry.is_empty()
            || entry.len() > 512
            || entry.chars().any(char::is_control)
            || (!entry.contains(':') && !entry.contains('='))
        {
            return Err(invalid_helper_spec("extra_hosts contains an invalid entry"));
        }
    }
    if !spec.work_dir.is_absolute() {
        return Err(invalid_helper_spec("work_dir must be absolute"));
    }
    if spec
        .work_dir
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(invalid_helper_spec(
            "work_dir must not contain parent components",
        ));
    }

    let metadata = tokio::fs::symlink_metadata(&spec.work_dir)
        .await
        .map_err(|source| DockerError::RemoteImportHelperIo {
            path: spec.work_dir.display().to_string(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_helper_spec(
            "work_dir must be a real existing directory",
        ));
    }
    let canonical = tokio::fs::canonicalize(&spec.work_dir)
        .await
        .map_err(|source| DockerError::RemoteImportHelperIo {
            path: spec.work_dir.display().to_string(),
            source,
        })?;
    if forbidden_helper_mount(&canonical) {
        return Err(invalid_helper_spec(format!(
            "work_dir {} is too broad or security-sensitive",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn forbidden_helper_mount(path: &Path) -> bool {
    if path.parent().is_none() {
        return true;
    }
    [
        "/etc",
        "/proc",
        "/sys",
        "/dev",
        "/root",
        "/run/docker.sock",
        "/var/run/docker.sock",
        "/run/podman/podman.sock",
        "/var/run/podman/podman.sock",
    ]
    .iter()
    .any(|forbidden| path == Path::new(forbidden) || path.starts_with(forbidden))
        || is_rootless_podman_socket(path)
}

fn is_rootless_podman_socket(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    path.file_name().is_some_and(|name| name == "podman.sock")
        && parent.file_name().is_some_and(|name| name == "podman")
        && parent
            .parent()
            .and_then(Path::parent)
            .is_some_and(|root| root == Path::new("/run/user"))
}

async fn measure_work_directory(path: &Path, stop_after: u64) -> Result<u64, DockerError> {
    let path = path.to_path_buf();
    let error_path = path.display().to_string();
    tokio::task::spawn_blocking(move || measure_work_directory_blocking(&path, stop_after))
        .await
        .map_err(|error| DockerError::RemoteImportHelperTask(error.to_string()))?
        .map_err(|source| DockerError::RemoteImportHelperIo {
            path: error_path,
            source,
        })
}

fn measure_work_directory_blocking(root: &Path, stop_after: u64) -> Result<u64, IoError> {
    let mut total = 0_u64;
    let mut entries = 0_usize;
    let mut pending = vec![(root.to_path_buf(), 0_usize)];

    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_WORK_DIRECTORY_DEPTH {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "remote import work directory nesting is too deep",
            ));
        }
        for entry in std::fs::read_dir(directory)? {
            entries += 1;
            if entries > MAX_WORK_DIRECTORY_ENTRIES {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "remote import work directory has too many entries",
                ));
            }
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "remote import work directory contains a symbolic link",
                ));
            }
            if file_type.is_dir() {
                pending.push((entry.path(), depth + 1));
            } else if file_type.is_file() {
                total = total.checked_add(metadata.len()).ok_or_else(|| {
                    IoError::new(
                        ErrorKind::InvalidData,
                        "remote import work directory size overflow",
                    )
                })?;
                if total > stop_after {
                    return Ok(total);
                }
            } else {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "remote import work directory contains a special file",
                ));
            }
        }
    }
    Ok(total)
}

fn sanitized_helper_output(stdout: CappedExecOutput, stderr: CappedExecOutput) -> CommandOutput {
    CommandOutput {
        stdout: truncate_log_tail(
            &redaction::redact_connection_url(&stdout.into_string()),
            HELPER_LOG_TAIL_CHARS,
        ),
        stderr: truncate_log_tail(
            &redaction::redact_connection_url(&stderr.into_string()),
            HELPER_LOG_TAIL_CHARS,
        ),
    }
}

fn invalid_helper_spec(reason: impl Into<String>) -> DockerError {
    DockerError::InvalidRemoteImportHelperSpec {
        reason: reason.into(),
    }
}

fn helper_timeout(timeout: Duration) -> DockerError {
    DockerError::RemoteImportHelperTimedOut {
        timeout_seconds: timeout.as_secs().max(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_body_has_only_the_work_mount_and_strict_sandboxing() {
        let spec = RemoteImportHelperSpec {
            image: "postgres:18.4".to_string(),
            work_dir: PathBuf::from("/var/lib/dbev/tmp/import-job"),
            script: "pg_dump --file=/work/source.sql".to_string(),
            extra_hosts: vec!["db.example.com:203.0.113.10".to_string()],
            timeout: Duration::from_secs(900),
            max_output_bytes: 8 * 1024 * 1024 * 1024,
        };
        let body =
            remote_import_helper_body(&spec, &spec.work_dir, &DockerSecurityPolicy::default());
        let labels = body.labels.as_ref().unwrap();
        let host = body.host_config.as_ref().unwrap();
        let mounts = host.mounts.as_ref().unwrap();

        assert_eq!(body.image.as_deref(), Some("postgres:18.4"));
        assert_eq!(body.user.as_deref(), Some("0:0"));
        assert_eq!(body.working_dir.as_deref(), Some(HELPER_WORK_DIR));
        assert_eq!(
            body.entrypoint.as_deref(),
            Some(&["/bin/sh".to_string()][..])
        );
        assert_eq!(body.env.as_deref(), Some(&["HOME=/tmp".to_string()][..]));
        assert_eq!(body.attach_stdin, Some(false));
        assert_eq!(body.open_stdin, Some(false));
        assert!(body.exposed_ports.is_none());
        assert_eq!(
            body.healthcheck
                .as_ref()
                .and_then(|healthcheck| healthcheck.test.as_deref()),
            Some(&["NONE".to_string()][..])
        );

        assert_eq!(labels.get(HELPER_LABEL).map(String::as_str), Some("true"));
        assert_eq!(labels.get(MANAGED_LABEL).map(String::as_str), Some("false"));
        assert_eq!(host.network_mode.as_deref(), Some("bridge"));
        assert_ne!(host.network_mode.as_deref(), Some("host"));
        assert_eq!(host.nano_cpus, Some(1_000_000_000));
        assert_eq!(host.memory, Some(1024 * 1024 * 1024));
        assert_eq!(host.memory_swap, host.memory);
        assert_eq!(host.pids_limit, Some(HELPER_PIDS_LIMIT));
        assert_eq!(host.readonly_rootfs, Some(true));
        assert_eq!(host.privileged, Some(false));
        assert_eq!(host.cap_drop, Some(vec!["ALL".to_string()]));
        assert!(
            host.security_opt
                .as_ref()
                .is_some_and(|options| options.iter().any(|option| option == "no-new-privileges"))
        );
        assert_eq!(host.devices, Some(Vec::new()));
        assert!(host.port_bindings.is_none());
        assert_eq!(
            host.extra_hosts.as_deref(),
            Some(&["db.example.com:203.0.113.10".to_string()][..])
        );
        assert_eq!(
            host.log_config
                .as_ref()
                .and_then(|config| config.typ.as_deref()),
            Some("none")
        );
        assert_eq!(host.auto_remove, Some(true));
        assert_eq!(
            host.tmpfs
                .as_ref()
                .and_then(|tmpfs| tmpfs.get("/tmp"))
                .map(String::as_str),
            Some(HELPER_TMPFS)
        );
        assert_eq!(mounts.len(), 1);
        assert_eq!(
            mounts[0].source.as_deref(),
            Some("/var/lib/dbev/tmp/import-job")
        );
        assert_eq!(mounts[0].target.as_deref(), Some(HELPER_WORK_DIR));
        assert_eq!(mounts[0].read_only, Some(false));
    }

    #[test]
    fn reconciliation_requires_the_exact_label_and_generated_name_shape() {
        let labels = HashMap::from([(HELPER_LABEL.to_string(), "true".to_string())]);
        let valid_names = vec!["/dbe-remote-import-0123456789abcdef0123456789abcdef".to_string()];

        assert!(is_owned_remote_import_helper(
            Some(&labels),
            Some(&valid_names),
        ));
        assert!(!is_owned_remote_import_helper(None, Some(&valid_names)));
        assert!(!is_owned_remote_import_helper(
            Some(&HashMap::from([(
                HELPER_LABEL.to_string(),
                "false".to_string()
            )])),
            Some(&valid_names),
        ));
        assert!(!is_owned_remote_import_helper(
            Some(&labels),
            Some(&["/dbe-remote-import-not-a-uuid".to_string()]),
        ));
        assert!(!is_owned_remote_import_helper(
            Some(&labels),
            Some(&["/dbe-remote-import-0123456789ABCDEF0123456789ABCDEF".to_string()]),
        ));
        assert!(!is_owned_remote_import_helper(
            Some(&labels),
            Some(&["/unrelated-0123456789abcdef0123456789abcdef".to_string()]),
        ));
    }

    #[tokio::test]
    async fn dropping_the_cancellation_guard_notifies_the_supervisor() {
        let cancellation = Arc::new(HelperCancellation::default());
        {
            let _guard = CancelHelperOnDrop::new(cancellation.clone());
        }

        tokio::time::timeout(Duration::from_millis(100), cancellation.cancelled())
            .await
            .expect("cancellation must be observable without a missed notification");
    }

    #[tokio::test]
    async fn concurrent_cancellation_notifications_are_not_lost() {
        for iteration in 0..256 {
            let cancellation = Arc::new(HelperCancellation::default());
            let waiter_cancellation = cancellation.clone();
            let waiter = tokio::spawn(async move {
                waiter_cancellation.cancelled().await;
            });
            if iteration % 2 == 0 {
                tokio::task::yield_now().await;
            }
            cancellation.cancel();
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("cancellation waiter must not miss a notification")
                .expect("cancellation waiter task must complete");
        }
    }
}
