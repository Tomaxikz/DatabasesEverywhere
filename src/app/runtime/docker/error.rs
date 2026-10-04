use crate::{runtime::docker::security, utils::limits::ResourceLimitError};
use bollard::errors::Error as BollardError;

#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    #[error("startup history could not be persisted: {0}")]
    StartupHistory(#[from] sqlx::Error),
    #[error(
        "automatic startup blocked for {0} after two unconfirmed startups; repair the cause, then explicitly start the instance or pool"
    )]
    AutostartBlocked(String),
    #[error("container engine did not confirm disabled automatic restarts for {0}")]
    RestartPolicyNotDisabled(String),
    #[error(transparent)]
    InvalidId(#[from] crate::utils::ids::IdError),
    #[error("docker api error: {0}")]
    Api(#[from] BollardError),
    #[error("podman api {operation} request failed: {reason}")]
    PodmanApiRequest {
        operation: &'static str,
        reason: String,
    },
    #[error("podman api {operation} failed with HTTP {status}: {message}")]
    PodmanApiResponse {
        operation: &'static str,
        status: u16,
        message: String,
    },
    #[error(
        "container engine mismatch: daemon.engine is {configured}, but the configured socket reports {reported}"
    )]
    EngineMismatch {
        configured: &'static str,
        reported: &'static str,
    },
    #[error("invalid container engine socket {path}: {source}")]
    InvalidEngineSocket {
        path: String,
        source: std::io::Error,
    },
    #[error(
        "rootless Podman was detected through {path}, but its non-root host uid/gid could not be determined; configure the direct user-owned Podman socket"
    )]
    RootlessPodmanOwnerUnavailable { path: String },
    #[error(
        "rootless Podman requires cgroup v2 so DBE CPU, memory, and PID limits remain enforceable"
    )]
    RootlessPodmanRequiresCgroupV2,
    #[error("unsupported Podman version {detected}; DBE requires Podman {minimum} or newer")]
    UnsupportedPodmanVersion {
        detected: String,
        minimum: &'static str,
    },
    #[error("docker security policy rejected spec: {0}")]
    Security(#[from] security::DockerSecurityError),
    #[error("invalid container resource limits: {0}")]
    ResourceLimit(#[from] ResourceLimitError),
    #[error("cpu limit {cpu_cores} cannot be represented in Docker nano-CPU units")]
    CpuLimitConversion { cpu_cores: f64 },
    #[error("managed container {instance_id} CPU burst policy failed: {reason}")]
    CpuBurstPolicy { instance_id: String, reason: String },
    #[error("memory limit {memory_mib} MiB cannot be represented in Docker bytes")]
    MemoryLimitConversion { memory_mib: u64 },
    #[error("failed to prepare bind mount source {path}: {source}")]
    MountSourceIo {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid bind mount source {path}: {reason}")]
    InvalidMountSource { path: String, reason: String },
    #[error("invalid file-transfer source {path}: expected a real regular file")]
    InvalidTransferSource { path: String },
    #[error("invalid container file-transfer path {path}")]
    InvalidContainerTransferPath { path: String },
    #[error(
        "refusing to modify same-name container {container}: it does not have the complete DBE ownership labels for instance {instance_id} and protocol {protocol}"
    )]
    UntrustedContainerNameCollision {
        container: String,
        instance_id: String,
        protocol: String,
    },
    #[error("managed container for instance {instance_id} and protocol {protocol} was not found")]
    ManagedContainerNotFound {
        instance_id: String,
        protocol: String,
    },
    #[error(
        "managed {protocol} container for instance {instance_id} has an invalid legacy credential environment: {reason}"
    )]
    InvalidLegacyCredentialEnvironment {
        instance_id: String,
        protocol: String,
        reason: String,
    },
    #[error(
        "managed container {instance_id} data bind mismatch at {destination}: expected {expected_source}, actual {actual_source}; recreate or migrate the container before using the selected disk-limit mode"
    )]
    DiskBindSourceMismatch {
        instance_id: String,
        destination: String,
        expected_source: String,
        actual_source: String,
    },
    #[error("managed container {container} did not report an immutable container id")]
    ManagedContainerIdUnavailable { container: String },
    #[error("managed container {container} did not report an immutable image id")]
    ManagedContainerImageIdUnavailable { container: String },
    #[error("managed container {container} did not report its current start generation")]
    ManagedContainerStartedAtUnavailable { container: String },
    #[error("DBE node ownership identity is unavailable for this container operation")]
    RuntimeNodeIdUnavailable,
    #[error("container log history exceeded its 10-second deadline")]
    LogsTimedOut,
    #[error("file transfer failed for {path}: {source}")]
    FileTransferIo {
        path: String,
        source: std::io::Error,
    },
    #[error("file transfer {direction} for {path} exceeded the {timeout_seconds}-second deadline")]
    FileTransferTimedOut {
        direction: &'static str,
        path: String,
        timeout_seconds: u64,
    },
    #[error("file transfer source {path} is {size} bytes; maximum is {max_bytes} bytes")]
    FileTransferTooLarge {
        path: String,
        size: u64,
        max_bytes: u64,
    },
    #[error("file transfer task failed: {0}")]
    FileTransferTask(String),
    #[error("invalid remote import helper specification: {reason}")]
    InvalidRemoteImportHelperSpec { reason: String },
    #[error("remote import helper work directory operation failed for {path}: {source}")]
    RemoteImportHelperIo {
        path: String,
        source: std::io::Error,
    },
    #[error("remote import helper filesystem task failed: {0}")]
    RemoteImportHelperTask(String),
    #[error("remote import helper state is uncertain: {reason}")]
    RemoteImportHelperStateUncertain { reason: String },
    #[error("remote import helper output is {size} bytes; maximum is {max_bytes} bytes")]
    RemoteImportHelperOutputTooLarge { size: u64, max_bytes: u64 },
    #[error("remote import helper exceeded its {timeout_seconds}-second deadline")]
    RemoteImportHelperTimedOut { timeout_seconds: u64 },
    #[error("remote import helper was cancelled")]
    RemoteImportHelperCancelled,
    #[error("remote import helper wait stream ended without an exit status")]
    RemoteImportHelperWaitEnded,
    #[error("remote import helper exited with code {exit_code}: {failure_output}")]
    RemoteImportHelperFailed {
        exit_code: i64,
        failure_output: String,
    },
    #[error("failed to force-remove remote import helper {container}: {source}")]
    RemoteImportHelperCleanupFailed {
        container: String,
        source: BollardError,
    },
    #[error(
        "timed out after {timeout_seconds} seconds while force-removing remote import helper {container}"
    )]
    RemoteImportHelperCleanupTimedOut {
        container: String,
        timeout_seconds: u64,
    },
    #[error("docker stats stream ended without data")]
    EmptyStatsStream,
    #[error("docker image pull failed for {image}: {message}")]
    ImagePullFailed { image: String, message: String },
    #[error("container image {image} has no command for the socket bridge to supervise")]
    MissingImageCommand { image: String },
    #[error(
        "container {instance_id} was not ready before timeout (status={status}, runtime_health={health:?}, startup_readiness={readiness_error:?})"
    )]
    ContainerNotReady {
        instance_id: String,
        status: String,
        health: Option<String>,
        readiness_error: Option<String>,
    },
    #[error(
        "docker exec failed in {container} with exit code {exit_code}: {operation}; output: {failure_output}"
    )]
    ExecFailed {
        container: String,
        operation: String,
        exit_code: i64,
        failure_output: String,
    },
    #[error("invalid streaming exec command")]
    InvalidExecCommand,
    #[error("invalid streaming exec environment")]
    InvalidExecEnvironment,
    #[error("invalid streaming exec {direction} file {path}")]
    InvalidExecStreamFile {
        direction: &'static str,
        path: String,
    },
    #[error("streaming exec {direction} failed for {path}: {source}")]
    ExecStreamIo {
        direction: &'static str,
        path: String,
        source: std::io::Error,
    },
    #[error("streaming exec input {path} is {size} bytes; maximum is {max_bytes} bytes")]
    ExecStreamInputTooLarge {
        path: String,
        size: u64,
        max_bytes: u64,
    },
    #[error("streaming exec output {path} exceeded the {max_bytes}-byte limit")]
    ExecStreamOutputTooLarge { path: String, max_bytes: u64 },
    #[error(
        "streaming exec failed in {container} with exit code {exit_code}; stderr: {failure_output}"
    )]
    ExecStreamFailed {
        container: String,
        exit_code: i64,
        failure_output: String,
    },
    #[error("streaming exec unexpectedly started detached in {container}")]
    ExecStreamDetached { container: String },
    #[error("streaming exec ended without an exit status")]
    ExecExitStatusUnavailable,
    #[error("streaming exec was cancelled in {container}; runtime-isolation recovery was applied")]
    ExecStreamCancelled { container: String },
    #[error("streaming exec task failed: {0}")]
    ExecStreamTask(String),
    #[error("docker exec timeout must be greater than zero")]
    InvalidExecTimeout,
    #[error(
        "PostgreSQL tenant role {username} in instance {instance_id} is the immutable bootstrap superuser; export the database and recreate the instance with purge before opening its gateway"
    )]
    LegacyPostgresBootstrapSuperuser {
        instance_id: String,
        username: String,
    },
    #[error("PostgreSQL tenant role {username} is missing from managed instance {instance_id}")]
    MissingPostgresTenantRole {
        instance_id: String,
        username: String,
    },
    #[error("PostgreSQL provisioning returned no recognized result for instance {instance_id}")]
    UnexpectedPostgresProvisioningOutput { instance_id: String },
    #[error("PostgreSQL authentication hardening failed for instance {instance_id}: {reason}")]
    PostgresAuthHardeningFailed { instance_id: String, reason: String },
    #[error(
        "docker exec timed out after {timeout_seconds} seconds in {container}: {operation}; runtime-isolation recovery was applied"
    )]
    ExecTimedOut {
        container: String,
        operation: String,
        timeout_seconds: u64,
    },
    #[error("failed to recover from timed-out docker exec in {container} ({operation}): {reason}")]
    ExecRecoveryFailed {
        container: String,
        operation: String,
        reason: String,
    },
}

impl DockerError {
    /// Returns true when DBE could not prove that an import helper stopped.
    /// Callers must fence the affected tenant and must not start rollback work
    /// that could race the helper.
    pub fn import_helper_state_uncertain(&self) -> bool {
        matches!(
            self,
            Self::RemoteImportHelperStateUncertain { .. }
                | Self::RemoteImportHelperCleanupFailed { .. }
                | Self::RemoteImportHelperCleanupTimedOut { .. }
        )
    }

    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::Api(BollardError::DockerResponseServerError {
                status_code: 404,
                ..
            }) | Self::PodmanApiResponse { status: 404, .. }
                | Self::ManagedContainerNotFound { .. }
        )
    }

    pub fn is_not_running(&self) -> bool {
        matches!(
            self,
            Self::Api(BollardError::DockerResponseServerError {
                status_code: 304,
                ..
            })
        )
    }
}
