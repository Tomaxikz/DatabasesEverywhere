//! Engine-native online backup strategies.
//!
//! A strategy captures a running database into daemon-owned staging without a
//! planned write freeze or container restart, verifies the capture with the
//! engine's native tooling, and names the restore recipe able to recover it.
//! The coordinator (`online.rs`) owns locking, durable job state, staging,
//! packaging, manifest construction and publication. Strategies never publish
//! artifacts and never restart or stop the serving runtime.
//!
//! Engines without a certified strategy return
//! [`StrategyError::Unsupported`]; the coordinator turns that into a clear
//! request failure instead of falling back to a weaker or frozen copy.
//!
//! Strategies run native tools in journaled helper containers
//! ([`OnlineBackupContext::run_helper`]) that write straight into staging.
//! They must honour [`OnlineBackupContext::deadline`] themselves; the
//! coordinator waits a short grace period past it before abandoning the work,
//! and only removes staging once every helper is confirmed gone.
//!
//! INTERFACE CHANGES
//! - `RestoreContext` gained `restore_target` (read-only for strategies).
//! - `verify` receives the registrar so native verifiers can run in helpers.
//! - Registration: `registry.rs` maps each `OnlineBackup` variant to the
//!   strategy whose `id()` is the matching `registry` constant.
//! - `BackupHelperSpec::data` mounts the instance data directory read-only
//!   for tools that copy live files next to a server session.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use futures::future::BoxFuture;

use crate::{
    routes::http::{response::ApiError, router::AppState},
    runtime::docker::{BackupHelperError, BackupHelperSpec, CommandOutput},
    server::{
        backup::manifest::{
            ConsistencyLevel, RecoveryCoordinates, RestoreRecipeRef, is_safe_relative,
        },
        metadata::InstanceMetadata,
        paths::InstancePaths,
    },
    utils::shell::sh_quote,
};

/// Prefix of every server-side or host-side resource name a backup job may
/// create. Cleanup only ever touches names carrying the owning job's tag.
pub(crate) const OWNED_RESOURCE_PREFIX: &str = "dbev_bk_";

#[derive(Debug, thiserror::Error)]
pub(crate) enum StrategyError {
    /// No certified strategy exists for this engine, version or layout.
    /// Strict online requests must fail; nothing was created.
    #[error("online backup is not supported: {0}")]
    Unsupported(String),
    /// The strategy was eligible but capture, verification or cleanup failed.
    #[error("online backup failed: {0}")]
    Failed(String),
}

impl StrategyError {
    pub(crate) fn failed(context: &str, error: impl std::fmt::Display) -> Self {
        Self::Failed(format!("{context}: {error}"))
    }

    /// Names the native tool in a failure; `Unsupported` stays as it is.
    pub(crate) fn for_tool(self, tool: &str) -> Self {
        match self {
            Self::Failed(reason) => Self::Failed(format!("{tool}: {reason}")),
            unsupported => unsupported,
        }
    }
}

/// `set -eu` plus the quoted argv. Secrets travel only in the environment.
pub(crate) fn exec_script(argv: &[String]) -> String {
    let argv = argv
        .iter()
        .map(|arg| sh_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    format!("set -eu\numask 077\nexec {argv}\n")
}

/// Runs short, bounded file work off the async runtime and joins it.
pub(crate) async fn blocking<T: Send + 'static>(
    context: &str,
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, StrategyError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| StrategyError::failed(context, error))?
        .map_err(|error| StrategyError::Failed(format!("{context}: {error}")))
}

/// Fails unless `path` is a plain relative path inside staging.
pub(crate) fn require_relative(path: &Path, what: &str) -> Result<(), StrategyError> {
    let text = path
        .to_str()
        .ok_or_else(|| StrategyError::Failed(format!("{what} is not utf-8")))?;
    if is_safe_relative(text) {
        Ok(())
    } else {
        Err(StrategyError::Failed(format!(
            "{what} is not a safe relative path"
        )))
    }
}

/// Refuses staging that overlaps the instance data or socket directories.
pub(crate) fn refuse_overlapping_staging(
    paths: &InstancePaths,
    staging: &StagingArea,
) -> Result<(), StrategyError> {
    for (source, what) in [
        (&paths.sockets, "the instance socket mount"),
        (&paths.data, "the instance data directory"),
    ] {
        if overlaps(source, &staging.root).map_err(StrategyError::Failed)? {
            return Err(StrategyError::Failed(format!("staging overlaps {what}")));
        }
    }
    Ok(())
}

fn overlaps(left: &Path, right: &Path) -> Result<bool, String> {
    let left = std::fs::canonicalize(left)
        .map_err(|error| format!("canonicalize {}: {error}", left.display()))?;
    let right = std::fs::canonicalize(right)
        .map_err(|error| format!("canonicalize {}: {error}", right.display()))?;
    Ok(left.starts_with(&right) || right.starts_with(&left))
}

impl From<StrategyError> for ApiError {
    fn from(error: StrategyError) -> Self {
        match error {
            StrategyError::Unsupported(reason) => ApiError::Conflict(format!(
                "online backup is not supported for this instance: {reason}"
            )),
            StrategyError::Failed(reason) => {
                ApiError::Runtime(format!("online backup failed: {reason}"))
            }
        }
    }
}

/// Identity of the job and runtime generation a capture belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BackupJobIdentity {
    pub job_id: uuid::Uuid,
    pub instance_id: String,
    /// Container id plus process start timestamp. Resources bound to a server
    /// process (sessions, temporary slots, exec helpers) die with it.
    pub runtime_generation: String,
}

impl BackupJobIdentity {
    /// Stable job tag embedded in owned resource names, e.g.
    /// `dbev_bk_<32 hex>`. Fits PostgreSQL's 63-byte identifier limit.
    pub(crate) fn resource_tag(&self) -> String {
        format!("{OWNED_RESOURCE_PREFIX}{}", self.job_id.simple())
    }

    /// Returns true when `name` was minted for this job.
    pub(crate) fn owns_name(&self, name: &str) -> bool {
        name.starts_with(&self.resource_tag())
    }
}

/// Inputs shared by preflight, capture and verification.
pub(crate) struct OnlineBackupContext<'a> {
    pub state: &'a AppState,
    pub metadata: &'a InstanceMetadata,
    pub paths: &'a InstancePaths,
    pub job: &'a BackupJobIdentity,
    /// Absolute deadline for capture plus verification. Strategies pass the
    /// remaining time to commands; the coordinator enforces it as well.
    pub deadline: Instant,
}

impl OnlineBackupContext<'_> {
    pub(crate) fn remaining(&self) -> Result<Duration, StrategyError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| StrategyError::Failed("online backup deadline elapsed".to_string()))
    }

    // There is deliberately no exec into the serving container: an exec's
    // timeout does not terminate its processes. Server work runs in helpers.

    /// Immutable image id of the running instance, so helper binaries match
    /// the server exactly.
    pub(crate) async fn runtime_image(&self) -> Result<String, StrategyError> {
        self.state
            .docker
            .container_immutable_image_id(self.metadata.protocol, self.metadata.runtime_id())
            .await
            .map_err(|error| StrategyError::failed("inspect runtime image", error))?
            .ok_or_else(|| StrategyError::Failed("runtime image id is unavailable".to_string()))
    }

    /// Runs a helper container. Its name is journaled before the container
    /// exists and released only once removal is confirmed; an unconfirmed
    /// removal stays journaled for coordinator cleanup.
    pub(crate) async fn run_helper(
        &self,
        registrar: &dyn OwnedResourceRegistrar,
        spec: &BackupHelperSpec,
    ) -> Result<CommandOutput, StrategyError> {
        let resource = OwnedResource {
            kind: OwnedResourceKind::HelperContainer,
            name: spec.name.clone(),
            survives_restart: true,
        };
        registrar.register(&resource).await?;
        let result = self.state.docker.run_backup_helper(spec).await;
        let removed = result
            .as_ref()
            .err()
            .is_none_or(BackupHelperError::removal_confirmed);
        // A missed release is harmless: cleanup finds no container.
        if removed && let Err(error) = registrar.released(&resource).await {
            tracing::warn!(helper = spec.name, %error, "backup helper removal was not journaled");
        }
        result.map_err(|error| StrategyError::Failed(error.to_string()))
    }
}

/// Daemon-owned staging for one capture, outside the source quota.
#[derive(Debug, Clone)]
pub(crate) struct StagingArea {
    /// Private, empty directory owned by this job. Strategies write their
    /// native output below it.
    pub root: PathBuf,
    /// Bytes reserved for native output; never more than restore extracts.
    /// Helpers are removed once staging exceeds it.
    pub native_budget_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OwnedResourceKind {
    /// A database session identified by an owned `application_name` or
    /// client name.
    ServerSession,
    /// A replication slot. Temporary slots end with their session; persistent
    /// ones survive restarts and must be dropped explicitly.
    ReplicationSlot,
    /// A helper process inside the instance container, identified by an
    /// owned marker (pid file or argv tag).
    HelperProcess,
    /// A helper container named with the job tag. The coordinator removes
    /// these itself (force-remove, then confirm absence); strategies never
    /// clean them.
    HelperContainer,
    /// A filesystem or storage snapshot.
    Snapshot,
}

impl OwnedResourceKind {
    pub(crate) const ALL: [Self; 5] = [
        Self::ServerSession,
        Self::ReplicationSlot,
        Self::HelperProcess,
        Self::HelperContainer,
        Self::Snapshot,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ServerSession => "server_session",
            Self::ReplicationSlot => "replication_slot",
            Self::HelperProcess => "helper_process",
            Self::HelperContainer => "helper_container",
            Self::Snapshot => "snapshot",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }
}

/// A resource the job creates and must clean up. Names must contain
/// [`BackupJobIdentity::resource_tag`] so cleanup can prove ownership.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct OwnedResource {
    pub kind: OwnedResourceKind,
    pub name: String,
    /// True when the resource outlives the runtime generation that created
    /// it (persistent slot, snapshot, helper container).
    pub survives_restart: bool,
}

/// Durable journal of owned resources. `register` must complete before the
/// resource is created; a crash afterwards leaves enough state for recovery
/// to clean it up.
pub(crate) trait OwnedResourceRegistrar: Send + Sync {
    fn register<'a>(
        &'a self,
        resource: &'a OwnedResource,
    ) -> BoxFuture<'a, Result<(), StrategyError>>;

    /// Records that the strategy released the resource itself.
    fn released<'a>(
        &'a self,
        resource: &'a OwnedResource,
    ) -> BoxFuture<'a, Result<(), StrategyError>>;
}

/// What a successful capture produced inside [`StagingArea::root`].
///
/// Everything here is recorded in the schema 2 manifest, which bounds it:
/// map keys and check names are lowercase identifiers (`[a-z0-9_.-]`, at most
/// 64 bytes), values are control-free text of at most 512 bytes, and lists
/// hold at most 64 entries. Paths are plain relative paths.
#[derive(Debug, Clone)]
pub(crate) struct CaptureResult {
    /// Directory (relative to the staging root) holding the recovered data
    /// tree. The coordinator packages exactly this tree.
    pub data_root: PathBuf,
    /// Where `data_root` belongs inside the instance data volume on restore
    /// (relative, e.g. `pgdata`).
    pub restore_target: PathBuf,
    pub consistency: ConsistencyLevel,
    pub recovery: RecoveryCoordinates,
    pub engine_version: Option<String>,
    /// Tool name -> exact version string, e.g. `pg_basebackup` -> `16.4`.
    pub tool_versions: BTreeMap<String, String>,
    /// Content intentionally excluded (e.g. `unlogged relation contents`).
    pub exclusions: Vec<String>,
    /// Optional native manifest (relative to the staging root), e.g.
    /// `pg/backup_manifest`. The coordinator records its checksum.
    pub native_manifest: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerificationCheck {
    /// Stable check name, e.g. `pg_verifybackup`.
    pub check: String,
    pub passed: bool,
    pub detail: Option<String>,
}

/// Context for cleaning a resource left by an interrupted job. Read by
/// strategies that own server-side resources (sessions, slots); the shipped
/// PostgreSQL strategy owns only helper containers, which the coordinator
/// removes itself.
#[allow(dead_code)]
pub(crate) struct CleanupContext<'a> {
    pub state: &'a AppState,
    pub metadata: &'a InstanceMetadata,
    pub job: &'a BackupJobIdentity,
    /// Whether the runtime still runs the generation recorded by the job.
    /// When false, generation-bound resources are already gone.
    pub generation_matches: bool,
}

/// Context for preparing an extracted capture before it is installed.
pub(crate) struct RestoreContext<'a> {
    pub recipe: &'a RestoreRecipeRef,
    /// Extracted, writable, data-volume-shaped staging tree. It replaces the
    /// instance data directory after preparation and startup validation.
    pub extracted_root: &'a Path,
    /// Where the captured `data_root` sits inside `extracted_root`
    /// (the manifest's `restore_target`, e.g. `pgdata`).
    pub restore_target: &'a Path,
}

impl RestoreContext<'_> {
    /// Refuses any recipe but `id@version` before the extracted tree is
    /// touched.
    pub(crate) fn require_recipe(&self, id: &str, version: u32) -> Result<(), StrategyError> {
        if self.recipe.id != id || self.recipe.version != version {
            return Err(StrategyError::Unsupported(format!(
                "recipe {}@{} is not {id}@{version}",
                self.recipe.id, self.recipe.version
            )));
        }
        Ok(())
    }
}

/// Reads a helper's report from staging and removes it, so staging holds only
/// the capture afterwards. Helper stdout is redacted and truncated; reports
/// must be neither.
pub(crate) async fn take_report(path: PathBuf, max_bytes: u64) -> Result<String, StrategyError> {
    blocking("read helper report", move || {
        let read = crate::io::files::read_bounded_private_file(&path, max_bytes);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("remove the report: {error}")),
        }
        String::from_utf8(read.map_err(|error| error.to_string())?)
            .map_err(|_| "the report is not UTF-8".to_string())
    })
    .await
}

pub(crate) trait OnlineBackupStrategy: Send + Sync {
    /// Stable strategy id recorded in manifests, e.g. `postgres.pg_basebackup`.
    fn id(&self) -> &'static str;

    /// Recipe written into manifests produced by this strategy.
    fn restore_recipe(&self) -> RestoreRecipeRef;

    /// Recipe versions this build can restore (always includes the current
    /// one). Older versions stay listed only while their restore path exists.
    fn restorable_recipe_versions(&self) -> &'static [u32];

    /// Cheap, side-effect-free eligibility check: credentials, versions,
    /// layout, tablespaces, free space. Returns `Unsupported` for anything the
    /// strategy cannot capture *and* recover.
    fn preflight<'a>(
        &'a self,
        ctx: &'a OnlineBackupContext<'a>,
    ) -> BoxFuture<'a, Result<(), StrategyError>>;

    /// Captures the running database into `staging`. Every server-side or
    /// helper resource must be registered before it is created and released
    /// (or left for `cleanup_owned`) afterwards.
    fn capture<'a>(
        &'a self,
        ctx: &'a OnlineBackupContext<'a>,
        staging: &'a StagingArea,
        registrar: &'a dyn OwnedResourceRegistrar,
    ) -> BoxFuture<'a, Result<CaptureResult, StrategyError>>;

    /// Runs native verification against the final staged capture. Any failed
    /// check fails the backup. Helpers it starts follow the capture rules.
    fn verify<'a>(
        &'a self,
        ctx: &'a OnlineBackupContext<'a>,
        staging: &'a StagingArea,
        capture: &'a CaptureResult,
        registrar: &'a dyn OwnedResourceRegistrar,
    ) -> BoxFuture<'a, Result<Vec<VerificationCheck>, StrategyError>>;

    /// Removes one resource previously registered by this strategy. Must be
    /// idempotent and must touch only the named resource. Default: the
    /// strategy owns only helper containers, which the coordinator removes
    /// itself, so anything else is refused.
    fn cleanup_owned<'a>(
        &'a self,
        _ctx: &'a CleanupContext<'a>,
        resource: &'a OwnedResource,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async move {
            Err(StrategyError::Failed(format!(
                "refusing to clean {} {}; this strategy owns only helper containers",
                resource.kind.as_str(),
                resource.name
            )))
        })
    }

    /// Turns an extracted capture into a data tree the runtime can start from
    /// (e.g. recovery signal files, ownership). Default: not restorable.
    fn prepare_restore<'a>(
        &'a self,
        _ctx: &'a RestoreContext<'a>,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async {
            Err(StrategyError::Unsupported(
                "this strategy has no restore recipe in this build".to_string(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_tags_are_job_scoped_and_fit_identifier_limits() {
        let job = BackupJobIdentity {
            job_id: uuid::Uuid::new_v4(),
            instance_id: "inst_one".to_string(),
            runtime_generation: "abc@2026-01-01T00:00:00Z".to_string(),
        };
        let tag = job.resource_tag();
        assert!(tag.len() < 63);
        assert!(job.owns_name(&format!("{tag}_slot")));
        let other = BackupJobIdentity {
            job_id: uuid::Uuid::new_v4(),
            ..job.clone()
        };
        assert!(!other.owns_name(&format!("{tag}_slot")));
        assert!(!job.owns_name(OWNED_RESOURCE_PREFIX));
    }

    #[test]
    fn unsupported_maps_to_a_clear_conflict() {
        let error: ApiError =
            StrategyError::Unsupported("no certified strategy".to_string()).into();
        assert!(
            matches!(error, ApiError::Conflict(message) if message.contains("no certified strategy"))
        );
    }
}
