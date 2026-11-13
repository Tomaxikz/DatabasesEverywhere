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

pub(crate) const OWNED_RESOURCE_PREFIX: &str = "dbev_bk_";

#[derive(Debug, thiserror::Error)]
pub(crate) enum StrategyError {
    #[error("online backup is not supported: {0}")]
    Unsupported(String),
    #[error("online backup failed: {0}")]
    Failed(String),
}

impl StrategyError {
    pub(crate) fn failed(context: &str, error: impl std::fmt::Display) -> Self {
        Self::Failed(format!("{context}: {error}"))
    }

    pub(crate) fn for_tool(self, tool: &str) -> Self {
        match self {
            Self::Failed(reason) => Self::Failed(format!("{tool}: {reason}")),
            unsupported => unsupported,
        }
    }
}

pub(crate) fn exec_script(argv: &[String]) -> String {
    let argv = argv
        .iter()
        .map(|arg| sh_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    format!("set -eu\numask 077\nexec {argv}\n")
}

pub(crate) async fn blocking<T: Send + 'static>(
    context: &str,
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, StrategyError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| StrategyError::failed(context, error))?
        .map_err(|error| StrategyError::Failed(format!("{context}: {error}")))
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BackupJobIdentity {
    pub job_id: uuid::Uuid,
    pub instance_id: String,
    pub runtime_generation: String,
}

impl BackupJobIdentity {
    pub(crate) fn resource_tag(&self) -> String {
        format!("{OWNED_RESOURCE_PREFIX}{}", self.job_id.simple())
    }

    pub(crate) fn owns_name(&self, name: &str) -> bool {
        name.starts_with(&self.resource_tag())
    }
}

pub(crate) struct OnlineBackupContext<'a> {
    pub state: &'a AppState,
    pub metadata: &'a InstanceMetadata,
    pub paths: &'a InstancePaths,
    pub job: &'a BackupJobIdentity,
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

    pub(crate) async fn runtime_image(&self) -> Result<String, StrategyError> {
        self.state
            .docker
            .container_immutable_image_id(self.metadata.protocol, self.metadata.runtime_id())
            .await
            .map_err(|error| StrategyError::failed("inspect runtime image", error))?
            .ok_or_else(|| StrategyError::Failed("runtime image id is unavailable".to_string()))
    }

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
        if removed && let Err(error) = registrar.released(&resource).await {
            tracing::warn!(helper = spec.name, %error, "backup helper removal was not journaled");
        }
        result.map_err(|error| StrategyError::Failed(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StagingArea {
    pub root: PathBuf,
    /// never more than restore extracts.
    pub native_budget_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OwnedResourceKind {
    ServerSession,
    ReplicationSlot,
    HelperProcess,
    /// strategies never clean them.
    HelperContainer,
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct OwnedResource {
    pub kind: OwnedResourceKind,
    pub name: String,
    pub survives_restart: bool,
}

/// a crash afterwards leaves enough state for recovery to clean it up.
pub(crate) trait OwnedResourceRegistrar: Send + Sync {
    fn register<'a>(
        &'a self,
        resource: &'a OwnedResource,
    ) -> BoxFuture<'a, Result<(), StrategyError>>;

    fn released<'a>(
        &'a self,
        resource: &'a OwnedResource,
    ) -> BoxFuture<'a, Result<(), StrategyError>>;
}

#[derive(Debug, Clone)]
pub(crate) struct CaptureResult {
    pub data_root: PathBuf,
    pub restore_target: PathBuf,
    pub consistency: ConsistencyLevel,
    pub recovery: RecoveryCoordinates,
    pub engine_version: Option<String>,
    pub tool_versions: BTreeMap<String, String>,
    /// Content intentionally excluded.
    pub exclusions: Vec<String>,
    pub native_manifest: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerificationCheck {
    pub check: String,
    pub passed: bool,
    pub detail: Option<String>,
}

#[allow(dead_code)]
pub(crate) struct CleanupContext<'a> {
    pub state: &'a AppState,
    pub metadata: &'a InstanceMetadata,
    pub job: &'a BackupJobIdentity,
    pub generation_matches: bool,
}

pub(crate) struct RestoreContext<'a> {
    pub recipe: &'a RestoreRecipeRef,
    pub extracted_root: &'a Path,
    pub restore_target: &'a Path,
}

impl RestoreContext<'_> {
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

/// The extracted root must hold only `target`, and the capture must not contain it.
pub(crate) fn lift_restore_tree(
    extracted_root: &Path,
    target: &str,
    check: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let names = entry_names(extracted_root)?;
    if names != [target] {
        return Err(format!(
            "the extracted backup must hold only {target}, found {names:?}"
        ));
    }
    let tree = extracted_root.join(target);
    check(&tree)?;
    let entries = entry_names(&tree)?;
    if entries.iter().any(|name| name == target) {
        return Err(format!("the backup itself contains {target}"));
    }
    for name in entries {
        let entry = tree.join(&name);
        std::fs::rename(&entry, extracted_root.join(&name))
            .map_err(|error| format!("install {}: {error}", entry.display()))?;
    }
    std::fs::remove_dir(&tree).map_err(|error| format!("remove {}: {error}", tree.display()))
}

fn entry_names(directory: &Path) -> Result<Vec<String>, String> {
    let mut names = std::fs::read_dir(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(|error| format!("{}: {error}", directory.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names)
}

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
    fn id(&self) -> &'static str;

    fn restore_recipe(&self) -> RestoreRecipeRef;

    fn restorable_recipe_versions(&self) -> &'static [u32];

    fn preflight<'a>(
        &'a self,
        ctx: &'a OnlineBackupContext<'a>,
    ) -> BoxFuture<'a, Result<(), StrategyError>>;

    fn capture<'a>(
        &'a self,
        ctx: &'a OnlineBackupContext<'a>,
        staging: &'a StagingArea,
        registrar: &'a dyn OwnedResourceRegistrar,
    ) -> BoxFuture<'a, Result<CaptureResult, StrategyError>>;

    fn verify<'a>(
        &'a self,
        ctx: &'a OnlineBackupContext<'a>,
        staging: &'a StagingArea,
        capture: &'a CaptureResult,
        registrar: &'a dyn OwnedResourceRegistrar,
    ) -> BoxFuture<'a, Result<Vec<VerificationCheck>, StrategyError>>;

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

    fn restore_kind(&self) -> RestoreKind {
        RestoreKind::DataDirectory
    }

    fn restore_after_start<'a>(
        &'a self,
        _ctx: &'a AfterStartRestoreContext<'a>,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async {
            Err(StrategyError::Unsupported(
                "this strategy has no after-start restore in this build".to_string(),
            ))
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreKind {
    DataDirectory,
    AfterStart,
}

pub(crate) struct AfterStartRestoreContext<'a> {
    pub state: &'a AppState,
    pub metadata: &'a InstanceMetadata,
    pub recipe: &'a RestoreRecipeRef,
    pub payload: &'a Path,
}

impl AfterStartRestoreContext<'_> {
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
}
