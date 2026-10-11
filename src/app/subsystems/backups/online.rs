//! Durable online backup coordinator.
//!
//! Each capture is journaled in `backup_jobs` before anything is created and
//! advances `admitted -> capturing -> captured -> validated -> published`.
//! Owned server-side and helper resources are journaled by the strategy before
//! creation; on failure, timeout or daemon restart only those resources, in
//! the matching runtime generation, are cleaned up. The serving database is
//! never stopped, frozen or restarted by this path.
//!
//! The caller holds the instance management lock from admission through
//! [`capture_online`] (capture, native verification, packaging and structural
//! validation) and releases it before publication; [`finish_publication`]
//! then records the outcome.
//!
//! Admission applies the persisted backend's physical restore-layout gate,
//! and the native budget equals what restore extracts, so every published
//! capture is restorable by the existing path. Native tools run in helper
//! containers; staging and its reservation are released only after every
//! helper is confirmed gone.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use futures::future::BoxFuture;

use super::{
    recovery::cleanup_job_resources,
    strategy::{
        BackupJobIdentity, CaptureResult, OnlineBackupContext, OnlineBackupStrategy, OwnedResource,
        OwnedResourceKind, OwnedResourceRegistrar, StagingArea, StrategyError, VerificationCheck,
    },
};
use crate::{
    routes::http::{response::ApiError, router::AppState},
    server::{
        backup::{
            BackupBundle, BackupLayout,
            manifest::{
                ArtifactFormat, BackupMethod, BackupScope, CaptureInterval, EngineRecord,
                FileChecksum, ManifestDetails, ValidationRecord, is_safe_relative,
            },
            sha256_file,
        },
        disk::capacity::DiskCapacityReservation,
        jobs::import_export::{
            DATA_ARCHIVE_ENTRY_DISK_OVERHEAD_BYTES, MAX_DATA_ARCHIVE_ENTRIES, StagedDataArchive,
            now_rfc3339,
        },
        metadata::InstanceMetadata,
        paths::InstancePaths,
    },
    storage::backup_jobs::{
        BackupJobRecord, BackupJobRepository, BackupJobState, BackupResourceRecord,
    },
    utils::time::now_unix,
};

const ARCHIVE_STRUCTURE_CHECK: &str = "archive_structure";
/// Strategies enforce the deadline themselves; past it the coordinator waits
/// this long for their helpers to be removed before abandoning the work.
const DEADLINE_GRACE: Duration = Duration::from_secs(3 * 60);
const HELPER_RETRY_DELAY: Duration = Duration::from_secs(60);

/// A capture that passed native verification and structural validation and
/// is packaged at `bundle.archive`, ready for manifest construction.
pub(super) struct ValidatedCapture {
    pub job_id: String,
    pub details: ManifestDetails,
}

/// Bytes needed in staging: native output plus the packaged archive.
pub(super) fn staging_budget(native_bytes: u64, archive_bytes: u64) -> u64 {
    native_bytes.saturating_add(archive_bytes)
}

/// Limits of one online capture. `native_budget_bytes` is what restore
/// extracts into the instance; nothing larger is published.
pub(super) struct CaptureBudget {
    pub native_budget_bytes: u64,
    pub max_archive_bytes: u64,
}

pub(super) async fn capture_online(
    state: &AppState,
    metadata: &InstanceMetadata,
    strategy: &'static dyn OnlineBackupStrategy,
    bundle: &BackupBundle,
    backup_id: &str,
    budget: CaptureBudget,
    // Staging reservation. Kept past a failure while a helper may still exist.
    reservation: &mut Option<DiskCapacityReservation>,
) -> Result<ValidatedCapture, ApiError> {
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    // Phase 1 is limited to layouts the existing physical restore accepts.
    crate::subsystems::import_export::check_restore_layout(state, metadata, &paths).map_err(
        |error| {
            ApiError::from(StrategyError::Unsupported(format!(
                "the instance storage layout cannot be restored physically, so an online capture would be unrestorable: {error}"
            )))
        },
    )?;
    let job_id = uuid::Uuid::new_v4();
    let capture_root = capture_root_for(bundle, job_id)?;
    ensure_outside_source(&paths.data, &capture_root).await?;
    let generation = runtime_generation(state, metadata).await?;
    let identity = BackupJobIdentity {
        job_id,
        instance_id: metadata.instance_id.clone(),
        runtime_generation: generation,
    };
    let deadline = Instant::now()
        + Duration::from_secs(
            state
                .config
                .backups
                .online_timeout_minutes
                .saturating_mul(60),
        );
    let ctx = OnlineBackupContext {
        state,
        metadata,
        paths: &paths,
        job: &identity,
        deadline,
    };
    // Preflight is side-effect free: what can be rejected without a server
    // session fails before any journal entry, staging or server resource
    // exists. Inventory that needs sessions runs during capture, in helpers.
    strategy.preflight(&ctx).await.map_err(ApiError::from)?;
    let recipe = strategy.restore_recipe();
    if !strategy
        .restorable_recipe_versions()
        .contains(&recipe.version)
    {
        return Err(ApiError::Runtime(format!(
            "{} cannot restore its own recipe version {}",
            strategy.id(),
            recipe.version
        )));
    }

    let image = EngineRecord {
        version: None,
        image: state
            .docker
            .container_image(metadata.protocol, metadata.runtime_id())
            .await
            .ok()
            .flatten(),
        image_digest: state
            .docker
            .container_immutable_image_id(metadata.protocol, metadata.runtime_id())
            .await
            .ok()
            .flatten(),
    };
    let repository = &state.backup_jobs;
    let now = now_rfc3339();
    repository
        .admit(&BackupJobRecord {
            job_id: job_id.to_string(),
            instance_id: metadata.instance_id.clone(),
            backup_id: backup_id.to_string(),
            strategy: strategy.id().to_string(),
            runtime_generation: identity.runtime_generation.clone(),
            source_identity: serde_json::json!({
                "protocol": metadata.protocol.as_str(),
                "runtime_id": metadata.runtime_id(),
                "container": metadata.runtime.container_name,
                "image": image.image,
                "image_digest": image.image_digest,
            })
            .to_string(),
            staging_path: capture_root.display().to_string(),
            state: BackupJobState::Admitted,
            error: None,
            created_at: now.clone(),
            updated_at: now,
        })
        .await
        .map_err(journal_error)?;

    let staging = StagingArea {
        root: capture_root,
        native_budget_bytes: budget.native_budget_bytes,
    };
    let job = Job {
        state,
        metadata,
        strategy,
        identity: &identity,
        repository,
        staging: &staging,
    };
    match job
        .run(&ctx, bundle, &paths, image, budget.max_archive_bytes)
        .await
    {
        Ok(details) => Ok(ValidatedCapture {
            job_id: job_id.to_string(),
            details,
        }),
        Err(error) => Err(job.fail(error, reservation).await),
    }
}

/// Records the publication outcome after the management lock was released.
/// A failure whose uploaded objects could not be removed stays
/// `cleanup_pending` until recovery removes them.
pub(super) async fn finish_publication(
    state: &AppState,
    job_id: &str,
    published: Result<(), &ApiError>,
    cleanup_pending: bool,
) {
    let (to, error) = match published {
        Ok(()) => (BackupJobState::Published, None),
        Err(error) if cleanup_pending => (BackupJobState::CleanupPending, Some(error.to_string())),
        Err(error) => (BackupJobState::Failed, Some(error.to_string())),
    };
    if let Err(journal) = state
        .backup_jobs
        .transition(job_id, to, error.as_deref(), &now_rfc3339())
        .await
    {
        tracing::warn!(job_id, %journal, "could not record online backup publication outcome");
    }
    if let Err(error) = state.backup_jobs.prune_terminal().await {
        tracing::warn!(%error, "could not prune finished backup jobs");
    }
}

struct Job<'a> {
    state: &'a AppState,
    metadata: &'a InstanceMetadata,
    strategy: &'static dyn OnlineBackupStrategy,
    identity: &'a BackupJobIdentity,
    repository: &'a BackupJobRepository,
    staging: &'a StagingArea,
}

impl Job<'_> {
    async fn run(
        &self,
        ctx: &OnlineBackupContext<'_>,
        bundle: &BackupBundle,
        paths: &InstancePaths,
        mut engine: EngineRecord,
        max_archive_bytes: u64,
    ) -> Result<ManifestDetails, ApiError> {
        crate::server::backup::prepare_private_dir(&self.staging.root, "online backup staging")
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        // Rootless Podman resolves bind-mount sources as its own account,
        // which must traverse the daemon-owned staging ancestors.
        if let Some(owner) = self.state.docker.rootless_podman_host_owner() {
            let backups_root = PathBuf::from(self.state.config.paths.backups_root());
            crate::server::backup::allow_staging_traversal(
                &backups_root,
                &self.staging.root,
                owner,
            )
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        }
        self.advance(BackupJobState::Capturing).await?;
        let started_at_unix = now_unix();
        let registrar = JournalRegistrar {
            repository: self.repository,
            job: self.identity,
        };
        let capture = bounded(
            ctx,
            "capture",
            self.strategy.capture(ctx, self.staging, &registrar),
        )
        .await?;
        let finished_at_unix = now_unix();
        self.advance(BackupJobState::Captured).await?;
        // A strategy may leave cleanup to the coordinator; nothing it owns
        // may outlive the capture.
        self.release_leftovers().await?;

        let checks = bounded(
            ctx,
            "verification",
            self.strategy
                .verify(ctx, self.staging, &capture, &registrar),
        )
        .await?;
        self.release_leftovers().await?;
        if let Some(failed) = checks.iter().find(|check| !check.passed) {
            return Err(ApiError::Runtime(format!(
                "online backup verification {} failed: {}",
                failed.check,
                failed.detail.as_deref().unwrap_or("no detail")
            )));
        }
        let (data_root, restore_target) = capture_paths(&self.staging.root, &capture)?;
        let checksums = native_manifest_checksum(&self.staging.root, &capture).await?;
        package_capture(
            paths,
            &data_root,
            &restore_target,
            &bundle.archive,
            max_archive_bytes,
        )
        .await?;
        let (structure, expanded_bytes) = validate_archive_structure(
            paths,
            &restore_target,
            &bundle.archive,
            self.staging.native_budget_bytes,
        )
        .await?;
        remove_staging(&self.staging.root).await;

        engine.version = capture.engine_version.clone();
        let mut details = online_details(
            self.strategy,
            capture,
            CaptureInterval {
                started_at_unix,
                finished_at_unix,
            },
            engine,
            &restore_target,
            checksums,
            checks.into_iter().chain([structure]).collect(),
        );
        details.expanded_bytes = Some(expanded_bytes);
        details
            .validate(BackupLayout::Physical)
            .map_err(|error| ApiError::Runtime(format!("online backup manifest: {error}")))?;
        self.advance(BackupJobState::Validated).await?;
        Ok(details)
    }

    async fn advance(&self, to: BackupJobState) -> Result<(), ApiError> {
        self.repository
            .transition(&self.identity.job_id.to_string(), to, None, &now_rfc3339())
            .await
            .map_err(journal_error)
    }

    async fn release_leftovers(&self) -> Result<(), ApiError> {
        let remaining = cleanup_job_resources(
            self.state,
            Some(self.metadata),
            self.strategy,
            self.identity,
            true,
        )
        .await?;
        if remaining.is_empty() {
            Ok(())
        } else {
            Err(ApiError::Runtime(format!(
                "online backup could not release {} owned resource(s)",
                remaining.len()
            )))
        }
    }

    /// Cleans up after a failed attempt and records the terminal state. The
    /// primary error is preserved; cleanup failures are appended. Staging is
    /// removed only once no owned resource remains; while a helper may still
    /// exist, its staging reservation stays held.
    async fn fail(
        &self,
        error: ApiError,
        reservation: &mut Option<DiskCapacityReservation>,
    ) -> ApiError {
        let job_id = self.identity.job_id.to_string();
        let generation_matches = runtime_generation(self.state, self.metadata)
            .await
            .is_ok_and(|current| current == self.identity.runtime_generation);
        let remaining = cleanup_job_resources(
            self.state,
            Some(self.metadata),
            self.strategy,
            self.identity,
            generation_matches,
        )
        .await;
        match &remaining {
            Ok(remaining) if remaining.is_empty() => remove_staging(&self.staging.root).await,
            Ok(remaining) => {
                let helpers: Vec<String> = remaining
                    .iter()
                    .filter(|record| {
                        OwnedResourceKind::parse(&record.kind)
                            == Some(OwnedResourceKind::HelperContainer)
                    })
                    .map(|record| record.name.clone())
                    .collect();
                if !helpers.is_empty()
                    && let Some(held) = reservation.take()
                {
                    hold_until_helpers_removed(self.state.clone(), helpers, held);
                }
            }
            // The journal itself failed; keep staging for recovery.
            Err(_) => {}
        }
        let (to, error) = match remaining {
            Ok(remaining) if remaining.is_empty() => (BackupJobState::Failed, error),
            Ok(remaining) => (
                BackupJobState::CleanupPending,
                append_error(
                    error,
                    &format!(
                        "{} owned resource(s) await cleanup by a later backup or daemon restart",
                        remaining.len()
                    ),
                ),
            ),
            Err(cleanup) => (
                BackupJobState::CleanupPending,
                append_error(error, &format!("cleanup failed: {cleanup}")),
            ),
        };
        if let Err(journal) = self
            .repository
            .transition(&job_id, to, Some(&error.to_string()), &now_rfc3339())
            .await
        {
            tracing::error!(job_id, %journal, "could not record failed online backup job");
        }
        tracing::warn!(
            event = "audit online_backup_failed",
            instance_id = self.metadata.instance_id,
            job_id,
            strategy = self.strategy.id(),
            state = to.as_str(),
            %error,
        );
        error
    }
}

pub(super) struct JournalRegistrar<'a> {
    pub(super) repository: &'a BackupJobRepository,
    pub(super) job: &'a BackupJobIdentity,
}

impl OwnedResourceRegistrar for JournalRegistrar<'_> {
    fn register<'a>(
        &'a self,
        resource: &'a OwnedResource,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async move {
            if !self.job.owns_name(&resource.name) {
                return Err(StrategyError::Failed(format!(
                    "owned resource {} does not carry the job tag",
                    resource.name
                )));
            }
            self.repository
                .register_resource(
                    &self.job.job_id.to_string(),
                    &BackupResourceRecord {
                        kind: resource.kind.as_str().to_string(),
                        name: resource.name.clone(),
                        survives_restart: resource.survives_restart,
                    },
                    &now_rfc3339(),
                )
                .await
                .map_err(|error| StrategyError::failed("journal owned resource", error))
        })
    }

    fn released<'a>(
        &'a self,
        resource: &'a OwnedResource,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async move {
            self.repository
                .release_resource(
                    &self.job.job_id.to_string(),
                    resource.kind.as_str(),
                    &resource.name,
                )
                .await
                .map_err(|error| StrategyError::failed("journal released resource", error))
        })
    }
}

/// Strategies stop their own helpers at the deadline and return once removal
/// is confirmed. Only work that overruns the grace period is dropped; its
/// helper supervisors keep running and owned cleanup waits for them before
/// anything is released.
async fn bounded<T>(
    ctx: &OnlineBackupContext<'_>,
    phase: &str,
    work: BoxFuture<'_, Result<T, StrategyError>>,
) -> Result<T, ApiError> {
    let remaining = ctx.remaining().map_err(ApiError::from)?;
    match tokio::time::timeout(remaining.saturating_add(DEADLINE_GRACE), work).await {
        Ok(result) => result.map_err(ApiError::from),
        Err(_) => Err(ApiError::Runtime(format!(
            "online backup {phase} exceeded its deadline; the backup was abandoned and the database kept running"
        ))),
    }
}

/// Retries removal of helpers whose removal could not be confirmed and only
/// then releases their staging reservation. Journal recovery removes the
/// staging itself after the same confirmation.
fn hold_until_helpers_removed(
    state: AppState,
    helpers: Vec<String>,
    reservation: DiskCapacityReservation,
) {
    tokio::spawn(async move {
        let _reservation = reservation;
        let mut pending = helpers;
        loop {
            let mut still_pending = Vec::new();
            for name in pending {
                if let Err(error) = state.docker.remove_backup_helper(&name).await {
                    tracing::warn!(helper = name, %error,
                        "backup helper removal is unconfirmed; its staging reservation stays held");
                    still_pending.push(name);
                }
            }
            if still_pending.is_empty() {
                return;
            }
            pending = still_pending;
            tokio::time::sleep(HELPER_RETRY_DELAY).await;
        }
    });
}

pub(super) async fn runtime_generation(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<String, ApiError> {
    let identity = state
        .docker
        .verified_container_identity(metadata.protocol, metadata.runtime_id())
        .await
        .map_err(|error| ApiError::Runtime(format!("inspect backup source runtime: {error}")))?
        .ok_or_else(|| ApiError::Conflict("backup source container does not exist".to_string()))?;
    Ok(format!("{}@{}", identity.id, identity.started_at))
}

/// Capture staging is a sibling of the bundle directory so storage drivers
/// that snapshot the bundle (Kopia) never see raw native output.
fn capture_root_for(bundle: &BackupBundle, job_id: uuid::Uuid) -> Result<PathBuf, ApiError> {
    let parent = bundle
        .directory
        .parent()
        .ok_or_else(|| ApiError::Runtime("backup bundle directory has no parent".to_string()))?;
    Ok(parent.join(format!(".{}.capture", job_id.simple())))
}

/// Staging must not live inside the source data directory, where it would
/// consume the database's own disk quota.
async fn ensure_outside_source(data: &Path, capture_root: &Path) -> Result<(), ApiError> {
    let staging_parent = capture_root
        .parent()
        .ok_or_else(|| ApiError::Runtime("backup staging has no parent".to_string()))?;
    let canonical = |path: PathBuf| async move {
        tokio::fs::canonicalize(&path)
            .await
            .map_err(|error| ApiError::Runtime(format!("resolve {}: {error}", path.display())))
    };
    let data = canonical(data.to_path_buf()).await?;
    let staging = canonical(staging_parent.to_path_buf()).await?;
    if staging.starts_with(&data) || data.starts_with(&staging) {
        return Err(ApiError::Conflict(
            "backup staging overlaps the instance data directory; configure paths.backups outside the database volume".to_string(),
        ));
    }
    Ok(())
}

fn capture_paths(
    staging_root: &Path,
    capture: &CaptureResult,
) -> Result<(PathBuf, String), ApiError> {
    let data_root = capture
        .data_root
        .to_str()
        .filter(|path| is_safe_relative(path));
    let restore_target = capture
        .restore_target
        .to_str()
        .filter(|path| is_safe_relative(path));
    match (data_root, restore_target) {
        (Some(data_root), Some(restore_target)) => {
            Ok((staging_root.join(data_root), restore_target.to_string()))
        }
        _ => Err(ApiError::Runtime(
            "online backup strategy returned unsafe capture paths".to_string(),
        )),
    }
}

async fn native_manifest_checksum(
    staging_root: &Path,
    capture: &CaptureResult,
) -> Result<Vec<FileChecksum>, ApiError> {
    let Some(relative) = capture.native_manifest.as_deref() else {
        return Ok(Vec::new());
    };
    let relative = relative
        .to_str()
        .filter(|path| is_safe_relative(path))
        .ok_or_else(|| ApiError::Runtime("native manifest path is unsafe".to_string()))?;
    let path = staging_root.join(relative);
    let size_bytes = tokio::fs::symlink_metadata(&path)
        .await
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.len())
        .ok_or_else(|| ApiError::Runtime("native backup manifest is missing".to_string()))?;
    let sha256 = sha256_file(&path)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(vec![FileChecksum {
        path: relative.to_string(),
        size_bytes,
        sha256,
    }])
}

async fn package_capture(
    paths: &InstancePaths,
    data_root: &Path,
    restore_target: &str,
    archive: &Path,
    max_archive_bytes: u64,
) -> Result<(), ApiError> {
    let root_name = data_directory_name(paths)?;
    let data_root = data_root.to_path_buf();
    let restore_target = PathBuf::from(restore_target);
    let archive = archive.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut packaged =
            StagedDataArchive::create(&root_name, &data_root, &archive, max_archive_bytes)?;
        packaged.append_directory_chain(&restore_target, &data_root)?;
        packaged.append_tree(&data_root, &restore_target)?;
        packaged.finish()
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("online backup packaging failed: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("online backup packaging failed: {error}")))
}

/// Re-reads the packaged archive: every entry must sit below the data
/// directory root, the restore target must be present, and the archive must
/// fit what restore extracts, using restore's own accounting (entry size plus
/// a per-entry allowance, and its entry limit). Returns that expansion.
async fn validate_archive_structure(
    paths: &InstancePaths,
    restore_target: &str,
    archive: &Path,
    restore_capacity: u64,
) -> Result<(VerificationCheck, u64), ApiError> {
    let root = PathBuf::from(data_directory_name(paths)?);
    let target = root.join(restore_target);
    let archive = archive.to_path_buf();
    let (entries, expanded) = tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&archive)?;
        let mut reader = tar::Archive::new(flate2::read::GzDecoder::new(file));
        let invalid = |reason: String| std::io::Error::new(std::io::ErrorKind::InvalidData, reason);
        let mut entries = 0_usize;
        let mut expanded = 0_u64;
        let mut found_target = false;
        for entry in reader.entries()? {
            let entry = entry?;
            let path = entry.path()?.into_owned();
            entries += 1;
            if !path.starts_with(&root) {
                return Err(invalid(format!(
                    "unexpected archive entry {}",
                    path.display()
                )));
            }
            expanded = expanded
                .saturating_add(entry.header().size()?)
                .saturating_add(DATA_ARCHIVE_ENTRY_DISK_OVERHEAD_BYTES);
            found_target |= path == target;
        }
        if !found_target {
            return Err(invalid("archive is missing its restore target".to_string()));
        }
        Ok((entries, expanded))
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("archive validation task failed: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("online backup archive is invalid: {error}")))?;
    check_restorable(entries, expanded, restore_capacity)?;
    Ok((
        VerificationCheck {
            check: ARCHIVE_STRUCTURE_CHECK.to_string(),
            passed: true,
            detail: Some(format!(
                "{entries} entries expanding to {expanded} of {restore_capacity} restorable bytes"
            )),
        },
        expanded,
    ))
}

/// Rejects a capture the existing restore path would refuse to extract.
fn check_restorable(entries: usize, expanded: u64, restore_capacity: u64) -> Result<(), ApiError> {
    if entries > MAX_DATA_ARCHIVE_ENTRIES {
        return Err(ApiError::Runtime(format!(
            "online backup has {entries} archive entries; restore extracts at most {MAX_DATA_ARCHIVE_ENTRIES}, so it was not published"
        )));
    }
    if expanded > restore_capacity {
        return Err(ApiError::Runtime(format!(
            "online backup expands to {expanded} bytes; restore into this instance extracts at most {restore_capacity} bytes, so it was not published"
        )));
    }
    Ok(())
}

fn data_directory_name(paths: &InstancePaths) -> Result<String, ApiError> {
    paths
        .data
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| ApiError::Runtime("invalid instance data path".to_string()))
}

fn online_details(
    strategy: &dyn OnlineBackupStrategy,
    capture: CaptureResult,
    interval: CaptureInterval,
    engine: EngineRecord,
    restore_target: &str,
    checksums: Vec<FileChecksum>,
    checks: Vec<VerificationCheck>,
) -> ManifestDetails {
    ManifestDetails {
        format: ArtifactFormat::OnlineCapture,
        method: BackupMethod::OnlineStrategy,
        strategy: Some(strategy.id().to_string()),
        scope: BackupScope::DedicatedRuntime,
        restore_recipe: strategy.restore_recipe(),
        consistency: capture.consistency,
        capture: interval,
        recovery: capture.recovery,
        engine,
        tool_versions: capture.tool_versions,
        restore_target: Some(restore_target.to_string()),
        exclusions: capture.exclusions,
        checksums,
        validation: checks
            .into_iter()
            .map(|check| ValidationRecord {
                check: check.check,
                passed: check.passed,
                detail: check.detail,
            })
            .collect(),
        expanded_bytes: None,
    }
}

pub(super) async fn remove_staging(path: &Path) {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "failed to remove online backup staging")
        }
    }
}

fn append_error(error: ApiError, context: &str) -> ApiError {
    match error {
        ApiError::Conflict(message) => ApiError::Conflict(format!("{message}; {context}")),
        error => ApiError::Runtime(format!("{error}; {context}")),
    }
}

pub(super) fn journal_error(error: crate::storage::backup_jobs::BackupJobStorageError) -> ApiError {
    ApiError::Runtime(format!("backup job journal: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn staging_inside_the_source_volume_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("volumes/inst_one");
        let inside = data.join(".staging/inst_one");
        let outside = temp.path().join("backups/.staging/inst_one");
        for directory in [&inside, &outside] {
            tokio::fs::create_dir_all(directory).await.unwrap();
        }
        assert!(
            ensure_outside_source(&data, &inside.join(".job.capture"))
                .await
                .is_err()
        );
        ensure_outside_source(&data, &outside.join(".job.capture"))
            .await
            .unwrap();
    }

    #[test]
    fn strategy_capture_paths_must_stay_inside_staging() {
        let capture = |data_root: &str, restore_target: &str| CaptureResult {
            data_root: PathBuf::from(data_root),
            restore_target: PathBuf::from(restore_target),
            consistency: crate::server::backup::manifest::ConsistencyLevel::PhysicalRecoveryPoint,
            recovery: Default::default(),
            engine_version: None,
            tool_versions: Default::default(),
            exclusions: Vec::new(),
            native_manifest: None,
        };
        let root = Path::new("/staging");
        let (data, target) = capture_paths(root, &capture("base", "pgdata")).unwrap();
        assert_eq!(data, Path::new("/staging/base"));
        assert_eq!(target, "pgdata");
        for (data_root, target) in [("../x", "pgdata"), ("base", "/abs"), ("base", "a/../b")] {
            assert!(capture_paths(root, &capture(data_root, target)).is_err());
        }
    }

    #[test]
    fn staging_budget_covers_native_output_and_packaging() {
        assert_eq!(staging_budget(10, 5), 15);
        assert_eq!(staging_budget(u64::MAX, 5), u64::MAX);
    }

    #[test]
    fn captures_restore_cannot_extract_are_not_published() {
        check_restorable(10, 1024, 1024).unwrap();
        assert!(check_restorable(10, 1025, 1024).is_err());
        assert!(check_restorable(MAX_DATA_ARCHIVE_ENTRIES + 1, 1, u64::MAX).is_err());
    }

    #[tokio::test]
    async fn archive_expansion_uses_restore_accounting() {
        let temp = tempfile::tempdir().unwrap();
        let child = |name: &str| temp.path().join(name).join("inst_one");
        let paths = InstancePaths {
            instance_id: "inst_one".to_string(),
            data: child("volumes"),
            logs: child("logs"),
            sockets: child("sockets"),
            artifacts: child("artifacts"),
            exports: child("exports"),
            imports: child("imports"),
            backups: child("backups"),
            runtime_config: child("runtime"),
            socket_bridge_binary: temp.path().join("bridge"),
        };
        let staged = temp.path().join("staging/pgdata");
        std::fs::create_dir_all(staged.join("pg_wal")).unwrap();
        std::fs::write(staged.join("PG_VERSION"), b"18\n").unwrap();
        std::fs::write(staged.join("pg_wal/segment"), vec![0_u8; 4096]).unwrap();
        let archive = temp.path().join("capture.tar.gz");
        package_capture(&paths, &staged, "18/docker", &archive, 1 << 30)
            .await
            .unwrap();
        let (check, expanded) = validate_archive_structure(&paths, "18/docker", &archive, 1 << 30)
            .await
            .unwrap();
        assert!(check.passed);
        // Every entry carries restore's per-entry allowance on top of its size.
        assert!(expanded >= 4096 + 3 + 4 * DATA_ARCHIVE_ENTRY_DISK_OVERHEAD_BYTES);
        assert!(
            validate_archive_structure(&paths, "18/docker", &archive, expanded - 1)
                .await
                .is_err()
        );
    }
}
