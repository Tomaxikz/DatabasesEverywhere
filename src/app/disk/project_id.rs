use std::{
    fs::{File, OpenOptions},
    hash::Hasher,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use super::DiskLimitError;

const REGISTRY_DIRECTORY: &str = ".dbe-project-quota-ids";
const REGISTRY_LOCK_FILE: &str = ".allocation.lock";
const PENDING_SUFFIX: &str = ".pending";
const RELEASED_SUFFIX: &str = ".released";

/// DBE allocates only from this many consecutive IDs starting at
/// `disk.project_id_base` (or the remaining IDs before `u32::MAX`). Operators
/// must reserve this range for DBE when native filesystem quotas are enabled.
const PROJECT_ID_ALLOCATION_RANGE_SIZE: u64 = 1_000_000;

pub(super) async fn allocate_in(
    owner_id: &str,
    registry_root: &Path,
    base: u32,
) -> Result<u32, DiskLimitError> {
    let registry = registry_path(registry_root);
    let owner_id = owner_id.to_string();
    tokio::task::spawn_blocking(move || allocate_sync(&registry, &owner_id, base))
        .await
        .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

pub(super) async fn find_active_in(
    owner_id: &str,
    registry_root: &Path,
    base: u32,
) -> Result<Option<u32>, DiskLimitError> {
    find_claim_in(owner_id, registry_root, base)
        .await
        .map(|claim| {
            claim
                .filter(|claim| claim.state == ProjectIdState::Active)
                .map(|claim| claim.id)
        })
}

pub(super) async fn find_pending_in(
    owner_id: &str,
    registry_root: &Path,
    base: u32,
) -> Result<Option<u32>, DiskLimitError> {
    find_claim_in(owner_id, registry_root, base)
        .await
        .map(|claim| {
            claim
                .filter(|claim| claim.state == ProjectIdState::Pending)
                .map(|claim| claim.id)
        })
}

/// Publish an allocated project ID as active only after its filesystem tree
/// has been adopted and its hard limit has been installed successfully.
pub(super) async fn activate_in(
    owner_id: &str,
    registry_root: &Path,
    project_id: u32,
) -> Result<(), DiskLimitError> {
    let registry = registry_path(registry_root);
    let owner_id = owner_id.to_string();
    tokio::task::spawn_blocking(move || activate_sync(&registry, &owner_id, project_id))
        .await
        .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

pub(super) async fn find_claim_in(
    owner_id: &str,
    registry_root: &Path,
    base: u32,
) -> Result<Option<ProjectIdClaim>, DiskLimitError> {
    let registry = registry_path(registry_root);
    let owner_id = owner_id.to_string();
    tokio::task::spawn_blocking(move || find_sync(&registry, &owner_id, base))
        .await
        .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

pub(super) async fn release_in(
    owner_id: &str,
    registry_root: &Path,
    base: u32,
) -> Result<Option<u32>, DiskLimitError> {
    let registry = registry_path(registry_root);
    let owner_id = owner_id.to_string();
    tokio::task::spawn_blocking(move || release_sync(&registry, &owner_id, base))
        .await
        .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

pub(super) fn default_registry_root(data_path: &Path) -> Result<&Path, DiskLimitError> {
    data_path
        .parent()
        .ok_or_else(|| registry_error(data_path, "instance data path has no parent"))
}

fn registry_path(registry_root: &Path) -> PathBuf {
    registry_root.join(REGISTRY_DIRECTORY)
}

fn find_sync(
    registry: &Path,
    owner_id: &str,
    base: u32,
) -> Result<Option<ProjectIdClaim>, DiskLimitError> {
    validate_instance_id(registry, owner_id)?;
    if !open_existing_registry(registry)? {
        return Ok(None);
    }
    let _allocation_lock = lock_registry(registry)?;
    find_locked(registry, owner_id, base)
}

fn release_sync(registry: &Path, owner_id: &str, base: u32) -> Result<Option<u32>, DiskLimitError> {
    validate_instance_id(registry, owner_id)?;
    if !open_existing_registry(registry)? {
        return Ok(None);
    }
    let _allocation_lock = lock_registry(registry)?;
    let Some(claim) = find_locked(registry, owner_id, base)? else {
        return Ok(None);
    };
    write_tombstone(registry, claim.id, owner_id).map_err(|source| {
        DiskLimitError::ProjectIdRegistry {
            path: tombstone_path(registry, claim.id).display().to_string(),
            source,
        }
    })?;
    remove_pending(registry, claim.id, owner_id).map_err(|source| {
        DiskLimitError::ProjectIdRegistry {
            path: pending_path(registry, claim.id).display().to_string(),
            source,
        }
    })?;
    Ok(Some(claim.id))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProjectIdClaim {
    pub(super) id: u32,
    pub(super) state: ProjectIdState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectIdState {
    Pending,
    Active,
    Released,
}

fn find_locked(
    registry: &Path,
    owner_id: &str,
    base: u32,
) -> Result<Option<ProjectIdClaim>, DiskLimitError> {
    let span = allocation_span(base);
    let initial = initial_project_id(owner_id, base, span);
    let mut released_claim = None;

    for offset in 0..span {
        let relative = (u64::from(initial - base) + offset) % span;
        let candidate = base + u32::try_from(relative).expect("project id relative value fits u32");
        let claim_path = registry.join(candidate.to_string());
        let pending = pending_path(registry, candidate);
        let tombstone = tombstone_path(registry, candidate);
        let claim_owner =
            read_owner(&claim_path).map_err(|source| DiskLimitError::ProjectIdRegistry {
                path: claim_path.display().to_string(),
                source,
            })?;
        let released_owner =
            read_owner(&tombstone).map_err(|source| DiskLimitError::ProjectIdRegistry {
                path: tombstone.display().to_string(),
                source,
            })?;
        let pending_owner =
            read_owner(&pending).map_err(|source| DiskLimitError::ProjectIdRegistry {
                path: pending.display().to_string(),
                source,
            })?;

        validate_candidate_owners(
            &claim_path,
            claim_owner.as_deref(),
            &pending,
            pending_owner.as_deref(),
            &tombstone,
            released_owner.as_deref(),
        )?;

        if claim_owner.as_deref() == Some(owner_id)
            || pending_owner.as_deref() == Some(owner_id)
            || (claim_owner.is_none() && released_owner.as_deref() == Some(owner_id))
        {
            let claim = ProjectIdClaim {
                id: candidate,
                state: if released_owner.is_some() {
                    ProjectIdState::Released
                } else if pending_owner.is_some() {
                    ProjectIdState::Pending
                } else {
                    // Claims written before the pending-state protocol are
                    // already in service and therefore remain active.
                    ProjectIdState::Active
                },
            };
            if claim.state != ProjectIdState::Released {
                return Ok(Some(claim));
            }
            released_claim.get_or_insert(claim);
        }
        if claim_owner.is_none() && pending_owner.is_none() && released_owner.is_none() {
            return Ok(released_claim);
        }
    }

    Ok(released_claim)
}

fn open_existing_registry(path: &Path) -> Result<bool, DiskLimitError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(DiskLimitError::ProjectIdRegistry {
                path: path.display().to_string(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(registry_error(path, "registry must be a real directory"));
    }
    Ok(true)
}

fn tombstone_path(registry: &Path, project_id: u32) -> PathBuf {
    registry.join(format!("{project_id}{RELEASED_SUFFIX}"))
}

fn pending_path(registry: &Path, project_id: u32) -> PathBuf {
    registry.join(format!("{project_id}{PENDING_SUFFIX}"))
}

fn validate_candidate_owners(
    claim_path: &Path,
    claim_owner: Option<&str>,
    pending_path: &Path,
    pending_owner: Option<&str>,
    tombstone_path: &Path,
    released_owner: Option<&str>,
) -> Result<(), DiskLimitError> {
    let mut owners = [claim_owner, pending_owner, released_owner]
        .into_iter()
        .flatten();
    let Some(expected) = owners.next() else {
        return Ok(());
    };
    if owners.all(|owner| owner == expected) {
        return Ok(());
    }
    let path = if released_owner.is_some() {
        tombstone_path
    } else if pending_owner.is_some() {
        pending_path
    } else {
        claim_path
    };
    Err(registry_error(
        path,
        "project id claim state files have different owners",
    ))
}

fn read_owner(path: &Path) -> Result<Option<String>, std::io::Error> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "project id claim must be a real regular file",
        ));
    }
    let mut owner = String::new();
    OpenOptions::new()
        .read(true)
        .open(path)?
        .take(1025)
        .read_to_string(&mut owner)?;
    if owner.len() > 1024 || !owner.ends_with('\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "project id claim contains invalid owner data",
        ));
    }
    owner.pop();
    if owner.is_empty() || owner.bytes().any(|byte| matches!(byte, b'\n' | b'\r')) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "project id claim contains invalid owner data",
        ));
    }
    Ok(Some(owner))
}

fn write_tombstone(registry: &Path, project_id: u32, owner_id: &str) -> Result<(), std::io::Error> {
    let path = tombstone_path(registry, project_id);
    match create_owner_file(&path, owner_id) {
        Ok(()) => {
            sync_directory(registry)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_owner(&path)?.as_deref() == Some(owner_id) {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "project id tombstone belongs to another owner",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn remove_pending(registry: &Path, project_id: u32, owner_id: &str) -> Result<(), std::io::Error> {
    let path = pending_path(registry, project_id);
    let Some(pending_owner) = read_owner(&path)? else {
        return Ok(());
    };
    if pending_owner != owner_id {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "project id pending marker belongs to another owner",
        ));
    }
    std::fs::remove_file(path)?;
    sync_directory(registry)
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path)?.sync_all()
}

fn create_owner_file(path: &Path, owner_id: &str) -> Result<(), std::io::Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    let write_result = file
        .write_all(owner_id.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all());
    if let Err(error) = write_result {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn activate_sync(registry: &Path, owner_id: &str, project_id: u32) -> Result<(), DiskLimitError> {
    validate_instance_id(registry, owner_id)?;
    if !open_existing_registry(registry)? {
        return Err(registry_error(
            registry,
            "project id registry does not exist",
        ));
    }
    let _allocation_lock = lock_registry(registry)?;
    let claim_path = registry.join(project_id.to_string());
    let pending = pending_path(registry, project_id);
    let tombstone = tombstone_path(registry, project_id);
    let claim_owner =
        read_owner(&claim_path).map_err(|source| DiskLimitError::ProjectIdRegistry {
            path: claim_path.display().to_string(),
            source,
        })?;
    let pending_owner =
        read_owner(&pending).map_err(|source| DiskLimitError::ProjectIdRegistry {
            path: pending.display().to_string(),
            source,
        })?;
    let released_owner =
        read_owner(&tombstone).map_err(|source| DiskLimitError::ProjectIdRegistry {
            path: tombstone.display().to_string(),
            source,
        })?;
    validate_candidate_owners(
        &claim_path,
        claim_owner.as_deref(),
        &pending,
        pending_owner.as_deref(),
        &tombstone,
        released_owner.as_deref(),
    )?;
    if released_owner.is_some() {
        return Err(registry_error(
            &tombstone,
            "released project id cannot be activated",
        ));
    }
    if claim_owner.as_deref() != Some(owner_id) {
        return Err(registry_error(
            &claim_path,
            "project id claim is missing or belongs to another owner",
        ));
    }
    remove_pending(registry, project_id, owner_id).map_err(|source| {
        DiskLimitError::ProjectIdRegistry {
            path: pending.display().to_string(),
            source,
        }
    })
}

/// Publish the pending marker before the claim itself. A crash between these
/// writes leaves a recoverable reservation, never an apparently active claim.
fn publish_pending_claim(
    registry: &Path,
    project_id: u32,
    owner_id: &str,
) -> Result<Claim, std::io::Error> {
    let pending = pending_path(registry, project_id);
    match claim(&pending, owner_id)? {
        Claim::OwnedByAnother => return Ok(Claim::OwnedByAnother),
        Claim::Created | Claim::AlreadyOwned => {}
    }
    match claim(&registry.join(project_id.to_string()), owner_id)? {
        Claim::Created | Claim::AlreadyOwned => Ok(Claim::AlreadyOwned),
        Claim::OwnedByAnother => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "project id was claimed by another owner after pending publication",
        )),
    }
}

fn allocate_sync(registry: &Path, instance_id: &str, base: u32) -> Result<u32, DiskLimitError> {
    validate_instance_id(registry, instance_id)?;
    create_private_registry(registry)?;
    let _allocation_lock = lock_registry(registry)?;
    let span = allocation_span(base);
    let initial = initial_project_id(instance_id, base, span);

    for offset in 0..span {
        let relative = (u64::from(initial - base) + offset) % span;
        let candidate = base + u32::try_from(relative).expect("project id relative value fits u32");
        let path = registry.join(candidate.to_string());
        let pending = pending_path(registry, candidate);
        let tombstone = tombstone_path(registry, candidate);
        let claim_owner =
            read_owner(&path).map_err(|source| DiskLimitError::ProjectIdRegistry {
                path: path.display().to_string(),
                source,
            })?;
        let pending_owner =
            read_owner(&pending).map_err(|source| DiskLimitError::ProjectIdRegistry {
                path: pending.display().to_string(),
                source,
            })?;
        let released_owner =
            read_owner(&tombstone).map_err(|source| DiskLimitError::ProjectIdRegistry {
                path: tombstone.display().to_string(),
                source,
            })?;
        validate_candidate_owners(
            &path,
            claim_owner.as_deref(),
            &pending,
            pending_owner.as_deref(),
            &tombstone,
            released_owner.as_deref(),
        )?;
        if released_owner.is_some() {
            // A released project ID is never reused, even by the same owner.
            // Old inodes can therefore never become charged to a recreated
            // tenant after an uncertain or partially completed cleanup.
            continue;
        }
        if claim_owner.as_deref() == Some(instance_id) && pending_owner.is_none() {
            // Legacy and already-activated claims have no pending marker.
            return Ok(candidate);
        }
        if pending_owner.as_deref() == Some(instance_id) {
            match publish_pending_claim(registry, candidate, instance_id) {
                Ok(Claim::Created | Claim::AlreadyOwned) => return Ok(candidate),
                Ok(Claim::OwnedByAnother) => continue,
                Err(source) => {
                    return Err(DiskLimitError::ProjectIdRegistry {
                        path: path.display().to_string(),
                        source,
                    });
                }
            }
        }
        if claim_owner.is_some() || pending_owner.is_some() {
            continue;
        }
        match publish_pending_claim(registry, candidate, instance_id) {
            Ok(Claim::Created | Claim::AlreadyOwned) => return Ok(candidate),
            Ok(Claim::OwnedByAnother) => {}
            Err(source) => {
                return Err(DiskLimitError::ProjectIdRegistry {
                    path: path.display().to_string(),
                    source,
                });
            }
        }
    }

    Err(DiskLimitError::ProjectIdExhausted { base })
}

fn allocation_span(base: u32) -> u64 {
    (u64::from(u32::MAX) - u64::from(base) + 1).min(PROJECT_ID_ALLOCATION_RANGE_SIZE)
}

fn validate_instance_id(registry: &Path, instance_id: &str) -> Result<(), DiskLimitError> {
    if instance_id.is_empty()
        || instance_id.len() > 1_023
        || instance_id
            .bytes()
            .any(|byte| matches!(byte, b'\n' | b'\r'))
    {
        return Err(registry_error(
            registry,
            "instance id must be 1..=1023 bytes and contain no line breaks",
        ));
    }
    Ok(())
}

fn create_private_registry(path: &Path) -> Result<(), DiskLimitError> {
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(DiskLimitError::ProjectIdRegistry {
                path: path.display().to_string(),
                source,
            });
        }
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| DiskLimitError::ProjectIdRegistry {
            path: path.display().to_string(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(registry_error(path, "registry must be a real directory"));
    }
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |source| DiskLimitError::ProjectIdRegistry {
                path: path.display().to_string(),
                source,
            },
        )?;
    }
    Ok(())
}

fn lock_registry(registry: &Path) -> Result<File, DiskLimitError> {
    let path = registry.join(REGISTRY_LOCK_FILE);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }

    let lock = options
        .open(&path)
        .map_err(|source| DiskLimitError::ProjectIdRegistry {
            path: path.display().to_string(),
            source,
        })?;
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|source| DiskLimitError::ProjectIdRegistry {
            path: path.display().to_string(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(registry_error(
            &path,
            "project id allocation lock must be a real regular file",
        ));
    }
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| DiskLimitError::ProjectIdRegistry {
                path: path.display().to_string(),
                source,
            },
        )?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).map_err(|source| {
            DiskLimitError::ProjectIdRegistry {
                path: path.display().to_string(),
                source: source.into(),
            }
        })?;
    }
    Ok(lock)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Claim {
    Created,
    AlreadyOwned,
    OwnedByAnother,
}

fn claim(path: &Path, instance_id: &str) -> Result<Claim, std::io::Error> {
    match create_owner_file(path, instance_id) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(Claim::Created)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_owner(path)?.as_deref() == Some(instance_id) {
                Ok(Claim::AlreadyOwned)
            } else {
                Ok(Claim::OwnedByAnother)
            }
        }
        Err(error) => Err(error),
    }
}

fn initial_project_id(instance_id: &str, base: u32, span: u64) -> u32 {
    let mut hasher = Fnv1a32::default();
    hasher.write(instance_id.as_bytes());
    base + u32::try_from(hasher.finish() % span).expect("project id relative value fits u32")
}

fn registry_error(path: &Path, message: &str) -> DiskLimitError {
    DiskLimitError::ProjectIdRegistry {
        path: path.display().to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, message),
    }
}

#[derive(Default)]
struct Fnv1a32(u32);

impl Hasher for Fnv1a32 {
    fn write(&mut self, bytes: &[u8]) {
        let mut hash = if self.0 == 0 { 0x811c_9dc5 } else { self.0 };
        for byte in bytes {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        self.0 = hash;
    }

    fn finish(&self) -> u64 {
        u64::from(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_is_stable_and_persisted() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);

        let first = allocate_sync(&registry, "inst_one", 200_000).unwrap();
        let second = allocate_sync(&registry, "inst_one", 200_000).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            find_sync(&registry, "inst_one", 200_000).unwrap(),
            Some(ProjectIdClaim {
                id: first,
                state: ProjectIdState::Pending,
            })
        );
        assert_eq!(
            std::fs::read_to_string(registry.join(first.to_string())).unwrap(),
            "inst_one\n"
        );
        assert_eq!(
            std::fs::read_to_string(pending_path(&registry, first)).unwrap(),
            "inst_one\n"
        );
    }

    #[test]
    fn activation_is_the_only_pending_to_active_transition() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        let base = 200_000;
        let id = allocate_sync(&registry, "tenant", base).unwrap();

        assert_eq!(
            find_sync(&registry, "tenant", base).unwrap(),
            Some(ProjectIdClaim {
                id,
                state: ProjectIdState::Pending,
            })
        );
        activate_sync(&registry, "tenant", id).unwrap();
        assert_eq!(
            find_sync(&registry, "tenant", base).unwrap(),
            Some(ProjectIdClaim {
                id,
                state: ProjectIdState::Active,
            })
        );
        assert!(!pending_path(&registry, id).exists());

        // Activation and subsequent allocation are idempotent and do not
        // recreate the pending marker.
        activate_sync(&registry, "tenant", id).unwrap();
        assert_eq!(allocate_sync(&registry, "tenant", base).unwrap(), id);
        assert!(!pending_path(&registry, id).exists());
    }

    #[test]
    fn interrupted_pending_publication_is_recovered_by_retry() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        let base = u32::MAX;
        create_private_registry(&registry).unwrap();
        let id = initial_project_id("tenant", base, allocation_span(base));

        // This is the only on-disk state possible between publishing the
        // pending marker and publishing the owner claim.
        claim(&pending_path(&registry, id), "tenant").unwrap();
        assert!(!registry.join(id.to_string()).exists());
        assert_eq!(allocate_sync(&registry, "tenant", base).unwrap(), id);
        assert!(registry.join(id.to_string()).is_file());
        assert_eq!(
            find_sync(&registry, "tenant", base).unwrap(),
            Some(ProjectIdClaim {
                id,
                state: ProjectIdState::Pending,
            })
        );

        // Another owner cannot steal the interrupted reservation.
        assert!(matches!(
            allocate_sync(&registry, "other", base),
            Err(DiskLimitError::ProjectIdExhausted { .. })
        ));
    }

    #[test]
    fn pending_is_published_before_a_claim_write_failure() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        create_private_registry(&registry).unwrap();
        let id = 200_001;
        std::fs::create_dir(registry.join(id.to_string())).unwrap();

        assert!(publish_pending_claim(&registry, id, "tenant").is_err());
        assert_eq!(
            std::fs::read_to_string(pending_path(&registry, id)).unwrap(),
            "tenant\n"
        );
    }

    #[test]
    fn legacy_claim_without_pending_marker_remains_active() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        let base = u32::MAX;
        create_private_registry(&registry).unwrap();
        let id = initial_project_id("legacy", base, allocation_span(base));
        claim(&registry.join(id.to_string()), "legacy").unwrap();

        assert_eq!(
            find_sync(&registry, "legacy", base).unwrap(),
            Some(ProjectIdClaim {
                id,
                state: ProjectIdState::Active,
            })
        );
        assert_eq!(allocate_sync(&registry, "legacy", base).unwrap(), id);
        assert!(!pending_path(&registry, id).exists());
    }

    #[test]
    fn colliding_instances_probe_to_distinct_ids() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        let base = u32::MAX - 1;
        let first_name = "inst_collision_0";
        let initial = initial_project_id(first_name, base, 2);
        let second_name = (1..100)
            .map(|value| format!("inst_collision_{value}"))
            .find(|name| initial_project_id(name, base, 2) == initial)
            .unwrap();

        let first = allocate_sync(&registry, first_name, base).unwrap();
        let second = allocate_sync(&registry, &second_name, base).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn explicit_global_registry_prevents_cross_parent_collisions() {
        let temp = tempfile::tempdir().unwrap();
        let registry_root = temp.path().join("global-quota-registry");
        std::fs::create_dir(&registry_root).unwrap();
        let registry = registry_path(&registry_root);
        let base = u32::MAX - 1;
        let first_name = "tenant_from_pool_a";
        let initial = initial_project_id(first_name, base, 2);
        let second_name = (0..1_000)
            .map(|value| format!("tenant_from_pool_b_{value}"))
            .find(|name| initial_project_id(name, base, 2) == initial)
            .unwrap();

        let first = allocate_sync(&registry, first_name, base).unwrap();
        let second = allocate_sync(&registry, &second_name, base).unwrap();

        assert_ne!(first, second);
        assert_eq!(first, initial);
    }

    #[test]
    fn release_is_idempotent_and_never_frees_the_claim_for_another_owner() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        let base = u32::MAX;
        let id = allocate_sync(&registry, "tenant_one", base).unwrap();

        assert_eq!(
            find_sync(&registry, "tenant_one", base).unwrap(),
            Some(ProjectIdClaim {
                id,
                state: ProjectIdState::Pending,
            })
        );

        assert_eq!(
            release_sync(&registry, "tenant_one", base).unwrap(),
            Some(id)
        );
        assert_eq!(
            release_sync(&registry, "tenant_one", base).unwrap(),
            Some(id)
        );
        assert_eq!(
            std::fs::read_to_string(registry.join(id.to_string())).unwrap(),
            "tenant_one\n"
        );
        assert_eq!(
            find_sync(&registry, "tenant_one", base).unwrap(),
            Some(ProjectIdClaim {
                id,
                state: ProjectIdState::Released,
            })
        );
        assert!(!pending_path(&registry, id).exists());
        assert_eq!(
            std::fs::read_to_string(tombstone_path(&registry, id)).unwrap(),
            "tenant_one\n"
        );
        assert!(matches!(
            allocate_sync(&registry, "tenant_two", base),
            Err(DiskLimitError::ProjectIdExhausted { .. })
        ));
        assert!(matches!(
            allocate_sync(&registry, "tenant_one", base),
            Err(DiskLimitError::ProjectIdExhausted { .. })
        ));
        assert!(tombstone_path(&registry, id).exists());
    }

    #[test]
    fn recreated_owner_gets_a_new_id_without_reactivating_its_tombstone() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        let base = u32::MAX - 1;
        let old_id = allocate_sync(&registry, "tenant_one", base).unwrap();
        release_sync(&registry, "tenant_one", base).unwrap();

        let new_id = allocate_sync(&registry, "tenant_one", base).unwrap();

        assert_ne!(old_id, new_id);
        assert!(tombstone_path(&registry, old_id).exists());
        assert_eq!(
            find_sync(&registry, "tenant_one", base).unwrap(),
            Some(ProjectIdClaim {
                id: new_id,
                state: ProjectIdState::Pending,
            })
        );
    }

    #[test]
    fn release_tombstones_a_pending_only_reservation() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        let base = u32::MAX;
        create_private_registry(&registry).unwrap();
        let id = initial_project_id("tenant", base, allocation_span(base));
        claim(&pending_path(&registry, id), "tenant").unwrap();

        assert_eq!(release_sync(&registry, "tenant", base).unwrap(), Some(id));
        assert!(!pending_path(&registry, id).exists());
        assert_eq!(
            find_sync(&registry, "tenant", base).unwrap(),
            Some(ProjectIdClaim {
                id,
                state: ProjectIdState::Released,
            })
        );
        assert!(matches!(
            allocate_sync(&registry, "tenant", base),
            Err(DiskLimitError::ProjectIdExhausted { .. })
        ));
    }

    #[test]
    fn allocation_is_confined_to_the_reserved_range() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        let base = 200_000;

        let id = allocate_sync(&registry, "inst_one", base).unwrap();

        assert!(id >= base);
        assert!(u64::from(id) < u64::from(base) + PROJECT_ID_ALLOCATION_RANGE_SIZE);
        assert_eq!(allocation_span(base), PROJECT_ID_ALLOCATION_RANGE_SIZE);
        assert_eq!(allocation_span(u32::MAX - 1), 2);
    }

    #[test]
    fn concurrent_allocation_for_one_instance_returns_one_id() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let registry = Arc::new(temp.path().join(REGISTRY_DIRECTORY));
        let barrier = Arc::new(Barrier::new(8));
        let handles = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    allocate_sync(&registry, "inst_one", 200_000).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let ids = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();

        assert!(ids.iter().all(|id| *id == ids[0]));
    }

    #[test]
    fn registry_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        let id = allocate_sync(&registry, "inst_one", 200_000).unwrap();

        assert_eq!(
            std::fs::metadata(&registry).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(registry.join(id.to_string()))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(pending_path(&registry, id))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(registry.join(REGISTRY_LOCK_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
