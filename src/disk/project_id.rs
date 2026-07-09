use std::{
    fs::{File, OpenOptions},
    hash::Hasher,
    io::{Read, Write},
    path::Path,
};

use super::DiskLimitError;

const REGISTRY_DIRECTORY: &str = ".dbe-project-quota-ids";
const REGISTRY_LOCK_FILE: &str = ".allocation.lock";

/// DBE allocates only from this many consecutive IDs starting at
/// `disk.project_id_base` (or the remaining IDs before `u32::MAX`). Operators
/// must reserve this range for DBE when native filesystem quotas are enabled.
const PROJECT_ID_ALLOCATION_RANGE_SIZE: u64 = 1_000_000;

pub(super) async fn allocate(
    instance_id: &str,
    data_path: &Path,
    base: u32,
) -> Result<u32, DiskLimitError> {
    let parent = data_path
        .parent()
        .ok_or_else(|| registry_error(data_path, "instance data path has no parent"))?;
    let registry = parent.join(REGISTRY_DIRECTORY);
    let instance_id = instance_id.to_string();
    tokio::task::spawn_blocking(move || allocate_blocking(&registry, &instance_id, base))
        .await
        .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

fn allocate_blocking(registry: &Path, instance_id: &str, base: u32) -> Result<u32, DiskLimitError> {
    validate_instance_id(registry, instance_id)?;
    create_private_registry(registry)?;
    let _allocation_lock = lock_registry(registry)?;
    let span = allocation_span(base);
    let initial = initial_project_id(instance_id, base, span);

    for offset in 0..span {
        let relative = (u64::from(initial - base) + offset) % span;
        let candidate = base + u32::try_from(relative).expect("project id relative value fits u32");
        let path = registry.join(candidate.to_string());
        match claim(&path, instance_id) {
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
    #[cfg(unix)]
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
    #[cfg(unix)]
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
    #[cfg(unix)]
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
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }

    match options.open(path) {
        Ok(mut file) => {
            let write_result = file
                .write_all(instance_id.as_bytes())
                .and_then(|_| file.write_all(b"\n"))
                .and_then(|_| file.sync_all());
            if let Err(error) = write_result {
                drop(file);
                let _ = std::fs::remove_file(path);
                return Err(error);
            }
            Ok(Claim::Created)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)?;
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
                .take(1024)
                .read_to_string(&mut owner)?;
            if owner.trim_end() == instance_id {
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

        let first = allocate_blocking(&registry, "inst_one", 200_000).unwrap();
        let second = allocate_blocking(&registry, "inst_one", 200_000).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            std::fs::read_to_string(registry.join(first.to_string())).unwrap(),
            "inst_one\n"
        );
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

        let first = allocate_blocking(&registry, first_name, base).unwrap();
        let second = allocate_blocking(&registry, &second_name, base).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn allocation_is_confined_to_the_reserved_range() {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        let base = 200_000;

        let id = allocate_blocking(&registry, "inst_one", base).unwrap();

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
                    allocate_blocking(&registry, "inst_one", 200_000).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let ids = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();

        assert!(ids.iter().all(|id| *id == ids[0]));
    }

    #[cfg(unix)]
    #[test]
    fn registry_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join(REGISTRY_DIRECTORY);
        let id = allocate_blocking(&registry, "inst_one", 200_000).unwrap();

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
            std::fs::metadata(registry.join(REGISTRY_LOCK_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
