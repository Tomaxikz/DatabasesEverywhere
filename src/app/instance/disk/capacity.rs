use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use tokio::sync::Mutex as AsyncMutex;

const DISK_SAFETY_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FilesystemIdentity(String);

#[derive(Debug, Default)]
struct ReservationState {
    gate: AsyncMutex<()>,
    reserved_bytes_by_filesystem: Mutex<HashMap<FilesystemIdentity, u64>>,
}

impl ReservationState {
    fn lock_reserved_totals(&self) -> MutexGuard<'_, HashMap<FilesystemIdentity, u64>> {
        self.reserved_bytes_by_filesystem
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Serializes output-capacity checks and tracks reservations across all users
/// sharing this service instance.
#[derive(Debug, Clone, Default)]
pub(crate) struct DiskCapacityService {
    state: Arc<ReservationState>,
}

impl DiskCapacityService {
    pub(crate) async fn reserve(
        &self,
        root: &Path,
        requested: u64,
    ) -> Result<DiskCapacityReservation, CapacityError> {
        validate_root(root).await?;

        // Keep the gate through the disk sample so concurrent reservations
        // cannot both admit against the same available bytes.
        let _gate = self.state.gate.lock().await;
        let metadata = std::fs::metadata(root).map_err(CapacityError::IdentifyFilesystem)?;
        let filesystem = filesystem_identity(&metadata);
        let already_reserved = self
            .state
            .lock_reserved_totals()
            .get(&filesystem)
            .copied()
            .unwrap_or(0);

        ensure_disk_space(root, requested, already_reserved).await?;

        let mut totals = self.state.lock_reserved_totals();
        let total = totals.entry(filesystem.clone()).or_default();
        *total = total
            .checked_add(requested)
            .ok_or(CapacityError::Overflow)?;
        drop(totals);

        Ok(DiskCapacityReservation {
            filesystem,
            bytes: requested,
            state: self.state.clone(),
        })
    }

    pub(crate) async fn roots_share_filesystem(
        &self,
        first: &Path,
        second: &Path,
    ) -> Result<bool, CapacityError> {
        let first = filesystem_identity_for_root(first).await?;
        let second = filesystem_identity_for_root(second).await?;
        Ok(first == second)
    }

    #[cfg(test)]
    pub(crate) fn reserved_bytes(&self) -> u64 {
        self.state.lock_reserved_totals().values().copied().sum()
    }
}

#[derive(Debug)]
pub(crate) struct DiskCapacityReservation {
    filesystem: FilesystemIdentity,
    bytes: u64,
    state: Arc<ReservationState>,
}

impl Drop for DiskCapacityReservation {
    fn drop(&mut self) {
        let mut totals = self.state.lock_reserved_totals();
        let Some(total) = totals.get_mut(&self.filesystem) else {
            debug_assert!(false, "output capacity reservation identity was missing");
            return;
        };
        let Some(remaining) = total.checked_sub(self.bytes) else {
            debug_assert!(false, "output capacity reservation underflow");
            return;
        };
        if remaining == 0 {
            totals.remove(&self.filesystem);
        } else {
            *total = remaining;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CapacityError {
    #[error("failed to inspect output filesystem root: {0}")]
    InspectRoot(std::io::Error),
    #[error("output filesystem root must be a real directory")]
    InvalidRoot,
    #[error("failed to identify output filesystem: {0}")]
    IdentifyFilesystem(std::io::Error),
    #[error("storage path is not valid UTF-8")]
    PathNotUtf8,
    #[error("failed to inspect storage capacity: {0}")]
    InspectCapacity(std::io::Error),
    #[error("output capacity reservation overflowed")]
    Overflow,
    #[error(
        "operation needs {required} bytes of output capacity including the safety reserve, but only {available} bytes are available"
    )]
    Insufficient { required: u64, available: u64 },
}

async fn validate_root(root: &Path) -> Result<(), CapacityError> {
    let metadata = tokio::fs::symlink_metadata(root)
        .await
        .map_err(CapacityError::InspectRoot)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CapacityError::InvalidRoot);
    }
    Ok(())
}

async fn filesystem_identity_for_root(root: &Path) -> Result<FilesystemIdentity, CapacityError> {
    validate_root(root).await?;
    let metadata = tokio::fs::symlink_metadata(root)
        .await
        .map_err(CapacityError::InspectRoot)?;
    Ok(filesystem_identity(&metadata))
}

fn filesystem_identity(metadata: &std::fs::Metadata) -> FilesystemIdentity {
    use std::os::unix::fs::MetadataExt;
    FilesystemIdentity(format!("unix-device:{}", metadata.dev()))
}

async fn ensure_disk_space(
    root: &Path,
    requested: u64,
    already_reserved: u64,
) -> Result<(), CapacityError> {
    let path = root.to_str().ok_or(CapacityError::PathNotUtf8)?.to_string();
    let sample = crate::subsystems::monitoring::resources::read_host_disk(&path)
        .await
        .map_err(CapacityError::InspectCapacity)?;
    let required = required_capacity(requested, already_reserved)?;
    if sample.available_bytes < required {
        return Err(CapacityError::Insufficient {
            required,
            available: sample.available_bytes,
        });
    }
    Ok(())
}

fn required_capacity(requested: u64, already_reserved: u64) -> Result<u64, CapacityError> {
    requested
        .checked_add(already_reserved)
        .and_then(|bytes| bytes.checked_add(DISK_SAFETY_RESERVE_BYTES))
        .ok_or(CapacityError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_capacity_includes_existing_reservations_and_safety_reserve() {
        assert_eq!(
            required_capacity(1024, 2048).unwrap(),
            DISK_SAFETY_RESERVE_BYTES + 3072
        );
        assert!(matches!(
            required_capacity(u64::MAX, 1),
            Err(CapacityError::Overflow)
        ));
    }

    #[tokio::test]
    async fn reservations_share_filesystem_totals_and_release_exactly_once() {
        let service = DiskCapacityService::default();
        let directory = tempfile::tempdir().unwrap();
        let first = service.reserve(directory.path(), 1024).await.unwrap();
        let second = service.reserve(directory.path(), 2048).await.unwrap();
        assert_eq!(service.reserved_bytes(), 3072);

        drop(first);
        assert_eq!(service.reserved_bytes(), 2048);
        drop(second);
        assert_eq!(service.reserved_bytes(), 0);
    }

    #[tokio::test]
    async fn reservation_rejects_symlink_roots() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = directory.path().join("link");
        symlink(&target, &link).unwrap();

        assert!(matches!(
            DiskCapacityService::default().reserve(&link, 1).await,
            Err(CapacityError::InvalidRoot)
        ));
    }
}
