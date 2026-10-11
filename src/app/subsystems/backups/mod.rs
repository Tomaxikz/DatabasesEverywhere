const DEFAULT_BROWSE_LIMIT: usize = 25;
const MAX_BROWSE_LIMIT: usize = 100;
const MAX_BROWSE_OBJECT_ID_BYTES: usize = 1024;
const PHYSICAL_BACKUP_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

mod catalog;
mod checks;
mod handlers;
mod online;
mod publication;
mod recovery;
pub(crate) mod registry;
mod restore;
mod run;
mod scheduler;
mod storage;
pub(crate) mod strategy;
mod types;

pub use handlers::{
    backup_status, browse_instance_backup, delete_instance_backup, list_instance_backups,
    list_unsupported_backups, restore_instance_backup, run_all_backups, run_instance_backup,
};

pub(crate) use recovery::recover_interrupted_backups;
pub use scheduler::start_scheduler;
pub(crate) use storage::{prepare_backup_download, purge_instance_backups, require_backup};
pub use types::{BackupContentsResponse, BackupInfo, BackupStatusResponse};

#[cfg(test)]
mod tests;
