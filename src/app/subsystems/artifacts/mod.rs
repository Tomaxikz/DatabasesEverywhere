#[cfg(test)]
use uuid::Uuid;

mod one_use;
pub(crate) use one_use::{
    check_export_slot, instance_spool_root, run_export_sweeper, sweep_one_use_exports,
};

const DOWNLOAD_PURPOSE: &str = "artifact_download";
const DEFAULT_DOWNLOAD_TTL_SECONDS: i64 = 120;
const MAX_DOWNLOAD_TTL_SECONDS: i64 = 900;
const MAX_CONSUMED_DOWNLOAD_TICKETS: usize = 16_384;
const MAX_ACTIVE_DOWNLOADS: usize = 128;
const MAX_ACTIVE_DOWNLOADS_PER_PEER: usize = 32;
const DOWNLOAD_STREAM_BUFFER_BYTES: usize = 128 * 1024;
const HASH_READ_BUFFER_BYTES: usize = 64 * 1024;

mod checksum;
mod download;
mod files;
mod handlers;
mod stream;
mod tickets;
mod types;

pub(crate) use files::{instance_export_root, verified_artifact_path};
pub(crate) use handlers::artifact_download_url;
pub use handlers::{
    apply_retention, create_artifact_download, create_backup_download, delete_artifact,
    download_artifact, download_backup, list_instance_artifacts,
};

pub use tickets::ArtifactDownloadTickets;
pub use types::{DeleteArtifactResponse, DownloadUrlResponse};

#[cfg(test)]
mod tests;
