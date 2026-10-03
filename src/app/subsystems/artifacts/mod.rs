use std::{
    collections::HashMap,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    pin::Pin,
    sync::Arc,
    sync::Mutex as StdMutex,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::header,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures::Stream;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    fs::File,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

mod one_use;
pub(crate) use one_use::{
    check_export_slot, instance_spool_root, run_export_sweeper, sweep_one_use_exports,
};

use crate::routes::http::{
    policy::ApiRequestContext,
    response::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResponse, ApiResult},
    router::AppState,
};
use crate::{
    auth::scopes,
    io::files::{is_safe_flat_file_name, safe_header_filename},
    utils::constants::jwt::{AUDIENCE, ISSUER},
    utils::{ids::validate_instance_id, time::now_unix},
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
use checksum::*;
use download::*;
pub(crate) use files::*;
pub use handlers::*;
use stream::*;
pub use tickets::*;
pub use types::*;

#[cfg(test)]
mod tests;
