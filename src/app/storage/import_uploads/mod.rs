use sqlx::{Row, SqlitePool};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::databases::protocol::Protocol;

pub const MAX_CATALOG_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_LAST_ERROR_BYTES: usize = 16 * 1024;
const MAX_TOKEN_BYTES: usize = 128;
const MAX_FILENAME_BYTES: usize = 255;
const SHA256_HEX_LEN: usize = 64;
const MAX_ACTIVE_LIST_LIMIT: u32 = 500;
const MAX_SCAN_LIMIT: u32 = 1_000;

mod errors;
mod models;
mod queries;
mod repository;
mod transitions;
mod validation;

pub use errors::*;
pub use models::*;
pub use repository::ImportUploadRepository;
use validation::*;

#[cfg(test)]
mod tests;
