use std::str::FromStr;

use sqlx::SqlitePool;

use crate::{
    placement::model::PlacementError,
    shared::protocol::Protocol,
    storage::secrets::{SecretStore, SecretStoreError},
};

mod capacity;
mod reservations;
mod runtime;

#[derive(Debug, Clone)]
pub struct PlacementRepository {
    pool: SqlitePool,
    secrets: Option<SecretStore>,
}

pub(super) fn u64_to_i64(value: u64, field: &'static str) -> Result<i64, PlacementRepositoryError> {
    i64::try_from(value).map_err(|_| PlacementRepositoryError::IntegerOverflow { field, value })
}

pub(super) fn parse_protocol(value: String) -> Result<Protocol, PlacementRepositoryError> {
    Protocol::from_str(&value).map_err(|_| PlacementRepositoryError::InvalidValue {
        field: "protocol",
        value,
    })
}

pub(super) fn i64_to_u64(value: i64, field: &'static str) -> Result<u64, PlacementRepositoryError> {
    u64::try_from(value).map_err(|_| PlacementRepositoryError::InvalidInteger { field, value })
}

#[derive(Debug, thiserror::Error)]
pub enum PlacementRepositoryError {
    #[error("sqlite query failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("runtime json serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("runtime secret storage failed: {0}")]
    Secrets(#[from] SecretStoreError),
    #[error(transparent)]
    Placement(#[from] PlacementError),
    #[error("engine runtime {0} does not exist")]
    RuntimeNotFound(String),
    #[error("engine runtime {0} has no capacity for this reservation")]
    CapacityUnavailable(String),
    #[error("instance {0} already has a runtime reservation")]
    AlreadyReserved(String),
    #[error("instance {0} has no runtime reservation")]
    ReservationNotFound(String),
    #[error("instance {0} reservation is not attached to matching shared metadata")]
    ReservationNotAttached(String),
    #[error("database {database:?} already exists in shared runtime {runtime_id}")]
    DatabaseInUse {
        runtime_id: String,
        database: String,
    },
    #[error("username {username:?} already exists in shared runtime {runtime_id}")]
    UsernameInUse {
        runtime_id: String,
        username: String,
    },
    #[error("instance {0} is still attached to its shared runtime")]
    InstanceStillAttached(String),
    #[error("invalid runtime reservation: {0}")]
    InvalidReservation(String),
    #[error("runtime field {field} contains invalid value {value:?}")]
    InvalidValue { field: &'static str, value: String },
    #[error("runtime field {field} contains invalid integer {value}")]
    InvalidInteger { field: &'static str, value: i64 },
    #[error("runtime field {field} value {value} exceeds SQLite integer capacity")]
    IntegerOverflow { field: &'static str, value: u64 },
    #[error("engine runtime {runtime_id} has an invalid encrypted admin secret")]
    InvalidAdminSecret {
        runtime_id: String,
        #[source]
        source: SecretStoreError,
    },
}

#[cfg(test)]
mod tests;
