use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RespLimits {
    pub max_nesting: usize,
    pub max_bulk_len: usize,
    pub max_array_len: usize,
    pub max_line_len: usize,
    pub max_total_values: usize,
    pub max_response_bytes: usize,
}

impl Default for RespLimits {
    fn default() -> Self {
        Self {
            max_nesting: 32,
            max_bulk_len: 64 * 1024 * 1024,
            max_array_len: 16 * 1024,
            max_line_len: 64 * 1024,
            max_total_values: 100_000,
            max_response_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespValue {
    Simple(Vec<u8>),
    Error(Vec<u8>),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
    Array(Option<Vec<RespValue>>),
}

impl RespValue {
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::Simple(_) => "simple string",
            Self::Error(_) => "error",
            Self::Integer(_) => "integer",
            Self::Bulk(Some(_)) => "bulk string",
            Self::Bulk(None) => "null bulk string",
            Self::Array(Some(_)) => "array",
            Self::Array(None) => "null array",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPage {
    pub next_cursor: u64,
    pub keys: Vec<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RedisRespError {
    #[error("redis endpoint has no resolved addresses")]
    NoResolvedAddresses,
    #[error("redis {operation} timed out after {timeout:?}")]
    Timeout {
        operation: &'static str,
        timeout: Duration,
    },
    #[error("failed to connect to redis endpoint {host}:{port}: {message}")]
    Connect {
        host: String,
        port: u16,
        message: String,
    },
    #[error("redis TLS server name is invalid: {0}")]
    InvalidTlsServerName(String),
    #[error("redis I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("redis protocol error: {0}")]
    Protocol(String),
    #[error("redis response exceeded {limit_name} limit ({limit})")]
    LimitExceeded {
        limit_name: &'static str,
        limit: usize,
    },
    #[error("redis server rejected the command: {0}")]
    Server(String),
    #[error("redis {operation} expected {expected}, received {actual}")]
    UnexpectedResponse {
        operation: &'static str,
        expected: &'static str,
        actual: &'static str,
    },
    #[error("invalid redis command argument: {0}")]
    InvalidArgument(&'static str),
}

pub type RedisRespResult<T> = Result<T, RedisRespError>;

#[derive(Debug, thiserror::Error)]
pub enum RedisRelayError {
    #[error("redis source relay failed: {0}")]
    Source(#[source] RedisRespError),
    #[error("redis target relay failed: {0}")]
    Target(#[source] RedisRespError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisRestoreExpiration {
    Persistent,
    AbsoluteUnixMilliseconds(u64),
}
