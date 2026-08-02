use std::{fmt, future::Future, net::SocketAddr, path::Path, pin::Pin, sync::Arc, time::Duration};

use secrecy::{ExposeSecret, SecretString};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpStream, UnixStream},
    time::{Instant, timeout_at},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{self, ClientConfig, RootCertStore, pki_types::ServerName},
};

use super::security::ResolvedRemoteEndpoint;

const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(60);
const RELAY_BUFFER_BYTES: usize = 64 * 1024;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

type BoxedIo = Box<dyn AsyncReadWrite>;

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
    fn kind(&self) -> &'static str {
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

pub struct RespConnection {
    io: BufReader<BoxedIo>,
    limits: RespLimits,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl fmt::Debug for RespConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RespConnection")
            .field("limits", &self.limits)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .finish_non_exhaustive()
    }
}

impl RespConnection {
    pub async fn connect_source(
        endpoint: &ResolvedRemoteEndpoint,
        connect_timeout: Duration,
    ) -> RedisRespResult<Self> {
        Self::connect_source_with_options(
            endpoint,
            connect_timeout,
            DEFAULT_IO_TIMEOUT,
            DEFAULT_IO_TIMEOUT,
            RespLimits::default(),
        )
        .await
    }

    pub async fn connect_source_with_options(
        endpoint: &ResolvedRemoteEndpoint,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
        limits: RespLimits,
    ) -> RedisRespResult<Self> {
        if endpoint.addresses.is_empty() {
            return Err(RedisRespError::NoResolvedAddresses);
        }

        let deadline = Instant::now() + connect_timeout;
        let mut last_error = None;
        let tls = if endpoint.tls {
            Some((
                tls_connector(),
                tls_server_name(&endpoint.host)
                    .map_err(|_| RedisRespError::InvalidTlsServerName(endpoint.host.clone()))?,
            ))
        } else {
            None
        };

        for resolved in &endpoint.addresses {
            let address = SocketAddr::new(resolved.ip(), endpoint.port);
            let tcp = match timeout_at(deadline, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    last_error = Some(error.to_string());
                    continue;
                }
                Err(_) => {
                    return Err(RedisRespError::Timeout {
                        operation: "connect",
                        timeout: connect_timeout,
                    });
                }
            };
            if let Err(error) = tcp.set_nodelay(true) {
                last_error = Some(error.to_string());
                continue;
            }

            if let Some((connector, server_name)) = &tls {
                match timeout_at(deadline, connector.connect(server_name.clone(), tcp)).await {
                    Ok(Ok(stream)) => {
                        return Ok(Self::from_stream(
                            stream,
                            limits,
                            read_timeout,
                            write_timeout,
                        ));
                    }
                    Ok(Err(error)) => {
                        last_error = Some(error.to_string());
                    }
                    Err(_) => {
                        return Err(RedisRespError::Timeout {
                            operation: "TLS handshake",
                            timeout: connect_timeout,
                        });
                    }
                }
            } else {
                return Ok(Self::from_stream(tcp, limits, read_timeout, write_timeout));
            }
        }

        Err(RedisRespError::Connect {
            host: endpoint.host.clone(),
            port: endpoint.port,
            message: last_error.unwrap_or_else(|| "all connection attempts failed".to_string()),
        })
    }

    pub async fn connect_unix(path: &Path, connect_timeout: Duration) -> RedisRespResult<Self> {
        Self::connect_unix_with_options(
            path,
            connect_timeout,
            DEFAULT_IO_TIMEOUT,
            DEFAULT_IO_TIMEOUT,
            RespLimits::default(),
        )
        .await
    }

    pub async fn connect_unix_with_options(
        path: &Path,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
        limits: RespLimits,
    ) -> RedisRespResult<Self> {
        let stream = timeout_at(Instant::now() + connect_timeout, UnixStream::connect(path))
            .await
            .map_err(|_| RedisRespError::Timeout {
                operation: "Unix socket connect",
                timeout: connect_timeout,
            })??;
        Ok(Self::from_stream(
            stream,
            limits,
            read_timeout,
            write_timeout,
        ))
    }

    pub fn from_stream<S>(
        stream: S,
        limits: RespLimits,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Self
    where
        S: AsyncReadWrite + 'static,
    {
        Self {
            io: BufReader::new(Box::new(stream)),
            limits,
            read_timeout,
            write_timeout,
        }
    }

    pub async fn command(&mut self, arguments: &[&[u8]]) -> RedisRespResult<RespValue> {
        self.write_command(arguments).await?;
        let value = self.read_response().await?;
        if let RespValue::Error(message) = value {
            return Err(RedisRespError::Server(
                String::from_utf8_lossy(&message).into_owned(),
            ));
        }
        Ok(value)
    }

    pub async fn auth(
        &mut self,
        username: Option<&str>,
        password: &SecretString,
    ) -> RedisRespResult<()> {
        let password = password.expose_secret().as_bytes();
        let response = match username.filter(|username| !username.is_empty()) {
            Some(username) => {
                self.command(&[b"AUTH", username.as_bytes(), password])
                    .await?
            }
            None => self.command(&[b"AUTH", password]).await?,
        };
        expect_simple(response, "AUTH", b"OK")
    }

    pub async fn select(&mut self, database: u32) -> RedisRespResult<()> {
        let database = database.to_string();
        let response = self.command(&[b"SELECT", database.as_bytes()]).await?;
        expect_simple(response, "SELECT", b"OK")
    }

    pub async fn ping(&mut self) -> RedisRespResult<()> {
        let response = self.command(&[b"PING"]).await?;
        expect_simple(response, "PING", b"PONG")
    }

    pub async fn info_server(&mut self) -> RedisRespResult<Vec<u8>> {
        match self.command(&[b"INFO", b"server"]).await? {
            RespValue::Bulk(Some(info)) => Ok(info),
            value => Err(unexpected("INFO server", "bulk string", &value)),
        }
    }

    pub async fn info_cluster(&mut self) -> RedisRespResult<Vec<u8>> {
        match self.command(&[b"INFO", b"cluster"]).await? {
            RespValue::Bulk(Some(info)) => Ok(info),
            value => Err(unexpected("INFO cluster", "bulk string", &value)),
        }
    }

    pub async fn scan(&mut self, cursor: u64, count: u32) -> RedisRespResult<ScanPage> {
        if count == 0 {
            return Err(RedisRespError::InvalidArgument(
                "SCAN COUNT must be greater than zero",
            ));
        }
        let cursor = cursor.to_string();
        let count = count.to_string();
        let response = self
            .command(&[b"SCAN", cursor.as_bytes(), b"COUNT", count.as_bytes()])
            .await?;
        parse_scan_page(response)
    }

    pub async fn pttl(&mut self, key: &[u8]) -> RedisRespResult<i64> {
        match self.command(&[b"PTTL", key]).await? {
            RespValue::Integer(ttl) => Ok(ttl),
            value => Err(unexpected("PTTL", "integer", &value)),
        }
    }

    /// Relays a binary DUMP response into RESTORE without buffering the serialized value.
    ///
    /// Returns `false` when the source key disappeared before DUMP produced a value.
    pub async fn relay_dump_to_restore_replace(
        &mut self,
        target: &mut RespConnection,
        key: &[u8],
        expiration: RedisRestoreExpiration,
        max_serialized_length: usize,
    ) -> Result<bool, RedisRelayError> {
        self.write_command(&[b"DUMP", key])
            .await
            .map_err(RedisRelayError::Source)?;

        let source_timeout = self.read_timeout;
        let source_deadline = Instant::now() + source_timeout;
        let serialized_length = match timeout_at(
            source_deadline,
            self.read_streaming_bulk_length("DUMP", max_serialized_length),
        )
        .await
        {
            Ok(result) => result.map_err(RedisRelayError::Source)?,
            Err(_) => {
                return Err(RedisRelayError::Source(RedisRespError::Timeout {
                    operation: "read",
                    timeout: source_timeout,
                }));
            }
        };
        let Some(serialized_length) = serialized_length else {
            return Ok(false);
        };

        let (ttl, use_absolute_ttl) = match expiration {
            RedisRestoreExpiration::Persistent => ("0".to_string(), false),
            RedisRestoreExpiration::AbsoluteUnixMilliseconds(deadline) => {
                (deadline.to_string(), true)
            }
        };
        let argument_lengths = [
            b"RESTORE".len(),
            key.len(),
            ttl.len(),
            serialized_length,
            b"REPLACE".len(),
            b"ABSTTL".len(),
        ];
        target
            .validate_streamed_restore_command_lengths(
                &argument_lengths[..if use_absolute_ttl { 6 } else { 5 }],
                serialized_length,
                max_serialized_length,
            )
            .map_err(RedisRelayError::Target)?;

        let target_timeout = target.write_timeout;
        let target_deadline = Instant::now() + target_timeout;
        match timeout_at(
            target_deadline,
            target.write_restore_prefix(key, ttl.as_bytes(), serialized_length, use_absolute_ttl),
        )
        .await
        {
            Ok(result) => result.map_err(RedisRelayError::Target)?,
            Err(_) => {
                return Err(RedisRelayError::Target(RedisRespError::Timeout {
                    operation: "write",
                    timeout: target_timeout,
                }));
            }
        }

        let mut buffer = [0_u8; RELAY_BUFFER_BYTES];
        let mut remaining = serialized_length;
        while remaining > 0 {
            let chunk_length = remaining.min(buffer.len());
            match timeout_at(
                source_deadline,
                self.io.read_exact(&mut buffer[..chunk_length]),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    return Err(RedisRelayError::Source(map_unexpected_eof(error)));
                }
                Err(_) => {
                    return Err(RedisRelayError::Source(RedisRespError::Timeout {
                        operation: "read",
                        timeout: source_timeout,
                    }));
                }
            }
            match timeout_at(
                target_deadline,
                target.io.write_all(&buffer[..chunk_length]),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(RedisRelayError::Target(RedisRespError::Io(error)));
                }
                Err(_) => {
                    return Err(RedisRelayError::Target(RedisRespError::Timeout {
                        operation: "write",
                        timeout: target_timeout,
                    }));
                }
            }
            remaining -= chunk_length;
        }

        match timeout_at(source_deadline, self.read_crlf()).await {
            Ok(result) => result.map_err(RedisRelayError::Source)?,
            Err(_) => {
                return Err(RedisRelayError::Source(RedisRespError::Timeout {
                    operation: "read",
                    timeout: source_timeout,
                }));
            }
        }
        match timeout_at(target_deadline, async {
            if use_absolute_ttl {
                target
                    .io
                    .write_all(b"\r\n$7\r\nREPLACE\r\n$6\r\nABSTTL\r\n")
                    .await?;
            } else {
                target.io.write_all(b"\r\n$7\r\nREPLACE\r\n").await?;
            }
            target.io.flush().await
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Err(RedisRelayError::Target(RedisRespError::Io(error)));
            }
            Err(_) => {
                return Err(RedisRelayError::Target(RedisRespError::Timeout {
                    operation: "write",
                    timeout: target_timeout,
                }));
            }
        }

        target
            .read_expected_simple_response("RESTORE", b"OK")
            .await
            .map_err(RedisRelayError::Target)?;
        Ok(true)
    }

    pub async fn flushdb(&mut self) -> RedisRespResult<()> {
        let response = self.command(&[b"FLUSHDB"]).await?;
        expect_simple(response, "FLUSHDB", b"OK")
    }

    pub async fn acl_load(&mut self) -> RedisRespResult<()> {
        let response = self.command(&[b"ACL", b"LOAD"]).await?;
        expect_simple(response, "ACL LOAD", b"OK")
    }

    pub async fn read_response(&mut self) -> RedisRespResult<RespValue> {
        let mut budget = ParseBudget {
            values_left: self.limits.max_total_values,
            bytes_left: self.limits.max_response_bytes,
        };
        let timeout = self.read_timeout;
        timeout_at(Instant::now() + timeout, self.read_value(0, &mut budget))
            .await
            .map_err(|_| RedisRespError::Timeout {
                operation: "read",
                timeout,
            })?
    }

    async fn write_command(&mut self, arguments: &[&[u8]]) -> RedisRespResult<()> {
        if arguments.is_empty() {
            return Err(RedisRespError::InvalidArgument(
                "command must contain at least one argument",
            ));
        }
        if arguments.len() > self.limits.max_array_len {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound array length",
                limit: self.limits.max_array_len,
            });
        }
        if arguments
            .iter()
            .any(|argument| argument.len() > self.limits.max_bulk_len)
        {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound bulk length",
                limit: self.limits.max_bulk_len,
            });
        }
        let encoded_size = command_encoded_size(arguments)?;
        if encoded_size > self.limits.max_response_bytes {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound command bytes",
                limit: self.limits.max_response_bytes,
            });
        }

        let timeout = self.write_timeout;
        timeout_at(Instant::now() + timeout, async {
            self.io
                .write_all(format!("*{}\r\n", arguments.len()).as_bytes())
                .await?;
            for argument in arguments {
                self.io
                    .write_all(format!("${}\r\n", argument.len()).as_bytes())
                    .await?;
                self.io.write_all(argument).await?;
                self.io.write_all(b"\r\n").await?;
            }
            self.io.flush().await
        })
        .await
        .map_err(|_| RedisRespError::Timeout {
            operation: "write",
            timeout,
        })??;
        Ok(())
    }

    fn validate_streamed_restore_command_lengths(
        &self,
        argument_lengths: &[usize],
        serialized_length: usize,
        max_serialized_length: usize,
    ) -> RedisRespResult<()> {
        if argument_lengths.is_empty() {
            return Err(RedisRespError::InvalidArgument(
                "command must contain at least one argument",
            ));
        }
        if argument_lengths.len() > self.limits.max_array_len {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound array length",
                limit: self.limits.max_array_len,
            });
        }
        if serialized_length > max_serialized_length {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound streamed bulk length",
                limit: max_serialized_length,
            });
        }
        if argument_lengths
            .iter()
            .enumerate()
            .any(|(index, length)| index != 3 && *length > self.limits.max_bulk_len)
        {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound bulk length",
                limit: self.limits.max_bulk_len,
            });
        }
        let encoded_size = command_encoded_size_from_lengths(
            argument_lengths.len(),
            argument_lengths.iter().copied(),
        )?;
        let framing_bytes = encoded_size.checked_sub(serialized_length).ok_or_else(|| {
            RedisRespError::Protocol("streamed command length underflow".to_string())
        })?;
        if framing_bytes > self.limits.max_response_bytes {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound command framing bytes",
                limit: self.limits.max_response_bytes,
            });
        }
        Ok(())
    }

    async fn write_restore_prefix(
        &mut self,
        key: &[u8],
        ttl: &[u8],
        serialized_length: usize,
        use_absolute_ttl: bool,
    ) -> RedisRespResult<()> {
        self.io
            .write_all(if use_absolute_ttl {
                b"*6\r\n$7\r\nRESTORE\r\n"
            } else {
                b"*5\r\n$7\r\nRESTORE\r\n"
            })
            .await?;
        self.io
            .write_all(format!("${}\r\n", key.len()).as_bytes())
            .await?;
        self.io.write_all(key).await?;
        self.io.write_all(b"\r\n").await?;
        self.io
            .write_all(format!("${}\r\n", ttl.len()).as_bytes())
            .await?;
        self.io.write_all(ttl).await?;
        self.io.write_all(b"\r\n").await?;
        self.io
            .write_all(format!("${serialized_length}\r\n").as_bytes())
            .await?;
        Ok(())
    }

    async fn read_streaming_bulk_length(
        &mut self,
        operation: &'static str,
        max_streaming_bulk_len: usize,
    ) -> RedisRespResult<Option<usize>> {
        let max_response_bytes = max_streaming_bulk_len
            .checked_add(self.limits.max_line_len)
            .and_then(|limit| limit.checked_add(5))
            .ok_or_else(|| {
                RedisRespError::Protocol("streaming response length overflow".to_string())
            })?;
        let mut budget = ParseBudget {
            values_left: self.limits.max_total_values,
            bytes_left: max_response_bytes,
        };
        budget.consume_value(self.limits.max_total_values)?;
        let prefix = self.io.read_u8().await.map_err(map_unexpected_eof)?;
        budget.consume_bytes(1, max_response_bytes)?;
        match prefix {
            b'$' => {
                let line = self
                    .read_line_with_response_limit(&mut budget, max_response_bytes)
                    .await?;
                let length = parse_nullable_length(&line, "bulk string")?;
                let Some(length) = length else {
                    return Ok(None);
                };
                if length > max_streaming_bulk_len {
                    return Err(RedisRespError::LimitExceeded {
                        limit_name: "streaming bulk length",
                        limit: max_streaming_bulk_len,
                    });
                }
                budget.consume_bytes(
                    length.checked_add(2).ok_or_else(|| {
                        RedisRespError::Protocol("bulk string length overflow".to_string())
                    })?,
                    max_response_bytes,
                )?;
                Ok(Some(length))
            }
            b'-' => {
                let message = self
                    .read_line_with_response_limit(&mut budget, max_response_bytes)
                    .await?;
                Err(RedisRespError::Server(
                    String::from_utf8_lossy(&message).into_owned(),
                ))
            }
            b'+' => Err(RedisRespError::UnexpectedResponse {
                operation,
                expected: "bulk string or null",
                actual: "simple string",
            }),
            b':' => Err(RedisRespError::UnexpectedResponse {
                operation,
                expected: "bulk string or null",
                actual: "integer",
            }),
            b'*' => Err(RedisRespError::UnexpectedResponse {
                operation,
                expected: "bulk string or null",
                actual: "array",
            }),
            other => Err(RedisRespError::Protocol(format!(
                "unsupported RESP2 type prefix 0x{other:02x}"
            ))),
        }
    }

    async fn read_expected_simple_response(
        &mut self,
        operation: &'static str,
        expected: &'static [u8],
    ) -> RedisRespResult<()> {
        let timeout = self.read_timeout;
        timeout_at(Instant::now() + timeout, async {
            let mut budget = ParseBudget {
                values_left: self.limits.max_total_values,
                bytes_left: self.limits.max_response_bytes,
            };
            budget.consume_value(self.limits.max_total_values)?;
            let prefix = self.io.read_u8().await.map_err(map_unexpected_eof)?;
            budget.consume_bytes(1, self.limits.max_response_bytes)?;
            match prefix {
                b'+' => {
                    let actual = self.read_line(&mut budget).await?;
                    if actual == expected {
                        Ok(())
                    } else {
                        Err(RedisRespError::UnexpectedResponse {
                            operation,
                            expected: "expected simple string",
                            actual: "different simple string",
                        })
                    }
                }
                b'-' => {
                    let message = self.read_line(&mut budget).await?;
                    Err(RedisRespError::Server(
                        String::from_utf8_lossy(&message).into_owned(),
                    ))
                }
                b'$' => Err(RedisRespError::UnexpectedResponse {
                    operation,
                    expected: "expected simple string",
                    actual: "bulk string",
                }),
                b':' => Err(RedisRespError::UnexpectedResponse {
                    operation,
                    expected: "expected simple string",
                    actual: "integer",
                }),
                b'*' => Err(RedisRespError::UnexpectedResponse {
                    operation,
                    expected: "expected simple string",
                    actual: "array",
                }),
                other => Err(RedisRespError::Protocol(format!(
                    "unsupported RESP2 type prefix 0x{other:02x}"
                ))),
            }
        })
        .await
        .map_err(|_| RedisRespError::Timeout {
            operation: "read",
            timeout,
        })?
    }

    fn read_value<'a>(
        &'a mut self,
        depth: usize,
        budget: &'a mut ParseBudget,
    ) -> Pin<Box<dyn Future<Output = RedisRespResult<RespValue>> + Send + 'a>> {
        Box::pin(async move {
            if depth > self.limits.max_nesting {
                return Err(RedisRespError::LimitExceeded {
                    limit_name: "nesting depth",
                    limit: self.limits.max_nesting,
                });
            }
            budget.consume_value(self.limits.max_total_values)?;

            let prefix = self.io.read_u8().await.map_err(map_unexpected_eof)?;
            budget.consume_bytes(1, self.limits.max_response_bytes)?;
            match prefix {
                b'+' => {
                    let line = self.read_line(budget).await?;
                    Ok(RespValue::Simple(line))
                }
                b'-' => {
                    let line = self.read_line(budget).await?;
                    Ok(RespValue::Error(line))
                }
                b':' => {
                    let line = self.read_line(budget).await?;
                    Ok(RespValue::Integer(parse_i64(&line, "integer")?))
                }
                b'$' => {
                    let line = self.read_line(budget).await?;
                    let length = parse_nullable_length(&line, "bulk string")?;
                    let Some(length) = length else {
                        return Ok(RespValue::Bulk(None));
                    };
                    if length > self.limits.max_bulk_len {
                        return Err(RedisRespError::LimitExceeded {
                            limit_name: "bulk length",
                            limit: self.limits.max_bulk_len,
                        });
                    }
                    budget.consume_bytes(
                        length.checked_add(2).ok_or_else(|| {
                            RedisRespError::Protocol("bulk string length overflow".to_string())
                        })?,
                        self.limits.max_response_bytes,
                    )?;
                    let mut value = vec![0_u8; length];
                    self.io
                        .read_exact(&mut value)
                        .await
                        .map_err(map_unexpected_eof)?;
                    self.read_crlf().await?;
                    Ok(RespValue::Bulk(Some(value)))
                }
                b'*' => {
                    let line = self.read_line(budget).await?;
                    let length = parse_nullable_length(&line, "array")?;
                    let Some(length) = length else {
                        return Ok(RespValue::Array(None));
                    };
                    if length > self.limits.max_array_len {
                        return Err(RedisRespError::LimitExceeded {
                            limit_name: "array length",
                            limit: self.limits.max_array_len,
                        });
                    }
                    let mut values = Vec::with_capacity(length);
                    for _ in 0..length {
                        values.push(self.read_value(depth + 1, budget).await?);
                    }
                    Ok(RespValue::Array(Some(values)))
                }
                other => Err(RedisRespError::Protocol(format!(
                    "unsupported RESP2 type prefix 0x{other:02x}"
                ))),
            }
        })
    }

    async fn read_line(&mut self, budget: &mut ParseBudget) -> RedisRespResult<Vec<u8>> {
        let max_response_bytes = self.limits.max_response_bytes;
        self.read_line_with_response_limit(budget, max_response_bytes)
            .await
    }

    async fn read_line_with_response_limit(
        &mut self,
        budget: &mut ParseBudget,
        max_response_bytes: usize,
    ) -> RedisRespResult<Vec<u8>> {
        let mut output = Vec::new();
        loop {
            let available = self.io.fill_buf().await.map_err(map_unexpected_eof)?;
            if available.is_empty() {
                return Err(RedisRespError::Protocol(
                    "unexpected EOF while reading RESP line".to_string(),
                ));
            }
            if let Some(cr_index) = available.iter().position(|byte| *byte == b'\r') {
                let prospective = output.len().checked_add(cr_index).ok_or_else(|| {
                    RedisRespError::Protocol("RESP line length overflow".to_string())
                })?;
                if prospective > self.limits.max_line_len {
                    return Err(RedisRespError::LimitExceeded {
                        limit_name: "line length",
                        limit: self.limits.max_line_len,
                    });
                }
                output.extend_from_slice(&available[..cr_index]);
                self.io.consume(cr_index + 1);
                budget.consume_bytes(cr_index + 1, max_response_bytes)?;
                let newline = self.io.read_u8().await.map_err(map_unexpected_eof)?;
                budget.consume_bytes(1, max_response_bytes)?;
                if newline != b'\n' {
                    return Err(RedisRespError::Protocol(
                        "RESP line was not terminated by CRLF".to_string(),
                    ));
                }
                return Ok(output);
            }

            let chunk_length = available.len();
            let prospective = output
                .len()
                .checked_add(chunk_length)
                .ok_or_else(|| RedisRespError::Protocol("RESP line length overflow".to_string()))?;
            if prospective > self.limits.max_line_len {
                return Err(RedisRespError::LimitExceeded {
                    limit_name: "line length",
                    limit: self.limits.max_line_len,
                });
            }
            output.extend_from_slice(available);
            self.io.consume(chunk_length);
            budget.consume_bytes(chunk_length, max_response_bytes)?;
        }
    }

    async fn read_crlf(&mut self) -> RedisRespResult<()> {
        let mut delimiter = [0_u8; 2];
        self.io
            .read_exact(&mut delimiter)
            .await
            .map_err(map_unexpected_eof)?;
        if delimiter != *b"\r\n" {
            return Err(RedisRespError::Protocol(
                "bulk string was not terminated by CRLF".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ParseBudget {
    values_left: usize,
    bytes_left: usize,
}

impl ParseBudget {
    fn consume_value(&mut self, limit: usize) -> RedisRespResult<()> {
        self.values_left =
            self.values_left
                .checked_sub(1)
                .ok_or(RedisRespError::LimitExceeded {
                    limit_name: "total response values",
                    limit,
                })?;
        Ok(())
    }

    fn consume_bytes(&mut self, bytes: usize, limit: usize) -> RedisRespResult<()> {
        self.bytes_left =
            self.bytes_left
                .checked_sub(bytes)
                .ok_or(RedisRespError::LimitExceeded {
                    limit_name: "total response bytes",
                    limit,
                })?;
        Ok(())
    }
}

fn tls_connector() -> TlsConnector {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn tls_server_name(host: &str) -> Result<ServerName<'static>, ()> {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    ServerName::try_from(host.to_string()).map_err(|_| ())
}

fn parse_scan_page(value: RespValue) -> RedisRespResult<ScanPage> {
    let RespValue::Array(Some(mut outer)) = value else {
        return Err(unexpected("SCAN", "two-element array", &value));
    };
    if outer.len() != 2 {
        return Err(RedisRespError::Protocol(
            "SCAN response must contain cursor and keys".to_string(),
        ));
    }
    let keys = outer.pop().expect("length checked");
    let cursor = outer.pop().expect("length checked");
    let cursor = match cursor {
        RespValue::Bulk(Some(cursor)) | RespValue::Simple(cursor) => {
            parse_u64(&cursor, "SCAN cursor")?
        }
        value => return Err(unexpected("SCAN cursor", "string", &value)),
    };
    let RespValue::Array(Some(keys)) = keys else {
        return Err(unexpected("SCAN keys", "array", &keys));
    };
    let keys = keys
        .into_iter()
        .map(|key| match key {
            RespValue::Bulk(Some(key)) => Ok(key),
            value => Err(unexpected("SCAN key", "bulk string", &value)),
        })
        .collect::<RedisRespResult<Vec<_>>>()?;
    Ok(ScanPage {
        next_cursor: cursor,
        keys,
    })
}

fn expect_simple(
    value: RespValue,
    operation: &'static str,
    expected: &'static [u8],
) -> RedisRespResult<()> {
    match value {
        RespValue::Simple(actual) if actual == expected => Ok(()),
        value => Err(unexpected(operation, "expected simple string", &value)),
    }
}

fn unexpected(
    operation: &'static str,
    expected: &'static str,
    value: &RespValue,
) -> RedisRespError {
    RedisRespError::UnexpectedResponse {
        operation,
        expected,
        actual: value.kind(),
    }
}

fn parse_nullable_length(value: &[u8], kind: &'static str) -> RedisRespResult<Option<usize>> {
    let signed = parse_i64(value, kind)?;
    if signed == -1 {
        return Ok(None);
    }
    if signed < 0 {
        return Err(RedisRespError::Protocol(format!(
            "{kind} has invalid negative length {signed}"
        )));
    }
    usize::try_from(signed)
        .map(Some)
        .map_err(|_| RedisRespError::Protocol(format!("{kind} length is too large")))
}

fn parse_i64(value: &[u8], kind: &'static str) -> RedisRespResult<i64> {
    let value = std::str::from_utf8(value)
        .map_err(|_| RedisRespError::Protocol(format!("{kind} is not ASCII")))?;
    value
        .parse()
        .map_err(|_| RedisRespError::Protocol(format!("{kind} is not a valid integer")))
}

fn parse_u64(value: &[u8], kind: &'static str) -> RedisRespResult<u64> {
    let value = std::str::from_utf8(value)
        .map_err(|_| RedisRespError::Protocol(format!("{kind} is not ASCII")))?;
    value
        .parse()
        .map_err(|_| RedisRespError::Protocol(format!("{kind} is not a valid unsigned integer")))
}

fn command_encoded_size(arguments: &[&[u8]]) -> RedisRespResult<usize> {
    command_encoded_size_from_lengths(arguments.len(), arguments.iter().map(|value| value.len()))
}

fn command_encoded_size_from_lengths(
    argument_count: usize,
    argument_lengths: impl IntoIterator<Item = usize>,
) -> RedisRespResult<usize> {
    let mut total = 1_usize
        .checked_add(decimal_digits(argument_count))
        .and_then(|size| size.checked_add(2))
        .ok_or_else(|| RedisRespError::Protocol("command length overflow".to_string()))?;
    for argument_length in argument_lengths {
        total = total
            .checked_add(1)
            .and_then(|size| size.checked_add(decimal_digits(argument_length)))
            .and_then(|size| size.checked_add(2))
            .and_then(|size| size.checked_add(argument_length))
            .and_then(|size| size.checked_add(2))
            .ok_or_else(|| RedisRespError::Protocol("command length overflow".to_string()))?;
    }
    Ok(total)
}

fn decimal_digits(mut value: usize) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

fn map_unexpected_eof(error: std::io::Error) -> RedisRespError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        RedisRespError::Protocol("unexpected EOF in RESP response".to_string())
    } else {
        RedisRespError::Io(error)
    }
}

#[cfg(test)]
mod tests;
