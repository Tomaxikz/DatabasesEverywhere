use std::{fmt, net::SocketAddr, path::Path, time::Duration};

use secrecy::{ExposeSecret, SecretString};

use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    net::{TcpStream, UnixStream},
    time::{Instant, timeout_at},
};

use super::security::ResolvedRemoteEndpoint;

mod types;
pub use types::{
    RedisRelayError, RedisRespError, RedisRespResult, RedisRestoreExpiration, RespLimits,
    RespValue, ScanPage,
};
mod budget;
mod helpers;
use helpers::{expect_simple, parse_scan_page, tls_connector, tls_server_name, unexpected};
mod reader;
mod restore;

const RELAY_BUFFER_BYTES: usize = 64 * 1024;
const RESTORE_SERIALIZED_VALUE_ARGUMENT_INDEX: usize = 3;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

type BoxedIo = Box<dyn AsyncReadWrite>;

pub struct RespConnection {
    pub(super) io: BufReader<BoxedIo>,
    pub(super) limits: RespLimits,
    pub(super) read_timeout: Duration,
    pub(super) write_timeout: Duration,
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
    pub async fn connect_source_limited(
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

    pub async fn connect_unix_limited(
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

    pub async fn flushdb(&mut self) -> RedisRespResult<()> {
        let response = self.command(&[b"FLUSHDB"]).await?;
        expect_simple(response, "FLUSHDB", b"OK")
    }

    pub async fn acl_load(&mut self) -> RedisRespResult<()> {
        let response = self.command(&[b"ACL", b"LOAD"]).await?;
        expect_simple(response, "ACL LOAD", b"OK")
    }
}

#[cfg(test)]
mod tests;
