use std::sync::Arc;

use tokio::io::{
    self, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

const MYSQL_COM_CHANGE_USER: u8 = 0x11;
const MYSQL_COM_CREATE_DB: u8 = 0x05;
const MYSQL_COM_DROP_DB: u8 = 0x06;
const MYSQL_COM_QUERY: u8 = 0x03;
const MYSQL_COM_STMT_PREPARE: u8 = 0x16;
const MYSQL_COM_STMT_EXECUTE: u8 = 0x17;
const MYSQL_MAX_SINGLE_PACKET_PAYLOAD: usize = 0x00ff_ffff;
const MONGODB_OP_QUERY: i32 = 2004;
const MONGODB_OP_COMPRESSED: i32 = 2012;
const MONGODB_OP_MSG: i32 = 2013;
const MONGODB_MAX_CSTRING_BYTES: usize = 1024;

use super::GatewayStream;
use crate::{gateway::tunnel, server::monitoring::ActivityCounter};

const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;
const SQL_PREFIX_BYTES: usize = 512;
const QUERY_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(super) type MysqlTunnel = (
    GatewayStream,
    tunnel::MeteredBackend<tunnel::BackendStream>,
    bool,
    Arc<ActivityCounter>,
);
pub(super) type MongodbTunnel = (
    GatewayStream,
    tunnel::MeteredBackend<tunnel::BackendStream>,
    Arc<ActivityCounter>,
);

struct ActivitySession(Arc<ActivityCounter>);

impl ActivitySession {
    fn open(counter: Arc<ActivityCounter>) -> Self {
        counter.connection_opened();
        Self(counter)
    }
}

impl Drop for ActivitySession {
    fn drop(&mut self) {
        self.0.connection_closed();
    }
}

const FRAME_READ_AHEAD: usize = 1024;
const TAIL_CHUNK_BYTES: usize = 8 * 1024;

#[derive(Default)]
struct FrameBuffers {
    prefix: Vec<u8>,
    tail: Vec<u8>,
}

impl FrameBuffers {
    /// Forward the validated prefix immediately, including any bytes of this frame
    /// already in the reader. Retain the requested body prefix for classification.
    async fn forward(
        &mut self,
        reader: &mut BufReader<impl AsyncRead + Unpin>,
        writer: &mut (impl AsyncWrite + Unpin),
        mut remaining: usize,
        capture: usize,
        eof: &'static str,
    ) -> io::Result<&[u8]> {
        let body_start = self.prefix.len();
        let capture_end = body_start + capture.min(remaining);
        let ready = remaining.min(reader.buffer().len());
        self.prefix.extend_from_slice(&reader.buffer()[..ready]);
        reader.consume(ready);
        writer.write_all(&self.prefix).await?;
        remaining -= ready;

        while remaining > 0 {
            let chunk = remaining.min(TAIL_CHUNK_BYTES);
            if self.tail.len() < chunk {
                self.tail.resize(chunk, 0);
            }
            let n = reader.read(&mut self.tail[..chunk]).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, eof));
            }
            let keep = capture_end.saturating_sub(self.prefix.len()).min(n);
            self.prefix.extend_from_slice(&self.tail[..keep]);
            writer.write_all(&self.tail[..n]).await?;
            remaining -= n;
        }
        writer.flush().await?;
        Ok(&self.prefix[body_start..capture_end])
    }
}

mod classify;
mod handshake;
mod mongodb;
mod mysql;
mod postgres;
#[cfg(test)]
mod tests;

pub(super) use handshake::{
    accept_direct_tls, read_clickhouse_hello, read_http_headers, read_resp_initial_frame,
};
pub(super) use mongodb::proxy_mongodb_session;
pub(super) use mysql::proxy_mysql_session;
pub(super) use postgres::proxy_postgres_session;
