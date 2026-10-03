use std::sync::Arc;
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;

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

use super::{GatewayStream, ListenerError};
use crate::{
    gateway::protocols::{clickhouse, mariadb, redis},
    gateway::tunnel,
    instance::monitoring::{ActivityCounter, OperationKind},
    subsystems::import_export::inspection::validate_shared_mysql_command,
    utils::protocol::Protocol,
};

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

async fn copy_exact(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    bytes: usize,
    eof: &'static str,
) -> Result<(), ListenerError> {
    let mut payload = reader.take(bytes as u64);
    if io::copy(&mut payload, writer).await? != bytes as u64 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, eof).into());
    }
    Ok(())
}

mod classify;
mod handshake;
mod mongodb;
mod mysql;
mod postgres;
#[cfg(test)]
mod tests;

use classify::*;
pub(super) use handshake::*;
pub(super) use mongodb::*;
pub(super) use mysql::*;
pub(super) use postgres::*;
