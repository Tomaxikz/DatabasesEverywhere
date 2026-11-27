//! Endpoint configuration, its validation and the QUIC transport settings derived from it.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{IdleTimeout, TransportConfig, VarInt};

use super::BindError;
use crate::identity::Identity;

/// Most streams one peer may be allowed to have open on one connection. quinn sets up
/// bookkeeping for every stream credit it advertises, so this bounds that work.
pub const MAX_STREAMS_PER_PEER_LIMIT: u32 = 16_384;
/// Largest `accept_backlog`: every queued entry holds a stream and its connection.
pub const MAX_ACCEPT_BACKLOG_LIMIT: usize = 65_536;
/// Largest `max_connections` and `max_handshakes`.
pub const MAX_CONNECTIONS_LIMIT: usize = 65_536;
/// Smallest `stream_receive_window`: the stream header and status must fit comfortably.
pub const MIN_STREAM_WINDOW: u32 = 16 * 1024;
/// Largest receive window of a stream or connection.
pub const MAX_WINDOW: u32 = 1 << 30;
/// Longest accepted value of any duration setting: one day. Longer ones are not practical
/// and would overflow the absolute deadlines built from them.
pub const MAX_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// Settings of a [`Tether`](super::Tether). Build one with [`Config::new`] and set the
/// public fields you want to change; new fields may be added without a breaking change.
#[derive(Debug)]
#[non_exhaustive]
pub struct Config {
    /// UDP address to listen on and dial from.
    pub bind: SocketAddr,
    pub identity: Identity,
    /// Streams one peer may have open to this node at once, per connection (1 to
    /// [`MAX_STREAMS_PER_PEER_LIMIT`]). Default 1024.
    pub max_streams_per_peer: u32,
    /// Accepted streams waiting for the application to take them (1 to
    /// [`MAX_ACCEPT_BACKLOG_LIMIT`]). Beyond this, new streams are answered with
    /// `Status::Unavailable`. Default 256.
    pub accept_backlog: usize,
    /// Time allowed for the header exchange on one stream, in either direction, including
    /// the status writes on the answering side. Default 5 s. Every duration setting is
    /// at most one day.
    pub header_timeout: Duration,
    /// Time allowed to establish a connection to a peer. Default 10 s.
    pub connect_timeout: Duration,
    /// A connection with no traffic for this long is closed (at least 1 ms). Default 30 s.
    pub idle_timeout: Duration,
    /// Interval of keep-alive packets on an otherwise idle connection. Must be shorter than
    /// `idle_timeout` to keep connections with open but silent streams alive. Default 10 s.
    pub keep_alive: Duration,
    /// Live inbound connections across all peers (1 to [`MAX_CONNECTIONS_LIMIT`]). A
    /// connection over the limit is closed as soon as its peer is known. Default 256.
    pub max_connections: usize,
    /// Live inbound connections from one authenticated node, at most `max_connections`.
    /// Default 2: one is normal, the second lets a node that lost its first connection
    /// reconnect before this side noticed.
    pub max_connections_per_peer: usize,
    /// Inbound handshakes in progress at once (1 to [`MAX_CONNECTIONS_LIMIT`]). Attempts
    /// beyond it are refused; once more than half are in use, peers whose address is not
    /// yet validated are asked to retry first. Default 64.
    pub max_handshakes: usize,
    /// Time an inbound handshake may take before it is dropped. Default 10 s.
    pub handshake_timeout: Duration,
    /// Bytes a peer may send on one stream before the reader must catch up
    /// ([`MIN_STREAM_WINDOW`] to [`MAX_WINDOW`]). Default 1 MiB.
    pub stream_receive_window: u32,
    /// Bytes a peer may send across all streams of a connection before the readers must
    /// catch up (at least `stream_receive_window`, at most [`MAX_WINDOW`]). Default 32 MiB.
    pub connection_receive_window: u32,
}

impl Config {
    /// A configuration with conservative defaults for everything but the two required
    /// values.
    pub fn new(bind: SocketAddr, identity: Identity) -> Self {
        Self {
            bind,
            identity,
            max_streams_per_peer: 1024,
            accept_backlog: 256,
            header_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            keep_alive: Duration::from_secs(10),
            max_connections: 256,
            max_connections_per_peer: 2,
            max_handshakes: 64,
            handshake_timeout: Duration::from_secs(10),
            stream_receive_window: 1024 * 1024,
            connection_receive_window: 32 * 1024 * 1024,
        }
    }
}

pub(super) fn validate(config: &Config) -> Result<(), BindError> {
    if !(1..=MAX_STREAMS_PER_PEER_LIMIT).contains(&config.max_streams_per_peer) {
        return Err(BindError::Config(
            "max_streams_per_peer must be between 1 and 16384",
        ));
    }
    if !(1..=MAX_ACCEPT_BACKLOG_LIMIT).contains(&config.accept_backlog) {
        return Err(BindError::Config(
            "accept_backlog must be between 1 and 65536",
        ));
    }
    for (value, name) in [
        (
            config.header_timeout,
            "header_timeout must be between 1 ns and one day",
        ),
        (
            config.connect_timeout,
            "connect_timeout must be between 1 ns and one day",
        ),
        (
            config.keep_alive,
            "keep_alive must be between 1 ns and one day",
        ),
        (
            config.handshake_timeout,
            "handshake_timeout must be between 1 ns and one day",
        ),
    ] {
        if value.is_zero() || value > MAX_DURATION {
            return Err(BindError::Config(name));
        }
    }
    if config.idle_timeout > MAX_DURATION {
        return Err(BindError::Config("idle_timeout must be at most one day"));
    }
    // QUIC carries the idle timeout in whole milliseconds; a smaller one would become zero,
    // which means "never".
    if config.idle_timeout < Duration::from_millis(1) {
        return Err(BindError::Config("idle_timeout must be at least 1 ms"));
    }
    // QUIC encodes the idle timeout in whole milliseconds, so compare against that.
    let encoded_idle =
        Duration::from_millis(u64::try_from(config.idle_timeout.as_millis()).unwrap_or(u64::MAX));
    if config.keep_alive >= encoded_idle {
        return Err(BindError::Config(
            "keep_alive must be shorter than idle_timeout",
        ));
    }
    if !(1..=MAX_CONNECTIONS_LIMIT).contains(&config.max_connections) {
        return Err(BindError::Config(
            "max_connections must be between 1 and 65536",
        ));
    }
    if !(1..=config.max_connections).contains(&config.max_connections_per_peer) {
        return Err(BindError::Config(
            "max_connections_per_peer must be between 1 and max_connections",
        ));
    }
    if !(1..=MAX_CONNECTIONS_LIMIT).contains(&config.max_handshakes) {
        return Err(BindError::Config(
            "max_handshakes must be between 1 and 65536",
        ));
    }
    if !(MIN_STREAM_WINDOW..=MAX_WINDOW).contains(&config.stream_receive_window) {
        return Err(BindError::Config(
            "stream_receive_window must be between 16 KiB and 1 GiB",
        ));
    }
    if !(config.stream_receive_window..=MAX_WINDOW).contains(&config.connection_receive_window) {
        return Err(BindError::Config(
            "connection_receive_window must be between stream_receive_window and 1 GiB",
        ));
    }
    Ok(())
}

/// Which way a connection is used. They differ only in the streams the peer may open.
#[derive(Clone, Copy)]
pub(super) enum Role {
    /// Accepts connections; peers open streams on them.
    Listening,
    /// Dials connections; only this side opens streams on them, so the peer gets none.
    Dialing,
}

pub(super) fn transport(config: &Config, role: Role) -> Result<Arc<TransportConfig>, BindError> {
    let idle = IdleTimeout::try_from(config.idle_timeout)
        .map_err(|_| BindError::Config("idle_timeout is too large"))?;
    let peer_streams = match role {
        Role::Listening => config.max_streams_per_peer,
        Role::Dialing => 0,
    };
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(peer_streams))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(config.stream_receive_window))
        .receive_window(VarInt::from_u32(config.connection_receive_window))
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0)
        .max_idle_timeout(Some(idle))
        .keep_alive_interval(Some(config.keep_alive));
    Ok(Arc::new(transport))
}
