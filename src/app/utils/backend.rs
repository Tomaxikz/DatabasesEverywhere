use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::utils::protocol::Protocol;

pub const CONTAINER_SOCKET_DIRECTORY: &str = "/run/dbev";
pub const POSTGRES_SOCKET_DIRECTORY: &str = "/var/run/postgresql";
pub const MARIADB_SOCKET_DIRECTORY: &str = "/run/mysqld";
pub const MYSQL_SOCKET_DIRECTORY: &str = "/var/run/mysqld";
pub const SOCKET_BRIDGE_CONTAINER_PATH: &str = "/opt/dbev/dbev-socket-bridge";

const CLICKHOUSE_HTTP_SOCKET_FILENAME: &str = "clickhouse-http.sock";
const QDRANT_HTTP_SOCKET_FILENAME: &str = "qdrant-http.sock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackendEndpoint {
    UnixSocket {
        socket_path: String,
    },
    /// Legacy metadata only. New instances must use `UnixSocket`.
    DockerTcp {
        host: String,
        port: u16,
    },
}

pub fn backend_socket_path(socket_directory: &Path, protocol: Protocol) -> PathBuf {
    socket_directory.join(socket_filename(protocol))
}

pub fn container_backend_socket_path(protocol: Protocol) -> String {
    let engine = protocol.engine();
    format!(
        "{}/{}",
        engine.container_socket_directory(),
        engine.socket_filename()
    )
}

pub fn clickhouse_http_socket_path(native_socket_path: &Path) -> Option<PathBuf> {
    native_socket_path
        .parent()
        .map(|parent| parent.join(CLICKHOUSE_HTTP_SOCKET_FILENAME))
}

pub fn clickhouse_http_socket() -> String {
    format!("{CONTAINER_SOCKET_DIRECTORY}/{CLICKHOUSE_HTTP_SOCKET_FILENAME}")
}

pub fn qdrant_http_socket_path(grpc_socket_path: &Path) -> Option<PathBuf> {
    grpc_socket_path
        .parent()
        .map(|parent| parent.join(QDRANT_HTTP_SOCKET_FILENAME))
}

pub fn qdrant_http_socket() -> String {
    format!("{CONTAINER_SOCKET_DIRECTORY}/{QDRANT_HTTP_SOCKET_FILENAME}")
}

fn socket_filename(protocol: Protocol) -> &'static str {
    protocol.engine().socket_filename()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_each_protocol_to_a_private_socket() {
        let root = Path::new("/run/dbev/sockets/instance");

        assert_eq!(
            backend_socket_path(root, Protocol::Postgres),
            root.join(".s.PGSQL.5432")
        );
        assert_eq!(
            backend_socket_path(root, Protocol::Mariadb),
            root.join("mysqld.sock")
        );
        assert_eq!(
            backend_socket_path(root, Protocol::Mysql),
            root.join("mysqld.sock")
        );
        assert_eq!(
            container_backend_socket_path(Protocol::Mysql),
            "/var/run/mysqld/mysqld.sock"
        );
        assert_eq!(
            container_backend_socket_path(Protocol::Redis),
            "/run/dbev/redis.sock"
        );
        assert_eq!(
            container_backend_socket_path(Protocol::Valkey),
            "/run/dbev/valkey.sock"
        );
    }

    #[test]
    fn secondary_protocol_sockets_are_distinct_siblings() {
        assert_eq!(
            clickhouse_http_socket_path(Path::new("/run/private/clickhouse-native.sock")),
            Some(PathBuf::from("/run/private/clickhouse-http.sock"))
        );
        assert_eq!(
            qdrant_http_socket_path(Path::new("/run/private/qdrant-grpc.sock")),
            Some(PathBuf::from("/run/private/qdrant-http.sock"))
        );
    }
}
