use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::shared::protocol::Protocol;

pub const CONTAINER_SOCKET_DIRECTORY: &str = "/run/dbev";
pub const POSTGRES_SOCKET_DIRECTORY: &str = "/var/run/postgresql";
pub const MARIADB_SOCKET_DIRECTORY: &str = "/run/mysqld";
pub const MYSQL_SOCKET_DIRECTORY: &str = "/var/run/mysqld";
pub const SOCKET_BRIDGE_CONTAINER_PATH: &str = "/opt/dbev/dbev-socket-bridge";

const POSTGRES_SOCKET_FILENAME: &str = ".s.PGSQL.5432";
const MARIADB_SOCKET_FILENAME: &str = "mysqld.sock";
const MYSQL_SOCKET_FILENAME: &str = "mysqld.sock";
const REDIS_SOCKET_FILENAME: &str = "redis.sock";
const MONGODB_SOCKET_FILENAME: &str = "mongodb-27017.sock";
const CLICKHOUSE_NATIVE_SOCKET_FILENAME: &str = "clickhouse-native.sock";
const CLICKHOUSE_HTTP_SOCKET_FILENAME: &str = "clickhouse-http.sock";
const QDRANT_GRPC_SOCKET_FILENAME: &str = "qdrant-grpc.sock";

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
    let directory = match protocol {
        Protocol::Postgres => POSTGRES_SOCKET_DIRECTORY,
        Protocol::Mariadb => MARIADB_SOCKET_DIRECTORY,
        Protocol::Mysql => MYSQL_SOCKET_DIRECTORY,
        Protocol::Redis | Protocol::Mongodb | Protocol::Clickhouse | Protocol::Qdrant => {
            CONTAINER_SOCKET_DIRECTORY
        }
    };
    format!("{directory}/{}", socket_filename(protocol))
}

pub fn clickhouse_http_socket_path(native_socket_path: &Path) -> Option<PathBuf> {
    native_socket_path
        .parent()
        .map(|parent| parent.join(CLICKHOUSE_HTTP_SOCKET_FILENAME))
}

pub fn container_clickhouse_http_socket_path() -> String {
    format!("{CONTAINER_SOCKET_DIRECTORY}/{CLICKHOUSE_HTTP_SOCKET_FILENAME}")
}

fn socket_filename(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => POSTGRES_SOCKET_FILENAME,
        Protocol::Redis => REDIS_SOCKET_FILENAME,
        Protocol::Mariadb => MARIADB_SOCKET_FILENAME,
        Protocol::Mysql => MYSQL_SOCKET_FILENAME,
        Protocol::Mongodb => MONGODB_SOCKET_FILENAME,
        Protocol::Clickhouse => CLICKHOUSE_NATIVE_SOCKET_FILENAME,
        Protocol::Qdrant => QDRANT_GRPC_SOCKET_FILENAME,
    }
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
    }

    #[test]
    fn clickhouse_http_socket_is_a_sibling_of_native_socket() {
        assert_eq!(
            clickhouse_http_socket_path(Path::new("/run/private/clickhouse-native.sock")),
            Some(PathBuf::from("/run/private/clickhouse-http.sock"))
        );
    }
}
