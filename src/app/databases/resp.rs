use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};

use crate::{
    protocols::redis::password_route_sha256,
    runtime::docker::{DockerInstanceSpec, DockerMount},
    shared::{
        backend::{CONTAINER_SOCKET_DIRECTORY, container_backend_socket_path},
        files::atomic_write_private,
        protocol::Protocol,
    },
};

pub(crate) fn instance_spec(
    protocol: Protocol,
    instance_id: &str,
    image: &str,
    data_path: PathBuf,
    logs_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    let server = match protocol {
        Protocol::Redis => "redis-server",
        Protocol::Valkey => "valkey-server",
        _ => panic!("RESP container spec requires Redis or Valkey"),
    };

    DockerInstanceSpec {
        instance_id: instance_id.to_string(),
        protocol,
        image: image.to_string(),
        project_id: None,
        user: None,
        working_dir: None,
        entrypoint: None,
        cpu_cores: 1.0,
        memory_mib: 512,
        disk_mib: 10240,
        pids_limit: None,
        data_path,
        data_target: "/data".to_string(),
        logs_path,
        logs_target: "/logs".to_string(),
        extra_mounts: vec![DockerMount {
            source: runtime_path,
            target: CONTAINER_SOCKET_DIRECTORY.to_string(),
            read_only: false,
        }],
        socket_bridges: Vec::new(),
        env: Vec::new(),
        command: vec![
            server.to_string(),
            "--appendonly".to_string(),
            "yes".to_string(),
            "--aclfile".to_string(),
            "/data/users.acl".to_string(),
            "--port".to_string(),
            "0".to_string(),
            "--unixsocket".to_string(),
            container_backend_socket_path(protocol),
            "--unixsocketperm".to_string(),
            "660".to_string(),
        ],
    }
}

pub(crate) async fn write_acl_file(
    data_path: &Path,
    username: &str,
    password: &SecretString,
) -> Result<(), RespProvisionError> {
    validate_acl_username(username)?;

    let password_hash = password_route_sha256(password.expose_secret().as_bytes());
    let acl = tenant_acl(username, &password_hash);
    replace_acl_file(data_path, acl.into_bytes()).await
}

/// Restores previously captured ACL bytes during a failed credential
/// rotation. The destination is replaced without following a container-made
/// symlink and is durably committed before the database is restarted.
pub(crate) async fn restore_acl_file(
    data_path: &Path,
    acl: &[u8],
) -> Result<(), RespProvisionError> {
    replace_acl_file(data_path, acl.to_vec()).await
}

async fn replace_acl_file(data_path: &Path, contents: Vec<u8>) -> Result<(), RespProvisionError> {
    let path = data_path.join("users.acl");
    let write_path = path.clone();
    tokio::task::spawn_blocking(move || atomic_write_private(&write_path, &contents))
        .await
        .map_err(|error| RespProvisionError::WriteAcl {
            path: path.display().to_string(),
            source: std::io::Error::other(error),
        })?
        .map_err(|source| RespProvisionError::WriteAcl {
            path: path.display().to_string(),
            source,
        })
}

fn validate_acl_username(username: &str) -> Result<(), RespProvisionError> {
    if username.is_empty()
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
        || username.eq_ignore_ascii_case("dbe_health")
    {
        return Err(RespProvisionError::InvalidUsername);
    }
    Ok(())
}

fn tenant_acl(username: &str, password_hash: &str) -> String {
    let health = "user dbe_health on nopass -@all +ping\n";
    if username == "default" {
        format!("user default on #{password_hash} ~* &* +@all\n{health}")
    } else {
        format!("user default off\n{health}user {username} on #{password_hash} ~* &* +@all\n")
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RespProvisionError {
    #[error(
        "database ACL username may only contain ascii letters, digits, _, -, ., and @ and may not be dbe_health"
    )]
    InvalidUsername,
    #[error("failed to write database ACL file {path}: {source}")]
    WriteAcl {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_private_redis_and_valkey_specs() {
        for (protocol, image, server, socket) in [
            (
                Protocol::Redis,
                "redis:8.8.0",
                "redis-server",
                "/run/dbev/redis.sock",
            ),
            (
                Protocol::Valkey,
                "valkey/valkey:9.1.1",
                "valkey-server",
                "/run/dbev/valkey.sock",
            ),
        ] {
            let spec = instance_spec(
                protocol,
                "instance",
                image,
                PathBuf::from("/tmp/data"),
                PathBuf::from("/tmp/logs"),
                PathBuf::from("/tmp/run"),
            );

            assert_eq!(spec.protocol, protocol);
            assert_eq!(spec.image, image);
            assert_eq!(spec.command[0], server);
            assert_eq!(spec.extra_mounts[0].target, CONTAINER_SOCKET_DIRECTORY);
            assert!(spec.command.windows(2).any(|args| args == ["--port", "0"]));
            assert!(
                spec.command
                    .windows(2)
                    .any(|args| args == ["--unixsocket", socket])
            );
            assert!(spec.socket_bridges.is_empty());
        }
    }

    #[test]
    fn rejects_unsafe_or_reserved_acl_usernames() {
        for username in ["bad name", "dbe_health"] {
            assert!(
                matches!(
                    validate_acl_username(username),
                    Err(RespProvisionError::InvalidUsername)
                ),
                "accepted ACL username: {username}"
            );
        }
    }

    #[test]
    fn acl_generation_handles_default_and_named_tenants() {
        let acl = tenant_acl("default", "abc123");

        assert_eq!(acl.matches("user default ").count(), 1);
        assert!(acl.contains("user default on #abc123 ~* &* +@all"));
        assert!(acl.contains("user dbe_health on nopass -@all +ping"));

        let acl = tenant_acl("app_redis", "abc123");

        assert!(acl.contains("user default off"));
        assert!(acl.contains("user app_redis on #abc123 ~* &* +@all"));
        assert!(acl.contains("user dbe_health on nopass -@all +ping"));
    }

    #[tokio::test]
    async fn acl_replacement_does_not_follow_the_destination_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim");
        let acl = directory.path().join("users.acl");
        std::fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, &acl).unwrap();

        write_acl_file(
            directory.path(),
            "app_user",
            &SecretString::from("new-password"),
        )
        .await
        .unwrap();

        assert_eq!(std::fs::read(victim).unwrap(), b"untouched");
        assert!(!std::fs::symlink_metadata(acl).unwrap().is_symlink());
    }
}
