use std::path::Path;

use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::shared::files::atomic_write_private;

pub async fn write_acl_file(
    data_path: &Path,
    username: &str,
    password: &SecretString,
) -> Result<(), RedisProvisionError> {
    validate_acl_username(username)?;

    let password_hash = sha256_hex(password.expose_secret().as_bytes());
    let acl = redis_acl(username, &password_hash);
    replace_acl_file(data_path, acl.into_bytes()).await
}

/// Restores previously captured ACL bytes during a failed credential
/// rotation. The destination is replaced without following a container-made
/// symlink and is durably committed before the database is restarted.
pub async fn restore_acl_file(data_path: &Path, acl: &[u8]) -> Result<(), RedisProvisionError> {
    replace_acl_file(data_path, acl.to_vec()).await
}

async fn replace_acl_file(data_path: &Path, contents: Vec<u8>) -> Result<(), RedisProvisionError> {
    let path = data_path.join("users.acl");
    let write_path = path.clone();
    tokio::task::spawn_blocking(move || atomic_write_private(&write_path, &contents))
        .await
        .map_err(|error| RedisProvisionError::WriteAcl {
            path: path.display().to_string(),
            source: std::io::Error::other(error),
        })?
        .map_err(|source| RedisProvisionError::WriteAcl {
            path: path.display().to_string(),
            source,
        })
}

fn validate_acl_username(username: &str) -> Result<(), RedisProvisionError> {
    if username.is_empty()
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
        || username.eq_ignore_ascii_case("dbe_health")
    {
        return Err(RedisProvisionError::InvalidUsername);
    }
    Ok(())
}

fn redis_acl(username: &str, password_hash: &str) -> String {
    let health = "user dbe_health on nopass -@all +ping\n";
    if username == "default" {
        format!("user default on #{password_hash} ~* &* +@all\n{health}")
    } else {
        format!("user default off\n{health}user {username} on #{password_hash} ~* &* +@all\n")
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[derive(Debug, thiserror::Error)]
pub enum RedisProvisionError {
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
    fn rejects_acl_username_with_whitespace() {
        let error = validate_acl_username("bad name").unwrap_err();

        assert!(matches!(error, RedisProvisionError::InvalidUsername));
    }

    #[test]
    fn rejects_reserved_health_username() {
        let error = validate_acl_username("dbe_health").unwrap_err();

        assert!(matches!(error, RedisProvisionError::InvalidUsername));
    }

    #[test]
    fn default_user_acl_does_not_duplicate_default() {
        let acl = redis_acl("default", "abc123");

        assert_eq!(acl.matches("user default ").count(), 1);
        assert!(acl.contains("user default on #abc123 ~* &* +@all"));
        assert!(acl.contains("user dbe_health on nopass -@all +ping"));
    }

    #[test]
    fn named_user_acl_disables_default_user() {
        let acl = redis_acl("app_redis", "abc123");

        assert!(acl.contains("user default off"));
        assert!(acl.contains("user app_redis on #abc123 ~* &* +@all"));
        assert!(acl.contains("user dbe_health on nopass -@all +ping"));
    }

    #[test]
    fn hashes_password_as_sha256_hex() {
        assert_eq!(
            sha256_hex(b"test-password"),
            "c638833f69bbfb3c267afa0a74434812436b8f08a81fd263c6be6871de4f1265"
        );
    }

    #[cfg(unix)]
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
