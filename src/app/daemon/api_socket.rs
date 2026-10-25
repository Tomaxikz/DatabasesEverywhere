//! The API on a Unix socket. It is always served, with the router TCP uses,
//! so `dbev --cli` reaches standalone nodes whose network API is off.

use std::{
    ffi::OsStr,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::{
        fd::OwnedFd,
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::{SocketAddr as UnixSocketAddr, UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
};

use anyhow::Context;
use axum::{Extension, Router, extract::ConnectInfo};
use axum_server::{Handle, accept::DefaultAcceptor};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};

use super::{
    admission::ApiConnectionAcceptor, runtime_paths::create_runtime_dirs,
    server::configure_api_http,
};

/// Socket clients have no address. They all share this one, so per-peer
/// limits, rate limits and request logs see the socket as one local peer.
pub(super) const API_SOCKET_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

const SOCKET_MODE: u32 = 0o600;

pub(super) struct ApiSocket {
    listener: UnixListener,
    file: SocketFile,
}

impl ApiSocket {
    /// Binds `path` with mode 0600 in a private daemon-owned directory,
    /// replacing a socket left by an earlier run but nothing else.
    pub(super) fn bind(path: &str) -> anyhow::Result<Self> {
        let path = PathBuf::from(path);
        let (Some(directory_path), Some(name)) = (path.parent(), path.file_name()) else {
            anyhow::bail!("api socket path {} has no file name", path.display());
        };
        let directory = private_directory(directory_path)?;
        remove_stale_socket(&directory, name, &path)?;

        // The process umask (0077) leaves the new socket owner-only until it
        // is set to exactly 0600 below.
        let listener = UnixListener::bind(&path)
            .with_context(|| format!("failed to bind API socket {}", path.display()))?;
        rustix::fs::chmodat(
            &directory,
            name,
            Mode::from_raw_mode(SOCKET_MODE),
            AtFlags::empty(),
        )
        .map_err(std::io::Error::from)
        .with_context(|| format!("failed to restrict API socket {} to 0600", path.display()))?;
        let stat = rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)
            .with_context(|| format!("failed to inspect API socket {}", path.display()))?;
        let daemon_uid = rustix::process::geteuid().as_raw();
        if FileType::from_raw_mode(stat.st_mode) != FileType::Socket
            || stat.st_uid != daemon_uid
            || stat.st_mode & 0o7777 != SOCKET_MODE
        {
            anyhow::bail!(
                "api socket {} must be a socket owned by uid {daemon_uid} with mode 0600",
                path.display()
            );
        }
        listener
            .set_nonblocking(true)
            .context("failed to configure the API socket as non-blocking")?;
        tracing::info!(path = %path.display(), mode = "0600", "api socket listener started");
        Ok(Self {
            listener,
            file: SocketFile {
                path,
                device: stat.st_dev,
                inode: stat.st_ino,
            },
        })
    }

    /// Serves until `handle` shuts down, then removes the socket file.
    pub(super) async fn serve(
        self,
        router: Router,
        acceptor: ApiConnectionAcceptor<DefaultAcceptor>,
        handle: Handle<UnixSocketAddr>,
    ) -> anyhow::Result<()> {
        let Self {
            listener,
            file: _file,
        } = self;
        let mut server = axum_server::from_unix(listener)
            .context("failed to create API socket server")?
            .acceptor(acceptor);
        configure_api_http(&mut server);
        server
            .handle(handle)
            .serve(
                router
                    .layer(Extension(ConnectInfo(API_SOCKET_PEER)))
                    .into_make_service(),
            )
            .await
            .context("api socket server failed")
    }
}

/// Creates the socket's directory like a runtime root and restricts it to
/// 0700. A rootless Podman traversal grant (0710) is kept: the socket's own
/// mode still admits only the daemon user.
fn private_directory(path: &Path) -> anyhow::Result<OwnedFd> {
    create_runtime_dirs(path).with_context(|| {
        format!(
            "failed to securely create API socket directory {}",
            path.display()
        )
    })?;
    crate::io::ownership::secure_private_dir_keeping_traversal(path).with_context(|| {
        format!(
            "failed to restrict API socket directory {} to mode 0700",
            path.display()
        )
    })?;
    let directory = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| {
        format!(
            "failed to securely open API socket directory {}",
            path.display()
        )
    })?;
    let stat = rustix::fs::fstat(&directory).map_err(std::io::Error::from)?;
    super::runtime_paths::require_runtime_owner(
        path,
        stat.st_uid,
        rustix::process::geteuid().as_raw(),
    )?;
    Ok(directory)
}

/// Removes a socket file left by a daemon that is gone. Never follows a
/// symlink, and refuses anything else, including a socket still served.
fn remove_stale_socket(directory: &OwnedFd, name: &OsStr, path: &Path) -> anyhow::Result<()> {
    let stat = match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => {
            return Err(std::io::Error::from(error))
                .with_context(|| format!("failed to inspect API socket {}", path.display()));
        }
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::Socket {
        anyhow::bail!(
            "refusing to replace {}: it exists and is not a socket",
            path.display()
        );
    }
    if UnixStream::connect(path).is_ok() {
        anyhow::bail!(
            "another process is serving the API socket {}",
            path.display()
        );
    }
    rustix::fs::unlinkat(directory, name, AtFlags::empty())
        .map_err(std::io::Error::from)
        .with_context(|| format!("failed to remove stale API socket {}", path.display()))?;
    tracing::info!(path = %path.display(), "removed stale api socket");
    Ok(())
}

/// The bound socket file, removed when serving ends unless it was replaced.
struct SocketFile {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if !metadata.file_type().is_socket()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return;
        }
        if let Err(error) = fs::remove_file(&self.path) {
            tracing::warn!(%error, path = %self.path.display(), "failed to remove api socket");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, time::Duration};

    use reqwest::StatusCode;

    use super::*;
    use crate::{
        auth::api_token::ApiToken,
        config::Config,
        routes::http::router::build_router,
        server::{manager::InstanceManager, state::InstanceStore},
        storage::{repositories::InstanceRepository, sqlite},
        subsystems::test_support,
    };

    const TOKEN: &str = "test-api-token-0123456789abcdef-01";

    #[tokio::test]
    async fn serves_the_api_router_with_a_local_peer_identity() {
        let directory = tempfile::tempdir().unwrap();
        let socket_directory = directory.path().join("run");
        fs::create_dir(&socket_directory).unwrap();
        fs::set_permissions(&socket_directory, fs::Permissions::from_mode(0o755)).unwrap();
        let path = socket_directory.join("api.sock");
        drop(UnixListener::bind(&path).unwrap());

        let socket = ApiSocket::bind(&path.display().to_string()).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(
            fs::metadata(&socket_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );

        let state_directory = tempfile::tempdir().unwrap();
        let router = build_router(test_state(state_directory.path()).await);
        let acceptor =
            ApiConnectionAcceptor::new((), &Default::default()).sharing(DefaultAcceptor::new());
        let handle = Handle::new();
        let server = tokio::spawn(socket.serve(router, acceptor, handle.clone()));
        handle.listening().await.unwrap();

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = reqwest::Client::builder()
            .unix_socket(path.as_path())
            .build()
            .unwrap();
        let response = client
            .get("http://localhost/api/system")
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["api_version"], crate::subsystems::system::API_VERSION);

        let response = client
            .get("http://localhost/api/system")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Download handlers extract the peer address; without one they fail.
        let response = client
            .get("http://localhost/api/instances/inst_one/artifacts/art_one/download?token=bad")
            .send()
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        handle.graceful_shutdown(Some(Duration::from_secs(1)));
        server.await.unwrap().unwrap();
        assert!(fs::symlink_metadata(&path).is_err());
    }

    #[test]
    fn refuses_to_replace_anything_but_a_stale_socket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("api.sock");

        fs::write(&path, b"keep").unwrap();
        let error = ApiSocket::bind(&path.display().to_string()).err().unwrap();
        assert!(error.to_string().contains("is not a socket"), "{error:#}");
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        fs::remove_file(&path).unwrap();

        let target = directory.path().join("target.sock");
        let _target = UnixListener::bind(&target).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let error = ApiSocket::bind(&path.display().to_string()).err().unwrap();
        assert!(error.to_string().contains("is not a socket"), "{error:#}");
        assert!(
            fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_socket()
        );
        fs::remove_file(&path).unwrap();

        let _live = UnixListener::bind(&path).unwrap();
        let error = ApiSocket::bind(&path.display().to_string()).err().unwrap();
        assert!(error.to_string().contains("another process"), "{error:#}");
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
    }

    async fn test_state(directory: &Path) -> crate::state::AppState {
        let pool = sqlite::connect(directory).await.unwrap();
        let instances = InstanceStore::default();
        let manager =
            InstanceManager::new(instances.clone(), InstanceRepository::new(pool.clone()));
        let config = Config {
            uuid: "node-uuid".to_string(),
            token_id: "token-id".to_string(),
            token: TOKEN.to_string(),
            jwt_signing_key: "test-jwt-signing-key-0123456789abcdef-02".to_string(),
            ..Default::default()
        };
        let api_token = ApiToken::from_config(&config);
        test_support::state(
            config,
            directory.join("config.yml"),
            api_token,
            instances,
            manager,
            pool,
        )
    }
}
