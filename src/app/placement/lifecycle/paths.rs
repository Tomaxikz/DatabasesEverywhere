use std::path::{Component, Path};

use anyhow::{Context, bail, ensure};
use rustix::{
    fs::{Mode, OFlags, fchmod, fchown, fstat, mkdirat, open, openat},
    process::{Gid, Uid},
};

use crate::{
    api::http::state::AppState,
    instances::paths::InstancePaths,
    placement::EngineRuntime,
    shared::{
        backend::{
            CONTAINER_SOCKET_DIRECTORY, MARIADB_SOCKET_DIRECTORY, MYSQL_SOCKET_DIRECTORY,
            POSTGRES_SOCKET_DIRECTORY,
        },
        ownership::HostOwner,
        protocol::Protocol,
    },
};

/// Boot and API power operations hold the pool lock before entering here.
/// Restore only volatile sockets, never missing data/configuration directories.
pub(crate) async fn prepare_socket_directory(
    state: &AppState,
    runtime: &EngineRuntime,
) -> anyhow::Result<()> {
    let paths = InstancePaths::new(&state.config.paths, &runtime.runtime_id)?;
    let target = socket_target(runtime.protocol)?;
    let source = state
        .docker
        .container_bind_source(runtime.protocol, &runtime.runtime_id, target)
        .await?;
    ensure!(
        source.as_deref() == Some(paths.sockets.as_path()),
        "shared pool socket bind does not match the configured runtime path"
    );
    let configured_user = state
        .docker
        .configured_container_user(runtime.protocol, &runtime.runtime_id)
        .await?;
    let owner = socket_owner(
        state.docker.rootless_podman_host_owner(),
        configured_user.as_deref(),
    )?;
    let sockets = paths.sockets;
    tokio::task::spawn_blocking(move || ensure_socket_directory(&sockets, owner))
        .await
        .context("shared pool socket preparation task failed")??;
    Ok(())
}

fn socket_target(protocol: Protocol) -> anyhow::Result<&'static str> {
    match protocol {
        Protocol::Postgres => Ok(POSTGRES_SOCKET_DIRECTORY),
        Protocol::Mysql => Ok(MYSQL_SOCKET_DIRECTORY),
        Protocol::Mariadb => Ok(MARIADB_SOCKET_DIRECTORY),
        Protocol::Mongodb | Protocol::Clickhouse => Ok(CONTAINER_SOCKET_DIRECTORY),
        _ => bail!("{protocol} does not support shared pools"),
    }
}

fn socket_owner(
    rootless: Option<(u32, u32)>,
    configured_user: Option<&str>,
) -> anyhow::Result<HostOwner> {
    // Rootless container IDs are namespace-local, not host filesystem IDs.
    let (uid, gid) = if let Some(owner) = rootless {
        ensure!(owner.0 != 0, "rootless Podman host uid must not be 0");
        owner
    } else {
        let user = configured_user.unwrap_or("0:0").trim();
        let user = if user.is_empty() || user == "root" {
            "0:0"
        } else {
            user
        };
        let (uid, gid) = user.split_once(':').unwrap_or((user, user));
        let gid = if gid.is_empty() { uid } else { gid };
        (
            uid.parse::<u32>()
                .context("pool container uid must be numeric")?,
            gid.parse::<u32>()
                .context("pool container gid must be numeric")?,
        )
    };
    ensure!(
        uid != u32::MAX && gid != u32::MAX,
        "invalid pool socket owner"
    );
    Ok(HostOwner { uid, gid })
}

fn ensure_socket_directory(path: &Path, owner: HostOwner) -> anyhow::Result<()> {
    let parent = path.parent().context("pool socket path has no parent")?;
    let name = path
        .file_name()
        .context("pool socket path has no directory name")?;
    ensure!(path.is_absolute(), "pool socket path must be absolute");

    // The daemon prepares the sockets root at startup. Walk it without following
    // symlinks, then create/open the pool leaf relative to the pinned parent FD.
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut root = open("/", flags, Mode::empty())?;
    for component in parent.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => root = openat(&root, name, flags, Mode::empty())?,
            _ => bail!("pool socket root must not contain relative components"),
        }
    }
    ensure!(
        fstat(&root)?.st_uid == rustix::process::geteuid().as_raw(),
        "pool socket root must be owned by the daemon"
    );
    match mkdirat(&root, name, Mode::RWXU) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    let directory = openat(&root, name, flags, Mode::empty())?;
    let metadata = fstat(&directory)?;
    if metadata.st_uid != owner.uid || metadata.st_gid != owner.gid {
        fchown(
            &directory,
            Some(Uid::from_raw(owner.uid)),
            Some(Gid::from_raw(owner.gid)),
        )?;
    }
    fchmod(&directory, Mode::RWXU)?;
    // Do not unlink/chown children: restart can arrive while the pool is running.
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    };

    use super::*;

    fn current_owner(path: &Path) -> HostOwner {
        let metadata = fs::metadata(path).unwrap();
        HostOwner {
            uid: metadata.uid(),
            gid: metadata.gid(),
        }
    }

    #[test]
    fn missing_pool_socket_directory_is_recreated_without_touching_data() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("sockets");
        let data = temp.path().join("data");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&data).unwrap();
        fs::write(data.join("keep"), b"database data").unwrap();
        let owner = current_owner(&root);
        for protocol in [
            Protocol::Postgres,
            Protocol::Mysql,
            Protocol::Mariadb,
            Protocol::Mongodb,
            Protocol::Clickhouse,
        ] {
            let path = root.join(format!("pool_{protocol}"));
            ensure_socket_directory(&path, owner).unwrap();
            let metadata = fs::metadata(&path).unwrap();
            assert_eq!((metadata.uid(), metadata.gid()), (owner.uid, owner.gid));
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
            assert!(socket_target(protocol).is_ok());
        }
        assert_eq!(fs::read(data.join("keep")).unwrap(), b"database data");
        assert!(!temp.path().join("runtime-configs").exists());
    }

    #[test]
    fn repeated_preparation_preserves_live_socket_and_child_ownership() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("pool");
        let owner = current_owner(temp.path());
        ensure_socket_directory(&path, owner).unwrap();
        let socket = path.join("live.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let before = fs::symlink_metadata(&socket).unwrap();
        ensure_socket_directory(&path, owner).unwrap();
        let after = fs::symlink_metadata(&socket).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
        assert!(std::os::unix::net::UnixStream::connect(socket).is_ok());
    }

    #[test]
    fn socket_preparation_rejects_symlinks_and_non_directories() {
        let temp = tempfile::tempdir().unwrap();
        let owner = current_owner(temp.path());
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        let link = temp.path().join("link");
        symlink(&outside, &link).unwrap();
        assert!(ensure_socket_directory(&link, owner).is_err());
        assert!(ensure_socket_directory(&link.join("pool"), owner).is_err());
        assert!(!outside.join("pool").exists());
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let file = temp.path().join("file");
        fs::write(&file, b"keep").unwrap();
        assert!(ensure_socket_directory(&file, owner).is_err());
        assert_eq!(fs::read(file).unwrap(), b"keep");
    }

    #[test]
    fn socket_owner_uses_host_ids_for_rootless_and_configured_ids_for_docker() {
        assert_eq!(
            socket_owner(Some((1000, 1001)), Some("999:999")).unwrap(),
            HostOwner {
                uid: 1000,
                gid: 1001
            }
        );
        assert_eq!(
            socket_owner(None, Some("101:102")).unwrap(),
            HostOwner { uid: 101, gid: 102 }
        );
        assert_eq!(
            socket_owner(None, Some("999")).unwrap(),
            HostOwner { uid: 999, gid: 999 }
        );
        assert_eq!(
            socket_owner(None, None).unwrap(),
            HostOwner { uid: 0, gid: 0 }
        );
        for user in ["database", "101:group", "-1:0", "4294967295:0"] {
            assert!(socket_owner(None, Some(user)).is_err());
        }
        assert!(socket_owner(Some((0, 0)), None).is_err());
    }

    #[test]
    fn every_shared_engine_uses_its_configured_socket_mount() {
        for (protocol, target) in [
            (Protocol::Postgres, "/var/run/postgresql"),
            (Protocol::Mysql, "/var/run/mysqld"),
            (Protocol::Mariadb, "/run/mysqld"),
            (Protocol::Mongodb, "/run/dbev"),
            (Protocol::Clickhouse, "/run/dbev"),
        ] {
            assert_eq!(socket_target(protocol).unwrap(), target);
        }
        for protocol in [Protocol::Redis, Protocol::Valkey, Protocol::Qdrant] {
            assert!(socket_target(protocol).is_err());
        }
    }
}
