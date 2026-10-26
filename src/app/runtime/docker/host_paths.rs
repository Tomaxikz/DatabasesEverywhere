//! Host paths for a dbev running inside a container. Docker resolves bind
//! sources on the host, so paths under dbev's own mounts are rewritten to
//! their host side, the way Wings does it. Outside a container nothing
//! changes.

use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{Context, bail};

use super::DockerRuntime;

static HOST_PATHS: OnceLock<HostPaths> = OnceLock::new();

const CONTAINER_MARKERS: [&str; 2] = ["/.dockerenv", "/run/.containerenv"];

#[derive(Debug, Default)]
struct HostPaths {
    /// (inside, host), longest inside path first.
    mounts: Vec<(PathBuf, PathBuf)>,
}

impl HostPaths {
    fn new(mut mounts: Vec<(PathBuf, PathBuf)>) -> Self {
        mounts.sort_by_key(|(inside, _)| std::cmp::Reverse(inside.components().count()));
        Self { mounts }
    }

    fn to_host(&self, path: &Path) -> PathBuf {
        self.mounts
            .iter()
            .find_map(|(inside, host)| Some(host.join(path.strip_prefix(inside).ok()?)))
            .unwrap_or_else(|| path.to_path_buf())
    }

    fn to_container(&self, path: &Path) -> Option<PathBuf> {
        if self.mounts.is_empty() {
            return Some(path.to_path_buf());
        }
        self.mounts
            .iter()
            .filter_map(|(inside, host)| Some((inside, path.strip_prefix(host).ok()?)))
            .min_by_key(|(_, rest)| rest.components().count())
            .map(|(inside, rest)| inside.join(rest))
    }

    /// What a foreign mount of `path` covers in here: the path itself, or
    /// every mount below it when it's a parent folder like `/srv`.
    fn visible(&self, path: &Path) -> Vec<PathBuf> {
        if let Some(inside) = self.to_container(path) {
            return vec![inside];
        }
        self.mounts
            .iter()
            .filter(|(_, host)| host.starts_with(path))
            .map(|(inside, _)| inside.clone())
            .collect()
    }

    fn uncovered<'a>(&self, roots: &'a [PathBuf]) -> Vec<&'a Path> {
        roots
            .iter()
            .filter(|root| {
                !self
                    .mounts
                    .iter()
                    .any(|(inside, _)| root.starts_with(inside))
            })
            .map(PathBuf::as_path)
            .collect()
    }
}

fn host_paths() -> &'static HostPaths {
    HOST_PATHS.get_or_init(HostPaths::default)
}

/// Where Docker finds `path` on the host.
pub(crate) fn to_host(path: &Path) -> PathBuf {
    host_paths().to_host(path)
}

/// A host path as dbev sees it, or `None` when it isn't mounted in here.
pub(crate) fn to_container(path: &Path) -> Option<PathBuf> {
    host_paths().to_container(path)
}

pub(crate) fn visible(path: &Path) -> Vec<PathBuf> {
    host_paths().visible(path)
}

impl DockerRuntime {
    /// Learns dbev's own mounts when it runs in a container and refuses to
    /// go on when one of `roots` isn't mounted from the host.
    pub(crate) async fn detect_host_paths(&self, roots: &[PathBuf]) -> anyhow::Result<()> {
        let Some(id) = own_container_id()? else {
            return Ok(());
        };
        let inspection = self
            .docker
            .inspect_container(&id, None)
            .await
            .with_context(|| format!("failed to inspect dbev's own container {id}"))?;
        let mounts = inspection
            .mounts
            .unwrap_or_default()
            .into_iter()
            .filter_map(|mount| {
                let source = mount.source.filter(|source| !source.is_empty())?;
                Some((PathBuf::from(mount.destination?), PathBuf::from(source)))
            })
            .collect();
        let paths = HostPaths::new(mounts);
        let uncovered = paths.uncovered(roots);
        if !uncovered.is_empty() {
            let list = uncovered
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "dbev runs in container {id}, but {list} is not mounted from the host; \
                 databases could not reach it. Mount it as a volume or move it under one."
            );
        }
        for (inside, host) in &paths.mounts {
            tracing::debug!(inside = %inside.display(), host = %host.display(), "container mount");
        }
        tracing::info!(container = %id, mounts = paths.mounts.len(), "translating host paths for Docker");
        if HOST_PATHS.set(paths).is_err() {
            bail!("host paths were already detected");
        }
        Ok(())
    }
}

fn own_container_id() -> anyhow::Result<Option<String>> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    if let Some(id) = id_from_mountinfo(&mountinfo) {
        return Ok(Some(id));
    }
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    if let Some(id) = id_from_cgroup(&cgroup) {
        return Ok(Some(id));
    }
    if CONTAINER_MARKERS
        .iter()
        .any(|marker| Path::new(marker).exists())
    {
        bail!("dbev runs in a container but could not find its container id");
    }
    Ok(None)
}

/// Docker and Podman bind `/etc/hostname` from the container's own folder.
fn id_from_mountinfo(mountinfo: &str) -> Option<String> {
    mountinfo.lines().find_map(|line| {
        let mut fields = line.split(' ').skip(3);
        let root = fields.next()?;
        let mount_point = fields.next()?;
        matches!(
            mount_point,
            "/etc/hostname" | "/etc/hosts" | "/etc/resolv.conf"
        )
        .then(|| root.split('/').find(|part| is_container_id(part)))
        .flatten()
        .map(str::to_owned)
    })
}

/// `docker-<id>.scope`, `libpod-<id>.scope` or `/docker/<id>`.
fn id_from_cgroup(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .find_map(|line| {
            line.rsplit('/')
                .next()?
                .split(['-', '.'])
                .find(|part| is_container_id(part))
        })
        .map(str::to_owned)
}

fn is_container_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4f1c0a3e9b7d2c6a8e5f1b3d7c9a2e4f6b8d0c1a3e5f7b9d2c4a6e8f0b1d3c5a";

    fn paths() -> HostPaths {
        HostPaths::new(vec![
            ("/var/lib/dbev".into(), "/srv/node-a/data".into()),
            ("/var/lib/dbev/volumes".into(), "/mnt/big/volumes".into()),
            ("/run/dbev".into(), "/srv/node-a/run".into()),
        ])
    }

    #[test]
    fn paths_under_a_mount_go_to_its_host_side() {
        let paths = paths();
        assert_eq!(
            paths.to_host(Path::new("/var/lib/dbev/metadata")),
            Path::new("/srv/node-a/data/metadata")
        );
        assert_eq!(
            paths.to_host(Path::new("/var/lib/dbev/volumes/abc")),
            Path::new("/mnt/big/volumes/abc")
        );
        assert_eq!(
            paths.to_host(Path::new("/run/dbev")),
            Path::new("/srv/node-a/run")
        );
        assert_eq!(
            paths.to_host(Path::new("/opt/other")),
            Path::new("/opt/other")
        );
        assert_eq!(
            paths
                .to_container(Path::new("/mnt/big/volumes/abc"))
                .unwrap(),
            Path::new("/var/lib/dbev/volumes/abc")
        );
        assert_eq!(paths.to_container(Path::new("/var/lib/docker/x")), None);
    }

    #[test]
    fn without_mounts_nothing_changes() {
        let paths = HostPaths::default();
        assert_eq!(
            paths.to_host(Path::new("/var/lib/dbev")),
            Path::new("/var/lib/dbev")
        );
        assert_eq!(
            paths.to_container(Path::new("/var/lib/dbev")).unwrap(),
            Path::new("/var/lib/dbev")
        );
    }

    #[test]
    fn a_parent_folder_mount_covers_everything_below_it() {
        let visible = paths().visible(Path::new("/srv"));
        assert!(visible.contains(&PathBuf::from("/var/lib/dbev")));
        assert!(visible.contains(&PathBuf::from("/run/dbev")));
        assert!(paths().visible(Path::new("/home")).is_empty());
    }

    #[test]
    fn folders_outside_the_mounts_are_reported() {
        let roots = vec![
            PathBuf::from("/var/lib/dbev/backups"),
            PathBuf::from("/run/dbev/sockets"),
            PathBuf::from("/tmp/dbev"),
        ];
        assert_eq!(paths().uncovered(&roots), [Path::new("/tmp/dbev")]);
    }

    #[test]
    fn finds_the_container_id_from_docker_and_podman_mounts() {
        let docker = format!(
            "1 0 0:1 / / rw - overlay overlay rw\n\
             2 1 8:1 /var/lib/docker/containers/{ID}/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n"
        );
        assert_eq!(id_from_mountinfo(&docker).as_deref(), Some(ID));
        let podman = format!(
            "2 1 8:1 /containers/storage/overlay-containers/{ID}/userdata/hosts /etc/hosts rw - ext4 /dev/sda1 rw\n"
        );
        assert_eq!(id_from_mountinfo(&podman).as_deref(), Some(ID));
        assert_eq!(
            id_from_mountinfo("1 0 0:1 / / rw - ext4 /dev/sda1 rw\n"),
            None
        );
    }

    #[test]
    fn finds_the_container_id_from_the_cgroup() {
        assert_eq!(
            id_from_cgroup(&format!("0::/system.slice/docker-{ID}.scope\n")).as_deref(),
            Some(ID)
        );
        assert_eq!(
            id_from_cgroup(&format!("0::/docker/{ID}\n")).as_deref(),
            Some(ID)
        );
        assert_eq!(id_from_cgroup("0::/system.slice/dbev.service\n"), None);
    }
}
