//! Reads a managed container's CPU and memory counters straight from its cgroup.
//!
//! The values mirror the fields each engine's Docker-compatible stats endpoint reports, so
//! callers apply the same formulas to either source:
//! - `cpu_total_usage_ns` is `cpu_stats.cpu_usage.total_usage` (v2 `cpu.stat` `usage_usec` x 1000,
//!   v1 `cpuacct.usage`) for both Docker and Podman.
//! - `memory_usage_bytes` is `memory_stats.usage` (v2 `memory.current`, v1
//!   `memory.usage_in_bytes`) for both engines.
//! - `memory_inactive_file_bytes` is the `memory_stats.stats` inactive-file entry. Docker
//!   includes that map; Podman's compat endpoint returns `Stats: nil`, so it stays `None` there.

use std::{
    fs::OpenOptions,
    io::{ErrorKind, Read},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use procfs::process::MountInfo;

use crate::{
    config::DaemonEngine,
    io::cgroup::{membership_path, safe_relative_path, unescape_mountinfo},
};

const MAX_STAT_FILE_BYTES: u64 = 64 * 1024;
/// The containerized daemon sees the host through `/host/proc`; a host install uses `/proc`.
const PROCESS_VIEWS: [(&str, &str); 2] = [
    ("/host/proc", "/host/proc/1/mountinfo"),
    ("/proc", "/proc/self/mountinfo"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CgroupCounters {
    pub cpu_total_usage_ns: u64,
    pub memory_usage_bytes: u64,
    pub memory_inactive_file_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CgroupStatsReader {
    layout: CgroupLayout,
    engine: DaemonEngine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CgroupLayout {
    Unified(PathBuf),
    Legacy { cpuacct: PathBuf, memory: PathBuf },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CgroupStatsError {
    #[error("container PID {pid} is not visible in a local process namespace")]
    ProcessNotVisible { pid: u32 },
    #[error("PID {pid} is not inside a local cgroup named for container {container_id}")]
    NotContainerCgroup { pid: u32, container_id: String },
    #[error("invalid cgroup metadata: {0}")]
    InvalidMetadata(String),
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountKind {
    Unified,
    Legacy,
}

#[derive(Debug, Clone)]
struct CgroupMount {
    kind: MountKind,
    controllers: Vec<String>,
    root: PathBuf,
    mountpoint: PathBuf,
}

impl CgroupStatsReader {
    /// Binds to the cgroup that holds `pid`, accepting it only when that cgroup is named for
    /// `container_id`. A remote engine, a foreign PID namespace, or a reused PID fails here.
    pub(crate) fn bind(
        pid: u32,
        container_id: &str,
        engine: DaemonEngine,
    ) -> Result<Self, CgroupStatsError> {
        if pid == 0 || container_id.trim().is_empty() {
            return Err(CgroupStatsError::ProcessNotVisible { pid });
        }
        let mut process_visible = false;
        for (proc_root, mountinfo_path) in PROCESS_VIEWS {
            let cgroup_path = Path::new(proc_root).join(pid.to_string()).join("cgroup");
            let cgroups = match read_bounded(&cgroup_path) {
                Ok(cgroups) => cgroups,
                Err(CgroupStatsError::Io { source, .. })
                    if source.kind() == ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            process_visible = true;
            let mountinfo = match read_mountinfo(Path::new(mountinfo_path)) {
                Ok(mountinfo) => mountinfo,
                Err(CgroupStatsError::Io { source, .. })
                    if source.kind() == ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            let Some(layout) = resolve_layout(&cgroups, &mountinfo, container_id)? else {
                continue;
            };
            let reader = Self { layout, engine };
            reader.read()?;
            return Ok(reader);
        }
        Err(if process_visible {
            CgroupStatsError::NotContainerCgroup {
                pid,
                container_id: container_id.to_string(),
            }
        } else {
            CgroupStatsError::ProcessNotVisible { pid }
        })
    }

    pub(crate) fn read(&self) -> Result<CgroupCounters, CgroupStatsError> {
        let reports_memory_stat = self.engine == DaemonEngine::Docker;
        match &self.layout {
            CgroupLayout::Unified(directory) => {
                let cpu_stat_path = directory.join("cpu.stat");
                let usage_usec = stat_value(&read_bounded(&cpu_stat_path)?, "usage_usec")
                    .ok_or_else(|| invalid(&cpu_stat_path, "has no usage_usec entry"))?;
                let cpu_total_usage_ns = usage_usec
                    .checked_mul(1_000)
                    .ok_or_else(|| invalid(&cpu_stat_path, "usage_usec overflowed"))?;
                let memory_usage_bytes = read_u64(&directory.join("memory.current"))?;
                let memory_inactive_file_bytes = if reports_memory_stat {
                    stat_value(
                        &read_bounded(&directory.join("memory.stat"))?,
                        "inactive_file",
                    )
                } else {
                    None
                };
                Ok(CgroupCounters {
                    cpu_total_usage_ns,
                    memory_usage_bytes,
                    memory_inactive_file_bytes,
                })
            }
            CgroupLayout::Legacy { cpuacct, memory } => {
                let cpu_total_usage_ns = read_u64(&cpuacct.join("cpuacct.usage"))?;
                let memory_usage_bytes = read_u64(&memory.join("memory.usage_in_bytes"))?;
                let memory_inactive_file_bytes = if reports_memory_stat {
                    let stat = read_bounded(&memory.join("memory.stat"))?;
                    stat_value(&stat, "total_inactive_file")
                        .or_else(|| stat_value(&stat, "inactive_file"))
                } else {
                    None
                };
                Ok(CgroupCounters {
                    cpu_total_usage_ns,
                    memory_usage_bytes,
                    memory_inactive_file_bytes,
                })
            }
        }
    }
}

/// Engines use v1 controllers whenever the host mounts them (hybrid hosts included), so prefer
/// them over the unified hierarchy just as Docker and Podman do.
fn resolve_layout(
    cgroups: &str,
    mountinfo: &str,
    container_id: &str,
) -> Result<Option<CgroupLayout>, CgroupStatsError> {
    let mounts = parse_cgroup_mounts(mountinfo);
    let legacy =
        membership_path(cgroups, Some("cpuacct")).zip(membership_path(cgroups, Some("memory")));
    if let Some((cpuacct, memory)) = legacy {
        let (Some(cpuacct), Some(memory)) = (
            container_scope(&cpuacct, container_id),
            container_scope(&memory, container_id),
        ) else {
            return Ok(None);
        };
        let cpuacct = resolve_directory(&mounts, MountKind::Legacy, Some("cpuacct"), &cpuacct)?;
        let memory = resolve_directory(&mounts, MountKind::Legacy, Some("memory"), &memory)?;
        return Ok(cpuacct
            .zip(memory)
            .map(|(cpuacct, memory)| CgroupLayout::Legacy { cpuacct, memory }));
    }
    let Some(unified) = membership_path(cgroups, None) else {
        return Ok(None);
    };
    let Some(scope) = container_scope(&unified, container_id) else {
        return Ok(None);
    };
    Ok(resolve_directory(&mounts, MountKind::Unified, None, &scope)?.map(CgroupLayout::Unified))
}

/// Engines report the container's own cgroup, which may sit above the init process's leaf
/// (for example a systemd-managed sub-cgroup), so cut the path at the container's component.
/// Podman's conmon scope also carries the ID but is not the container.
fn container_scope(membership: &str, container_id: &str) -> Option<String> {
    let mut scope = String::new();
    let mut end = None;
    for component in membership
        .split('/')
        .filter(|component| !component.is_empty())
    {
        scope.push('/');
        scope.push_str(component);
        if component.contains(container_id) && !component.contains("conmon") {
            end = Some(scope.len());
        }
    }
    end.map(|end| scope[..end].to_string())
}

fn parse_cgroup_mounts(mountinfo: &str) -> Vec<CgroupMount> {
    mountinfo
        .lines()
        .filter_map(|line| MountInfo::from_line(line).ok())
        .filter_map(|mount| {
            let kind = match mount.fs_type.as_str() {
                "cgroup2" => MountKind::Unified,
                "cgroup" => MountKind::Legacy,
                _ => return None,
            };
            let root = absolute_kernel_path(&unescape_mountinfo(&mount.root)).ok()?;
            let mountpoint =
                absolute_kernel_path(&unescape_mountinfo(&mount.mount_point.to_string_lossy()))
                    .ok()?;
            Some(CgroupMount {
                kind,
                controllers: mount.super_options.into_keys().collect(),
                root,
                mountpoint,
            })
        })
        .collect()
}

fn resolve_directory(
    mounts: &[CgroupMount],
    kind: MountKind,
    controller: Option<&str>,
    membership: &str,
) -> Result<Option<PathBuf>, CgroupStatsError> {
    let membership = absolute_kernel_path(membership)?;
    Ok(mounts
        .iter()
        .filter(|mount| {
            mount.kind == kind
                && controller.is_none_or(|controller| {
                    mount.controllers.iter().any(|value| value == controller)
                })
                && membership.starts_with(&mount.root)
        })
        .max_by_key(|mount| mount.root.components().count())
        .and_then(|mount| {
            membership
                .strip_prefix(&mount.root)
                .ok()
                .map(|relative| mount.mountpoint.join(relative))
        }))
}

fn absolute_kernel_path(value: &str) -> Result<PathBuf, CgroupStatsError> {
    if !value.starts_with('/') {
        return Err(CgroupStatsError::InvalidMetadata(format!(
            "kernel path was not absolute: {value}"
        )));
    }
    let relative = safe_relative_path(value).ok_or_else(|| {
        CgroupStatsError::InvalidMetadata(format!("kernel path contained traversal: {value}"))
    })?;
    Ok(Path::new("/").join(relative))
}

fn stat_value(contents: &str, key: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == key)
            .then(|| fields.next()?.parse().ok())
            .flatten()
    })
}

fn read_u64(path: &Path) -> Result<u64, CgroupStatsError> {
    read_bounded(path)?
        .trim()
        .parse()
        .map_err(|_| invalid(path, "did not contain an unsigned integer"))
}

fn invalid(path: &Path, problem: &str) -> CgroupStatsError {
    CgroupStatsError::InvalidMetadata(format!("{} {problem}", path.display()))
}

fn io_error(path: &Path, source: std::io::Error) -> CgroupStatsError {
    CgroupStatsError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// mountinfo can be large on busy hosts; it is read once per bind, never per sample.
fn read_mountinfo(path: &Path) -> Result<String, CgroupStatsError> {
    std::fs::read_to_string(path).map_err(|source| io_error(path, source))
}

fn read_bounded(path: &Path) -> Result<String, CgroupStatsError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32);
    let file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let mut bytes = Vec::new();
    file.take(MAX_STAT_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STAT_FILE_BYTES {
        return Err(invalid(
            path,
            &format!("exceeded {MAX_STAT_FILE_BYTES} bytes"),
        ));
    }
    String::from_utf8(bytes).map_err(|_| invalid(path, "was not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn unified_mountinfo(mountpoint: &Path) -> String {
        format!(
            "36 25 0:32 / {} rw,nosuid,nodev,noexec - cgroup2 cgroup2 rw\n",
            mountpoint.display()
        )
    }

    fn write_unified(directory: &Path) {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(
            directory.join("cpu.stat"),
            "usage_usec 1500\nuser_usec 1000\nsystem_usec 500\n",
        )
        .unwrap();
        std::fs::write(directory.join("memory.current"), "4096\n").unwrap();
        std::fs::write(
            directory.join("memory.stat"),
            "anon 1024\nfile 3072\nactive_file 2048\ninactive_file 1024\n",
        )
        .unwrap();
    }

    #[test]
    fn container_scope_stops_at_the_container_component() {
        assert_eq!(
            container_scope(&format!("/system.slice/docker-{ID}.scope"), ID).as_deref(),
            Some(format!("/system.slice/docker-{ID}.scope").as_str())
        );
        assert_eq!(
            container_scope(&format!("/machine.slice/libpod-{ID}.scope/container"), ID).as_deref(),
            Some(format!("/machine.slice/libpod-{ID}.scope").as_str())
        );
        assert_eq!(
            container_scope(&format!("/docker/{ID}/init.scope"), ID).as_deref(),
            Some(format!("/docker/{ID}").as_str())
        );
        assert_eq!(
            container_scope(&format!("/machine.slice/libpod-conmon-{ID}.scope"), ID),
            None
        );
        assert_eq!(container_scope("/user.slice/session-1.scope", ID), None);
    }

    #[test]
    fn unified_counters_match_docker_and_podman_compat_fields() {
        let temporary = tempfile::tempdir().unwrap();
        let mount = temporary.path().join("cgroup");
        let scope = format!("system.slice/docker-{ID}.scope");
        write_unified(&mount.join(&scope));

        let layout = resolve_layout(
            &format!("0::/{scope}/init.scope\n"),
            &unified_mountinfo(&mount),
            ID,
        )
        .unwrap()
        .unwrap();
        assert_eq!(layout, CgroupLayout::Unified(mount.join(&scope)));

        let docker = CgroupStatsReader {
            layout: layout.clone(),
            engine: DaemonEngine::Docker,
        };
        assert_eq!(
            docker.read().unwrap(),
            CgroupCounters {
                cpu_total_usage_ns: 1_500_000,
                memory_usage_bytes: 4096,
                memory_inactive_file_bytes: Some(1024),
            }
        );
        // Podman's compat endpoint reports memory.current with no memory.stat map.
        let podman = CgroupStatsReader {
            layout,
            engine: DaemonEngine::Podman,
        };
        assert_eq!(
            podman.read().unwrap(),
            CgroupCounters {
                cpu_total_usage_ns: 1_500_000,
                memory_usage_bytes: 4096,
                memory_inactive_file_bytes: None,
            }
        );
    }

    #[test]
    fn legacy_hierarchies_take_precedence_on_hybrid_hosts() {
        let temporary = tempfile::tempdir().unwrap();
        let cpu_mount = temporary.path().join("cpu,cpuacct");
        let memory_mount = temporary.path().join("memory");
        let unified_mount = temporary.path().join("unified");
        let cpuacct = cpu_mount.join(format!("docker/{ID}"));
        let memory = memory_mount.join(format!("docker/{ID}"));
        std::fs::create_dir_all(&cpuacct).unwrap();
        std::fs::create_dir_all(&memory).unwrap();
        std::fs::write(cpuacct.join("cpuacct.usage"), "123456789\n").unwrap();
        std::fs::write(memory.join("memory.usage_in_bytes"), "8192\n").unwrap();
        std::fs::write(
            memory.join("memory.stat"),
            "inactive_file 100\ntotal_inactive_file 2048\n",
        )
        .unwrap();
        let mountinfo = format!(
            "30 25 0:26 / {} rw - cgroup2 cgroup2 rw\n\
             31 25 0:27 / {} rw - cgroup cgroup rw,cpu,cpuacct\n\
             32 25 0:28 / {} rw - cgroup cgroup rw,memory\n",
            unified_mount.display(),
            cpu_mount.display(),
            memory_mount.display()
        );
        let cgroups =
            format!("4:cpu,cpuacct:/docker/{ID}\n3:memory:/docker/{ID}\n0::/docker/{ID}\n");

        let layout = resolve_layout(&cgroups, &mountinfo, ID).unwrap().unwrap();
        assert_eq!(
            layout,
            CgroupLayout::Legacy {
                cpuacct: cpuacct.clone(),
                memory: memory.clone()
            }
        );
        let reader = CgroupStatsReader {
            layout,
            engine: DaemonEngine::Docker,
        };
        assert_eq!(
            reader.read().unwrap(),
            CgroupCounters {
                cpu_total_usage_ns: 123_456_789,
                memory_usage_bytes: 8192,
                memory_inactive_file_bytes: Some(2048),
            }
        );
    }

    #[test]
    fn foreign_or_traversing_memberships_do_not_bind() {
        let temporary = tempfile::tempdir().unwrap();
        let mountinfo = unified_mountinfo(temporary.path());
        assert_eq!(
            resolve_layout("0::/user.slice/session-2.scope\n", &mountinfo, ID).unwrap(),
            None
        );
        assert!(resolve_layout(&format!("0::/../docker-{ID}.scope\n"), &mountinfo, ID).is_err());
        // A v2 host without a cgroup2 mount in view cannot resolve the directory.
        assert_eq!(
            resolve_layout(&format!("0::/docker-{ID}.scope\n"), "", ID).unwrap(),
            None
        );
    }

    #[test]
    fn missing_memory_controller_fails_the_read() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("scope");
        write_unified(&directory);
        std::fs::remove_file(directory.join("memory.current")).unwrap();
        let reader = CgroupStatsReader {
            layout: CgroupLayout::Unified(directory),
            engine: DaemonEngine::Docker,
        };
        assert!(matches!(reader.read(), Err(CgroupStatsError::Io { .. })));
    }

    #[test]
    fn bind_rejects_a_pid_outside_the_container_cgroup() {
        // This test process is never inside a cgroup named for the fake container ID.
        let error =
            CgroupStatsReader::bind(std::process::id(), ID, DaemonEngine::Docker).unwrap_err();
        assert!(matches!(
            error,
            CgroupStatsError::NotContainerCgroup { .. }
                | CgroupStatsError::ProcessNotVisible { .. }
        ));
    }

    /// Read-only: inspects an existing running container and never changes it.
    #[tokio::test]
    #[ignore = "requires DBE_DOCKER_STATS_CONTAINER naming a running container on a local Docker engine"]
    async fn live_docker_counters_track_the_engine_stats_api() {
        use futures::StreamExt;

        let container = std::env::var("DBE_DOCKER_STATS_CONTAINER")
            .expect("DBE_DOCKER_STATS_CONTAINER must name a running container");
        let docker = bollard::Docker::connect_with_local_defaults().unwrap();
        let inspection = docker.inspect_container(&container, None).await.unwrap();
        let id = inspection.id.clone().unwrap();
        let pid = inspection
            .state
            .and_then(|state| state.pid)
            .and_then(|pid| u32::try_from(pid).ok())
            .unwrap();
        let reader = tokio::task::spawn_blocking(move || {
            CgroupStatsReader::bind(pid, &id, DaemonEngine::Docker)
        })
        .await
        .unwrap()
        .unwrap();

        let engine = docker
            .stats(
                &container,
                Some(
                    bollard::query_parameters::StatsOptionsBuilder::default()
                        .stream(false)
                        .one_shot(true)
                        .build(),
                ),
            )
            .next()
            .await
            .unwrap()
            .unwrap();
        let direct = reader.read().unwrap();
        let engine_cpu = engine
            .cpu_stats
            .unwrap()
            .cpu_usage
            .unwrap()
            .total_usage
            .unwrap();
        let engine_memory = engine.memory_stats.unwrap();
        let engine_inactive = engine_memory
            .stats
            .as_ref()
            .and_then(|stats| {
                stats
                    .get("total_inactive_file")
                    .or(stats.get("inactive_file"))
            })
            .copied();
        println!(
            "engine cpu={engine_cpu} memory={:?} inactive={engine_inactive:?}",
            engine_memory.usage
        );
        println!("direct {direct:?}");

        // Read after the engine sample, so the monotonic counter can only be equal or ahead.
        assert!(direct.cpu_total_usage_ns >= engine_cpu);
        assert!(direct.cpu_total_usage_ns - engine_cpu < 5_000_000_000);
        let engine_usage = engine_memory.usage.unwrap();
        assert!(direct.memory_usage_bytes.abs_diff(engine_usage) < 64 * 1024 * 1024);
        assert_eq!(
            direct.memory_inactive_file_bytes.is_some(),
            engine_inactive.is_some()
        );
    }
}
