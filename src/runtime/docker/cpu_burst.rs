use std::{
    fs::OpenOptions,
    io::{ErrorKind, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use crate::{
    runtime::docker::{DockerError, DockerRuntime},
    shared::{
        cgroup::{membership_path, safe_relative_path, unescape_mountinfo},
        protocol::Protocol,
    },
};

const MAX_CONTROL_FILE_BYTES: u64 = 256;
const GENERATION_RETRIES: usize = 2;
const PROCESS_VIEWS: [(&str, &str); 2] = [
    ("/host/proc", "/host/proc/1/mountinfo"),
    ("/proc", "/proc/self/mountinfo"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CpuBurstPolicyStatus {
    Applied,
    AlreadyConfigured,
    Inactive,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpuBurstMode {
    FullQuota,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedProcessGeneration {
    container_id: String,
    pid: u32,
    started_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CgroupKind {
    Unified,
    LegacyCpu,
}

#[derive(Debug, Clone)]
struct CgroupMount {
    kind: CgroupKind,
    root: PathBuf,
    mountpoint: PathBuf,
}

#[derive(Debug, thiserror::Error)]
enum CpuBurstError {
    #[error("container process ended while its CPU cgroup was being inspected")]
    ProcessGone,
    #[error("invalid kernel cgroup metadata: {0}")]
    InvalidMetadata(String),
    #[error("failed to {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: String,
        source: std::io::Error,
    },
    #[error("CPU burst control {path} did not retain the requested value {expected}")]
    Verification { path: String, expected: u64 },
}

impl DockerRuntime {
    /// Enforces DBE's fixed latency policy: every bounded managed database may
    /// accumulate at most one additional quota window of CPU time.
    pub(crate) async fn apply_cpu_burst_policy(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<CpuBurstPolicyStatus, DockerError> {
        self.set_cpu_burst_policy(protocol, instance_id, CpuBurstMode::FullQuota)
            .await
    }

    pub(crate) async fn enforce_cpu_burst_policy(&self, protocol: Protocol, instance_id: &str) {
        match self.apply_cpu_burst_policy(protocol, instance_id).await {
            Ok(CpuBurstPolicyStatus::Applied) => tracing::debug!(
                event = "cpu_burst_policy_applied",
                instance_id,
                protocol = %protocol,
                "enabled one quota window of CPU burst credit"
            ),
            Ok(CpuBurstPolicyStatus::AlreadyConfigured) => {}
            Ok(CpuBurstPolicyStatus::Inactive) => tracing::debug!(
                instance_id,
                protocol = %protocol,
                "CPU burst policy deferred because the managed container is not running"
            ),
            Ok(CpuBurstPolicyStatus::Unsupported) => tracing::warn!(
                event = "cpu_burst_policy_unavailable",
                instance_id,
                protocol = %protocol,
                "host cgroups do not expose CFS burst control; retaining the normal CPU quota"
            ),
            Err(error) => tracing::warn!(
                event = "cpu_burst_policy_failed",
                instance_id,
                protocol = %protocol,
                %error,
                "failed to enable CPU burst credit; retaining the normal CPU quota"
            ),
        }
    }

    /// Clears an earlier burst before changing the quota. Linux rejects a new
    /// quota smaller than the currently configured burst, so this must happen
    /// before a downward CPU-limit update.
    pub(super) async fn clear_cpu_burst_before_limit_update(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) {
        match self
            .set_cpu_burst_policy(protocol, instance_id, CpuBurstMode::Disabled)
            .await
        {
            Ok(_) => {}
            Err(error) => tracing::warn!(
                event = "cpu_burst_policy_clear_failed",
                instance_id,
                protocol = %protocol,
                %error,
                "could not clear CPU burst credit before updating the CPU quota"
            ),
        }
    }

    async fn set_cpu_burst_policy(
        &self,
        protocol: Protocol,
        instance_id: &str,
        mode: CpuBurstMode,
    ) -> Result<CpuBurstPolicyStatus, DockerError> {
        for _ in 0..GENERATION_RETRIES {
            let Some(generation) = self
                .managed_process_generation(protocol, instance_id)
                .await?
            else {
                return Ok(CpuBurstPolicyStatus::Inactive);
            };
            let pid = generation.pid;
            let container_id = generation.container_id.clone();
            let result = tokio::task::spawn_blocking(move || {
                apply_cpu_burst_for_process(pid, &container_id, mode)
            })
            .await
            .map_err(|error| DockerError::CpuBurstPolicy {
                instance_id: instance_id.to_string(),
                reason: format!("CPU cgroup worker failed: {error}"),
            })?;
            let result = match result {
                Ok(result) => result,
                Err(CpuBurstError::ProcessGone) => continue,
                Err(error) => {
                    return Err(DockerError::CpuBurstPolicy {
                        instance_id: instance_id.to_string(),
                        reason: error.to_string(),
                    });
                }
            };
            if self
                .managed_process_generation(protocol, instance_id)
                .await?
                .as_ref()
                == Some(&generation)
            {
                return Ok(result);
            }
        }
        Ok(CpuBurstPolicyStatus::Inactive)
    }

    async fn managed_process_generation(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<ManagedProcessGeneration>, DockerError> {
        let Some(response) = self
            .verified_managed_container_inspection(protocol, instance_id)
            .await?
        else {
            return Ok(None);
        };
        let container = self.container_name(protocol, instance_id)?;
        let container_id = response
            .id
            .filter(|id| !id.trim().is_empty())
            .ok_or(DockerError::ManagedContainerIdUnavailable { container })?;
        let Some(state) = response.state.filter(|state| state.running == Some(true)) else {
            return Ok(None);
        };
        let Some(pid) = state.pid.and_then(|pid| u32::try_from(pid).ok()) else {
            return Ok(None);
        };
        if pid == 0 {
            return Ok(None);
        }
        let started_at = state
            .started_at
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| DockerError::CpuBurstPolicy {
                instance_id: instance_id.to_string(),
                reason: "running container did not report its start generation".to_string(),
            })?;
        Ok(Some(ManagedProcessGeneration {
            container_id,
            pid,
            started_at,
        }))
    }
}

fn apply_cpu_burst_for_process(
    pid: u32,
    container_id: &str,
    mode: CpuBurstMode,
) -> Result<CpuBurstPolicyStatus, CpuBurstError> {
    let mut process_entry_found = false;
    for (proc_root, mountinfo) in PROCESS_VIEWS {
        let cgroup_path = Path::new(proc_root).join(pid.to_string()).join("cgroup");
        let cgroups = match std::fs::read_to_string(&cgroup_path) {
            Ok(cgroups) => {
                process_entry_found = true;
                cgroups
            }
            Err(source) if source.kind() == ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(CpuBurstError::Io {
                    operation: "read",
                    path: cgroup_path.display().to_string(),
                    source,
                });
            }
        };
        if !cgroup_metadata_identifies_container(&cgroups, container_id) {
            continue;
        }
        let mountinfo_path = Path::new(mountinfo);
        let mountinfo =
            std::fs::read_to_string(mountinfo_path).map_err(|source| CpuBurstError::Io {
                operation: "read",
                path: mountinfo_path.display().to_string(),
                source,
            })?;
        return apply_cpu_burst_from_metadata(&cgroups, &mountinfo, mode);
    }
    if process_entry_found {
        Err(CpuBurstError::InvalidMetadata(format!(
            "PID {pid} did not belong to managed container {container_id} in a visible host process namespace"
        )))
    } else {
        Err(CpuBurstError::ProcessGone)
    }
}

fn cgroup_metadata_identifies_container(cgroups: &str, container_id: &str) -> bool {
    !container_id.is_empty()
        && [
            membership_path(cgroups, None),
            membership_path(cgroups, Some("cpu")),
        ]
        .into_iter()
        .flatten()
        .any(|path| {
            path.split('/')
                .any(|component| component.contains(container_id))
        })
}

fn apply_cpu_burst_from_metadata(
    cgroups: &str,
    mountinfo: &str,
    mode: CpuBurstMode,
) -> Result<CpuBurstPolicyStatus, CpuBurstError> {
    let mounts = parse_cgroup_mounts(mountinfo)?;
    let mut controls = Vec::with_capacity(2);
    if let Some(path) = membership_path(cgroups, None)
        && let Some(directory) = resolve_cgroup_directory(&mounts, CgroupKind::Unified, &path)?
    {
        controls.push((CgroupKind::Unified, directory));
    }
    if let Some(path) = membership_path(cgroups, Some("cpu"))
        && let Some(directory) = resolve_cgroup_directory(&mounts, CgroupKind::LegacyCpu, &path)?
        && !controls.iter().any(|(_, existing)| existing == &directory)
    {
        controls.push((CgroupKind::LegacyCpu, directory));
    }

    let mut configured = 0_usize;
    let mut changed = false;
    for (kind, directory) in controls {
        let Some(control_changed) = configure_control(kind, &directory, mode)? else {
            continue;
        };
        configured += 1;
        changed |= control_changed;
    }
    Ok(match (configured, changed) {
        (0, _) => CpuBurstPolicyStatus::Unsupported,
        (_, true) => CpuBurstPolicyStatus::Applied,
        (_, false) => CpuBurstPolicyStatus::AlreadyConfigured,
    })
}

fn configure_control(
    kind: CgroupKind,
    directory: &Path,
    mode: CpuBurstMode,
) -> Result<Option<bool>, CpuBurstError> {
    let (quota_path, period_path, burst_path) = match kind {
        CgroupKind::Unified => (
            directory.join("cpu.max"),
            None,
            directory.join("cpu.max.burst"),
        ),
        CgroupKind::LegacyCpu => (
            directory.join("cpu.cfs_quota_us"),
            Some(directory.join("cpu.cfs_period_us")),
            directory.join("cpu.cfs_burst_us"),
        ),
    };
    let Some(current_burst) = read_optional_control_u64(&burst_path)? else {
        return Ok(None);
    };
    let desired = match mode {
        CpuBurstMode::Disabled => 0,
        CpuBurstMode::FullQuota => match kind {
            CgroupKind::Unified => {
                let Some(value) = read_optional_control(&quota_path)? else {
                    return Ok(None);
                };
                parse_v2_quota(&value, &quota_path)?
            }
            CgroupKind::LegacyCpu => {
                let Some(value) = read_optional_control(&quota_path)? else {
                    return Ok(None);
                };
                let quota = value.trim().parse::<i64>().map_err(|_| {
                    CpuBurstError::InvalidMetadata(format!(
                        "{} did not contain an integer quota",
                        quota_path.display()
                    ))
                })?;
                if quota <= 0 {
                    return Ok(None);
                }
                let period_path = period_path.as_ref().expect("legacy CPU period path exists");
                let Some(period) = read_optional_control_u64(period_path)? else {
                    return Ok(None);
                };
                if period == 0 {
                    return Err(CpuBurstError::InvalidMetadata(format!(
                        "{} contained a zero period",
                        period_path.display()
                    )));
                }
                u64::try_from(quota).map_err(|_| {
                    CpuBurstError::InvalidMetadata(format!(
                        "{} contained an invalid quota",
                        quota_path.display()
                    ))
                })?
            }
        },
    };
    if current_burst == desired {
        return Ok(Some(false));
    }
    write_control(&burst_path, desired)?;
    if read_optional_control_u64(&burst_path)? != Some(desired) {
        return Err(CpuBurstError::Verification {
            path: burst_path.display().to_string(),
            expected: desired,
        });
    }
    Ok(Some(true))
}

fn parse_v2_quota(value: &str, path: &Path) -> Result<u64, CpuBurstError> {
    let mut fields = value.split_whitespace();
    let quota = fields
        .next()
        .ok_or_else(|| CpuBurstError::InvalidMetadata(format!("{} was empty", path.display())))?;
    let period = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            CpuBurstError::InvalidMetadata(format!(
                "{} did not contain a positive period",
                path.display()
            ))
        })?;
    if fields.next().is_some() {
        return Err(CpuBurstError::InvalidMetadata(format!(
            "{} contained unexpected fields",
            path.display()
        )));
    }
    let _ = period;
    if quota == "max" {
        return Err(CpuBurstError::InvalidMetadata(format!(
            "{} did not contain a bounded quota",
            path.display()
        )));
    }
    quota
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            CpuBurstError::InvalidMetadata(format!(
                "{} did not contain a positive quota",
                path.display()
            ))
        })
}

fn parse_cgroup_mounts(mountinfo: &str) -> Result<Vec<CgroupMount>, CpuBurstError> {
    let mut mounts = Vec::new();
    for line in mountinfo.lines() {
        let Some((before_separator, after_separator)) = line.split_once(" - ") else {
            continue;
        };
        let mut after = after_separator.split_whitespace();
        let Some(filesystem) = after.next() else {
            continue;
        };
        let _source = after.next();
        let super_options = after.next().unwrap_or_default();
        let kind = match filesystem {
            "cgroup2" => CgroupKind::Unified,
            "cgroup"
                if super_options
                    .split(',')
                    .any(|controller| controller == "cpu") =>
            {
                CgroupKind::LegacyCpu
            }
            _ => continue,
        };
        let fields = before_separator.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 {
            return Err(CpuBurstError::InvalidMetadata(
                "cgroup mountinfo entry had fewer than five fields".to_string(),
            ));
        }
        let root = absolute_kernel_path(&unescape_mountinfo(fields[3]))?;
        let mountpoint = absolute_kernel_path(&unescape_mountinfo(fields[4]))?;
        mounts.push(CgroupMount {
            kind,
            root,
            mountpoint,
        });
    }
    Ok(mounts)
}

fn resolve_cgroup_directory(
    mounts: &[CgroupMount],
    kind: CgroupKind,
    membership: &str,
) -> Result<Option<PathBuf>, CpuBurstError> {
    let membership = absolute_kernel_path(membership)?;
    Ok(mounts
        .iter()
        .filter(|mount| mount.kind == kind && membership.starts_with(&mount.root))
        .max_by_key(|mount| mount.root.components().count())
        .and_then(|mount| {
            membership
                .strip_prefix(&mount.root)
                .ok()
                .map(|relative| mount.mountpoint.join(relative))
        }))
}

fn absolute_kernel_path(value: &str) -> Result<PathBuf, CpuBurstError> {
    if !value.starts_with('/') {
        return Err(CpuBurstError::InvalidMetadata(format!(
            "kernel path was not absolute: {value}"
        )));
    }
    let relative = safe_relative_path(value).ok_or_else(|| {
        CpuBurstError::InvalidMetadata(format!("kernel path contained traversal: {value}"))
    })?;
    Ok(Path::new("/").join(relative))
}

fn read_optional_control_u64(path: &Path) -> Result<Option<u64>, CpuBurstError> {
    let Some(value) = read_optional_control(path)? else {
        return Ok(None);
    };
    value.trim().parse::<u64>().map(Some).map_err(|_| {
        CpuBurstError::InvalidMetadata(format!(
            "{} did not contain an unsigned integer",
            path.display()
        ))
    })
}

fn read_optional_control(path: &Path) -> Result<Option<String>, CpuBurstError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(CpuBurstError::Io {
                operation: "open",
                path: path.display().to_string(),
                source,
            });
        }
    };
    let mut bytes = Vec::new();
    file.take(MAX_CONTROL_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| CpuBurstError::Io {
            operation: "read",
            path: path.display().to_string(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONTROL_FILE_BYTES {
        return Err(CpuBurstError::InvalidMetadata(format!(
            "{} exceeded {MAX_CONTROL_FILE_BYTES} bytes",
            path.display()
        )));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| CpuBurstError::InvalidMetadata(format!("{} was not UTF-8", path.display())))
}

fn write_control(path: &Path, value: u64) -> Result<(), CpuBurstError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .truncate(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32);
    let mut file = options.open(path).map_err(|source| CpuBurstError::Io {
        operation: "open",
        path: path.display().to_string(),
        source,
    })?;
    file.write_all(value.to_string().as_bytes())
        .map_err(|source| CpuBurstError::Io {
            operation: "write",
            path: path.display().to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mountinfo_line(kind: CgroupKind, mountpoint: &Path) -> String {
        let (filesystem, options) = match kind {
            CgroupKind::Unified => ("cgroup2", "rw"),
            CgroupKind::LegacyCpu => ("cgroup", "rw,cpu,cpuacct"),
        };
        format!(
            "36 25 0:32 / {} rw,nosuid,nodev,noexec - {filesystem} cgroup {options}\n",
            mountpoint.display()
        )
    }

    #[test]
    fn enables_one_full_v2_quota_window() {
        let temporary = tempfile::tempdir().unwrap();
        let mount = temporary.path().join("cgroup");
        let leaf = mount.join("system.slice/docker-test.scope");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(leaf.join("cpu.max"), "200000 100000\n").unwrap();
        std::fs::write(leaf.join("cpu.max.burst"), "0\n").unwrap();

        let status = apply_cpu_burst_from_metadata(
            "0::/system.slice/docker-test.scope\n",
            &mountinfo_line(CgroupKind::Unified, &mount),
            CpuBurstMode::FullQuota,
        )
        .unwrap();

        assert_eq!(status, CpuBurstPolicyStatus::Applied);
        assert_eq!(
            std::fs::read_to_string(leaf.join("cpu.max.burst")).unwrap(),
            "200000"
        );
    }

    #[test]
    fn enables_and_clears_v1_burst_credit() {
        let temporary = tempfile::tempdir().unwrap();
        let mount = temporary.path().join("cpu");
        let leaf = mount.join("docker/test");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(leaf.join("cpu.cfs_quota_us"), "50000\n").unwrap();
        std::fs::write(leaf.join("cpu.cfs_period_us"), "100000\n").unwrap();
        std::fs::write(leaf.join("cpu.cfs_burst_us"), "0\n").unwrap();
        let metadata = "4:cpu,cpuacct:/docker/test\n";
        let mountinfo = mountinfo_line(CgroupKind::LegacyCpu, &mount);

        assert_eq!(
            apply_cpu_burst_from_metadata(metadata, &mountinfo, CpuBurstMode::FullQuota).unwrap(),
            CpuBurstPolicyStatus::Applied
        );
        assert_eq!(
            std::fs::read_to_string(leaf.join("cpu.cfs_burst_us")).unwrap(),
            "50000"
        );
        assert_eq!(
            apply_cpu_burst_from_metadata(metadata, &mountinfo, CpuBurstMode::Disabled).unwrap(),
            CpuBurstPolicyStatus::Applied
        );
        assert_eq!(
            std::fs::read_to_string(leaf.join("cpu.cfs_burst_us")).unwrap(),
            "0"
        );
    }

    #[test]
    fn missing_kernel_burst_control_falls_back_without_creating_it() {
        let temporary = tempfile::tempdir().unwrap();
        let mount = temporary.path().join("cgroup");
        let leaf = mount.join("docker/test");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(leaf.join("cpu.max"), "100000 100000\n").unwrap();

        assert_eq!(
            apply_cpu_burst_from_metadata(
                "0::/docker/test\n",
                &mountinfo_line(CgroupKind::Unified, &mount),
                CpuBurstMode::FullQuota,
            )
            .unwrap(),
            CpuBurstPolicyStatus::Unsupported
        );
        assert!(!leaf.join("cpu.max.burst").exists());
    }

    #[test]
    fn most_specific_cgroup_mount_root_is_used() {
        let temporary = tempfile::tempdir().unwrap();
        let broad = temporary.path().join("broad");
        let scoped = temporary.path().join("scoped");
        let leaf = scoped.join("container");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(leaf.join("cpu.max"), "75000 100000\n").unwrap();
        std::fs::write(leaf.join("cpu.max.burst"), "0\n").unwrap();
        let mountinfo = format!(
            "{}36 25 0:33 /tenant {} rw - cgroup2 cgroup rw\n",
            mountinfo_line(CgroupKind::Unified, &broad),
            scoped.display()
        );

        assert_eq!(
            apply_cpu_burst_from_metadata(
                "0::/tenant/container\n",
                &mountinfo,
                CpuBurstMode::FullQuota,
            )
            .unwrap(),
            CpuBurstPolicyStatus::Applied
        );
        assert_eq!(
            std::fs::read_to_string(leaf.join("cpu.max.burst")).unwrap(),
            "75000"
        );
    }

    #[test]
    fn traversal_in_kernel_metadata_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let error = apply_cpu_burst_from_metadata(
            "0::/docker/../victim\n",
            &mountinfo_line(CgroupKind::Unified, temporary.path()),
            CpuBurstMode::FullQuota,
        )
        .unwrap_err();
        assert!(matches!(error, CpuBurstError::InvalidMetadata(_)));
    }

    #[test]
    fn process_membership_must_contain_the_exact_container_id() {
        let container_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(cgroup_metadata_identifies_container(
            &format!("0::/system.slice/docker-{container_id}.scope\n"),
            container_id
        ));
        assert!(!cgroup_metadata_identifies_container(
            "0::/system.slice/docker-unrelated.scope\n",
            container_id
        ));
    }
}
