use super::*;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(super) struct HostResourceProvider;

impl SchedulerResourceProvider for HostResourceProvider {
    fn sample(&self) -> SchedulerResourceSample {
        host_resource_sample()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CgroupReadingState {
    Present,
    Absent,
    Invalid,
}

#[derive(Clone, Copy)]
struct CgroupReading<T> {
    value: Option<T>,
    state: CgroupReadingState,
}

impl<T> CgroupReading<T> {
    fn present(value: Option<T>) -> Self {
        Self {
            value,
            state: CgroupReadingState::Present,
        }
    }

    fn absent() -> Self {
        Self {
            value: None,
            state: CgroupReadingState::Absent,
        }
    }

    fn invalid() -> Self {
        Self {
            value: None,
            state: CgroupReadingState::Invalid,
        }
    }

    fn valid(self) -> bool {
        self.state != CgroupReadingState::Invalid
    }
}

fn host_resource_sample() -> SchedulerResourceSample {
    let host_memory = host_available_memory_mib();
    let host_cpu = std::thread::available_parallelism().ok().map(usize::from);
    let cgroups = match std::fs::read_to_string("/proc/self/cgroup") {
        Ok(value) => value,
        Err(_) if cfg!(target_os = "linux") => {
            return SchedulerResourceSample {
                available_memory_mib: None,
                cpu_units: None,
                memory_valid: false,
                cpu_valid: false,
            };
        }
        Err(_) => {
            return SchedulerResourceSample {
                available_memory_mib: host_memory,
                cpu_units: host_cpu,
                memory_valid: host_memory.is_some(),
                cpu_valid: host_cpu.is_some(),
            };
        }
    };

    resource_sample_from_cgroups(
        host_memory,
        host_cpu,
        &cgroups,
        &[Path::new("/sys/fs/cgroup")],
        &[
            Path::new("/sys/fs/cgroup/memory"),
            Path::new("/sys/fs/cgroup"),
        ],
        &[
            Path::new("/sys/fs/cgroup/cpu"),
            Path::new("/sys/fs/cgroup/cpu,cpuacct"),
            Path::new("/sys/fs/cgroup"),
        ],
    )
}

fn resource_sample_from_cgroups(
    host_memory: Option<u64>,
    host_cpu: Option<usize>,
    cgroups: &str,
    v2_roots: &[&Path],
    v1_memory_roots: &[&Path],
    v1_cpu_roots: &[&Path],
) -> SchedulerResourceSample {
    let unified = cgroup_path(cgroups, None);
    let v2_memory = unified
        .as_deref()
        .map_or_else(CgroupReading::absent, |path| {
            read_cgroup_v2_memory_sample(v2_roots, Some(path))
        });
    let v1_memory = cgroup_path(cgroups, Some("memory"))
        .map_or_else(CgroupReading::absent, |path| {
            read_cgroup_v1_memory_sample(v1_memory_roots, Some(&path))
        });
    let memory = merge_cgroup_readings(v2_memory, v1_memory);

    let v2_cpu = unified
        .as_deref()
        .map_or_else(CgroupReading::absent, |path| {
            read_cgroup_v2_cpu_sample(v2_roots, Some(path))
        });
    let v1_cpu = cgroup_path(cgroups, Some("cpu")).map_or_else(CgroupReading::absent, |path| {
        read_cgroup_v1_cpu_sample(v1_cpu_roots, Some(&path))
    });
    let cpu = merge_cgroup_readings(v2_cpu, v1_cpu);

    SchedulerResourceSample {
        available_memory_mib: minimum_present(host_memory, memory.value),
        cpu_units: effective_cpu_sample(host_cpu, cpu.value),
        memory_valid: memory.valid() && host_memory.is_some(),
        cpu_valid: cpu.valid() && host_cpu.is_some(),
    }
}

#[cfg(test)]
pub(super) fn test_resource_sample_from_cgroups(
    host_memory: Option<u64>,
    host_cpu: Option<usize>,
    cgroups: &str,
    v2_roots: &[&Path],
    v1_memory_roots: &[&Path],
    v1_cpu_roots: &[&Path],
) -> SchedulerResourceSample {
    resource_sample_from_cgroups(
        host_memory,
        host_cpu,
        cgroups,
        v2_roots,
        v1_memory_roots,
        v1_cpu_roots,
    )
}

fn merge_cgroup_readings<T: Ord + Copy>(
    v2: CgroupReading<T>,
    v1: CgroupReading<T>,
) -> CgroupReading<T> {
    if v2.state == CgroupReadingState::Invalid || v1.state == CgroupReadingState::Invalid {
        return CgroupReading::invalid();
    }
    if v2.state == CgroupReadingState::Present || v1.state == CgroupReadingState::Present {
        return CgroupReading::present(minimum_present(v2.value, v1.value));
    }
    CgroupReading::absent()
}

fn effective_cpu_sample(host: Option<usize>, cgroup: Option<usize>) -> Option<usize> {
    match (host, cgroup) {
        (Some(host), Some(cgroup)) => Some(host.min(cgroup).max(1)),
        (Some(host), None) => Some(host.max(1)),
        (None, _) => None,
    }
}

fn host_available_memory_mib() -> Option<u64> {
    let memory = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_host_available_memory_mib(&memory)
}

pub(super) fn parse_host_available_memory_mib(memory: &str) -> Option<u64> {
    let kib = memory.lines().find_map(|line| {
        let value = line.strip_prefix("MemAvailable:")?;
        value.split_whitespace().next()?.parse::<u64>().ok()
    })?;
    Some(kib / 1024)
}

fn read_cgroup_v2_memory_sample(roots: &[&Path], relative: Option<&str>) -> CgroupReading<u64> {
    let Ok((root, advertised)) = verified_v2_root(roots, "memory") else {
        return CgroupReading::invalid();
    };
    let Some(bases) = cgroup_bases_for_root(root, relative) else {
        return CgroupReading::invalid();
    };
    let Some(leaf) = bases.first() else {
        return CgroupReading::invalid();
    };
    match std::fs::read_to_string(leaf.join("memory.max")) {
        Ok(_) => read_memory_hierarchy(&bases, root, "memory.max", "memory.current", false, true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !advertised => {
            CgroupReading::absent()
        }
        Err(_) => CgroupReading::invalid(),
    }
}

fn read_cgroup_v1_memory_sample(roots: &[&Path], relative: Option<&str>) -> CgroupReading<u64> {
    let Some((root, bases)) = resolved_v1_hierarchy(roots, relative, "memory.limit_in_bytes")
    else {
        return CgroupReading::invalid();
    };
    read_memory_hierarchy(
        &bases,
        root,
        "memory.limit_in_bytes",
        "memory.usage_in_bytes",
        true,
        false,
    )
}

fn read_memory_hierarchy(
    bases: &[PathBuf],
    root: &Path,
    limit_file: &str,
    usage_file: &str,
    numeric_unlimited: bool,
    allow_missing_root_interface: bool,
) -> CgroupReading<u64> {
    let mut minimum = None;
    for base in bases {
        let limit_path = base.join(limit_file);
        let limit = match std::fs::read_to_string(&limit_path) {
            Ok(limit) => limit,
            Err(error)
                if allow_missing_root_interface
                    && base == root
                    && error.kind() == std::io::ErrorKind::NotFound =>
            {
                continue;
            }
            Err(_) => return CgroupReading::invalid(),
        };
        let limit_text = limit.trim();
        if limit_text == "max"
            || numeric_unlimited
                && limit_text
                    .parse::<u64>()
                    .is_ok_and(|limit| limit >= (1_u64 << 60))
        {
            if !stable_control_value(&limit_path, limit_text) {
                return CgroupReading::invalid();
            }
            continue;
        }
        let Ok(limit) = limit_text.parse::<u64>() else {
            return CgroupReading::invalid();
        };
        let Ok(usage) = std::fs::read_to_string(base.join(usage_file)) else {
            return CgroupReading::invalid();
        };
        let Ok(usage) = usage.trim().parse::<u64>() else {
            return CgroupReading::invalid();
        };
        if !stable_control_value(&limit_path, limit_text) {
            return CgroupReading::invalid();
        }
        minimum = minimum_present(minimum, Some(limit.saturating_sub(usage) / MIB));
    }
    CgroupReading::present(minimum)
}

#[cfg(test)]
pub(super) fn read_cgroup_memory(
    roots: &[&Path],
    relative: Option<&str>,
    limit_file: &str,
    usage_file: &str,
    numeric_unlimited: bool,
) -> Option<u64> {
    let sample = if numeric_unlimited {
        read_cgroup_v1_memory_sample(roots, relative)
    } else {
        read_cgroup_v2_memory_sample(roots, relative)
    };
    debug_assert_eq!(
        (limit_file, usage_file),
        if numeric_unlimited {
            ("memory.limit_in_bytes", "memory.usage_in_bytes")
        } else {
            ("memory.max", "memory.current")
        }
    );
    sample.valid().then_some(sample.value).flatten()
}

#[cfg(test)]
pub(super) fn cgroup_memory_sample_complete(
    roots: &[&Path],
    relative: Option<&str>,
    limit_file: &str,
    usage_file: &str,
    numeric_unlimited: bool,
) -> bool {
    let sample = if numeric_unlimited {
        read_cgroup_v1_memory_sample(roots, relative)
    } else {
        read_cgroup_v2_memory_sample(roots, relative)
    };
    debug_assert_eq!(
        (limit_file, usage_file),
        if numeric_unlimited {
            ("memory.limit_in_bytes", "memory.usage_in_bytes")
        } else {
            ("memory.max", "memory.current")
        }
    );
    sample.valid()
}

#[cfg(test)]
pub(super) fn parse_cgroup_memory_available_mib(
    limit: &str,
    usage: &str,
    numeric_unlimited: bool,
) -> Option<u64> {
    if limit.trim() == "max" {
        return None;
    }
    let limit = limit.trim().parse::<u64>().ok()?;
    if numeric_unlimited && limit >= (1_u64 << 60) {
        return None;
    }
    let usage = usage.trim().parse::<u64>().ok()?;
    Some(limit.saturating_sub(usage) / MIB)
}

fn read_cgroup_v2_cpu_sample(roots: &[&Path], relative: Option<&str>) -> CgroupReading<usize> {
    let Ok((root, advertised)) = verified_v2_root(roots, "cpu") else {
        return CgroupReading::invalid();
    };
    let Some(bases) = cgroup_bases_for_root(root, relative) else {
        return CgroupReading::invalid();
    };
    let Some(leaf) = bases.first() else {
        return CgroupReading::invalid();
    };
    match std::fs::read_to_string(leaf.join("cpu.max")) {
        Ok(_) => read_v2_cpu_hierarchy(&bases, root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !advertised => {
            CgroupReading::absent()
        }
        Err(_) => CgroupReading::invalid(),
    }
}

fn read_v2_cpu_hierarchy(bases: &[PathBuf], root: &Path) -> CgroupReading<usize> {
    let mut minimum = None;
    for base in bases {
        let value_path = base.join("cpu.max");
        let value = match std::fs::read_to_string(&value_path) {
            Ok(value) => value,
            Err(error) if base == root && error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return CgroupReading::invalid(),
        };
        if !stable_control_value(&value_path, &value) {
            return CgroupReading::invalid();
        }
        let mut values = value.split_whitespace();
        let Some(quota) = values.next() else {
            return CgroupReading::invalid();
        };
        let Some(period) = values.next().and_then(|value| value.parse::<u64>().ok()) else {
            return CgroupReading::invalid();
        };
        if period == 0 || values.next().is_some() {
            return CgroupReading::invalid();
        }
        if quota != "max" {
            let Some(units) = quota
                .parse::<u64>()
                .ok()
                .and_then(|quota| parse_cpu_quota_units(quota, period))
            else {
                return CgroupReading::invalid();
            };
            minimum = minimum_present(minimum, Some(units));
        }
    }
    CgroupReading::present(minimum)
}

#[cfg(test)]
pub(super) fn read_cgroup_v2_cpu_units(roots: &[&Path], relative: Option<&str>) -> Option<usize> {
    let sample = read_cgroup_v2_cpu_sample(roots, relative);
    sample.valid().then_some(sample.value).flatten()
}

#[cfg(test)]
pub(super) fn cgroup_v2_cpu_sample_complete(roots: &[&Path], relative: Option<&str>) -> bool {
    read_cgroup_v2_cpu_sample(roots, relative).valid()
}

fn read_cgroup_v1_cpu_sample(roots: &[&Path], relative: Option<&str>) -> CgroupReading<usize> {
    let Some((_root, bases)) = resolved_v1_hierarchy(roots, relative, "cpu.cfs_quota_us") else {
        return CgroupReading::invalid();
    };
    let mut minimum = None;
    for base in bases {
        let quota_path = base.join("cpu.cfs_quota_us");
        let period_path = base.join("cpu.cfs_period_us");
        let Ok(quota_text) = std::fs::read_to_string(&quota_path) else {
            return CgroupReading::invalid();
        };
        let Ok(period_text) = std::fs::read_to_string(&period_path) else {
            return CgroupReading::invalid();
        };
        let Ok(quota) = quota_text.trim().parse::<i64>() else {
            return CgroupReading::invalid();
        };
        let Ok(period) = period_text.trim().parse::<u64>() else {
            return CgroupReading::invalid();
        };
        if period == 0
            || !stable_control_value(&quota_path, &quota_text)
            || !stable_control_value(&period_path, &period_text)
        {
            return CgroupReading::invalid();
        }
        if quota > 0 {
            let Some(units) = parse_cpu_quota_units(u64::try_from(quota).unwrap_or(0), period)
            else {
                return CgroupReading::invalid();
            };
            minimum = minimum_present(minimum, Some(units));
        }
    }
    CgroupReading::present(minimum)
}

fn verified_v2_root<'a>(roots: &'a [&'a Path], controller: &str) -> Result<(&'a Path, bool), ()> {
    for root in roots {
        let controllers_path = root.join("cgroup.controllers");
        let controllers = match std::fs::read_to_string(&controllers_path) {
            Ok(controllers) => controllers,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(()),
        };
        if !stable_control_value(&controllers_path, &controllers) {
            return Err(());
        }
        let advertised = controllers
            .split_whitespace()
            .any(|value| value == controller);
        return Ok((*root, advertised));
    }
    Err(())
}

fn resolved_v1_hierarchy<'a>(
    roots: &'a [&'a Path],
    relative: Option<&str>,
    leaf_interface: &str,
) -> Option<(&'a Path, Vec<PathBuf>)> {
    for root in roots {
        let bases = cgroup_bases_for_root(root, relative)?;
        let leaf = bases.first()?;
        match std::fs::read_to_string(leaf.join(leaf_interface)) {
            Ok(_) => return Some((*root, bases)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        }
    }
    None
}

fn cgroup_bases_for_root(root: &Path, relative: Option<&str>) -> Option<Vec<PathBuf>> {
    let relative = match relative {
        Some(relative) => safe_cgroup_relative_path(relative)?,
        None => PathBuf::new(),
    };
    let mut candidates = Vec::new();
    let mut ancestor = relative;
    while ancestor.components().next().is_some() {
        candidates.push(root.join(&ancestor));
        if !ancestor.pop() {
            break;
        }
    }
    if candidates.last().is_none_or(|candidate| candidate != root) {
        candidates.push(root.to_path_buf());
    }
    Some(candidates)
}

fn stable_control_value(path: &Path, initial: &str) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .is_some_and(|confirmed| control_value_unchanged(initial, &confirmed))
}

pub(super) fn control_value_unchanged(initial: &str, confirmed: &str) -> bool {
    initial.trim() == confirmed.trim()
}

#[cfg(test)]
pub(super) fn parse_cgroup_v2_cpu_units(value: &str) -> Option<usize> {
    let mut values = value.split_whitespace();
    let quota = values.next()?;
    if quota == "max" {
        return None;
    }
    parse_cpu_quota_units(
        quota.parse::<u64>().ok()?,
        values.next()?.parse::<u64>().ok()?,
    )
}

#[cfg(test)]
pub(super) fn parse_cgroup_v1_cpu_units(quota: &str, period: &str) -> Option<usize> {
    let quota = quota.trim().parse::<i64>().ok()?;
    if quota <= 0 {
        return None;
    }
    parse_cpu_quota_units(
        u64::try_from(quota).ok()?,
        period.trim().parse::<u64>().ok()?,
    )
}

fn parse_cpu_quota_units(quota: u64, period: u64) -> Option<usize> {
    if period == 0 {
        return None;
    }
    usize::try_from(quota / period)
        .ok()
        .map(|units| units.max(1))
}

pub(super) fn cgroup_path(contents: &str, controller: Option<&str>) -> Option<String> {
    contents.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        match controller {
            None if controllers.is_empty() => Some(path.to_string()),
            Some(controller) if controllers.split(',').any(|value| value == controller) => {
                Some(path.to_string())
            }
            _ => None,
        }
    })
}

#[cfg(test)]
pub(super) fn cgroup_candidate_bases(roots: &[&Path], relative: Option<&str>) -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(roots.len().saturating_mul(2));
    for root in roots {
        let Some(bases) = cgroup_bases_for_root(root, relative) else {
            return Vec::new();
        };
        for candidate in bases {
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

pub(super) fn safe_cgroup_relative_path(value: &str) -> Option<PathBuf> {
    let mut path = PathBuf::new();
    for component in value.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || component.contains(['/', '\\']) {
            return None;
        }
        path.push(component);
    }
    Some(path)
}

pub(super) fn minimum_present<T: Ord + Copy>(left: Option<T>, right: Option<T>) -> Option<T> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}
