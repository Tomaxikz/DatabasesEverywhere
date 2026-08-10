use super::*;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(super) struct HostResourceProvider;

impl SchedulerResourceProvider for HostResourceProvider {
    fn sample(&self) -> SchedulerResourceSample {
        host_resource_sample()
    }
}

#[derive(Clone, Copy)]
struct CgroupReading<T> {
    value: Option<T>,
    valid: bool,
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

    if let Some(path) = cgroup_path(&cgroups, None) {
        let memory = read_cgroup_memory_sample(
            &[Path::new("/sys/fs/cgroup")],
            Some(&path),
            "memory.max",
            "memory.current",
            false,
        );
        let cpu = read_cgroup_v2_cpu_sample(&[Path::new("/sys/fs/cgroup")], Some(&path));
        return SchedulerResourceSample {
            available_memory_mib: minimum_present(host_memory, memory.value),
            cpu_units: effective_cpu_sample(host_cpu, cpu.value),
            memory_valid: memory.valid && host_memory.is_some(),
            cpu_valid: cpu.valid && host_cpu.is_some(),
        };
    }

    let memory = if let Some(path) = cgroup_path(&cgroups, Some("memory")) {
        read_cgroup_memory_sample(
            &[
                Path::new("/sys/fs/cgroup/memory"),
                Path::new("/sys/fs/cgroup"),
            ],
            Some(&path),
            "memory.limit_in_bytes",
            "memory.usage_in_bytes",
            true,
        )
    } else {
        CgroupReading {
            value: None,
            valid: true,
        }
    };
    let cpu = if let Some(path) = cgroup_path(&cgroups, Some("cpu")) {
        read_cgroup_v1_cpu_sample(
            &[
                Path::new("/sys/fs/cgroup/cpu"),
                Path::new("/sys/fs/cgroup/cpu,cpuacct"),
                Path::new("/sys/fs/cgroup"),
            ],
            Some(&path),
        )
    } else {
        CgroupReading {
            value: None,
            valid: true,
        }
    };
    SchedulerResourceSample {
        available_memory_mib: minimum_present(host_memory, memory.value),
        cpu_units: effective_cpu_sample(host_cpu, cpu.value),
        memory_valid: memory.valid && host_memory.is_some(),
        cpu_valid: cpu.valid && host_cpu.is_some(),
    }
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

fn read_cgroup_memory_sample(
    roots: &[&Path],
    relative: Option<&str>,
    limit_file: &str,
    usage_file: &str,
    numeric_unlimited: bool,
) -> CgroupReading<u64> {
    let mut minimum = None;
    let mut observed = false;
    for base in cgroup_candidate_bases(roots, relative) {
        let limit_path = base.join(limit_file);
        let limit = match std::fs::read_to_string(&limit_path) {
            Ok(limit) => limit,
            Err(_) if !numeric_unlimited && base.is_dir() => {
                return CgroupReading {
                    value: None,
                    valid: false,
                };
            }
            Err(_) => continue,
        };
        observed = true;
        let limit_text = limit.trim();
        if limit_text == "max" {
            if std::fs::read_to_string(&limit_path)
                .ok()
                .is_none_or(|confirmed| !control_value_unchanged(limit_text, &confirmed))
            {
                return CgroupReading {
                    value: None,
                    valid: false,
                };
            }
            continue;
        }
        let Ok(limit) = limit_text.parse::<u64>() else {
            return CgroupReading {
                value: None,
                valid: false,
            };
        };
        if numeric_unlimited && limit >= (1_u64 << 60) {
            if std::fs::read_to_string(&limit_path)
                .ok()
                .is_none_or(|confirmed| !control_value_unchanged(limit_text, &confirmed))
            {
                return CgroupReading {
                    value: None,
                    valid: false,
                };
            }
            continue;
        }
        let Ok(usage) = std::fs::read_to_string(base.join(usage_file)) else {
            return CgroupReading {
                value: None,
                valid: false,
            };
        };
        let Ok(usage) = usage.trim().parse::<u64>() else {
            return CgroupReading {
                value: None,
                valid: false,
            };
        };
        if std::fs::read_to_string(&limit_path)
            .ok()
            .is_none_or(|confirmed| !control_value_unchanged(limit_text, &confirmed))
        {
            return CgroupReading {
                value: None,
                valid: false,
            };
        }
        minimum = minimum_present(minimum, Some(limit.saturating_sub(usage) / MIB));
    }
    CgroupReading {
        value: minimum,
        valid: observed,
    }
}

#[cfg(test)]
pub(super) fn read_cgroup_memory(
    roots: &[&Path],
    relative: Option<&str>,
    limit_file: &str,
    usage_file: &str,
    numeric_unlimited: bool,
) -> Option<u64> {
    let sample =
        read_cgroup_memory_sample(roots, relative, limit_file, usage_file, numeric_unlimited);
    sample.valid.then_some(sample.value).flatten()
}

#[cfg(test)]
pub(super) fn cgroup_memory_sample_complete(
    roots: &[&Path],
    relative: Option<&str>,
    limit_file: &str,
    usage_file: &str,
    numeric_unlimited: bool,
) -> bool {
    read_cgroup_memory_sample(roots, relative, limit_file, usage_file, numeric_unlimited).valid
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
    let mut minimum = None;
    let mut observed = false;
    for base in cgroup_candidate_bases(roots, relative) {
        let value_path = base.join("cpu.max");
        let value = match std::fs::read_to_string(&value_path) {
            Ok(value) => value,
            Err(_) if base.is_dir() => {
                return CgroupReading {
                    value: None,
                    valid: false,
                };
            }
            Err(_) => continue,
        };
        observed = true;
        if std::fs::read_to_string(&value_path)
            .ok()
            .is_none_or(|confirmed| !control_value_unchanged(&value, &confirmed))
        {
            return CgroupReading {
                value: None,
                valid: false,
            };
        }
        let mut values = value.split_whitespace();
        let Some(quota) = values.next() else {
            return CgroupReading {
                value: None,
                valid: false,
            };
        };
        let Some(period) = values.next().and_then(|value| value.parse::<u64>().ok()) else {
            return CgroupReading {
                value: None,
                valid: false,
            };
        };
        if period == 0 {
            return CgroupReading {
                value: None,
                valid: false,
            };
        }
        if quota != "max" {
            let Some(units) = quota
                .parse::<u64>()
                .ok()
                .and_then(|quota| parse_cpu_quota_units(quota, period))
            else {
                return CgroupReading {
                    value: None,
                    valid: false,
                };
            };
            minimum = minimum_present(minimum, Some(units));
        }
    }
    CgroupReading {
        value: minimum,
        valid: observed,
    }
}

#[cfg(test)]
pub(super) fn read_cgroup_v2_cpu_units(roots: &[&Path], relative: Option<&str>) -> Option<usize> {
    let sample = read_cgroup_v2_cpu_sample(roots, relative);
    sample.valid.then_some(sample.value).flatten()
}

#[cfg(test)]
pub(super) fn cgroup_v2_cpu_sample_complete(roots: &[&Path], relative: Option<&str>) -> bool {
    read_cgroup_v2_cpu_sample(roots, relative).valid
}

fn read_cgroup_v1_cpu_sample(roots: &[&Path], relative: Option<&str>) -> CgroupReading<usize> {
    let mut minimum = None;
    let mut observed = false;
    for base in cgroup_candidate_bases(roots, relative) {
        let quota_path = base.join("cpu.cfs_quota_us");
        let period_path = base.join("cpu.cfs_period_us");
        let Ok(quota_text) = std::fs::read_to_string(&quota_path) else {
            continue;
        };
        observed = true;
        let Ok(quota) = quota_text.trim().parse::<i64>() else {
            return CgroupReading {
                value: None,
                valid: false,
            };
        };
        if std::fs::read_to_string(&quota_path)
            .ok()
            .is_none_or(|confirmed| !control_value_unchanged(&quota_text, &confirmed))
        {
            return CgroupReading {
                value: None,
                valid: false,
            };
        }
        if quota > 0 {
            let Ok(period) = std::fs::read_to_string(&period_path) else {
                return CgroupReading {
                    value: None,
                    valid: false,
                };
            };
            let stable = std::fs::read_to_string(&quota_path)
                .ok()
                .zip(std::fs::read_to_string(&period_path).ok())
                .is_some_and(|(confirmed_quota, confirmed_period)| {
                    control_value_unchanged(&quota_text, &confirmed_quota)
                        && control_value_unchanged(&period, &confirmed_period)
                });
            if !stable {
                return CgroupReading {
                    value: None,
                    valid: false,
                };
            }
            let Some(units) = parse_cgroup_v1_cpu_units(&quota.to_string(), &period) else {
                return CgroupReading {
                    value: None,
                    valid: false,
                };
            };
            minimum = minimum_present(minimum, Some(units));
        }
    }
    CgroupReading {
        value: minimum,
        valid: observed,
    }
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

pub(super) fn cgroup_candidate_bases(roots: &[&Path], relative: Option<&str>) -> Vec<PathBuf> {
    let relative = relative.and_then(safe_cgroup_relative_path);
    let mut candidates = Vec::with_capacity(roots.len().saturating_mul(2));
    for root in roots {
        if let Some(relative) = &relative {
            let mut ancestor = relative.clone();
            while ancestor.components().next().is_some() {
                let candidate = root.join(&ancestor);
                if !candidates.contains(&candidate) {
                    candidates.push(candidate);
                }
                if !ancestor.pop() {
                    break;
                }
            }
        }
        let root = (*root).to_path_buf();
        if !candidates.contains(&root) {
            candidates.push(root);
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
