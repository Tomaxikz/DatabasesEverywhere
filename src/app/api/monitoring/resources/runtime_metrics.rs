use std::time::Duration;

use bollard::models::ContainerStatsResponse;

pub(super) fn container_cpu_total(stats: &ContainerStatsResponse) -> Option<u64> {
    stats.cpu_stats.as_ref()?.cpu_usage.as_ref()?.total_usage
}

pub(super) fn cpu_percent_over_wall_time(
    previous_total: u64,
    current_total: u64,
    elapsed: Duration,
) -> f64 {
    let wall_delta_ns = elapsed.as_nanos() as f64;
    let cpu_delta_ns = current_total.saturating_sub(previous_total) as f64;
    if wall_delta_ns <= 0.0 || cpu_delta_ns <= 0.0 {
        return 0.0;
    }

    // Match Calagopus wings-rs: one fully occupied core is 100%, and work
    // spread across multiple cores can exceed 100%. Keep its 0.001% precision.
    ((cpu_delta_ns / wall_delta_ns) * 100.0 * 1000.0).round() / 1000.0
}

pub(super) fn docker_compatible_memory_usage(stats: &ContainerStatsResponse) -> Option<u64> {
    let memory = stats.memory_stats.as_ref()?;
    if stats.os_type.as_deref() == Some("windows") {
        return memory.privateworkingset.or(memory.usage);
    }

    let usage = memory.usage?;
    // Match `docker stats`: on Linux the CLI reports the working set rather
    // than raw cgroup usage by subtracting inactive file cache. Docker uses
    // total_inactive_file for cgroup v1 and inactive_file for cgroup v2.
    let inactive_file = memory
        .stats
        .as_ref()
        .and_then(|values| {
            values
                .get("total_inactive_file")
                .or_else(|| values.get("inactive_file"))
        })
        .copied()
        .unwrap_or(0);
    Some(usage.saturating_sub(inactive_file.min(usage)))
}
