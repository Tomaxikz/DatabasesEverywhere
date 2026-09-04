use std::time::{Duration, Instant};

use super::TrackerState;

pub(super) fn growth_rate(
    previous: Option<&TrackerState>,
    bytes: u64,
    now: Instant,
    base_scan_interval: Duration,
) -> f64 {
    let Some(previous) = previous else {
        return 0.0;
    };
    let elapsed = now
        .saturating_duration_since(previous.snapshot.sampled_at)
        .as_secs_f64();
    if elapsed <= f64::EPSILON {
        return previous.snapshot.growth_bytes_per_second;
    }
    let instantaneous =
        bytes.saturating_sub(previous.snapshot.usage.physical_bytes) as f64 / elapsed;
    let elapsed_intervals = elapsed / base_scan_interval.as_secs_f64().max(f64::EPSILON);
    let previous_weight = 0.6_f64.powf(elapsed_intervals).clamp(0.0, 1.0);
    // Wall-time decay prevents frequent partial scans from hiding prior bursts.
    (previous.snapshot.growth_bytes_per_second * previous_weight
        + instantaneous * (1.0 - previous_weight))
        .max(instantaneous * 0.75)
}
