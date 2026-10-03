use super::*;

#[derive(Debug)]
pub(super) struct SampleDecision {
    pub(super) snapshot: SoftDiskSnapshot,
    pub(super) warning: bool,
    pub(super) must_stop: bool,
    pub(super) already_blocked: bool,
    pub(super) recovered: bool,
}

pub(super) fn safety_reserve_bytes(
    config: &SoftDiskScannerConfig,
    protocol: Protocol,
    limit_bytes: u64,
    growth_bytes_per_second: f64,
) -> u64 {
    let maximum = limit_bytes / 5;
    let configured = mib_to_bytes(config.safety_reserve_mib).min(maximum);
    let exposure_seconds = full_scan_interval_secs(config, protocol)
        .saturating_add(config.scan_timeout_seconds)
        .saturating_add(config.shutdown_grace_seconds)
        .saturating_add(1);
    let predicted =
        (growth_bytes_per_second * exposure_seconds as f64).clamp(0.0, maximum as f64) as u64;
    configured.max(predicted).min(maximum)
}

pub(super) fn thresholds(
    config: &SoftDiskScannerConfig,
    protocol: Protocol,
    limit_bytes: u64,
    growth_bytes_per_second: f64,
) -> (u64, u64) {
    let reserve = safety_reserve_bytes(config, protocol, limit_bytes, growth_bytes_per_second);
    let stop_threshold_bytes = limit_bytes.saturating_sub(reserve);
    let configured_recovery =
        limit_bytes.saturating_mul(u64::from(config.recovery_percent.min(99))) / 100;
    let hysteresis_margin = (limit_bytes / 20).max(1);
    let recovery_threshold_bytes =
        configured_recovery.min(stop_threshold_bytes.saturating_sub(hysteresis_margin));
    (stop_threshold_bytes, recovery_threshold_bytes)
}

pub(super) fn full_scan_interval_secs(config: &SoftDiskScannerConfig, protocol: Protocol) -> u64 {
    if config.use_inotify && !protocol.engine().mmap_writes_bypass_inotify() {
        config
            .full_scan_interval_seconds
            .max(config.scan_interval_seconds)
    } else {
        config.scan_interval_seconds
    }
}

pub(super) fn predict_seconds_to_limit(current: u64, limit: u64, growth: f64) -> Option<u64> {
    if current >= limit {
        return Some(0);
    }
    if !growth.is_finite() || growth <= 0.0 {
        return None;
    }
    Some(((limit - current) as f64 / growth).ceil() as u64)
}
