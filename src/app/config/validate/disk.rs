use super::{ConfigValidationError, network::validate_absolute_path};

pub(super) fn validate_disk(disk: &crate::config::DiskConfig) -> Result<(), ConfigValidationError> {
    if disk.project_id_base == 0 {
        return Err(ConfigValidationError::InvalidProjectIdBase);
    }
    let binary = disk.fuse_quota_binary();
    if !binary.eq_ignore_ascii_case("embedded") {
        validate_absolute_path("disk.fuse_quota_binary", binary)?;
        if !is_lowercase_sha256_hex(disk.fuse_quota_binary_sha256.trim()) {
            return Err(ConfigValidationError::InvalidFuseQuotaBinarySha256);
        }
    }
    let scanner = &disk.soft_scanner;
    for (field, value, maximum) in [
        (
            "scan_interval_seconds",
            scanner.scan_interval_seconds,
            3_600,
        ),
        (
            "full_scan_interval_seconds",
            scanner.full_scan_interval_seconds,
            3_600,
        ),
        (
            "inotify_debounce_milliseconds",
            scanner.inotify_debounce_milliseconds,
            60_000,
        ),
        ("scan_timeout_seconds", scanner.scan_timeout_seconds, 3_600),
        (
            "shutdown_grace_seconds",
            scanner.shutdown_grace_seconds,
            300,
        ),
    ] {
        if value == 0 || value > maximum {
            return Err(ConfigValidationError::InvalidSoftDiskScanner { field });
        }
    }
    if scanner.max_dirty_paths_per_instance == 0 || scanner.max_dirty_paths_per_instance > 65_536 {
        return Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "max_dirty_paths_per_instance",
        });
    }
    if scanner.max_concurrent_scans == 0 || scanner.max_concurrent_scans > 64 {
        return Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "max_concurrent_scans",
        });
    }
    if scanner.max_cached_directories_global == 0
        || scanner.max_cached_directories_global > u32::MAX as usize
    {
        return Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "max_cached_directories_global",
        });
    }
    if scanner.max_entries_per_scan == 0 || scanner.max_entries_per_scan > 10_000_000 {
        return Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "max_entries_per_scan",
        });
    }
    if scanner.max_consecutive_scan_failures == 0 || scanner.max_consecutive_scan_failures > 10 {
        return Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "max_consecutive_scan_failures",
        });
    }
    if !(1..=99).contains(&scanner.recovery_percent) {
        return Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "recovery_percent",
        });
    }
    Ok(())
}

pub(super) fn is_lowercase_sha256_hex(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
