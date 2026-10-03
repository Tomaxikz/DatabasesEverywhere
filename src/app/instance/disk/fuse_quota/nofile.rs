use super::*;

pub(super) async fn set_helper_nofile_limit(peer_pid: i32) -> Result<(), DiskLimitError> {
    let limits_path = PathBuf::from(format!("/proc/{peer_pid}/limits"));
    let before = read_nofile_limits(&limits_path).await?;
    let desired_current = desired_nofile_current(before.maximum)?;
    if nofile_at_least(before.current, desired_current) {
        return Ok(());
    }

    let pid = rustix::process::Pid::from_raw(peer_pid).ok_or_else(|| {
        DiskLimitError::FuseSocket(format!(
            "fusequota control peer exposed invalid process id {peer_pid}"
        ))
    })?;
    rustix::process::prlimit(
        Some(pid),
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(desired_current),
            maximum: before.maximum,
        },
    )
    .map_err(|source| {
        DiskLimitError::FuseSocket(format!(
            "failed to raise RLIMIT_NOFILE for fusequota process {peer_pid}: {}",
            std::io::Error::from(source)
        ))
    })?;

    let after = read_nofile_limits(&limits_path).await?;
    if !nofile_at_least(after.current, desired_current) {
        return Err(DiskLimitError::FuseSocket(format!(
            "fusequota process {peer_pid} kept RLIMIT_NOFILE below {desired_current} after repair"
        )));
    }
    tracing::info!(
        helper_pid = peer_pid,
        old_soft_limit = ?before.current,
        new_soft_limit = ?after.current,
        hard_limit = ?after.maximum,
        "raised fusequota open-file limit"
    );
    Ok(())
}

async fn read_nofile_limits(limits_path: &Path) -> Result<NofileLimits, DiskLimitError> {
    let contents = tokio::fs::read_to_string(limits_path)
        .await
        .map_err(path_io_error(limits_path))?;
    parse_nofile_limits(&contents).map_err(DiskLimitError::FuseSocket)
}

pub(super) fn desired_nofile_current(maximum: Option<u64>) -> Result<u64, DiskLimitError> {
    let desired = maximum
        .map(|maximum| maximum.min(TARGET_FUSEQUOTA_NOFILE))
        .unwrap_or(TARGET_FUSEQUOTA_NOFILE);
    if desired < MINIMUM_FUSEQUOTA_NOFILE {
        return Err(DiskLimitError::FuseSocket(format!(
            "fusequota hard RLIMIT_NOFILE {desired} is below the required minimum {MINIMUM_FUSEQUOTA_NOFILE}; run dbev --setup to install the managed systemd limits"
        )));
    }
    Ok(desired)
}

fn nofile_at_least(current: Option<u64>, required: u64) -> bool {
    current.is_none_or(|current| current >= required)
}

pub(super) fn parse_nofile_limits(contents: &str) -> Result<NofileLimits, String> {
    let values = contents
        .lines()
        .find_map(|line| line.strip_prefix("Max open files"))
        .ok_or_else(|| "process limits did not contain Max open files".to_string())?
        .split_whitespace()
        .take(2)
        .map(parse_nofile_value)
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 2 {
        return Err("process Max open files limit was incomplete".to_string());
    }
    Ok(NofileLimits {
        current: values[0],
        maximum: values[1],
    })
}

fn parse_nofile_value(value: &str) -> Result<Option<u64>, String> {
    if value == "unlimited" {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|error| format!("invalid open-file limit {value:?}: {error}"))
}
