use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) enum ManagedBootAction {
    Start,
    Restart,
}

impl ManagedBootAction {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Restart => "restart",
        }
    }
}

pub(in super::super) fn managed_boot_action(
    status: InstanceStatus,
    desired_state: crate::instance::metadata::DesiredInstanceState,
) -> Option<ManagedBootAction> {
    if desired_state == crate::instance::metadata::DesiredInstanceState::Stopped {
        return None;
    }
    match status {
        InstanceStatus::Stopped | InstanceStatus::Booting => Some(ManagedBootAction::Start),
        InstanceStatus::Failed => Some(ManagedBootAction::Restart),
        InstanceStatus::Creating
        | InstanceStatus::Running
        | InstanceStatus::Quarantined
        | InstanceStatus::Deleting => None,
    }
}

pub(in super::super) async fn log_boot_container_failure(
    docker: &DockerRuntime,
    protocol: Protocol,
    instance_id: &str,
    message: &'static str,
    error: String,
) {
    let recent_container_logs = match docker.logs(protocol, instance_id, None).await {
        Ok(output) => {
            let combined = format!("{}{}", output.stdout, output.stderr);
            truncate_log_tail(combined.trim(), BOOT_FAILURE_LOG_TAIL_CHARS)
        }
        Err(log_error) => format!("failed to read container logs: {log_error}"),
    };

    tracing::warn!(
        instance_id,
        protocol = %protocol,
        reason = message,
        %error,
        %recent_container_logs,
        "managed instance boot start failed"
    );
}
