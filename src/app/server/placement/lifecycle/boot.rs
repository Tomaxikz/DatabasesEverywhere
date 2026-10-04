use super::MIN_CONTAINER_ID_PREFIX_LEN;
use crate::server::{metadata::DesiredInstanceState, placement::EngineRuntimeStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SharedBootAction {
    Start,
    Restart,
}

pub(super) fn shared_boot_action(
    status: EngineRuntimeStatus,
    desired: DesiredInstanceState,
) -> Option<SharedBootAction> {
    if desired == DesiredInstanceState::Stopped {
        return None;
    }
    match status {
        EngineRuntimeStatus::Stopped | EngineRuntimeStatus::Booting => {
            Some(SharedBootAction::Start)
        }
        EngineRuntimeStatus::Failed => Some(SharedBootAction::Restart),
        EngineRuntimeStatus::Creating
        | EngineRuntimeStatus::Running
        | EngineRuntimeStatus::Quarantined
        | EngineRuntimeStatus::Deleting => None,
    }
}

pub(super) fn container_ids_match(left: &str, right: &str) -> bool {
    let left = left.trim().strip_prefix("sha256:").unwrap_or(left.trim());
    let right = right.trim().strip_prefix("sha256:").unwrap_or(right.trim());
    left == right
        || (left.len().min(right.len()) >= MIN_CONTAINER_ID_PREFIX_LEN
            && (left.starts_with(right) || right.starts_with(left)))
}

pub(super) fn container_event_is_known_stale(
    event_container_id: Option<&str>,
    current_container_id: Option<&str>,
) -> bool {
    matches!(
        (event_container_id, current_container_id),
        (Some(event), Some(current)) if !container_ids_match(event, current)
    )
}
