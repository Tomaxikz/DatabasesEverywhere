use serde_json::Value;

use crate::routes::http::response::ApiError;

pub(super) fn check_snapshot_compatibility(source: &str, target: &str) -> Result<(), ApiError> {
    let source_parts = version_triplet(source).ok_or_else(|| {
        ApiError::BadRequest("remote qdrant reported an invalid version".to_string())
    })?;
    let target_parts = version_triplet(target).ok_or_else(|| {
        ApiError::Runtime("managed qdrant reported an invalid version".to_string())
    })?;
    let same_minor = source_parts.0 == target_parts.0 && source_parts.1 == target_parts.1;
    let compatible_patch = target_parts.2 >= source_parts.2;
    if !same_minor || !compatible_patch {
        return Err(ApiError::BadRequest(
            "remote qdrant snapshots are not compatible with the managed target; use the same major and minor version without a target patch downgrade"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) fn topology_is_standalone(response: &Value) -> Option<bool> {
    let result = response.get("result")?.as_object()?;
    let status = result.get("status")?.as_str()?;
    let peer_count = match result.get("peers") {
        None | Some(Value::Null) => 0,
        Some(Value::Object(peers)) => peers.len(),
        Some(_) => return None,
    };
    match status {
        "disabled" => Some(peer_count <= 1),
        "enabled" => Some(false),
        _ => None,
    }
}

pub(super) fn version_triplet(version: &str) -> Option<(u32, u32, u32)> {
    let core = version.trim_start_matches('v').split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let version = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    if parts.next().is_some() {
        return None;
    }
    Some(version)
}
