use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/backups/{backup_id}/contents",
        get(crate::subsystems::backups::browse_instance_backup),
    )
}
