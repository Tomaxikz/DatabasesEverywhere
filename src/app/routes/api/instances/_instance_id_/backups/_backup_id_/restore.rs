use axum::{Router, routing::post};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/backups/{backup_id}/restore",
        post(crate::subsystems::backups::restore_instance_backup),
    )
}
