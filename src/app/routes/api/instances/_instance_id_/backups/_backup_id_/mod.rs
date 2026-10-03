use axum::{Router, routing::delete};

use crate::state::AppState;

mod contents;
mod download;
mod restore;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/backups/{backup_id}",
            delete(crate::subsystems::backups::delete_instance_backup),
        )
        .merge(contents::router())
        .merge(download::router())
        .merge(restore::router())
}
