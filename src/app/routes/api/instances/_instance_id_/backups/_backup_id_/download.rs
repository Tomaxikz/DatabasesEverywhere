use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/backups/{backup_id}/download",
        get(crate::subsystems::artifacts::download_backup)
            .post(crate::subsystems::artifacts::create_backup_download),
    )
}
