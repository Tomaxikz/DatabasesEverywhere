use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/admin/backups/status",
        get(crate::subsystems::backups::backup_status),
    )
}
