use axum::{Router, routing::post};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/admin/backups/run",
        post(crate::subsystems::backups::run_all_backups),
    )
}
