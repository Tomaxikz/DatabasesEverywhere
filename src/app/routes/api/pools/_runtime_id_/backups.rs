use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/pools/{runtime_id}/backups",
        get(crate::subsystems::pools::streams::backups),
    )
}
