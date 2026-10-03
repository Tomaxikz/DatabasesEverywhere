use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/pools/{runtime_id}/logs",
        get(crate::subsystems::pools::streams::logs),
    )
}
