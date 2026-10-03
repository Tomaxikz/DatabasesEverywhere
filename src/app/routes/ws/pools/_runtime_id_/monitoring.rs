use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/ws/pools/{runtime_id}/monitoring",
        get(crate::subsystems::pools::streams::monitoring),
    )
}
