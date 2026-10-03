use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/ws/monitoring",
        get(crate::subsystems::monitoring::websocket::monitoring),
    )
}
