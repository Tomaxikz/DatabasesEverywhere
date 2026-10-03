use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/ws/instances/{instance_id}/import-export",
        get(crate::subsystems::monitoring::websocket::import_export),
    )
}
