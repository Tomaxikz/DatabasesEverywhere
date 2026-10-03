use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/resources",
        get(crate::subsystems::monitoring::resources::instance_resources),
    )
}
