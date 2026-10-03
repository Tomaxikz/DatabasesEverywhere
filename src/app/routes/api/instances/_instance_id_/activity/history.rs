use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/activity/history",
        get(crate::subsystems::monitoring::activity::history),
    )
}
