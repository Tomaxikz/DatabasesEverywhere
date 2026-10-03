use axum::{Router, routing::post};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/artifacts/retention",
        post(crate::subsystems::artifacts::apply_retention),
    )
}
