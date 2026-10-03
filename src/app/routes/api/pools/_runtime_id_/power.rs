use axum::{Router, routing::post};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/pools/{runtime_id}/power",
        post(crate::subsystems::pools::power),
    )
}
