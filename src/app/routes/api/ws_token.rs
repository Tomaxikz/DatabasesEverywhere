use axum::{Router, routing::post};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/ws-token",
        post(crate::subsystems::monitoring::tokens::issue_ws_token),
    )
}
