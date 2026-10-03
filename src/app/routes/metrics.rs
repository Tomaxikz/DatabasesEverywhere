use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/metrics",
        get(crate::subsystems::monitoring::metrics::metrics),
    )
}
