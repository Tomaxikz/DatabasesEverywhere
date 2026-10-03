use axum::{Router, routing::get};

use crate::state::AppState;

mod history;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/activity",
            get(crate::subsystems::monitoring::activity::current),
        )
        .merge(history::router())
}
