use axum::{Router, routing::get};

use crate::state::AppState;

mod summary;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/admin/resources",
            get(crate::subsystems::monitoring::resources::list_resources),
        )
        .merge(summary::router())
}
