use axum::{Router, routing::post};

use crate::state::AppState;

mod uploads;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/import",
            post(crate::subsystems::import_export::import_entry),
        )
        .merge(uploads::router())
}
