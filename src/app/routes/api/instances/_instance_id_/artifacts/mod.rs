use axum::{Router, routing::get};

use crate::state::AppState;

mod _artifact_id_;
mod retention;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/artifacts",
            get(crate::subsystems::artifacts::list_instance_artifacts),
        )
        .merge(_artifact_id_::router())
        .merge(retention::router())
}
