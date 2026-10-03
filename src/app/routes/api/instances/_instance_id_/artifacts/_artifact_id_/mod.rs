use axum::{Router, routing::delete};

use crate::state::AppState;

mod download;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/artifacts/{artifact_id}",
            delete(crate::subsystems::artifacts::delete_artifact),
        )
        .merge(download::router())
}
