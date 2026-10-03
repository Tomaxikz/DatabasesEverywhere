use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/artifacts/{artifact_id}/download",
        get(crate::subsystems::artifacts::download_artifact)
            .post(crate::subsystems::artifacts::create_artifact_download),
    )
}
