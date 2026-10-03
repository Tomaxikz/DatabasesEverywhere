use axum::{Router, routing::post};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/recovery/restore",
        post(crate::subsystems::import_export::recovery::restore_artifact),
    )
}
