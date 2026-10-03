use axum::{Router, routing::post};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/recovery/jobs/{job_id}/retry",
        post(crate::subsystems::import_export::recovery::retry_job),
    )
}
