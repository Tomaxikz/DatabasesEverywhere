use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/import-export/jobs/{job_id}",
        get(crate::subsystems::import_export::get_import_export_job),
    )
}
