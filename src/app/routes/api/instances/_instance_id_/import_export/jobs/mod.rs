use axum::{Router, routing::get};

use crate::state::AppState;

mod _job_id_;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/import-export/jobs",
            get(crate::subsystems::import_export::list_import_export_jobs),
        )
        .merge(_job_id_::router())
}
