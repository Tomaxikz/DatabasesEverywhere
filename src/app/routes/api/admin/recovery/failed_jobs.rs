use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/admin/recovery/failed-jobs",
        get(crate::subsystems::import_export::recovery::failed_jobs),
    )
}
