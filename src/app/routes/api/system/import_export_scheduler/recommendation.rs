use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/system/import-export-scheduler/recommendation",
        get(crate::subsystems::system::scheduler_recommendation),
    )
}
