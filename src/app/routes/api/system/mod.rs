use axum::{Router, routing::get};

use crate::state::AppState;

mod config;
mod import_export_scheduler;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/api/system", get(crate::subsystems::system::system))
        .merge(config::router())
        .merge(import_export_scheduler::router())
}
