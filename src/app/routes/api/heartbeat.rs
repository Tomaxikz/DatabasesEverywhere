use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/api/heartbeat", get(crate::subsystems::system::heartbeat))
}
