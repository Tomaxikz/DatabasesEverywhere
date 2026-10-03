use axum::{Router, routing::patch};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/system/config",
        patch(crate::subsystems::system::config::patch_config),
    )
}
