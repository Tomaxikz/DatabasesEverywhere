use axum::{Router, routing::patch};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/pools/{runtime_id}/image",
        patch(crate::subsystems::pools::image::update),
    )
}
