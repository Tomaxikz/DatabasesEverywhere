use axum::{Router, routing::post};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/admin/images/pull",
        post(crate::subsystems::instances::images::pull_image),
    )
}
