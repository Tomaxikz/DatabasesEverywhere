use axum::{Router, routing::patch};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/image",
        patch(crate::subsystems::instances::update_instance_image),
    )
}
