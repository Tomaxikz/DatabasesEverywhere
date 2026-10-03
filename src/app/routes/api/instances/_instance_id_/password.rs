use axum::{Router, routing::patch};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/password",
        patch(crate::subsystems::instances::reset_instance_password),
    )
}
