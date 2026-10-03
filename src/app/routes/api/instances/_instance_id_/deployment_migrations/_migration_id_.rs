use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/deployment-migrations/{migration_id}",
        get(crate::subsystems::instances::get_deployment_migration),
    )
}
