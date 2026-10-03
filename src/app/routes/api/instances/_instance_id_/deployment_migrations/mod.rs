use axum::{Router, routing::get};

use crate::state::AppState;

mod _migration_id_;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/deployment-migrations",
            get(crate::subsystems::instances::list_deployment_migrations)
                .post(crate::subsystems::instances::start_deployment_migration),
        )
        .merge(_migration_id_::router())
}
