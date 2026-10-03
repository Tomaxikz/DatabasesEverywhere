use axum::{Router, routing::get};

use crate::state::AppState;

mod _instance_id_;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances",
            get(crate::subsystems::instances::list_instances)
                .post(crate::subsystems::instances::create_instance),
        )
        .merge(_instance_id_::router())
}
