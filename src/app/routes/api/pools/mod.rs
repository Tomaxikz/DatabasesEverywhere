use axum::{Router, routing::get};

use crate::state::AppState;

mod _runtime_id_;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/pools",
            get(crate::subsystems::monitoring::resources::list_shared_pools)
                .post(crate::subsystems::pools::create),
        )
        .merge(_runtime_id_::router())
}
