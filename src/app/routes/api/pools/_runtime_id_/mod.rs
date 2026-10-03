use axum::{Router, routing::get};

use crate::state::AppState;

mod backups;
mod image;
mod instances;
mod logs;
mod power;
mod status;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/pools/{runtime_id}",
            get(crate::subsystems::monitoring::resources::get_shared_pool)
                .patch(crate::subsystems::pools::resize_pool)
                .delete(crate::subsystems::pools::delete),
        )
        .merge(backups::router())
        .merge(image::router())
        .merge(instances::router())
        .merge(logs::router())
        .merge(power::router())
        .merge(status::router())
}
