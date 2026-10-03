use axum::{Router, routing::get};

use crate::state::AppState;

mod _upload_id_;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/import/uploads",
            get(crate::subsystems::import_export::list_import_uploads),
        )
        .merge(_upload_id_::router())
}
