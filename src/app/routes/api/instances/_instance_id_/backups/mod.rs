use axum::{Router, routing::get};

use crate::state::AppState;

mod _backup_id_;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/backups",
            get(crate::subsystems::backups::list_instance_backups)
                .post(crate::subsystems::backups::run_instance_backup),
        )
        .merge(_backup_id_::router())
}
