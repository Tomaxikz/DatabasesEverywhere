use axum::{Router, routing::get};

use crate::state::AppState;

mod activity;
mod artifacts;
mod backups;
mod deployment_migrations;
mod export;
mod image;
mod import;
mod import_export;
mod limits;
mod logs;
mod password;
mod power;
mod reconcile;
mod recovery;
mod resources;
mod status;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}",
            get(crate::subsystems::instances::get_instance)
                .delete(crate::subsystems::instances::delete_instance),
        )
        .merge(activity::router())
        .merge(artifacts::router())
        .merge(backups::router())
        .merge(deployment_migrations::router())
        .merge(export::router())
        .merge(image::router())
        .merge(import::router())
        .merge(import_export::router())
        .merge(limits::router())
        .merge(logs::router())
        .merge(password::router())
        .merge(power::router())
        .merge(reconcile::router())
        .merge(recovery::router())
        .merge(resources::router())
        .merge(status::router())
}
