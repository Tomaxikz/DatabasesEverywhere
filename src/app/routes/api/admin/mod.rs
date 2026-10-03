use axum::Router;

use crate::state::AppState;

mod backups;
mod images;
mod recovery;
mod resources;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .merge(backups::router())
        .merge(images::router())
        .merge(recovery::router())
        .merge(resources::router())
}
