use axum::Router;

use crate::state::AppState;

mod jobs;
mod restore;

pub(crate) fn router() -> Router<AppState> {
    Router::new().merge(jobs::router()).merge(restore::router())
}
