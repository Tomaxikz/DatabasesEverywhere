use axum::Router;

use crate::state::AppState;

mod run;
mod status;

pub(crate) fn router() -> Router<AppState> {
    Router::new().merge(run::router()).merge(status::router())
}
