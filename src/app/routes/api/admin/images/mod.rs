use axum::Router;

use crate::state::AppState;

mod pull;

pub(crate) fn router() -> Router<AppState> {
    Router::new().merge(pull::router())
}
