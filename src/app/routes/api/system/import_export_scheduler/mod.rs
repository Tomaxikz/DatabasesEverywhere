use axum::Router;

use crate::state::AppState;

mod recommendation;

pub(crate) fn router() -> Router<AppState> {
    Router::new().merge(recommendation::router())
}
