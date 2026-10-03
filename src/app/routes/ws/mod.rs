use axum::Router;

use crate::state::AppState;

mod instances;
mod monitoring;
mod pools;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .merge(instances::router())
        .merge(monitoring::router())
        .merge(pools::router())
}
