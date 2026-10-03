use axum::Router;

use crate::state::AppState;

mod api;
mod metrics;
mod ws;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .merge(api::router())
        .merge(metrics::router())
        .merge(ws::router())
}

pub mod http;
