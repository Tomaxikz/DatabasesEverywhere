use crate::state::AppState;

pub(super) fn start(state: &AppState) {
    crate::subsystems::monitoring::resources::start_resource_sampler(state.clone());
}
