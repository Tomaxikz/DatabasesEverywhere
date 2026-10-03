use super::*;

fn refresh_capacity(shared: &Shared, state: &mut SchedulerState) {
    if !shared.refreshes_capacity() {
        return;
    }
    let sample = shared.resource_provider.sample();
    if shared.auto_memory_budget {
        if sample.memory_valid {
            let candidate = memory_budget_from_available(
                sample
                    .available_memory_mib
                    .unwrap_or(FALLBACK_AVAILABLE_MEMORY_MIB),
            );
            apply_capacity_sample(
                &mut state.capacity.memory_budget_mib,
                &mut state.pending_memory_increase_mib,
                candidate,
            );
        } else {
            state.pending_memory_increase_mib = None;
            state.capacity.memory_budget_mib = 1;
        }
    }
    if shared.auto_cpu_units {
        if sample.cpu_valid {
            apply_capacity_sample(
                &mut state.capacity.cpu_units,
                &mut state.pending_cpu_increase,
                sample.cpu_units.unwrap_or(1).max(1),
            );
        } else {
            state.pending_cpu_increase = None;
            state.capacity.cpu_units = 1;
        }
    }
}

fn apply_capacity_sample<T: Ord + Copy>(current: &mut T, pending: &mut Option<T>, candidate: T) {
    if candidate <= *current {
        *current = candidate;
        *pending = None;
        return;
    }
    if let Some(previous) = pending.take() {
        *current = previous.min(candidate);
    } else {
        *pending = Some(candidate);
    }
}

pub(super) fn dispatch(shared: &Arc<Shared>, state: &mut SchedulerState) {
    refresh_capacity(shared, state);
    reject_expired_unfit_jobs(shared, state);
    while state.accepting && state.active_jobs < state.capacity.max_active_jobs {
        let Some(index) = runnable_index(shared, state) else {
            break;
        };
        if index > 0
            && let Some(head) = state.waiting.front_mut()
        {
            head.bypasses = head.bypasses.saturating_add(1);
        }
        let Some(waiting) = state.waiting.remove(index) else {
            break;
        };
        reserve(state, waiting.cost);
        let permit = ExecutionPermit {
            shared: Arc::clone(shared),
            cost: Some(waiting.cost),
        };
        if let Err(returned) = waiting.ready.send(Ok(permit)) {
            if let Ok(mut permit) = returned {
                permit.cost = None;
            }
            release(state, waiting.cost);
        }
    }
    if state.accepting && !state.waiting.is_empty() {
        schedule_capacity_refresh(shared, state);
    }
}

fn reject_expired_unfit_jobs(shared: &Shared, state: &mut SchedulerState) {
    if state.capacity.mode != SchedulerMode::Dynamic {
        return;
    }
    let mut index = 0;
    while index < state.waiting.len() {
        let expired = state.waiting[index].queued_at.elapsed() >= shared.starvation_timeout;
        let unfit = !fits_hard_memory(state.capacity, state.waiting[index].cost);
        if expired && unfit {
            if let Some(waiting) = state.waiting.remove(index) {
                let _ = waiting
                    .ready
                    .send(Err(SchedulerAcquireError::InsufficientCapacity));
            }
        } else {
            index += 1;
        }
    }
}

fn schedule_capacity_refresh(shared: &Arc<Shared>, state: &mut SchedulerState) {
    if state.refresh_wakeup_scheduled || !shared.refreshes_capacity() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    state.refresh_wakeup_scheduled = true;
    let shared = Arc::downgrade(shared);
    let delay = shared
        .upgrade()
        .map(|shared| {
            shared
                .capacity_refresh_interval
                .max(MIN_REFRESH_WAKEUP_INTERVAL)
        })
        .unwrap_or(MIN_REFRESH_WAKEUP_INTERVAL);
    runtime.spawn(async move {
        tokio::time::sleep(delay).await;
        if let Some(shared) = shared.upgrade() {
            let mut state = lock_unpoisoned(&shared.state);
            state.refresh_wakeup_scheduled = false;
            dispatch(&shared, &mut state);
        }
    });
}

fn runnable_index(shared: &Shared, state: &SchedulerState) -> Option<usize> {
    let head = state.waiting.front()?;
    let head_fits_hard_memory = fits_hard_memory(state.capacity, head.cost);
    let head_runs_alone = state.active_jobs == 0 && head_fits_hard_memory;
    if fits(state.capacity, state, head.cost) || head_runs_alone {
        return Some(0);
    }
    let waiting_for_live_capacity =
        state.capacity.mode == SchedulerMode::Dynamic && !head_fits_hard_memory;
    let head_is_starving =
        head.bypasses >= shared.max_bypass || head.queued_at.elapsed() >= shared.starvation_timeout;
    if !waiting_for_live_capacity && head_is_starving {
        return None;
    }
    state
        .waiting
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, waiting)| waiting.sequence > head.sequence)
        .find_map(|(index, waiting)| fits(state.capacity, state, waiting.cost).then_some(index))
}

fn fits_hard_memory(capacity: SchedulerCapacity, cost: JobResourceCost) -> bool {
    capacity.mode == SchedulerMode::Manual || cost.memory_mib <= capacity.memory_budget_mib
}

fn fits(capacity: SchedulerCapacity, state: &SchedulerState, cost: JobResourceCost) -> bool {
    if capacity.mode == SchedulerMode::Manual {
        return state.active_jobs < capacity.max_active_jobs;
    }
    state.active_memory_mib.saturating_add(cost.memory_mib) <= capacity.memory_budget_mib
        && state.active_io_mib.saturating_add(cost.io_mib) <= capacity.io_budget_mib
        && state.active_cpu_units.saturating_add(cost.cpu_units) <= capacity.cpu_units
}

fn reserve(state: &mut SchedulerState, cost: JobResourceCost) {
    state.active_jobs = state.active_jobs.saturating_add(1);
    state.active_memory_mib = state.active_memory_mib.saturating_add(cost.memory_mib);
    state.active_io_mib = state.active_io_mib.saturating_add(cost.io_mib);
    state.active_cpu_units = state.active_cpu_units.saturating_add(cost.cpu_units);
}

pub(super) fn release(state: &mut SchedulerState, cost: JobResourceCost) {
    state.active_jobs = state.active_jobs.saturating_sub(1);
    state.active_memory_mib = state.active_memory_mib.saturating_sub(cost.memory_mib);
    state.active_io_mib = state.active_io_mib.saturating_sub(cost.io_mib);
    state.active_cpu_units = state.active_cpu_units.saturating_sub(cost.cpu_units);
}

pub(super) fn ratio(total: u64, each: u64) -> usize {
    usize::try_from(total / each.max(1)).unwrap_or(usize::MAX)
}
