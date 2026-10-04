use std::time::Duration;

mod admission;
mod boot_recovery;
mod container_events;
mod fuse_cleanup;
mod import_temp_cleanup;
mod legacy_credentials;
mod lifecycle;
pub(crate) mod logging;
pub(crate) mod maintenance;
mod orphan_reservations;
mod pool_recovery;
pub(crate) mod quarantine;
pub(crate) mod runtime_paths;
mod server;
mod services;
pub(crate) mod setup;
mod soft_disk_limiter;
mod startup;

pub(crate) use lifecycle::run_daemon;

#[cfg(test)]
mod tests;

const ACTIVE_OPERATION_DRAIN_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const API_MUTATION_DRAIN_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const API_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const WEBSOCKET_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const GATEWAY_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const GATEWAY_CONNECTION_FORCE_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
const API_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const API_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONTAINER_EVENT_RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(1);
const CONTAINER_EVENT_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);
