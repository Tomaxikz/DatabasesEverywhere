use std::{
    collections::HashMap,
    fs,
    io::{self, ErrorKind, IsTerminal, Read, Write},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    process::Command as StdCommand,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use axum::Router;
use axum_server::{Handle, accept::NoDelayAcceptor, tls_rustls::RustlsConfig};
use futures::StreamExt;
use hyper_util::rt::TokioTimer;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use secrecy::SecretString;
use serde::Deserialize;
use tokio::{io::AsyncWriteExt, net::TcpListener};

use crate::{
    api::{
        http::{
            response::ApiError,
            router::build_router,
            state::{AppState, AppStateData},
        },
        instances::progress::InstallProgressStore,
    },
    auth::api_token::ApiToken,
    config::{Config, DaemonEngine, DiskLimitMode, load::load_config},
    constants::{MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY, defaults},
    disk::DiskLimiter,
    gateway::{
        listeners, resolver::RouteResolver, security::GatewayConnectionLimiter,
        supervisor::GatewaySupervisor,
    },
    instances::{
        manager::InstanceManager, metadata::InstanceStatus, paths::InstancePaths, reconcile,
        state::InstanceStore,
    },
    jobs::import_export::ImportExportJobs,
    runtime::docker::{
        CpuBurstPolicyStatus, DockerContainerStatus, DockerRuntime, ManagedContainerEvent,
    },
    shared::{
        ids::validate_instance_id, images::has_sha256_digest, limits::mib_to_bytes,
        logs::truncate_log_tail, protocol::Protocol, time::now_rfc3339,
    },
    storage::{
        import_export_jobs::ImportExportJobRepository,
        import_uploads::ImportUploadRepository,
        repositories::{InstanceRepository, ProtectedSecretField},
        sqlite,
    },
};

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
pub(crate) mod setup;
mod soft_disk_limiter;
mod startup;

use crate::placement::lifecycle::*;
use crate::placement::tenant::recovery::*;
use admission::ApiConnectionAcceptor;
use boot_recovery::*;
use container_events::*;
use import_temp_cleanup::*;
pub(crate) use lifecycle::run_daemon;
use logging::*;
use orphan_reservations::*;
use runtime_paths::*;
use server::*;
use setup::*;
use soft_disk_limiter::*;
use startup::*;

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
