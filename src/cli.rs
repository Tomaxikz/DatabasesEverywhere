use std::{
    collections::HashMap,
    fs,
    future::Future,
    io::{self, ErrorKind, IsTerminal, Read, Write},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    pin::Pin,
    process::Command as StdCommand,
    sync::{Arc, Mutex, OnceLock},
    task::{Context as TaskContext, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use axum::Router;
use axum_server::{
    Handle,
    accept::{Accept, NoDelayAcceptor},
    tls_rustls::RustlsConfig,
};
use clap::{Parser, Subcommand};
use futures::StreamExt;
use hyper_util::rt::TokioTimer;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use secrecy::SecretString;
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    api::{
        api_response::ApiError,
        progress::InstallProgressStore,
        routes::{AppState, AppStateData, build_router},
    },
    auth::api_token::ApiToken,
    config::{Config, DaemonEngine, DiskLimitMode, load::load_config},
    constants::{self, defaults},
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
    runtime::docker::{DockerContainerStatus, DockerRuntime, ManagedContainerEvent},
    shared::{
        ids::validate_instance_id, images::has_sha256_digest, logs::truncate_log_tail,
        protocol::Protocol, time::now_rfc3339,
    },
    storage::{
        import_export_jobs::ImportExportJobRepository,
        repositories::{InstanceRepository, ProtectedSecretField},
        sqlite,
    },
};

mod boot_recovery;
mod container_events;
mod daemon;
mod maintenance;
mod runtime_paths;
mod server;
mod setup;
mod soft_disk_limiter;
mod startup;

use boot_recovery::*;
use container_events::*;
use daemon::*;
use maintenance::*;
use runtime_paths::*;
use server::*;
use setup::*;
use soft_disk_limiter::*;
use startup::*;

#[cfg(all(test, unix))]
mod tests;

const ACTIVE_OPERATION_DRAIN_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const API_MUTATION_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);
const API_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const WEBSOCKET_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const GATEWAY_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const GATEWAY_CONNECTION_FORCE_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
const API_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const API_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ACTIVE_API_CONNECTIONS: usize = 2_048;
const MAX_ACTIVE_API_CONNECTIONS_PER_PEER: usize = 256;
const MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY: usize = 8;
const CONTAINER_EVENT_RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(1);
const CONTAINER_EVENT_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct ApiConnectionAcceptor<A> {
    inner: A,
    limiter: Arc<ApiConnectionLimiter>,
}

impl<A> ApiConnectionAcceptor<A> {
    fn new(inner: A) -> Self {
        Self {
            inner,
            limiter: Arc::new(ApiConnectionLimiter::new(
                MAX_ACTIVE_API_CONNECTIONS,
                MAX_ACTIVE_API_CONNECTIONS_PER_PEER,
            )),
        }
    }
}

impl<S, A> Accept<TcpStream, S> for ApiConnectionAcceptor<A>
where
    S: Send + 'static,
    A: Accept<TcpStream, S> + Send + Sync,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A::Service: Send + 'static,
    A::Future: Send + 'static,
{
    type Stream = AdmittedApiStream<A::Stream>;
    type Service = A::Service;
    type Future =
        Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send + 'static>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let peer_ip = match stream.peer_addr() {
            Ok(peer) => peer.ip(),
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let permit = match self.limiter.try_acquire(peer_ip) {
            Some(permit) => permit,
            None => {
                return Box::pin(async {
                    Err(io::Error::new(
                        ErrorKind::WouldBlock,
                        "API connection admission capacity reached",
                    ))
                });
            }
        };
        let accepted = self.inner.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = accepted.await?;
            Ok((
                AdmittedApiStream {
                    inner: stream,
                    _permit: permit,
                },
                service,
            ))
        })
    }
}

#[derive(Debug)]
struct AdmittedApiStream<S> {
    inner: S,
    _permit: ApiConnectionPermit,
}

#[derive(Debug)]
struct ApiConnectionLimiter {
    global: Arc<Semaphore>,
    active: Mutex<HashMap<IpAddr, usize>>,
    max_active_per_peer: usize,
}

impl ApiConnectionLimiter {
    fn new(max_active: usize, max_active_per_peer: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_active.max(1))),
            active: Mutex::new(HashMap::new()),
            max_active_per_peer: max_active_per_peer.max(1),
        }
    }

    fn try_acquire(self: &Arc<Self>, peer_ip: IpAddr) -> Option<ApiConnectionPermit> {
        // Acquire global capacity before entering the per-peer map. The owned
        // permit is released automatically if the peer bucket is already full.
        let global = Arc::clone(&self.global).try_acquire_owned().ok()?;
        let peer_ip = canonical_peer_ip(peer_ip);
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = active.entry(peer_ip).or_default();
        if *count >= self.max_active_per_peer {
            return None;
        }
        *count += 1;
        Some(ApiConnectionPermit {
            _global: global,
            limiter: Arc::clone(self),
            peer_ip,
        })
    }
}

#[derive(Debug)]
struct ApiConnectionPermit {
    _global: OwnedSemaphorePermit,
    limiter: Arc<ApiConnectionLimiter>,
    peer_ip: IpAddr,
}

impl Drop for ApiConnectionPermit {
    fn drop(&mut self) {
        let mut active = self
            .limiter
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(count) = active.get_mut(&self.peer_ip) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            active.remove(&self.peer_ip);
        }
    }
}

fn canonical_peer_ip(peer_ip: IpAddr) -> IpAddr {
    match peer_ip {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map_or_else(
            || {
                let mut prefix = ipv6.octets();
                prefix[8..].fill(0);
                IpAddr::V6(prefix.into())
            },
            IpAddr::V4,
        ),
        ipv4 => ipv4,
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AdmittedApiStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AdmittedApiStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[derive(Debug, Parser)]
#[command(name = "dbev")]
#[command(about = "Container-backed database hosting daemon")]
pub struct Cli {
    #[arg(short, long, default_value = defaults::CONFIG_PATH)]
    config: PathBuf,
    #[command(flatten)]
    bench: crate::bench::BenchArgs,
    #[arg(long)]
    setup: bool,
    #[arg(long)]
    move_new_config: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Daemon,
    CheckConfig,
    DiskTest {
        #[arg(long, default_value_t = 16)]
        quota_mib: u64,
        #[arg(long, default_value_t = 64)]
        write_mib: u64,
    },
    Migrate,
    MigratePaths {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        force: bool,
    },
    DevClean,
    ResetMetadata,
    RepairProtectedSecret {
        #[arg(long)]
        instance_id: String,
        #[arg(long)]
        field: ProtectedSecretField,
        #[arg(long)]
        confirm_legacy_plaintext: bool,
    },
}

pub async fn run() -> anyhow::Result<()> {
    // Keep this call for library consumers that invoke the CLI without using
    // the bundled binary entry point. Setting the same mask twice is harmless.
    harden_process_file_creation();
    let cli = Cli::parse();
    if cli.bench.bench {
        if cli.setup || cli.move_new_config || cli.command.is_some() {
            anyhow::bail!("--bench cannot be combined with setup, migration, or daemon commands");
        }
        init_stdout_logging();
        return crate::bench::run(cli.config, cli.bench).await;
    }
    if cli.setup {
        init_stdout_logging();
        return setup_system(cli.config).await;
    }
    if cli.move_new_config {
        init_stdout_logging();
        return migrate_paths(cli.config, false, false).await;
    }
    match cli.command.unwrap_or(Command::Daemon) {
        Command::Daemon => run_daemon(cli.config).await,
        Command::CheckConfig => {
            let mut config = load_config(&cli.config)?;
            detect_and_log_disk_mode(&mut config)?;
            validate_runtime_support(&config).await?;
            println!("config ok");
            Ok(())
        }
        Command::DiskTest {
            quota_mib,
            write_mib,
        } => disk_test(cli.config, quota_mib, write_mib).await,
        Command::Migrate => migrate_metadata(cli.config).await,
        Command::MigratePaths { dry_run, force } => migrate_paths(cli.config, dry_run, force).await,
        Command::DevClean => dev_clean(cli.config).await,
        Command::ResetMetadata => reset_metadata(cli.config).await,
        Command::RepairProtectedSecret {
            instance_id,
            field,
            confirm_legacy_plaintext,
        } => {
            repair_protected_secret(cli.config, instance_id, field, confirm_legacy_plaintext).await
        }
    }
}

/// Restrict default permissions before the process creates logs, state, or
/// runtime files. Explicitly requested modes can still be tightened further.
pub fn harden_process_file_creation() {
    #[cfg(unix)]
    {
        use rustix::fs::Mode;

        rustix::process::umask(Mode::RWXG | Mode::RWXO);
    }
}
