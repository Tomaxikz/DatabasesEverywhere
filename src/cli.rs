use std::{
    fs,
    future::Future,
    io::{self, ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    pin::Pin,
    process::Command as StdCommand,
    sync::Arc,
    sync::OnceLock,
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
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpListener,
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
        images::has_sha256_digest, logs::truncate_log_tail, protocol::Protocol, time::now_rfc3339,
    },
    storage::{
        import_export_jobs::ImportExportJobRepository, repositories::InstanceRepository, sqlite,
    },
};

mod boot_recovery;
mod container_events;
mod daemon;
mod maintenance;
mod runtime_paths;
mod server;
mod setup;
mod startup;

use boot_recovery::*;
use container_events::*;
use daemon::*;
use maintenance::*;
use runtime_paths::*;
use server::*;
use setup::*;
use startup::*;

#[cfg(all(test, unix))]
mod tests;

const IMPORT_EXPORT_DRAIN_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const API_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const API_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const API_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ACTIVE_API_CONNECTIONS: usize = 2048;
const MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY: usize = 8;
const CONTAINER_EVENT_RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(1);
const CONTAINER_EVENT_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct ApiConnectionAcceptor<A> {
    inner: A,
    permits: Arc<Semaphore>,
}

impl<A> ApiConnectionAcceptor<A> {
    fn new(inner: A) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(MAX_ACTIVE_API_CONNECTIONS)),
        }
    }
}

impl<I, S, A> Accept<I, S> for ApiConnectionAcceptor<A>
where
    I: Send + 'static,
    S: Send + 'static,
    A: Accept<I, S> + Send + Sync,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A::Service: Send + 'static,
    A::Future: Send + 'static,
{
    type Stream = AdmittedApiStream<A::Stream>;
    type Service = A::Service;
    type Future =
        Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send + 'static>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let permit = match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Box::pin(async {
                    Err(io::Error::new(
                        ErrorKind::WouldBlock,
                        "API connection capacity reached",
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
    _permit: OwnedSemaphorePermit,
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
