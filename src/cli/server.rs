use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) enum GatewayListenerKind {
    Postgres,
    Redis,
    Valkey,
    Mariadb,
    Mysql,
    Mongodb,
    Clickhouse,
    ClickhouseHttp,
    Qdrant,
}

impl GatewayListenerKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::Valkey => "valkey",
            Self::Mariadb => "mariadb",
            Self::Mysql => "mysql",
            Self::Mongodb => "mongodb",
            Self::Clickhouse => "clickhouse",
            Self::ClickhouseHttp => "clickhouse_http",
            Self::Qdrant => "qdrant",
        }
    }
}

pub(super) struct PreparedGatewayListener {
    kind: GatewayListenerKind,
    bind: String,
    listener: TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
}

impl PreparedGatewayListener {
    async fn bind(
        kind: GatewayListenerKind,
        bind: String,
        tls: Option<tokio_rustls::TlsAcceptor>,
        limiter: GatewayConnectionLimiter,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(&bind)
            .await
            .with_context(|| format!("failed to bind {} listener on {bind}", kind.as_str()))?;
        Ok(Self {
            kind,
            bind,
            listener,
            tls,
            limiter,
        })
    }

    async fn run(
        self,
        resolver: RouteResolver,
        shutdown: tokio::sync::watch::Receiver<bool>,
        connections: crate::gateway::supervisor::GatewayConnectionTracker,
    ) -> Result<(), listeners::ListenerError> {
        let Self {
            kind,
            bind,
            listener,
            tls,
            limiter,
        } = self;
        match kind {
            GatewayListenerKind::Postgres => {
                listeners::run_postgres_listener(
                    listener,
                    &bind,
                    resolver,
                    tls,
                    limiter,
                    shutdown,
                    connections,
                )
                .await
            }
            GatewayListenerKind::Redis => {
                listeners::run_redis_listener(
                    listener,
                    &bind,
                    resolver,
                    tls,
                    limiter,
                    shutdown,
                    connections,
                )
                .await
            }
            GatewayListenerKind::Valkey => {
                listeners::run_valkey_listener(
                    listener,
                    &bind,
                    resolver,
                    tls,
                    limiter,
                    shutdown,
                    connections,
                )
                .await
            }
            GatewayListenerKind::Mariadb => {
                listeners::run_mariadb_listener(
                    listener,
                    &bind,
                    resolver,
                    tls,
                    limiter,
                    shutdown,
                    connections,
                )
                .await
            }
            GatewayListenerKind::Mysql => {
                listeners::run_mysql_listener(
                    listener,
                    &bind,
                    resolver,
                    tls,
                    limiter,
                    shutdown,
                    connections,
                )
                .await
            }
            GatewayListenerKind::Mongodb => {
                listeners::run_mongodb_listener(
                    listener,
                    &bind,
                    resolver,
                    tls,
                    limiter,
                    shutdown,
                    connections,
                )
                .await
            }
            GatewayListenerKind::Clickhouse => {
                listeners::run_clickhouse_listener(
                    listener,
                    &bind,
                    resolver,
                    tls,
                    limiter,
                    shutdown,
                    connections,
                )
                .await
            }
            GatewayListenerKind::ClickhouseHttp => {
                listeners::run_clickhouse_http_listener(
                    listener,
                    &bind,
                    resolver,
                    tls,
                    limiter,
                    shutdown,
                    connections,
                )
                .await
            }
            GatewayListenerKind::Qdrant => {
                listeners::run_qdrant_listener(
                    listener,
                    &bind,
                    resolver,
                    tls,
                    limiter,
                    shutdown,
                    connections,
                )
                .await
            }
        }
    }
}

pub(super) async fn start_gateway_listeners(
    config: &Config,
    store: InstanceStore,
    resources: crate::api::resources::ResourceCache,
    supervisor: GatewaySupervisor,
) -> anyhow::Result<()> {
    let connection_limit = config.security.db_connection_limit_per_minute;
    let expected = usize::from(config.postgres.enabled)
        + usize::from(config.redis.enabled)
        + usize::from(config.valkey.enabled)
        + usize::from(config.mariadb.enabled)
        + usize::from(config.mysql.enabled)
        + usize::from(config.mongodb.enabled)
        + usize::from(config.clickhouse.enabled) * 2
        + usize::from(config.qdrant.enabled);
    if !supervisor.begin(expected) {
        anyhow::bail!("daemon shutdown started before gateway listeners were bound");
    }

    let prepared = prepare_gateway_listeners(config, connection_limit).await;
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            supervisor.fail_and_stop("gateway listener bind failed");
            return Err(error);
        }
    };
    if supervisor.is_stopping() {
        anyhow::bail!("daemon shutdown started while gateway listeners were binding");
    }
    let resolver = RouteResolver::new(store, resources);
    let mut listeners = tokio::task::JoinSet::new();
    for listener in prepared {
        let protocol = listener.kind.as_str();
        let resolver = resolver.clone();
        let shutdown = supervisor.subscribe_shutdown();
        let connections = supervisor.connection_tracker();
        listeners.spawn(async move {
            let result = listener.run(resolver, shutdown, connections).await;
            (protocol, result)
        });
    }
    supervisor.mark_ready();

    if expected == 0 {
        return Ok(());
    }
    tokio::spawn(async move {
        while let Some(outcome) = listeners.join_next().await {
            if supervisor.is_stopping() {
                continue;
            }
            let failure = match outcome {
                Ok((protocol, Ok(()))) => format!("{protocol} listener stopped unexpectedly"),
                Ok((protocol, Err(error))) => {
                    tracing::error!(%error, protocol, "database listener stopped");
                    format!("{protocol} listener stopped")
                }
                Err(error) => {
                    tracing::error!(%error, "database listener task failed");
                    "database listener task failed".to_string()
                }
            };
            supervisor.fail_and_stop(failure);
            listeners.abort_all();
            while listeners.join_next().await.is_some() {}
            return;
        }
    });
    Ok(())
}

pub(super) async fn prepare_gateway_listeners(
    config: &Config,
    connection_limit: u32,
) -> anyhow::Result<Vec<PreparedGatewayListener>> {
    let mut prepared = Vec::new();
    let limiter = GatewayConnectionLimiter::new(connection_limit);
    if config.postgres.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Postgres,
                config.postgres.bind.clone(),
                listener_tls(config.postgres.tls, config)?,
                limiter.clone(),
            )
            .await?,
        );
    }
    if config.redis.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Redis,
                config.redis.bind.clone(),
                listener_tls(config.redis.tls, config)?,
                limiter.clone(),
            )
            .await?,
        );
    }
    if config.valkey.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Valkey,
                config.valkey.bind.clone(),
                listener_tls(config.valkey.tls, config)?,
                limiter.clone(),
            )
            .await?,
        );
    }
    if config.mariadb.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Mariadb,
                config.mariadb.bind.clone(),
                listener_tls(config.mariadb.tls, config)?,
                limiter.clone(),
            )
            .await?,
        );
    }
    if config.mysql.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Mysql,
                config.mysql.bind.clone(),
                listener_tls(config.mysql.tls, config)?,
                limiter.clone(),
            )
            .await?,
        );
    }
    if config.mongodb.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Mongodb,
                config.mongodb.bind.clone(),
                listener_tls(config.mongodb.tls, config)?,
                limiter.clone(),
            )
            .await?,
        );
    }
    if config.clickhouse.enabled {
        let tls = listener_tls(config.clickhouse.tls, config)?;
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Clickhouse,
                config.clickhouse.bind.clone(),
                tls.clone(),
                limiter.clone(),
            )
            .await?,
        );
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::ClickhouseHttp,
                config.clickhouse.http_bind.clone(),
                tls,
                limiter.clone(),
            )
            .await?,
        );
    }
    if config.qdrant.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Qdrant,
                config.qdrant.bind.clone(),
                listener_tls(config.qdrant.tls, config)?,
                limiter,
            )
            .await?,
        );
    }
    Ok(prepared)
}

pub(super) fn listener_tls(
    enabled: bool,
    config: &Config,
) -> anyhow::Result<Option<tokio_rustls::TlsAcceptor>> {
    if !enabled {
        return Ok(None);
    }
    crate::gateway::tls::acceptor(&config.tls.cert, &config.tls.key)
        .map(Some)
        .context("failed to configure database listener tls")
}

pub(super) async fn serve_api(
    config: &Config,
    router: Router,
    import_export_jobs: ImportExportJobs,
    install_progress: InstallProgressStore,
    api_rate_limiter: crate::api::security::ApiRateLimiter,
    daemon_shutdown: crate::api::routes::DaemonShutdown,
    gateway_supervisor: GatewaySupervisor,
) -> anyhow::Result<()> {
    let bind = config.api.bind_addr();
    if config.api.ssl.enabled {
        return serve_api_tls(
            config,
            router,
            import_export_jobs,
            install_progress,
            api_rate_limiter,
            daemon_shutdown,
            gateway_supervisor,
        )
        .await;
    }

    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("failed to bind API listener on {bind}"))?;
    tracing::info!(
        bind = %bind,
        configured_host = %config.api.host,
        port = config.api.port,
        max_active_connections = MAX_ACTIVE_API_CONNECTIONS,
        max_active_connections_per_peer = MAX_ACTIVE_API_CONNECTIONS_PER_PEER,
        header_read_timeout_seconds = API_HEADER_READ_TIMEOUT.as_secs(),
        "api listener started"
    );

    let listener = listener
        .into_std()
        .context("failed to convert API listener")?;
    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown_signal(
            import_export_jobs,
            install_progress,
            api_rate_limiter,
            daemon_shutdown,
            gateway_supervisor,
        )
        .await;
        shutdown_handle.graceful_shutdown(Some(API_CONNECTION_DRAIN_TIMEOUT));
    });

    let mut server = axum_server::from_tcp(listener)
        .context("failed to create API server")?
        .acceptor(ApiConnectionAcceptor::new(NoDelayAcceptor::new()));
    configure_api_http(&mut server);
    server
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("api server failed")
}

pub(super) async fn serve_api_tls(
    config: &Config,
    router: Router,
    import_export_jobs: ImportExportJobs,
    install_progress: InstallProgressStore,
    api_rate_limiter: crate::api::security::ApiRateLimiter,
    daemon_shutdown: crate::api::routes::DaemonShutdown,
    gateway_supervisor: GatewaySupervisor,
) -> anyhow::Result<()> {
    let bind_addr = config.api.bind_addr();
    let listener = std::net::TcpListener::bind(&bind_addr)
        .with_context(|| format!("failed to bind API listener on {bind_addr}"))?;
    listener
        .set_nonblocking(true)
        .context("failed to configure API TLS listener as non-blocking")?;
    let tls = api_rustls_config(config)
        .await
        .context("failed to build API TLS configuration")?;
    tracing::info!(
        cert = %config.api.ssl.cert,
        key = %config.api.ssl.key,
        require_client_cert = config.api.ssl.require_client_cert,
        "api tls configuration loaded"
    );

    tracing::info!(
        bind = %bind_addr,
        configured_host = %config.api.host,
        port = config.api.port,
        max_active_connections = MAX_ACTIVE_API_CONNECTIONS,
        max_active_connections_per_peer = MAX_ACTIVE_API_CONNECTIONS_PER_PEER,
        header_read_timeout_seconds = API_HEADER_READ_TIMEOUT.as_secs(),
        tls_handshake_timeout_seconds = API_TLS_HANDSHAKE_TIMEOUT.as_secs(),
        "api tls listener started"
    );
    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown_signal(
            import_export_jobs,
            install_progress,
            api_rate_limiter,
            daemon_shutdown,
            gateway_supervisor,
        )
        .await;
        shutdown_handle.graceful_shutdown(Some(API_CONNECTION_DRAIN_TIMEOUT));
    });

    let mut server = axum_server::from_tcp_rustls(listener, tls)
        .context("failed to create API TLS server")?
        .map(|acceptor| {
            ApiConnectionAcceptor::new(
                acceptor
                    .handshake_timeout(API_TLS_HANDSHAKE_TIMEOUT)
                    .acceptor(NoDelayAcceptor::new()),
            )
        });
    configure_api_http(&mut server);
    server
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("api tls server failed")
}

pub(super) fn configure_api_http<A, Acc>(server: &mut axum_server::Server<A, Acc>)
where
    A: axum_server::Address,
{
    server
        .http_builder()
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(API_HEADER_READ_TIMEOUT);
}

pub(super) async fn api_rustls_config(config: &Config) -> anyhow::Result<RustlsConfig> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    if !config.api.ssl.require_client_cert {
        return RustlsConfig::from_pem_file(&config.api.ssl.cert, &config.api.ssl.key)
            .await
            .with_context(|| {
                format!(
                    "failed to load API TLS cert/key from {} and {}",
                    config.api.ssl.cert, config.api.ssl.key
                )
            });
    }

    let cert_pem = tokio::fs::read(&config.api.ssl.cert)
        .await
        .with_context(|| format!("failed to read API TLS cert {}", config.api.ssl.cert))?;
    let key_pem = tokio::fs::read(&config.api.ssl.key)
        .await
        .with_context(|| format!("failed to read API TLS key {}", config.api.ssl.key))?;
    let ca_pem = tokio::fs::read(&config.api.ssl.client_ca)
        .await
        .with_context(|| format!("failed to read API client CA {}", config.api.ssl.client_ca))?;

    tokio::task::spawn_blocking(move || rustls_config_with_client_ca(cert_pem, key_pem, ca_pem))
        .await
        .context("failed to join TLS config builder")?
        .map(RustlsConfig::from_config)
}

pub(super) fn rustls_config_with_client_ca(
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let certs = CertificateDer::pem_reader_iter(cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse API TLS certificate")?;
    let key =
        PrivateKeyDer::from_pem_slice(&key_pem).context("failed to parse API TLS private key")?;

    let mut roots = rustls::RootCertStore::empty();
    let ca_certs = CertificateDer::pem_reader_iter(ca_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse API client CA certificates")?;
    for cert in ca_certs {
        roots.add(cert).context("failed to add API client CA")?;
    }

    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("failed to build API client certificate verifier")?;
    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("failed to build API TLS server config")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub(super) async fn shutdown_signal(
    import_export_jobs: ImportExportJobs,
    install_progress: InstallProgressStore,
    api_rate_limiter: crate::api::security::ApiRateLimiter,
    daemon_shutdown: crate::api::routes::DaemonShutdown,
    gateway_supervisor: GatewaySupervisor,
) {
    let signal = wait_for_termination_signal().await;
    let active_api_requests = api_rate_limiter.active_request_count();
    let active_websockets = api_rate_limiter.active_websocket_count();
    let active_mutations = daemon_shutdown.active_mutation_count();
    let active_gateway_connections = gateway_supervisor.active_connections();
    let active_import_export_jobs = import_export_jobs.active_count();
    let active_instance_creations = install_progress.active_creation_count();
    daemon_shutdown.trigger();
    import_export_jobs.close_admission();
    install_progress.close_creation_admission();
    gateway_supervisor.shutdown();
    tracing::info!(
        signal,
        phase = "admission_closed",
        active_api_requests,
        active_websockets,
        active_mutations,
        active_gateway_connections,
        active_import_export_jobs,
        active_instance_creations,
        "shutdown signal received; new mutations and background operations are no longer accepted"
    );

    let (mutations_drained, websocket_drained, gateway_drain) = tokio::join!(
        daemon_shutdown.wait_for_mutation_drain(API_MUTATION_DRAIN_TIMEOUT),
        api_rate_limiter.wait_for_websocket_drain(WEBSOCKET_DRAIN_TIMEOUT),
        gateway_supervisor.drain_connections(
            GATEWAY_CONNECTION_DRAIN_TIMEOUT,
            GATEWAY_CONNECTION_FORCE_CLOSE_TIMEOUT,
        ),
    );
    if mutations_drained {
        tracing::info!(phase = "mutation_drain", "active API mutations drained");
    } else {
        tracing::warn!(
            phase = "mutation_drain",
            remaining = daemon_shutdown.active_mutation_count(),
            timeout_seconds = API_MUTATION_DRAIN_TIMEOUT.as_secs(),
            "timed out waiting for active API mutations; the API connection deadline will now apply"
        );
    }
    if websocket_drained {
        tracing::info!(
            phase = "websocket_drain",
            active_at_start = active_websockets,
            "websocket clients received the restart close frame"
        );
    } else {
        tracing::warn!(
            phase = "websocket_drain",
            remaining = api_rate_limiter.active_websocket_count(),
            timeout_seconds = WEBSOCKET_DRAIN_TIMEOUT.as_secs(),
            "websocket close deadline elapsed"
        );
    }
    if gateway_drain.gracefully_drained {
        tracing::info!(
            phase = "gateway_drain",
            active_at_start = gateway_drain.active_at_start,
            "database gateway connections drained"
        );
    } else if gateway_drain.remaining == 0 {
        tracing::info!(
            phase = "gateway_drain",
            active_at_start = gateway_drain.active_at_start,
            "database gateway drain deadline elapsed; remaining proxy connections were closed"
        );
    } else {
        tracing::warn!(
            phase = "gateway_drain",
            active_at_start = gateway_drain.active_at_start,
            remaining = gateway_drain.remaining,
            "database gateway tasks did not exit before the forced-close deadline"
        );
    }
    tracing::info!(
        phase = "network_drain_complete",
        "network shutdown drain complete; managed database containers remain running"
    );
}

#[cfg(unix)]
pub(super) async fn wait_for_termination_signal() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};

    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => "SIGINT",
                _ = terminate.recv() => "SIGTERM",
            }
        }
        Err(error) => {
            tracing::warn!(%error, "failed to install SIGTERM handler; waiting for SIGINT only");
            let _ = tokio::signal::ctrl_c().await;
            "SIGINT"
        }
    }
}

#[cfg(not(unix))]
pub(super) async fn wait_for_termination_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "CTRL_C"
}

pub(super) static LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> =
    OnceLock::new();

pub(super) fn init_stdout_logging() {
    let filter = EnvFilter::try_from_env(constants::RUST_LOG_ENV)
        .unwrap_or_else(|_| EnvFilter::new("databases_everywhere=info,tower_http=info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .try_init();
}

pub(super) fn init_configured_logging(config: &Config) -> anyhow::Result<()> {
    fs::create_dir_all(&config.paths.logs)
        .with_context(|| format!("failed to create log directory {}", config.paths.logs))?;
    harden_runtime_directory(Path::new(&config.paths.logs))?;

    let filter = EnvFilter::try_from_env(constants::RUST_LOG_ENV)
        .unwrap_or_else(|_| EnvFilter::new("databases_everywhere=info,tower_http=info"));
    let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("dbev.log")
        .max_log_files(14)
        .build(&config.paths.logs)
        .with_context(|| format!("failed to initialize log file in {}", config.paths.logs))?;
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let _ = LOG_GUARD.set(guard);

    let result = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .with(fmt::layer().with_ansi(false).with_writer(file_writer))
        .try_init();

    if result.is_err() {
        tracing::debug!("logging was already initialized");
    }
    Ok(())
}

pub(super) fn startup_banner() -> String {
    format!(
        r#"     ____    ____    ______  _    __
    / __ \  / __ )  / ____/ | |  / /
   / / / / / __  | / __/    | | / /
  / /_/ / / /_/ / / /___    | |/ /
 /_____/ /_____/ /_____/     |___/

 DATABASES EVERYWHERE
 Isolated database workloads, managed from one control plane.

 RELEASE    {release:<18} API       {api}
 ENGINES    Docker / Podman    NETWORK   private sockets
 DATABASES  PostgreSQL / MySQL / MariaDB / MongoDB
            ClickHouse / Redis / Valkey / Qdrant"#,
        release = env!("CARGO_PKG_VERSION"),
        api = crate::api::system::API_VERSION,
    )
}
