//! Throwaway cluster authority, node certificates written to disk, and nodes started from
//! the same configuration the daemon reads.

use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use ::tether::Tether;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{Dispatch, MonitoredTasks, bind};
use crate::{
    config::{Config, RuntimeConfig, TetherForwardConfig, TetherPeerConfig},
    gateway::{
        listeners::{ClientSocket, ProtocolEntry},
        resolver::RouteResolver,
        security::GatewayConnectionLimiter,
        supervisor::GatewaySupervisor,
    },
};

pub(crate) struct Authority {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

pub(crate) fn authority() -> Authority {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("authority params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().expect("authority key");
    let cert = params.self_signed(&key).expect("authority certificate");
    Authority {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key),
    }
}

pub(crate) struct NodeSpec<'a> {
    pub(crate) name: &'a str,
    /// `(node, address, inbound)`
    pub(crate) peers: Vec<(&'a str, SocketAddr, bool)>,
    /// `(node, protocol)`; every forward binds an ephemeral port.
    pub(crate) forwards: Vec<(&'a str, &'a str)>,
    pub(crate) dispatch: Dispatch,
    pub(crate) supervisor: GatewaySupervisor,
    pub(crate) limiter: GatewayConnectionLimiter,
    /// How many connections each forward may carry.
    pub(crate) streams_limit: Option<usize>,
}

impl<'a> NodeSpec<'a> {
    pub(crate) fn new(name: &'a str) -> Self {
        Self::with_listener_cap(name, None)
    }

    /// `cap` is `gateway_connections_per_listener` for the protocols this node serves.
    pub(crate) fn with_listener_cap(name: &'a str, cap: Option<usize>) -> Self {
        let mut settings = Config::default();
        if let Some(cap) = cap {
            settings.daemon.limits.gateway_connections_per_listener = cap;
        }
        let supervisor = GatewaySupervisor::with_config(Arc::new(
            RuntimeConfig::new(settings).expect("valid limits"),
        ));
        assert!(supervisor.begin(0));
        supervisor.mark_ready();
        Self {
            name,
            peers: Vec::new(),
            forwards: Vec::new(),
            dispatch: Dispatch::new(),
            supervisor,
            limiter: GatewayConnectionLimiter::with_active_limit(600, 64),
            streams_limit: None,
        }
    }

    /// The resolver a handler under test is given: no instances.
    pub(crate) fn resolver(&self) -> RouteResolver {
        RouteResolver::new(
            crate::server::state::InstanceStore::default(),
            crate::subsystems::monitoring::resources::ResourceCache::default(),
            crate::gateway::protocols::qdrant::QdrantRouteKey::new(b"test"),
            self.supervisor.tenant_sessions(),
        )
    }

    /// Serves `protocol` with a stand-in handler that echoes until the client half-closes
    /// and then says goodbye. The count is how many connections reached it.
    pub(crate) fn serve_echo(&mut self, protocol: &'static str) -> Echo {
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let entry = self.entry(protocol, move |client, _, _| echo(client, seen.clone()));
        Echo {
            entry,
            connections: count,
        }
    }

    pub(crate) fn entry<H, F>(&mut self, protocol: &'static str, handler: H) -> Arc<ProtocolEntry>
    where
        H: Fn(ClientSocket, RouteResolver, Option<tokio_rustls::TlsAcceptor>) -> F
            + Send
            + Sync
            + 'static,
        F: std::future::Future<Output = Result<(), crate::gateway::listeners::ListenerError>>
            + Send
            + 'static,
    {
        let entry = ProtocolEntry::new(
            protocol,
            handler,
            self.resolver(),
            None,
            self.limiter.clone(),
            self.supervisor.connection_tracker(),
        );
        self.dispatch.insert(protocol, entry.clone());
        entry
    }
}

pub(crate) struct Echo {
    pub(crate) entry: Arc<ProtocolEntry>,
    pub(crate) connections: Arc<AtomicUsize>,
}

async fn echo(
    mut client: ClientSocket,
    count: Arc<AtomicUsize>,
) -> Result<(), crate::gateway::listeners::ListenerError> {
    count.fetch_add(1, Ordering::SeqCst);
    let mut buffer = [0u8; 1024];
    loop {
        match client.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => client.write_all(&buffer[..read]).await?,
        }
    }
    let _ = client.write_all(b"bye").await;
    let _ = client.shutdown().await;
    Ok(())
}

pub(crate) struct Node {
    pub(crate) tether: Tether,
    pub(crate) address: SocketAddr,
    pub(crate) forwards: Vec<SocketAddr>,
    pub(crate) supervisor: GatewaySupervisor,
    _files: TempDir,
    _tasks: MonitoredTasks,
}

/// A node certificate and the CA, written where a config can point at them.
pub(crate) struct IdentityFiles {
    pub(crate) ca: String,
    pub(crate) cert: String,
    pub(crate) key: String,
    pub(crate) dir: TempDir,
}

fn write(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write pem");
    path.to_string_lossy().into_owned()
}

impl Authority {
    pub(crate) fn pem(&self) -> &str {
        &self.cert_pem
    }

    pub(crate) fn files(&self, name: &str, trusted_ca_pem: &str) -> IdentityFiles {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("node params");
        params.subject_alt_names.push(SanType::DnsName(
            name.to_owned().try_into().expect("dns name"),
        ));
        let key = KeyPair::generate().expect("node key");
        let cert = params.signed_by(&key, &self.issuer).expect("node cert");
        let dir = tempfile::tempdir().expect("tempdir");
        IdentityFiles {
            ca: write(dir.path(), "ca.pem", trusted_ca_pem),
            cert: write(dir.path(), "cert.pem", &cert.pem()),
            key: write(dir.path(), "key.pem", &key.serialize_pem()),
            dir,
        }
    }

    /// Starts a node whose certificate this authority issued.
    pub(crate) async fn start(&self, spec: NodeSpec<'_>) -> Node {
        self.start_trusting(spec, &self.cert_pem).await
    }

    /// Starts a node with a certificate from this authority that trusts `ca_pem` instead.
    pub(crate) async fn start_trusting(&self, spec: NodeSpec<'_>, ca_pem: &str) -> Node {
        let files = self.files(spec.name, ca_pem);
        let mut config = Config::default();
        config.tether.enabled = true;
        config.tether.bind = "127.0.0.1:0".to_string();
        config.tether.node = spec.name.to_string();
        config.tether.ca = files.ca.clone();
        config.tether.cert = files.cert.clone();
        config.tether.key = files.key.clone();
        config.tether.peers = spec
            .peers
            .iter()
            .map(|(node, address, inbound)| TetherPeerConfig {
                node: (*node).to_string(),
                address: address.to_string(),
                inbound: *inbound,
            })
            .collect();
        config.tether.forwards = spec
            .forwards
            .iter()
            .map(|(node, protocol)| TetherForwardConfig {
                bind: "127.0.0.1:0".to_string(),
                node: (*node).to_string(),
                protocol: (*protocol).to_string(),
            })
            .collect();
        if let Some(limit) = spec.streams_limit {
            config.daemon.limits.gateway_connections_per_listener = limit;
        }
        let runtime = bind(&config, spec.dispatch, spec.limiter)
            .await
            .expect("tether binds");
        let tether = runtime.tether();
        let forwards = runtime.forward_addrs();
        let supervisor = spec.supervisor;
        let mut tasks = MonitoredTasks::new();
        runtime.spawn(&supervisor, &mut tasks).await;
        Node {
            address: tether.local_addr().expect("local address"),
            tether,
            forwards,
            supervisor,
            _files: files.dir,
            _tasks: tasks,
        }
    }
}
