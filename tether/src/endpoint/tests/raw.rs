//! Raw quinn peers for tests that must misbehave or stall on the wire.

use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{
    DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::aws_lc_rs,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
use tokio::{sync::mpsc, task::JoinHandle};

use super::support::{Issued, Kit, within};

/// A latch that blocks the *thread* of whoever waits on it, because rustls callbacks are
/// synchronous. It is how a test freezes one side of a handshake at a known point. Only
/// code running in an [`Island`] may wait on it: a worker of the test's own runtime that
/// blocks can strand tasks queued behind it and hang the test.
#[derive(Debug)]
pub struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    pub fn closed() -> Arc<Self> {
        Arc::new(Self {
            open: Mutex::new(false),
            changed: Condvar::new(),
        })
    }

    pub fn release(&self) {
        *self.open.lock().expect("gate lock") = true;
        self.changed.notify_all();
    }

    /// Releases the gate when dropped, so a failing test cannot leave a worker blocked.
    pub fn release_on_drop(self: &Arc<Self>) -> ReleaseOnDrop {
        ReleaseOnDrop(self.clone())
    }

    fn wait(&self) {
        let open = self.open.lock().expect("gate lock");
        // A ceiling only; tests release long before it.
        let _ = self
            .changed
            .wait_timeout_while(open, Duration::from_secs(30), |open| !*open)
            .expect("gate lock");
    }
}

pub struct ReleaseOnDrop(Arc<Gate>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// A runtime of its own for a raw peer, so a gate that blocks it cannot stall the test's
/// runtime. Dropping it abandons the runtime without waiting for its threads.
pub struct Island(Option<tokio::runtime::Runtime>);

impl Island {
    pub fn new() -> Self {
        Self(Some(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("island runtime"),
        ))
    }

    /// Runs `future` on the island and returns what it produced.
    pub async fn run<T: Send + 'static>(
        &self,
        future: impl Future<Output = T> + Send + 'static,
    ) -> T {
        self.0
            .as_ref()
            .expect("island is running")
            .spawn(future)
            .await
            .expect("island task")
    }

    fn spawn<T: Send + 'static>(
        &self,
        future: impl Future<Output = T> + Send + 'static,
    ) -> JoinHandle<T> {
        self.0.as_ref().expect("island is running").spawn(future)
    }
}

impl Drop for Island {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
}

/// A raw quinn client connected to a tether endpoint.
pub struct Raw {
    pub connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    _island: Option<Island>,
}

pub async fn raw_client(
    config: rustls::ClientConfig,
    address: SocketAddr,
    server_name: &str,
) -> Result<Raw, quinn::ConnectionError> {
    raw_client_with(
        config,
        quinn::TransportConfig::default(),
        address,
        server_name,
    )
    .await
}

pub async fn raw_client_with(
    config: rustls::ClientConfig,
    transport: quinn::TransportConfig,
    address: SocketAddr,
    server_name: &str,
) -> Result<Raw, quinn::ConnectionError> {
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("address")).expect("client endpoint");
    let mut client = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(config).expect("quic config"),
    ));
    client.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client);
    let connection = endpoint
        .connect(address, server_name)
        .expect("connect starts")
        .await?;
    Ok(Raw {
        connection,
        _endpoint: endpoint,
        _island: None,
    })
}

/// A raw client presenting `kit`'s certificate to the endpoint at `address`, which is the
/// node named "b".
pub async fn raw_to(address: SocketAddr, kit: &Kit) -> Raw {
    raw_client(
        kit.identity().client_config().expect("client config"),
        address,
        "b",
    )
    .await
    .expect("raw handshake")
}

/// Verifies like the real verifier but first waits for a gate, which stalls the client's
/// handshake right after it has seen the server's flight.
#[derive(Debug)]
struct GatedVerifier {
    inner: Arc<WebPkiServerVerifier>,
    gate: Arc<Gate>,
}

impl ServerCertVerifier for GatedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.gate.wait();
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A client whose handshake is frozen by a gate.
pub struct Stalled {
    island: Island,
    handle: JoinHandle<Result<Raw, quinn::ConnectionError>>,
}

impl Stalled {
    /// Waits for the handshake, which completes once the gate has been released.
    pub async fn finish(self) -> Result<Raw, quinn::ConnectionError> {
        let result = within(self.handle).await.expect("island task");
        result.map(|mut raw| {
            // The connection's driver lives on the island, which must outlive it.
            raw._island = Some(self.island);
            raw
        })
    }
}

/// Starts a handshake with the endpoint at `address` (the node "b") as `kit` and freezes it
/// until `gate` is released, so the endpoint's handshake permit stays taken.
pub fn stalled_client(
    kit: &Kit,
    authority_pem: &str,
    gate: Arc<Gate>,
    address: SocketAddr,
) -> Stalled {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(authority_pem.as_bytes()).expect("pem"))
        .expect("root");
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .expect("verifier");
    let chain = vec![CertificateDer::from_pem_slice(kit.cert_pem().as_bytes()).expect("pem")];
    let key = PrivateKeyDer::from_pem_slice(kit.key_pem().as_bytes()).expect("key pem");
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(GatedVerifier { inner, gate }))
        .with_client_auth_cert(chain, key)
        .expect("client auth");
    config.alpn_protocols = vec![crate::identity::ALPN.to_vec()];
    let island = Island::new();
    let handle = island.spawn(raw_client(config, address, "b"));
    Stalled { island, handle }
}

/// Picks the server certificate, after waiting for the gate if there is one.
#[derive(Debug)]
struct Resolver {
    key: Arc<CertifiedKey>,
    gate: Option<Arc<Gate>>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(gate) = &self.gate {
            gate.wait();
        }
        Some(self.key.clone())
    }
}

/// A quinn server that is not tether: it presents `issued`, asks for no client certificate
/// and hands every completed connection to the test.
pub struct RawServer {
    pub address: SocketAddr,
    pub connections: mpsc::UnboundedReceiver<quinn::Connection>,
    _island: Island,
}

/// Starts the server on an island of its own, so a gate in its handshake blocks only it.
pub async fn raw_server(issued: &Issued, gate: Option<Arc<Gate>>) -> RawServer {
    let chain = vec![issued.der.clone()];
    let key = PrivateKeyDer::from_pem_slice(issued.key_pem.as_bytes()).expect("key pem");
    let signer = aws_lc_rs::sign::any_supported_type(&key).expect("signing key");
    let resolver = Resolver {
        key: Arc::new(CertifiedKey::new(chain, signer)),
        gate,
    };
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![crate::identity::ALPN.to_vec()];
    let server = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(config).expect("quic config"),
    ));
    let (sender, connections) = mpsc::unbounded_channel();
    let island = Island::new();
    let address = island
        .run(async move {
            let endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().expect("address"))
                .expect("raw server binds");
            let address = endpoint.local_addr().expect("address");
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let sender = sender.clone();
                    tokio::spawn(async move {
                        // A dialer that refuses the certificate just ends the handshake.
                        if let Ok(connection) = incoming.await {
                            let _ = sender.send(connection);
                        }
                    });
                }
            });
            address
        })
        .await;
    RawServer {
        address,
        connections,
        _island: island,
    }
}
