//! Shared fixtures: a throwaway cluster authority, node identities and running endpoints.

use std::{future::Future, sync::Arc, time::Duration};

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::{RootCertStore, crypto::aws_lc_rs};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{
    Identity, NodeId, TargetId,
    endpoint::{Authorizer, Config, Incoming, Peer, Stream, Tether},
};

pub struct Authority {
    pub cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

/// A node's certificate material, so the same node can be started more than once.
pub struct Kit {
    pub name: String,
    cert_pem: String,
    key_pem: String,
    authority_pem: String,
}

/// One subject-alternative-name entry of a certificate to issue.
#[derive(Clone, Copy)]
pub enum San<'a> {
    Dns(&'a str),
    Ip(&'a str),
    Uri(&'a str),
}

/// A certificate and its key, issued with whatever names a test asks for.
pub struct Issued {
    pub cert_pem: String,
    pub key_pem: String,
    pub der: CertificateDer<'static>,
}

pub fn authority() -> Authority {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("authority params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().expect("authority key");
    let cert = params.self_signed(&key).expect("authority certificate");
    Authority {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key),
    }
}

impl Authority {
    pub fn kit(&self, name: &str) -> Kit {
        let issued = self.issue(&[San::Dns(name)]);
        Kit {
            name: name.to_owned(),
            cert_pem: issued.cert_pem,
            key_pem: issued.key_pem,
            authority_pem: self.cert_pem.clone(),
        }
    }

    pub fn issue(&self, names: &[San<'_>]) -> Issued {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("node params");
        for name in names {
            params.subject_alt_names.push(match name {
                San::Dns(name) => SanType::DnsName((*name).try_into().expect("dns name")),
                San::Ip(ip) => SanType::IpAddress(ip.parse().expect("ip")),
                San::Uri(uri) => SanType::URI((*uri).try_into().expect("uri")),
            });
        }
        let key = KeyPair::generate().expect("node key");
        let cert = params
            .signed_by(&key, &self.issuer)
            .expect("node certificate");
        Issued {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            der: cert.der().clone(),
        }
    }
}

impl Kit {
    pub fn id(&self) -> NodeId {
        node(&self.name)
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    pub fn identity(&self) -> Identity {
        Identity::from_pem(
            self.id(),
            self.cert_pem.as_bytes(),
            self.key_pem.as_bytes(),
            self.authority_pem.as_bytes(),
        )
        .expect("identity loads")
    }

    /// A rustls client configuration that trusts `authority_pem` (the cluster the target
    /// node belongs to) but presents this kit's own, possibly foreign, certificate.
    pub fn client_trusting(&self, trusted_authority_pem: &str) -> rustls::ClientConfig {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(trusted_authority_pem.as_bytes()).expect("pem"))
            .expect("root");
        let chain = vec![CertificateDer::from_pem_slice(self.cert_pem.as_bytes()).expect("pem")];
        let key = PrivateKeyDer::from_pem_slice(self.key_pem.as_bytes()).expect("key pem");
        let mut config =
            rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("versions")
                .with_root_certificates(roots)
                .with_client_auth_cert(chain, key)
                .expect("client auth");
        config.alpn_protocols = vec![crate::identity::ALPN.to_vec()];
        config
    }
}

pub fn node(name: &str) -> NodeId {
    name.parse().expect("valid node id")
}

pub fn target(name: &str) -> TargetId {
    name.parse().expect("valid target id")
}

pub struct AllowAll;

impl Authorizer for AllowAll {
    fn allows(&self, _peer: &NodeId, _target: &TargetId, _context: &[u8]) -> bool {
        true
    }
}

/// Refuses exactly one target name.
pub struct Deny(pub &'static str);

impl Authorizer for Deny {
    fn allows(&self, _peer: &NodeId, target: &TargetId, _context: &[u8]) -> bool {
        target.as_str() != self.0
    }
}

/// Timeouts short enough to keep tests quick but long enough for a loaded CI machine to
/// finish a handshake.
pub fn config(identity: Identity) -> Config {
    let mut config = Config::new("127.0.0.1:0".parse().expect("address"), identity);
    config.header_timeout = Duration::from_secs(2);
    config.connect_timeout = Duration::from_secs(5);
    config.idle_timeout = Duration::from_secs(10);
    config.keep_alive = Duration::from_secs(3);
    config
}

pub fn start(kit: &Kit) -> Tether {
    start_with(kit, Arc::new(AllowAll), |_| {})
}

pub fn start_with(
    kit: &Kit,
    authorizer: Arc<dyn Authorizer>,
    tweak: impl FnOnce(&mut Config),
) -> Tether {
    let mut config = config(kit.identity());
    tweak(&mut config);
    Tether::bind(config, authorizer).expect("endpoint binds")
}

pub fn peer(tether: &Tether) -> Peer {
    Peer {
        id: tether.node_id().clone(),
        address: tether.local_addr().expect("local address"),
    }
}

/// An accepted inbound stream with who opened it and for what.
pub struct Accepted {
    pub peer: NodeId,
    pub target: TargetId,
    pub context: Vec<u8>,
    pub stream: Stream,
}

/// Accepts every inbound stream on `tether` and forwards it, until the endpoint shuts down.
pub fn acceptor(tether: &Tether) -> (mpsc::UnboundedReceiver<Accepted>, JoinHandle<()>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let tether = tether.clone();
    let task = tokio::spawn(async move {
        while let Some(incoming) = tether.accept().await {
            let peer = incoming.peer().clone();
            let target = incoming.target().clone();
            let context = incoming.context().to_vec();
            if let Ok(stream) = incoming.accept().await {
                let _ = sender.send(Accepted {
                    peer,
                    target,
                    context,
                    stream,
                });
            }
        }
    });
    (receiver, task)
}

pub async fn next<T>(receiver: &mut mpsc::UnboundedReceiver<T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("nothing arrived in time")
        .expect("channel closed")
}

/// The next inbound stream the application sees, if any shows up within `wait`.
pub async fn next_incoming(tether: &Tether, wait: Duration) -> Option<Incoming> {
    tokio::time::timeout(wait, tether.accept())
        .await
        .ok()
        .flatten()
}

/// Polls `condition` until it holds. The wait is only a ceiling so a broken build fails
/// instead of hanging: the conditions are events that do happen.
pub async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "gave up waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Fails the test instead of hanging it when `future` does not finish.
pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .expect("did not finish in time")
}
