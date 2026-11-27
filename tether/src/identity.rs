//! A node's certificate identity and the TLS configurations built from it.
//!
//! The cluster has its own certificate authority. Each node holds a certificate from it
//! whose only DNS name is the node's [`NodeId`]. A dialer asks for the peer's node id as the
//! server name, so ordinary certificate verification proves it reached that node. A
//! listener requires a client certificate from the same authority and reads the caller's
//! node id from it with [`peer_node_id`].
//!
//! Only this authority is trusted: never the system or web roots. TLS 1.3 only. The
//! aws-lc-rs provider is passed explicitly, so nothing depends on a process-wide default.
//! Session resumption is off in both roles, so every connection performs a full handshake
//! and a certificate is checked for validity at the time of each connection.

use std::{fmt, sync::Arc};

use rustls::{
    RootCertStore,
    client::{Resumption, WebPkiServerVerifier, danger::ServerCertVerifier},
    crypto::{CryptoProvider, aws_lc_rs},
    server::WebPkiClientVerifier,
    sign::CertifiedKey,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject};
use x509_parser::{
    certificate::X509CertificateParser, nom::Parser, oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME,
};

use crate::id::NodeId;

/// The only application protocol tether endpoints offer and accept.
pub const ALPN: &[u8] = b"dbev-tether/1";

/// PEM problems carry fixed messages only: parser errors can quote the offending line, and
/// a mangled key file may put key bytes on it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    #[error("certificate or key could not be read: {0}")]
    Pem(&'static str),
    #[error("the private key does not belong to the node's certificate")]
    KeyMismatch,
    #[error("certificate is not valid for the expected node: {0}")]
    WrongNode(String),
    #[error("peer certificate does not carry exactly one valid node name")]
    NoNodeName,
    #[error("TLS configuration failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate verifier could not be built: {0}")]
    Verifier(String),
}

/// This node's certificate chain, private key and the cluster authority it trusts.
pub struct Identity {
    node_id: NodeId,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    roots: Arc<RootCertStore>,
}

// The key must never reach logs, so Debug is written by hand.
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
}

impl Identity {
    /// Loads an identity from PEM. `certificate_chain` starts with the node's own
    /// certificate; `authority` holds the cluster authority's certificate(s).
    ///
    /// Fails unless the node's certificate chains to `authority` and names exactly
    /// `node_id`, so a node cannot start with another node's or a mismatched certificate.
    pub fn from_pem(
        node_id: NodeId,
        certificate_chain: &[u8],
        private_key: &[u8],
        authority: &[u8],
    ) -> Result<Self, IdentityError> {
        let chain = CertificateDer::pem_slice_iter(certificate_chain)
            .map(|item| item.map(CertificateDer::into_owned))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| IdentityError::Pem("certificate chain is not valid PEM"))?;
        if chain.is_empty() {
            return Err(IdentityError::Pem("no certificate in chain"));
        }

        let mut keys = PrivateKeyDer::pem_slice_iter(private_key);
        let key = keys
            .next()
            .ok_or(IdentityError::Pem("no private key"))?
            .map_err(|_| IdentityError::Pem("private key is not valid PEM"))?;
        if keys.next().is_some() {
            return Err(IdentityError::Pem("more than one private key"));
        }

        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(authority) {
            let certificate = certificate
                .map_err(|_| IdentityError::Pem("authority certificate is not valid PEM"))?;
            roots.add(certificate).map_err(|_| {
                IdentityError::Pem("authority certificate is not a usable trust anchor")
            })?;
        }
        if roots.is_empty() {
            return Err(IdentityError::Pem("no authority certificate"));
        }
        let roots = Arc::new(roots);

        verify_chain(&node_id, &chain, &roots)?;
        let named = peer_node_id(&chain).map_err(|_| {
            IdentityError::WrongNode("certificate does not name exactly one node".into())
        })?;
        if named != node_id {
            return Err(IdentityError::WrongNode(format!(
                "certificate is for node {named}, not {node_id}"
            )));
        }
        check_key(&chain, &key)?;

        Ok(Self {
            node_id,
            chain,
            key,
            roots,
        })
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Configuration for accepting peers: requires a client certificate from the cluster
    /// authority and offers only [`ALPN`].
    pub fn server_config(&self) -> Result<rustls::ServerConfig, IdentityError> {
        let provider = provider();
        let verifier =
            WebPkiClientVerifier::builder_with_provider(self.roots.clone(), provider.clone())
                .build()
                .map_err(|error| IdentityError::Verifier(error.to_string()))?;
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.chain.clone(), self.key.clone_key())?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        // No tickets, so no connection can resume a session whose certificate was checked
        // earlier: each one is validated against the clock and the authority afresh.
        config.send_tls13_tickets = 0;
        Ok(config)
    }

    /// Configuration for dialing peers: presents this node's certificate, trusts only the
    /// cluster authority and offers only [`ALPN`].
    pub fn client_config(&self) -> Result<rustls::ClientConfig, IdentityError> {
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(self.roots.clone())
            .with_client_auth_cert(self.chain.clone(), self.key.clone_key())?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.resumption = Resumption::disabled();
        Ok(config)
    }
}

/// Fails unless `key` is usable by the provider and is the private half of the leaf's key,
/// so a mismatched pair is refused at load time instead of at the first handshake.
fn check_key(
    chain: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
) -> Result<(), IdentityError> {
    let signer = provider()
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(|_| IdentityError::Pem("private key is not a supported key"))?;
    CertifiedKey::new(chain.to_vec(), signer)
        .keys_match()
        .map_err(|_| IdentityError::KeyMismatch)
}

/// Runs the same checks a peer will run on this certificate, in both roles, so a
/// certificate that would be refused on the wire fails at startup instead.
fn verify_chain(
    node_id: &NodeId,
    chain: &[CertificateDer<'static>],
    roots: &Arc<RootCertStore>,
) -> Result<(), IdentityError> {
    let provider = provider();
    let server_name = ServerName::try_from(node_id.as_str().to_owned())
        .map_err(|error| IdentityError::WrongNode(error.to_string()))?;
    let (leaf, intermediates) = chain
        .split_first()
        .ok_or(IdentityError::Pem("no certificate in chain"))?;
    let now = UnixTime::now();

    WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
        .build()
        .map_err(|error| IdentityError::Verifier(error.to_string()))?
        .verify_server_cert(leaf, intermediates, &server_name, &[], now)
        .map_err(|error| IdentityError::WrongNode(format!("server role: {error}")))?;
    WebPkiClientVerifier::builder_with_provider(roots.clone(), provider)
        .build()
        .map_err(|error| IdentityError::Verifier(error.to_string()))?
        .verify_client_cert(leaf, intermediates, now)
        .map_err(|error| IdentityError::WrongNode(format!("client role: {error}")))?;
    Ok(())
}

/// Reads the node id from a peer's certificate chain that TLS has already verified against
/// the cluster authority. The first certificate's subject-alternative-name extension must
/// be exactly one primitive DNS-name entry holding a valid [`NodeId`], in canonical DER; an
/// IP address, URI, e-mail, any further entry or any other encoding makes the certificate
/// ambiguous and is refused. The subject's Common Name is ignored.
pub fn peer_node_id(chain: &[CertificateDer<'_>]) -> Result<NodeId, IdentityError> {
    let leaf = chain.first().ok_or(IdentityError::NoNodeName)?;
    // The parser only locates the extension; its own reading of general names is not
    // trusted, so unrelated extensions are not parsed and the SAN value is checked by hand.
    let (rest, certificate) = X509CertificateParser::new()
        .with_deep_parse_extensions(false)
        .parse(leaf)
        .map_err(|_| IdentityError::NoNodeName)?;
    if !rest.is_empty() {
        return Err(IdentityError::NoNodeName);
    }
    // Fails for a repeated extension, which also leaves the name ambiguous.
    let extension = certificate
        .get_extension_unique(&OID_X509_EXT_SUBJECT_ALT_NAME)
        .map_err(|_| IdentityError::NoNodeName)?
        .ok_or(IdentityError::NoNodeName)?;
    node_from_san_value(extension.value).ok_or(IdentityError::NoNodeName)
}

/// `value` must be exactly `SEQUENCE { [2] IMPLICIT IA5String }` in DER with short-form
/// lengths (a node id of at most 63 bytes always fits) and nothing after it.
fn node_from_san_value(value: &[u8]) -> Option<NodeId> {
    const SEQUENCE: u8 = 0x30;
    // Context-specific, primitive, tag number 2 (dNSName).
    const DNS_NAME: u8 = 0x82;
    let [SEQUENCE, outer, content @ ..] = value else {
        return None;
    };
    if usize::from(*outer) != content.len() || *outer >= 0x80 {
        return None;
    }
    let [DNS_NAME, inner, name @ ..] = content else {
        return None;
    };
    if usize::from(*inner) != name.len() || *inner >= 0x80 {
        return None;
    }
    std::str::from_utf8(name).ok()?.parse().ok()
}

#[cfg(test)]
mod tests;
