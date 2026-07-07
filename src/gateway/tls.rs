use std::{fs::File, io::BufReader, sync::Arc};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, thiserror::Error)]
pub enum GatewayTlsError {
    #[error("failed to open TLS cert {path}: {source}")]
    OpenCert {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to open TLS key {path}: {source}")]
    OpenKey {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read TLS cert {path}: {source}")]
    ReadCert {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read TLS key {path}: {source}")]
    ReadKey {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("TLS cert file {path} did not contain any certificates")]
    EmptyCert { path: String },
    #[error("TLS key file {path} did not contain a private key")]
    EmptyKey { path: String },
    #[error("TLS server config failed: {0}")]
    Config(#[from] rustls::Error),
}

pub fn acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, GatewayTlsError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, GatewayTlsError> {
    let file = File::open(path).map_err(|source| GatewayTlsError::OpenCert {
        path: path.to_string(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| GatewayTlsError::ReadCert {
            path: path.to_string(),
            source,
        })?;
    if certs.is_empty() {
        return Err(GatewayTlsError::EmptyCert {
            path: path.to_string(),
        });
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, GatewayTlsError> {
    let file = File::open(path).map_err(|source| GatewayTlsError::OpenKey {
        path: path.to_string(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|source| GatewayTlsError::ReadKey {
            path: path.to_string(),
            source,
        })?
        .ok_or_else(|| GatewayTlsError::EmptyKey {
            path: path.to_string(),
        })
}
