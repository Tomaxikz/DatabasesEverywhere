use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rustls::{ClientConfig, ClientConnection, Connection, ServerConnection};
use rustls_pki_types::{CertificateDer, ServerName};

use super::*;

struct Authority {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct Issued {
    cert_pem: String,
    key_pem: String,
    der: CertificateDer<'static>,
}

fn authority() -> Authority {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("authority params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().expect("authority key");
    let cert = params.self_signed(&key).expect("authority certificate");
    Authority {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key),
    }
}

fn issue(authority: &Authority, names: &[&str]) -> Issued {
    let params = CertificateParams::new(
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>(),
    )
    .expect("node params");
    issue_params(authority, params)
}

fn issue_params(authority: &Authority, params: CertificateParams) -> Issued {
    let key = KeyPair::generate().expect("node key");
    let cert = params
        .signed_by(&key, &authority.issuer)
        .expect("node certificate");
    Issued {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        der: cert.der().clone(),
    }
}

fn node(name: &str) -> NodeId {
    name.parse().expect("valid node id")
}

fn identity(authority: &Authority, name: &str) -> Identity {
    let issued = issue(authority, &[name]);
    Identity::from_pem(
        node(name),
        issued.cert_pem.as_bytes(),
        issued.key_pem.as_bytes(),
        authority.cert_pem.as_bytes(),
    )
    .expect("identity loads")
}

fn sans_of(sans: Vec<SanType>) -> Result<NodeId, IdentityError> {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.subject_alt_names = sans;
    let issued = issue_params(&authority(), params);
    peer_node_id(&[issued.der])
}

fn dns(name: &str) -> SanType {
    SanType::DnsName(name.try_into().expect("dns name"))
}

fn names_of(names: &[&str]) -> Result<NodeId, IdentityError> {
    let issued = issue(&authority(), names);
    peer_node_id(&[issued.der])
}

fn transfer(from: &mut Connection, to: &mut Connection) -> Result<bool, rustls::Error> {
    let mut buffer = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buffer).expect("write to vec");
    }
    let mut input = buffer.as_slice();
    while !input.is_empty() {
        to.read_tls(&mut input).expect("read from slice");
        to.process_new_packets()?;
    }
    Ok(!buffer.is_empty())
}

/// Drives both ends against each other in memory until the handshake completes or fails.
fn handshake(
    client_config: ClientConfig,
    server: &Identity,
    server_name: &str,
) -> Result<(Connection, Connection), rustls::Error> {
    let name = ServerName::try_from(server_name.to_owned()).expect("server name");
    let mut client = Connection::from(ClientConnection::new(Arc::new(client_config), name)?);
    let mut server = Connection::from(ServerConnection::new(Arc::new(
        server.server_config().expect("server config"),
    ))?);
    for _ in 0..16 {
        let mut progressed = false;
        progressed |= transfer(&mut client, &mut server)?;
        progressed |= transfer(&mut server, &mut client)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok((client, server));
        }
        if !progressed {
            break;
        }
    }
    Err(rustls::Error::General("handshake did not complete".into()))
}

#[test]
fn valid_certificate_loads() {
    let authority = authority();
    assert_eq!(identity(&authority, "a").node_id(), &node("a"));
}

#[test]
fn certificate_for_another_node_is_wrong_node() {
    let authority = authority();
    let issued = issue(&authority, &["b"]);
    let result = Identity::from_pem(
        node("a"),
        issued.cert_pem.as_bytes(),
        issued.key_pem.as_bytes(),
        authority.cert_pem.as_bytes(),
    );
    assert!(
        matches!(result, Err(IdentityError::WrongNode(_))),
        "{result:?}"
    );
}

#[test]
fn certificate_from_another_authority_is_rejected() {
    let trusted = authority();
    let issued = issue(&authority(), &["a"]);
    let result = Identity::from_pem(
        node("a"),
        issued.cert_pem.as_bytes(),
        issued.key_pem.as_bytes(),
        trusted.cert_pem.as_bytes(),
    );
    assert!(
        matches!(result, Err(IdentityError::WrongNode(_))),
        "{result:?}"
    );
}

#[test]
fn certificate_with_two_names_is_wrong_node_even_if_one_matches() {
    let authority = authority();
    let issued = issue(&authority, &["a", "b"]);
    let result = Identity::from_pem(
        node("a"),
        issued.cert_pem.as_bytes(),
        issued.key_pem.as_bytes(),
        authority.cert_pem.as_bytes(),
    );
    assert!(
        matches!(result, Err(IdentityError::WrongNode(_))),
        "{result:?}"
    );
}

#[test]
fn handshake_between_nodes_of_one_authority_negotiates_alpn_and_names_the_caller() {
    let authority = authority();
    let a = identity(&authority, "a");
    let b = identity(&authority, "b");
    let (client, server) =
        handshake(a.client_config().expect("client config"), &b, "b").expect("handshake");
    assert_eq!(client.alpn_protocol(), Some(ALPN));
    assert_eq!(server.alpn_protocol(), Some(ALPN));
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    let chain = server.peer_certificates().expect("client certificate");
    assert_eq!(peer_node_id(chain).expect("caller name"), node("a"));
}

#[test]
fn dialing_the_wrong_server_name_fails() {
    let authority = authority();
    let a = identity(&authority, "a");
    let b = identity(&authority, "b");
    let result = handshake(a.client_config().expect("client config"), &b, "c");
    assert!(result.is_err());
}

#[test]
fn client_certificate_from_another_authority_is_refused() {
    let authority = authority();
    let b = identity(&authority, "b");
    let stranger = identity(&self::authority(), "a");
    let result = handshake(stranger.client_config().expect("client config"), &b, "b");
    assert!(result.is_err());
}

#[test]
fn client_without_certificate_is_refused() {
    let authority = authority();
    let b = identity(&authority, "b");
    let mut roots = RootCertStore::empty();
    let ca = CertificateDer::pem_slice_iter(authority.cert_pem.as_bytes())
        .next()
        .expect("authority pem")
        .expect("authority der");
    roots.add(ca).expect("root");
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    assert!(handshake(config, &b, "b").is_err());
}

mod loading;
mod names;
