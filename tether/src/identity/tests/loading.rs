use super::*;

#[test]
fn malformed_pem_is_rejected_without_panicking() {
    let authority = authority();
    let issued = issue(&authority, &["a"]);
    let second_key = KeyPair::generate().expect("key").serialize_pem();
    let two_keys = format!("{}{second_key}", issued.key_pem);
    let load = |chain: &str, key: &str, authority: &str| {
        Identity::from_pem(
            node("a"),
            chain.as_bytes(),
            key.as_bytes(),
            authority.as_bytes(),
        )
    };
    let good_chain = issued.cert_pem.as_str();
    let good_key = issued.key_pem.as_str();
    let good_authority = authority.cert_pem.as_str();

    for result in [
        load(good_chain, "", good_authority),
        load(good_chain, &two_keys, good_authority),
        load(good_chain, good_key, ""),
        load("", good_key, good_authority),
        load("garbage", "garbage", "garbage"),
        load(
            "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
            good_key,
            good_authority,
        ),
    ] {
        assert!(matches!(result, Err(IdentityError::Pem(_))), "{result:?}");
    }
}

#[test]
fn a_private_key_that_is_not_the_certificates_is_refused_at_load() {
    let authority = authority();
    let issued = issue(&authority, &["a"]);
    let stranger = KeyPair::generate().expect("key").serialize_pem();
    let result = Identity::from_pem(
        node("a"),
        issued.cert_pem.as_bytes(),
        stranger.as_bytes(),
        authority.cert_pem.as_bytes(),
    );
    assert!(
        matches!(result, Err(IdentityError::KeyMismatch)),
        "{result:?}"
    );
}

#[test]
fn pem_errors_never_quote_the_input() {
    let authority = authority();
    let issued = issue(&authority, &["a"]);
    let body: String = issued
        .key_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    // A provisioning tool that loses the newline after the marker leaves key text on the
    // marker line, which the parser would quote.
    let mangle = |pem: &str, label: &str| {
        pem.replacen(
            &format!("-----BEGIN {label}-----\n"),
            &format!("-----BEGIN {label}-----{body}\n"),
            1,
        )
    };
    let key = mangle(&issued.key_pem, "PRIVATE KEY");
    let chain = mangle(&issued.cert_pem, "CERTIFICATE");
    let roots = mangle(&authority.cert_pem, "CERTIFICATE");
    assert_ne!(key, issued.key_pem, "the test did not mangle the key");
    let secret = &body[..24];
    for (name, result) in [
        (
            "key",
            Identity::from_pem(
                node("a"),
                issued.cert_pem.as_bytes(),
                key.as_bytes(),
                authority.cert_pem.as_bytes(),
            ),
        ),
        (
            "chain",
            Identity::from_pem(
                node("a"),
                chain.as_bytes(),
                issued.key_pem.as_bytes(),
                authority.cert_pem.as_bytes(),
            ),
        ),
        (
            "authority",
            Identity::from_pem(
                node("a"),
                issued.cert_pem.as_bytes(),
                issued.key_pem.as_bytes(),
                roots.as_bytes(),
            ),
        ),
    ] {
        let error = result.expect_err(name);
        let shown = format!("{error} {error:?}");
        assert!(matches!(error, IdentityError::Pem(_)), "{name}: {shown}");
        assert!(!shown.contains(secret), "{name} leaked: {shown}");
    }
}

/// Completes a handshake and then lets the server's post-handshake messages (session
/// tickets) reach the client.
fn handshake_with(
    client: &Arc<ClientConfig>,
    server: &Arc<rustls::ServerConfig>,
    server_name: &str,
) -> (Connection, Connection) {
    let name = ServerName::try_from(server_name.to_owned()).expect("server name");
    let mut client = Connection::from(ClientConnection::new(client.clone(), name).expect("client"));
    let mut server = Connection::from(ServerConnection::new(server.clone()).expect("server"));
    for _ in 0..8 {
        transfer(&mut client, &mut server).expect("client to server");
        transfer(&mut server, &mut client).expect("server to client");
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    (client, server)
}

fn kinds(
    client: &Arc<ClientConfig>,
    server: &Arc<rustls::ServerConfig>,
) -> [rustls::HandshakeKind; 2] {
    let first = handshake_with(client, server, "b");
    let second = handshake_with(client, server, "b");
    [
        first.1.handshake_kind().expect("first"),
        second.1.handshake_kind().expect("second"),
    ]
}

#[test]
fn no_connection_resumes_a_session_in_either_role() {
    let authority = authority();
    let a = identity(&authority, "a");
    let b = identity(&authority, "b");

    // The harness can see resumption: with rustls defaults on both sides the second
    // connection resumes.
    let mut default_client = a.client_config().expect("client config");
    default_client.resumption = rustls::client::Resumption::default();
    let mut default_server = b.server_config().expect("server config");
    default_server.send_tls13_tickets = 2;
    assert_eq!(
        kinds(
            &Arc::new(default_client.clone()),
            &Arc::new(default_server.clone())
        ),
        [rustls::HandshakeKind::Full, rustls::HandshakeKind::Resumed]
    );

    // Our server sends no tickets, so even a client that would resume cannot.
    assert_eq!(
        kinds(
            &Arc::new(default_client),
            &Arc::new(b.server_config().expect("server config"))
        ),
        [rustls::HandshakeKind::Full; 2]
    );
    // Our client refuses to resume even when the server offers tickets.
    assert_eq!(
        kinds(
            &Arc::new(a.client_config().expect("client config")),
            &Arc::new(default_server)
        ),
        [rustls::HandshakeKind::Full; 2]
    );
}

#[test]
fn debug_output_omits_key_material() {
    let authority = authority();
    let issued = issue(&authority, &["a"]);
    let identity = Identity::from_pem(
        node("a"),
        issued.cert_pem.as_bytes(),
        issued.key_pem.as_bytes(),
        authority.cert_pem.as_bytes(),
    )
    .expect("identity");
    let body: String = issued
        .key_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let shown = format!("{identity:?}");
    assert!(shown.contains("a"));
    assert!(!shown.contains(&body[..32]), "{shown}");
    assert!(!shown.contains("PRIVATE"), "{shown}");
}
