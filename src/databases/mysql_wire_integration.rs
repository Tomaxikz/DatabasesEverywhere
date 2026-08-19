use std::process::Command;

use crate::{
    gateway::{
        listeners::{ListenerError, run_mariadb_listener, run_mysql_listener},
        resolver::RouteResolver,
        security::GatewayConnectionLimiter,
        supervisor::GatewaySupervisor,
    },
    instances::state::InstanceStore,
    shared::protocol::Protocol,
};

pub(super) async fn start_gateway(
    protocol: Protocol,
    store: InstanceStore,
    tls: Option<tokio_rustls::TlsAcceptor>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<Result<(), ListenerError>>,
) {
    assert!(matches!(protocol, Protocol::Mariadb | Protocol::Mysql));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let supervisor = GatewaySupervisor::new();
    assert!(supervisor.begin(1));
    let connections = supervisor.connection_tracker();
    let bind = address.to_string();
    let gateway = tokio::spawn(async move {
        let resolver = RouteResolver::new(store, crate::api::resources::ResourceCache::default());
        match protocol {
            Protocol::Mariadb => {
                run_mariadb_listener(
                    listener,
                    &bind,
                    resolver,
                    tls,
                    GatewayConnectionLimiter::default(),
                    shutdown,
                    connections,
                )
                .await
            }
            Protocol::Mysql => {
                run_mysql_listener(
                    listener,
                    &bind,
                    resolver,
                    tls,
                    GatewayConnectionLimiter::default(),
                    shutdown,
                    connections,
                )
                .await
            }
            _ => unreachable!("protocol was asserted to use the MySQL wire protocol"),
        }
    });
    (address, gateway)
}

pub(super) fn test_tls_acceptor(directory: &std::path::Path) -> tokio_rustls::TlsAcceptor {
    let certificate = directory.join("certificate.pem");
    let key = directory.join("key.pem");
    let output = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&certificate)
        .output()
        .expect("generate test gateway certificate");
    assert!(
        output.status.success(),
        "test TLS certificate generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    crate::gateway::tls::acceptor(certificate.to_str().unwrap(), key.to_str().unwrap()).unwrap()
}

pub(super) fn run_jdbc_smoke(
    port: u16,
    tls_port: u16,
    database: &str,
    username: &str,
    password: &str,
) {
    if std::env::var("DBE_RUN_JDBC_SMOKE").ok().as_deref() != Some("1") {
        return;
    }
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/real_drivers/mysql/run.sh");
    let output = Command::new("bash")
        .arg(script)
        .env("DBE_DRIVER_HOST", "127.0.0.1")
        .env("DBE_DRIVER_PORT", port.to_string())
        .env("DBE_DRIVER_TLS_PORT", tls_port.to_string())
        .env("DBE_DRIVER_DATABASE", database)
        .env("DBE_DRIVER_USERNAME", username)
        .env("DBE_DRIVER_PASSWORD", password)
        .output()
        .expect("run real JDBC/Hikari compatibility smoke test");
    assert!(
        output.status.success(),
        "real JDBC/Hikari compatibility smoke test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
