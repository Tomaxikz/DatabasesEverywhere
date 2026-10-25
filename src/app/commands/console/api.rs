//! Client for the local daemon API, authenticated with the config token.
//!
//! The console never edits daemon state directly: every change goes through
//! the same endpoints, locks, validation and audit logs the panel uses. It
//! prefers the daemon's root-only Unix socket, which also serves standalone
//! nodes whose network API is off. Over TCP with TLS on, it trusts exactly the
//! certificate the daemon is configured to serve (it connects to a loopback
//! address, so hostname checks cannot apply).

use std::{
    net::IpAddr,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use reqwest::{Method, StatusCode};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{config::Config, databases::protocol::Protocol};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Backups and restores finish inside the request.
const LONG_REQUEST_TIMEOUT: Duration = Duration::from_secs(6 * 60 * 60);
pub(super) const LOG_TAIL_LINES: u32 = 500;
/// Requests over the socket still need a URL; its host is never resolved.
const SOCKET_REQUEST_BASE: &str = "http://localhost";

#[derive(Clone)]
pub(super) struct ApiClient {
    base_url: Arc<str>,
    request_base: Arc<str>,
    token: Arc<str>,
    client: reqwest::Client,
}

impl ApiClient {
    pub(super) fn from_config(config: &Config) -> anyhow::Result<Self> {
        if config.token.trim().is_empty() {
            bail!(
                "the config has no API token; run dbev --setup with the panel configuration first"
            );
        }
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let builder = reqwest::Client::builder()
            .timeout(LONG_REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none());
        let (base_url, request_base, builder) = match ApiTransport::from_config(config) {
            ApiTransport::Socket(path) => (
                format!("unix://{}", path.display()),
                SOCKET_REQUEST_BASE.to_string(),
                builder.unix_socket(path),
            ),
            ApiTransport::Network(url) => {
                let builder = if !config.api.ssl.enabled {
                    builder
                } else if config.api.ssl.require_client_cert {
                    bail!(
                        "the API requires client certificates, which the console does not present"
                    );
                } else {
                    builder.tls_backend_preconfigured(pinned_tls(&config.api.ssl.cert)?)
                };
                (url.clone(), url, builder)
            }
        };
        Ok(Self {
            base_url: Arc::from(base_url),
            request_base: Arc::from(request_base),
            token: Arc::from(config.token.as_str()),
            client: builder.build().context("failed to build the API client")?,
        })
    }

    /// Where the API is reached, for display: a URL, or the socket path.
    pub(super) fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn send<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
        timeout: Duration,
    ) -> anyhow::Result<T> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.request_base))
            .bearer_auth(&*self.token)
            .timeout(timeout);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| anyhow!("cannot reach the daemon API: {}", without_url(&error)))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .context("failed to read the API response")?;
        if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        serde_json::from_slice(&bytes).context("the API returned an unexpected response")
    }

    pub(super) async fn system(&self) -> anyhow::Result<SystemInfo> {
        self.send(Method::GET, "/api/system", None, REQUEST_TIMEOUT)
            .await
    }

    pub(super) async fn instances(&self) -> anyhow::Result<Vec<Instance>> {
        self.send(Method::GET, "/api/instances", None, REQUEST_TIMEOUT)
            .await
    }

    pub(super) async fn create(&self, request: &CreateRequest) -> anyhow::Result<()> {
        let body = serde_json::to_value(request)?;
        let _: serde_json::Value = self
            .send(Method::POST, "/api/instances", Some(body), REQUEST_TIMEOUT)
            .await?;
        Ok(())
    }

    pub(super) async fn progress(&self, id: &str) -> anyhow::Result<StatusResponse> {
        self.send(
            Method::GET,
            &format!("/api/instances/{}/status", segment(id)),
            None,
            REQUEST_TIMEOUT,
        )
        .await
    }

    pub(super) async fn power(&self, id: &str, action: PowerAction) -> anyhow::Result<()> {
        let body = serde_json::json!({ "action": action.as_str() });
        let _: serde_json::Value = self
            .send(
                Method::POST,
                &format!("/api/instances/{}/power", segment(id)),
                Some(body),
                LONG_REQUEST_TIMEOUT,
            )
            .await?;
        Ok(())
    }

    pub(super) async fn delete(&self, id: &str, reason: &str) -> anyhow::Result<()> {
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("confirm", "true")
            .append_pair("reason", reason)
            .finish();
        let _: serde_json::Value = self
            .send(
                Method::DELETE,
                &format!("/api/instances/{}?{query}", segment(id)),
                None,
                LONG_REQUEST_TIMEOUT,
            )
            .await?;
        Ok(())
    }

    pub(super) async fn logs(&self, id: &str) -> anyhow::Result<LogsResponse> {
        self.send(
            Method::GET,
            &format!("/api/instances/{}/logs?tail={LOG_TAIL_LINES}", segment(id)),
            None,
            REQUEST_TIMEOUT,
        )
        .await
    }

    pub(super) async fn backups(&self, id: &str) -> anyhow::Result<Vec<Backup>> {
        self.send(
            Method::GET,
            &format!("/api/instances/{}/backups", segment(id)),
            None,
            REQUEST_TIMEOUT,
        )
        .await
    }

    pub(super) async fn backup(&self, id: &str, mode: BackupMode) -> anyhow::Result<Backup> {
        self.send(
            Method::POST,
            &format!(
                "/api/instances/{}/backups?mode={}",
                segment(id),
                mode.as_str()
            ),
            None,
            LONG_REQUEST_TIMEOUT,
        )
        .await
    }

    pub(super) async fn restore(&self, id: &str, backup: &str, reason: &str) -> anyhow::Result<()> {
        let body = serde_json::json!({ "confirm": true, "reason": reason });
        let _: serde_json::Value = self
            .send(
                Method::POST,
                &format!(
                    "/api/instances/{}/backups/{}/restore",
                    segment(id),
                    segment(backup)
                ),
                Some(body),
                LONG_REQUEST_TIMEOUT,
            )
            .await?;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
enum ApiTransport {
    Socket(PathBuf),
    Network(String),
}

impl ApiTransport {
    /// The socket once the daemon has created it, or whenever there is no
    /// network API to fall back to; otherwise TCP, as configured.
    fn from_config(config: &Config) -> Self {
        let socket = Path::new(&config.api.socket_path);
        let present =
            std::fs::metadata(socket).is_ok_and(|metadata| metadata.file_type().is_socket());
        if present || !config.api.enabled {
            Self::Socket(socket.to_path_buf())
        } else {
            Self::Network(local_api_url(config))
        }
    }
}

/// The API listener as seen from this host: wildcard binds become loopback.
pub(super) fn local_api_url(config: &Config) -> String {
    let scheme = if config.api.ssl.enabled {
        "https"
    } else {
        "http"
    };
    let configured = config.api.host.trim().trim_matches(['[', ']']);
    let host = match configured.parse::<IpAddr>() {
        Ok(address) if address.is_unspecified() => "127.0.0.1".to_string(),
        Ok(address) if address.is_ipv6() => format!("[{address}]"),
        _ if configured.is_empty() => "127.0.0.1".to_string(),
        _ => configured.to_string(),
    };
    format!("{scheme}://{host}:{}", config.api.port)
}

fn segment(value: &str) -> String {
    crate::utils::percent::encode_unreserved(value.as_bytes())
}

fn api_error(status: StatusCode, body: &[u8]) -> anyhow::Error {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
        #[serde(default)]
        error_id: Option<String>,
    }
    match serde_json::from_slice::<ErrorBody>(body) {
        Ok(ErrorBody {
            error,
            error_id: Some(id),
        }) => anyhow!("{} {error} (error id {id})", status.as_u16()),
        Ok(ErrorBody { error, .. }) => anyhow!("{} {error}", status.as_u16()),
        Err(_) => anyhow!(
            "{} {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("")
        ),
    }
}

/// Connection failures carry the URL; the console already shows it.
fn without_url(error: &reqwest::Error) -> String {
    let mut message = error.to_string();
    if let Some(url) = error.url() {
        message = message.replace(&format!(" for url ({url})"), "");
    }
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message = format!("{message}: {cause}");
        source = cause.source();
    }
    message
}

/// A rustls client config that accepts exactly the configured certificate.
fn pinned_tls(cert_path: &str) -> anyhow::Result<rustls::ClientConfig> {
    let certificate = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("cannot read the API certificate {cert_path}"))?
        .next()
        .ok_or_else(|| anyhow!("the API certificate {cert_path} contains no certificate"))?
        .with_context(|| format!("cannot parse the API certificate {cert_path}"))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("TLS protocol setup failed")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertificate {
            certificate: certificate.into_owned(),
            provider,
        }))
        .with_no_client_auth();
    Ok(config)
}

#[derive(Debug)]
struct PinnedCertificate {
    certificate: CertificateDer<'static>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.certificate.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the API served a certificate other than the configured one".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct SystemInfo {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub api_version: String,
    #[serde(default)]
    pub api_host: String,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

impl SystemInfo {
    /// Protocols whose `<protocol>_enabled` flag is set.
    pub(super) fn enabled_protocols(&self) -> Vec<Protocol> {
        Protocol::ALL
            .into_iter()
            .filter(|protocol| {
                self.rest
                    .get(&format!("{}_enabled", protocol.as_str()))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
            })
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(super) struct Instance {
    pub instance_id: String,
    pub protocol: Protocol,
    pub deployment_mode: String,
    #[serde(default)]
    pub runtime_id: String,
    pub status: String,
    pub public: PublicEndpoint,
    pub database: DatabaseIdentity,
    pub limits: Limits,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub image: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(super) struct PublicEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(super) struct DatabaseIdentity {
    pub name: String,
    pub username: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(super) struct Limits {
    pub cpu_cores: f64,
    pub memory_mib: u64,
    pub disk_mib: u64,
    #[serde(default)]
    pub disk_enforced: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct StatusResponse {
    #[serde(default)]
    pub progress: Option<Progress>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct Progress {
    #[serde(default)]
    pub stage: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub percent: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct LogsResponse {
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(super) struct Backup {
    pub id: String,
    pub layout: String,
    pub size_bytes: u64,
    pub modified_at: String,
    #[serde(default)]
    pub consistency: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct CreateRequest {
    pub instance_id: String,
    pub protocol: Protocol,
    pub deployment_mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    pub database: String,
    pub username: String,
    pub password: String,
    pub public_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    pub project_id: String,
    pub limits: CreateLimits,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct CreateLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u64>,
    pub disk_mib: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PowerAction {
    Start,
    Stop,
    Restart,
}

impl PowerAction {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackupMode {
    Online,
    Offline,
}

impl BackupMode {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_and_ipv6_listeners_map_to_reachable_urls() {
        let mut config = Config::default();
        for (host, ssl, expected) in [
            ("0.0.0.0", false, "http://127.0.0.1:"),
            ("::", true, "https://127.0.0.1:"),
            ("::1", false, "http://[::1]:"),
            ("10.0.0.5", false, "http://10.0.0.5:"),
            ("", false, "http://127.0.0.1:"),
        ] {
            config.api.host = host.to_string();
            config.api.ssl.enabled = ssl;
            assert!(local_api_url(&config).starts_with(expected), "{host}");
        }
    }

    #[test]
    fn prefers_the_socket_and_falls_back_to_tcp() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("api.sock");
        let mut config = Config::default();
        config.api.socket_path = socket.display().to_string();
        let tcp = ApiTransport::Network(local_api_url(&config));

        assert_eq!(ApiTransport::from_config(&config), tcp);
        std::fs::write(&socket, b"not a socket").unwrap();
        assert_eq!(ApiTransport::from_config(&config), tcp);
        std::fs::remove_file(&socket).unwrap();

        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert_eq!(
            ApiTransport::from_config(&config),
            ApiTransport::Socket(socket.clone())
        );

        // With the network API off, a missing socket is the error to report.
        let mut config = Config::default();
        config.api.enabled = false;
        config.api.socket_path = directory.path().join("missing.sock").display().to_string();
        assert_eq!(
            ApiTransport::from_config(&config),
            ApiTransport::Socket(directory.path().join("missing.sock"))
        );
    }

    #[tokio::test]
    async fn talks_to_the_daemon_over_its_socket() {
        use axum::{http::HeaderMap, routing::get};

        const TOKEN: &str = "test-api-token-0123456789abcdef-01";
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let router = axum::Router::new().route(
            "/api/system",
            get(|headers: HeaderMap| async move {
                if headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    != Some(&format!("Bearer {TOKEN}"))
                {
                    return Err(StatusCode::UNAUTHORIZED);
                }
                Ok(axum::Json(serde_json::json!({ "version": "9.9.9" })))
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await });

        let mut config = Config {
            token: TOKEN.to_string(),
            ..Config::default()
        };
        config.api.socket_path = socket.display().to_string();
        // TCP-only requirements do not apply to the socket.
        config.api.ssl.enabled = true;
        config.api.ssl.require_client_cert = true;
        let client = ApiClient::from_config(&config).unwrap();

        assert_eq!(client.base_url(), format!("unix://{}", socket.display()));
        assert_eq!(client.system().await.unwrap().version, "9.9.9");
        server.abort();
    }

    #[test]
    fn api_errors_keep_the_public_message_and_error_id() {
        let error = api_error(
            StatusCode::CONFLICT,
            br#"{"error":"instance already exists","code":"conflict","error_id":"e1"}"#,
        );
        assert_eq!(
            error.to_string(),
            "409 instance already exists (error id e1)"
        );
        assert_eq!(
            api_error(StatusCode::BAD_GATEWAY, b"<html>").to_string(),
            "502 Bad Gateway"
        );
    }

    #[test]
    fn path_segments_cannot_escape_their_route() {
        assert_eq!(segment("inst/../x?y"), "inst%2F..%2Fx%3Fy");
    }

    #[test]
    fn create_requests_omit_unset_optional_fields() {
        let request = CreateRequest {
            instance_id: "inst_one".to_string(),
            protocol: Protocol::Postgres,
            deployment_mode: "dedicated",
            server_id: None,
            database: "app".to_string(),
            username: "app".to_string(),
            password: "secret".to_string(),
            public_host: "db.example.com".to_string(),
            public_port: None,
            project_id: "dbev-cli".to_string(),
            limits: CreateLimits {
                cpu_cores: Some(1.0),
                memory_mib: None,
                disk_mib: 1024,
            },
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["protocol"], "postgres");
        assert!(value.get("server_id").is_none());
        assert!(value.get("public_port").is_none());
        assert!(value["limits"].get("memory_mib").is_none());
    }

    #[test]
    fn enabled_protocols_follow_the_system_flags() {
        let system: SystemInfo = serde_json::from_value(serde_json::json!({
            "version": "0.9.0",
            "postgres_enabled": true,
            "redis_enabled": false,
            "qdrant_enabled": true
        }))
        .unwrap();
        assert_eq!(
            system.enabled_protocols(),
            [Protocol::Postgres, Protocol::Qdrant]
        );
    }
}
