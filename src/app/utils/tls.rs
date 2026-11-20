/// reqwest's rustls-no-provider feature requires a process provider even for HTTP-only clients.
pub(crate) fn http_client_builder() -> reqwest::ClientBuilder {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    reqwest::Client::builder()
}

pub(crate) fn mozilla_root_certificates() -> Vec<reqwest::Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|certificate| reqwest::Certificate::from_der(certificate).ok())
        .collect()
}
