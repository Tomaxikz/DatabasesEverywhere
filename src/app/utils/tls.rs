pub(crate) fn mozilla_root_certificates() -> Vec<reqwest::Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|certificate| reqwest::Certificate::from_der(certificate).ok())
        .collect()
}
