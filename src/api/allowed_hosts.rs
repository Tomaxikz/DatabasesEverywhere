use axum::http::{HeaderMap, Uri, header};

pub(crate) fn request_host(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(normalize_host)
        .or_else(|| {
            uri.authority()
                .map(|authority| normalize_host(authority.as_str()))
        })
}

pub(crate) fn normalize_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('/');
    host.parse::<axum::http::uri::Authority>()
        .map(|authority| {
            authority
                .host()
                .trim_matches(['[', ']'])
                .to_ascii_lowercase()
        })
        .unwrap_or_else(|_| host.trim_matches(['[', ']']).to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_host_prefers_the_header_and_falls_back_to_uri_authority() {
        let mut headers = HeaderMap::new();
        let uri = "https://panel.example.com:443/api/system"
            .parse::<Uri>()
            .expect("valid uri");

        assert_eq!(
            request_host(&headers, &uri),
            Some("panel.example.com".to_string())
        );

        headers.insert(header::HOST, "API.EXAMPLE.COM:8090".parse().unwrap());
        headers.insert(header::ORIGIN, "https://panel.example.com".parse().unwrap());
        assert_eq!(
            request_host(&headers, &uri),
            Some("api.example.com".to_string())
        );
    }
}
