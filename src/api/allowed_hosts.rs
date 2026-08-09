use axum::http::{HeaderMap, Uri};

pub fn request_host(headers: &HeaderMap) -> Option<String> {
    request_host_with_uri(headers, None)
}

pub fn request_host_with_uri(headers: &HeaderMap, uri: Option<&Uri>) -> Option<String> {
    headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(normalize_host)
        .or_else(|| {
            uri.and_then(Uri::authority)
                .map(|authority| normalize_host(authority.as_str()))
        })
}

pub fn origin_is_allowed(origin: &str, allowed_origins: &[String]) -> bool {
    let Some(origin) = crate::config::normalize_http_origin(origin) else {
        return false;
    };
    allowed_origins.iter().any(|allowed| {
        crate::config::normalize_http_origin(allowed).as_deref() == Some(origin.as_str())
    })
}

pub fn host_is_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    let host = normalize_host(host);
    allowed_hosts
        .iter()
        .map(|allowed| normalize_host(allowed))
        .any(|allowed| allowed == host)
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
    fn allows_origin_when_host_matches() {
        let allowed = vec!["https://panel.example.com".to_string()];

        assert!(origin_is_allowed("https://panel.example.com", &allowed));
        assert!(origin_is_allowed("https://panel.example.com:443", &allowed));
    }

    #[test]
    fn rejects_origin_when_scheme_or_port_does_not_match() {
        let allowed = vec!["https://panel.example.com".to_string()];

        assert!(!origin_is_allowed("https://other.example.com", &allowed));
        assert!(!origin_is_allowed("http://panel.example.com", &allowed));
        assert!(!origin_is_allowed(
            "https://panel.example.com:8443",
            &allowed
        ));
        assert!(!origin_is_allowed(
            "https://panel.example.com:99999",
            &allowed
        ));
    }

    #[test]
    fn uses_uri_authority_when_host_is_missing() {
        let headers = HeaderMap::new();
        let uri = "https://panel.example.com:443/api/system"
            .parse::<Uri>()
            .expect("valid uri");

        assert_eq!(
            request_host_with_uri(&headers, Some(&uri)),
            Some("panel.example.com".to_string())
        );
    }

    #[test]
    fn host_is_not_shadowed_by_an_allowed_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "evil.example.com".parse().unwrap());
        headers.insert("origin", "https://panel.example.com".parse().unwrap());

        assert_eq!(request_host(&headers), Some("evil.example.com".to_string()));
    }
}
