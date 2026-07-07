use axum::http::{HeaderMap, Uri};

pub fn request_host(headers: &HeaderMap) -> Option<String> {
    request_host_with_uri(headers, None)
}

pub fn request_host_with_uri(headers: &HeaderMap, uri: Option<&Uri>) -> Option<String> {
    headers
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .and_then(origin_host)
        .or_else(|| {
            headers
                .get("host")
                .and_then(|value| value.to_str().ok())
                .map(normalize_host)
        })
        .or_else(|| {
            uri.and_then(Uri::authority)
                .map(|authority| normalize_host(authority.as_str()))
        })
}

pub fn origin_is_allowed(origin: &str, allowed_hosts: &[String]) -> bool {
    let Some(host) = origin_host(origin) else {
        return false;
    };
    host_is_allowed(&host, allowed_hosts)
}

pub fn host_is_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    let host = normalize_host(host);
    allowed_hosts
        .iter()
        .map(|allowed| normalize_host(allowed))
        .any(|allowed| allowed == host)
}

fn origin_host(origin: &str) -> Option<String> {
    let rest = origin.split_once("://")?.1;
    let host = rest.split('/').next().unwrap_or(rest);
    Some(normalize_host(host))
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('/').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_origin_when_host_matches() {
        let allowed = vec!["panel.example.com".to_string()];

        assert!(origin_is_allowed("https://panel.example.com", &allowed));
    }

    #[test]
    fn rejects_origin_when_host_does_not_match() {
        let allowed = vec!["panel.example.com".to_string()];

        assert!(!origin_is_allowed("https://other.example.com", &allowed));
    }

    #[test]
    fn uses_uri_authority_when_host_is_missing() {
        let headers = HeaderMap::new();
        let uri = "https://panel.example.com:443/api/system"
            .parse::<Uri>()
            .expect("valid uri");

        assert_eq!(
            request_host_with_uri(&headers, Some(&uri)),
            Some("panel.example.com:443".to_string())
        );
    }
}
