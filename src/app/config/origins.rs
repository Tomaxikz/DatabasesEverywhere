use std::net::IpAddr;

/// Canonicalizes an HTTP(S) origin as scheme + host + effective port.
/// Explicit origin values may omit the default port and may carry one trailing
/// slash, but paths, queries, fragments, and user information are rejected.
pub(crate) fn normalize_http_origin(value: &str) -> Option<String> {
    let uri = value.trim().parse::<http::Uri>().ok()?;
    if uri.query().is_some() || !matches!(uri.path(), "" | "/") {
        return None;
    }
    canonical_uri_origin(&uri)
}

pub(crate) fn url_origin(value: &str) -> Option<String> {
    let uri = value.trim().parse::<http::Uri>().ok()?;
    canonical_uri_origin(&uri)
}

fn canonical_uri_origin(uri: &http::Uri) -> Option<String> {
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority
        .host()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let port = match authority.port_u16() {
        Some(port) => port,
        None if authority.as_str() == authority.host() => default_port,
        None => return None,
    };
    let rendered_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Some(format!("{scheme}://{rendered_host}:{port}"))
}

pub(crate) fn normalize_remote_import_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Ok(address) = value.parse::<IpAddr>() {
        return Some(address.to_string());
    }
    if let Some(address) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.parse::<std::net::Ipv6Addr>().ok())
    {
        return Some(address.to_string());
    }

    let host = value.strip_suffix('.').unwrap_or(value);
    if !is_plausible_dns_name(host) {
        return None;
    }

    if !host.split('.').all(is_valid_dns_label) {
        return None;
    }

    // libc resolvers accept several legacy numeric IPv4 spellings such as
    // `2130706433`, `127.1`, and `0x7f.0.0.1`. Reject numeric-looking names so
    // they cannot bypass the canonical IpAddr classification in the caller.
    let numeric_notation = host.split('.').all(is_numeric_ipv4_label);
    if numeric_notation {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

const MAX_DNS_NAME_LEN: usize = 253;
const MAX_DNS_LABEL_LEN: usize = 63;

fn is_plausible_dns_name(host: &str) -> bool {
    let has_forbidden_byte = host.bytes().any(|byte| {
        byte.is_ascii_control()
            || matches!(byte, b'/' | b'\\' | b':' | b'@' | b'#' | b'?' | b'[' | b']')
    });
    !host.is_empty() && host.len() <= MAX_DNS_NAME_LEN && host.is_ascii() && !has_forbidden_byte
}

fn is_valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_DNS_LABEL_LEN
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_numeric_ipv4_label(label: &str) -> bool {
    let is_decimal = label.bytes().all(|byte| byte.is_ascii_digit());
    let is_hexadecimal = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
        .is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
    is_decimal || is_hexadecimal
}
