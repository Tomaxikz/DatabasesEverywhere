const SECRET_MARKERS: &[&str] = &["PASSWORD", "TOKEN", "SECRET", "KEY"];

pub fn redact_value(key: &str, value: &str) -> String {
    if is_secret_key(key) {
        "[redacted]".to_string()
    } else {
        value.to_string()
    }
}

pub fn is_secret_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    SECRET_MARKERS.iter().any(|marker| upper.contains(marker))
}

pub fn redact_connection_url(value: &str) -> String {
    let Some((scheme, rest)) = value.split_once("://") else {
        return value.to_string();
    };
    let Some((userinfo, host)) = rest.split_once('@') else {
        return value.to_string();
    };
    if userinfo.contains(':') {
        format!("{scheme}://[redacted]@{host}")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_password_keys() {
        assert_eq!(redact_value("POSTGRES_PASSWORD", "secret"), "[redacted]");
    }

    #[test]
    fn redacts_urls_with_passwords() {
        assert_eq!(
            redact_connection_url("postgres://user:pass@localhost/db"),
            "postgres://[redacted]@localhost/db"
        );
    }
}
