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
    redact_secret_assignments(&redact_url_credentials(value))
}

fn redact_url_credentials(value: &str) -> String {
    let mut redacted = String::with_capacity(value.len());
    let mut cursor = 0;

    while let Some(relative_scheme_end) = value[cursor..].find("://") {
        let scheme_end = cursor + relative_scheme_end + 3;
        redacted.push_str(&value[cursor..scheme_end]);

        let authority = &value[scheme_end..];
        let authority_end = authority
            .char_indices()
            .find_map(|(index, character)| {
                (character.is_whitespace() || matches!(character, '/' | '?' | '#')).then_some(index)
            })
            .unwrap_or(authority.len());
        let authority = &authority[..authority_end];
        let Some(at) = authority.rfind('@') else {
            cursor = scheme_end;
            continue;
        };
        if !authority[..at].contains(':') {
            cursor = scheme_end;
            continue;
        }

        redacted.push_str("[redacted]");
        cursor = scheme_end + at;
    }

    redacted.push_str(&value[cursor..]);
    redacted
}

fn redact_secret_assignments(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut replacements = Vec::new();

    for (separator, byte) in bytes.iter().enumerate() {
        if !matches!(byte, b'=' | b':') {
            continue;
        }
        let Some(key) = assignment_key(value, separator) else {
            continue;
        };
        if !is_secret_key(key) {
            continue;
        }
        let Some((start, end)) = assignment_value_range(value, separator + 1, *byte) else {
            continue;
        };
        if replacements
            .last()
            .is_none_or(|(_, previous_end)| start >= *previous_end)
        {
            replacements.push((start, end));
        }
    }

    if replacements.is_empty() {
        return value.to_string();
    }
    let mut redacted = String::with_capacity(value.len());
    let mut cursor = 0;
    for (start, end) in replacements {
        redacted.push_str(&value[cursor..start]);
        redacted.push_str("[redacted]");
        cursor = end;
    }
    redacted.push_str(&value[cursor..]);
    redacted
}

fn assignment_key(value: &str, separator: usize) -> Option<&str> {
    let bytes = value.as_bytes();
    let mut end = separator;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    if end > 0 && matches!(bytes[end - 1], b'\'' | b'"') {
        let quote = bytes[end - 1];
        let quoted_end = end - 1;
        let start = bytes[..quoted_end]
            .iter()
            .rposition(|byte| *byte == quote)?
            + 1;
        return (start < quoted_end).then_some(&value[start..quoted_end]);
    }

    let mut start = end;
    while start > 0
        && (bytes[start - 1].is_ascii_alphanumeric() || matches!(bytes[start - 1], b'_' | b'-'))
    {
        start -= 1;
    }
    (start < end).then_some(&value[start..end])
}

fn assignment_value_range(
    value: &str,
    after_separator: usize,
    separator: u8,
) -> Option<(usize, usize)> {
    let mut start = after_separator;
    let bytes = value.as_bytes();
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    if start >= bytes.len() {
        return None;
    }

    if matches!(bytes[start], b'\'' | b'"') {
        let quote = bytes[start];
        let content_start = start + 1;
        let mut escaped = false;
        let relative_end = bytes[content_start..].iter().position(|byte| {
            if escaped {
                escaped = false;
                return false;
            }
            if *byte == b'\\' {
                escaped = true;
                return false;
            }
            *byte == quote
        })?;
        return Some((content_start, content_start + relative_end));
    }

    let end = value[start..]
        .char_indices()
        .find_map(|(index, character)| {
            (character.is_whitespace()
                || character == ';'
                || (separator == b':' && matches!(character, ',' | '}' | ']')))
            .then_some(start + index)
        })
        .unwrap_or(value.len());
    (start < end).then_some((start, end))
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

    #[test]
    fn redacts_multiple_urls_without_removing_surrounding_text() {
        assert_eq!(
            redact_connection_url(
                "first=postgres://user:pass@db/a second=mysql://root:secret@db/b"
            ),
            "first=postgres://[redacted]@db/a second=mysql://[redacted]@db/b"
        );
    }

    #[test]
    fn redacts_environment_and_json_secret_assignments() {
        assert_eq!(
            redact_connection_url("PASSWORD=hunter2 safe=value {\"api_token\": \"token-value\"}"),
            "PASSWORD=[redacted] safe=value {\"api_token\": \"[redacted]\"}"
        );
    }

    #[test]
    fn redacts_quoted_escapes_and_unquoted_commas() {
        assert_eq!(
            redact_connection_url("PASSWORD=one,two {\"token\":\"a\\\"b\"}"),
            "PASSWORD=[redacted] {\"token\":\"[redacted]\"}"
        );
    }

    #[test]
    fn leaves_urls_without_userinfo_unchanged() {
        assert_eq!(
            redact_connection_url("https://example.com/path"),
            "https://example.com/path"
        );
    }
}
