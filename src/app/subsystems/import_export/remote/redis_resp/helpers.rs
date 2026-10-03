use super::*;

pub(super) fn source_read_timeout(timeout: Duration) -> RedisRelayError {
    RedisRelayError::Source(RedisRespError::Timeout {
        operation: "read",
        timeout,
    })
}

pub(super) fn target_write_timeout(timeout: Duration) -> RedisRelayError {
    RedisRelayError::Target(RedisRespError::Timeout {
        operation: "write",
        timeout,
    })
}

pub(super) fn tls_connector() -> TlsConnector {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

pub(super) fn tls_server_name(host: &str) -> Result<ServerName<'static>, ()> {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    ServerName::try_from(host.to_string()).map_err(|_| ())
}

pub(super) fn parse_scan_page(value: RespValue) -> RedisRespResult<ScanPage> {
    let RespValue::Array(Some(mut outer)) = value else {
        return Err(unexpected("SCAN", "two-element array", &value));
    };
    if outer.len() != 2 {
        return Err(RedisRespError::Protocol(
            "SCAN response must contain cursor and keys".to_string(),
        ));
    }
    let keys = outer.pop().expect("length checked");
    let cursor = outer.pop().expect("length checked");
    let cursor = match cursor {
        RespValue::Bulk(Some(cursor)) | RespValue::Simple(cursor) => {
            parse_u64(&cursor, "SCAN cursor")?
        }
        value => return Err(unexpected("SCAN cursor", "string", &value)),
    };
    let RespValue::Array(Some(keys)) = keys else {
        return Err(unexpected("SCAN keys", "array", &keys));
    };
    let keys = keys
        .into_iter()
        .map(|key| match key {
            RespValue::Bulk(Some(key)) => Ok(key),
            value => Err(unexpected("SCAN key", "bulk string", &value)),
        })
        .collect::<RedisRespResult<Vec<_>>>()?;
    Ok(ScanPage {
        next_cursor: cursor,
        keys,
    })
}

pub(super) fn expect_simple(
    value: RespValue,
    operation: &'static str,
    expected: &'static [u8],
) -> RedisRespResult<()> {
    match value {
        RespValue::Simple(actual) if actual == expected => Ok(()),
        value => Err(unexpected(operation, "expected simple string", &value)),
    }
}

pub(super) fn unexpected(
    operation: &'static str,
    expected: &'static str,
    value: &RespValue,
) -> RedisRespError {
    RedisRespError::UnexpectedResponse {
        operation,
        expected,
        actual: value.kind(),
    }
}

pub(super) fn parse_nullable_length(
    value: &[u8],
    kind: &'static str,
) -> RedisRespResult<Option<usize>> {
    let signed = parse_i64(value, kind)?;
    if signed == -1 {
        return Ok(None);
    }
    if signed < 0 {
        return Err(RedisRespError::Protocol(format!(
            "{kind} has invalid negative length {signed}"
        )));
    }
    usize::try_from(signed)
        .map(Some)
        .map_err(|_| RedisRespError::Protocol(format!("{kind} length is too large")))
}

pub(super) fn parse_i64(value: &[u8], kind: &'static str) -> RedisRespResult<i64> {
    let value = std::str::from_utf8(value)
        .map_err(|_| RedisRespError::Protocol(format!("{kind} is not ASCII")))?;
    value
        .parse()
        .map_err(|_| RedisRespError::Protocol(format!("{kind} is not a valid integer")))
}

pub(super) fn parse_u64(value: &[u8], kind: &'static str) -> RedisRespResult<u64> {
    let value = std::str::from_utf8(value)
        .map_err(|_| RedisRespError::Protocol(format!("{kind} is not ASCII")))?;
    value
        .parse()
        .map_err(|_| RedisRespError::Protocol(format!("{kind} is not a valid unsigned integer")))
}

pub(super) fn command_encoded_size(arguments: &[&[u8]]) -> RedisRespResult<usize> {
    encoded_command_size(arguments.len(), arguments.iter().map(|value| value.len()))
}

pub(super) fn encoded_command_size(
    argument_count: usize,
    argument_lengths: impl IntoIterator<Item = usize>,
) -> RedisRespResult<usize> {
    let mut total = 1_usize
        .checked_add(decimal_digits(argument_count))
        .and_then(|size| size.checked_add(2))
        .ok_or_else(|| RedisRespError::Protocol("command length overflow".to_string()))?;
    for argument_length in argument_lengths {
        total = total
            .checked_add(1)
            .and_then(|size| size.checked_add(decimal_digits(argument_length)))
            .and_then(|size| size.checked_add(2))
            .and_then(|size| size.checked_add(argument_length))
            .and_then(|size| size.checked_add(2))
            .ok_or_else(|| RedisRespError::Protocol("command length overflow".to_string()))?;
    }
    Ok(total)
}

pub(super) fn decimal_digits(mut value: usize) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

pub(super) fn map_unexpected_eof(error: std::io::Error) -> RedisRespError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        RedisRespError::Protocol("unexpected EOF in RESP response".to_string())
    } else {
        RedisRespError::Io(error)
    }
}
