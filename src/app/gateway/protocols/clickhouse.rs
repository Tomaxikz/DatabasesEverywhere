use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClickhouseRoute {
    pub username: String,
    pub database: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClickhouseHttpRoute {
    pub username: String,
    pub database: String,
}

/// Native Server::Exception, with no tenant names, credentials or stack trace.
pub(crate) fn auth_error_packet() -> Vec<u8> {
    let mut packet = vec![2];
    packet.extend_from_slice(&516_i32.to_le_bytes());
    for value in ["DB::Exception", "Authentication failed.", ""] {
        write_uvarint(&mut packet, value.len() as u64);
        packet.extend_from_slice(value.as_bytes());
    }
    packet.push(0); // no nested exception
    packet
}

#[derive(Debug, thiserror::Error)]
pub enum ClickhouseParseError {
    #[error("clickhouse native hello is missing username")]
    MissingUsername,
    #[error("clickhouse native hello packet is incomplete")]
    IncompleteNativeHello,
    #[error("clickhouse native packet is not a client hello")]
    InvalidNativeHello,
    #[error("clickhouse native hello string is invalid utf8")]
    InvalidNativeUtf8,
    #[error("clickhouse http request is incomplete")]
    IncompleteHttpRequest,
    #[error("clickhouse http request is malformed")]
    InvalidHttpRequest,
    #[error("clickhouse http request is missing username")]
    MissingHttpUsername,
    #[error("clickhouse http basic authorization is invalid")]
    InvalidHttpBasicAuth,
}

const CLIENT_HELLO_PACKET_TYPE: u64 = 0;
const HTTP_HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";
const BASIC_AUTH_SCHEME_PREFIX: &[u8] = b"basic ";

pub fn parse_native_initial_route(bytes: &[u8]) -> Result<ClickhouseRoute, ClickhouseParseError> {
    let mut reader = NativeReader::new(bytes);
    let packet_type = reader.read_uvarint()?;
    if packet_type != CLIENT_HELLO_PACKET_TYPE {
        return Err(ClickhouseParseError::InvalidNativeHello);
    }

    reader.skip_client_identity()?;
    let database = reader.read_string()?;
    let username = reader.read_string()?;
    reader.read_string()?;

    if username.is_empty() {
        return Err(ClickhouseParseError::MissingUsername);
    }
    Ok(ClickhouseRoute { username, database })
}

pub fn native_hello_with_database(
    bytes: &[u8],
    database: &str,
) -> Result<Vec<u8>, ClickhouseParseError> {
    parse_native_initial_route(bytes)?;
    if database.is_empty() {
        return Err(ClickhouseParseError::InvalidNativeHello);
    }

    let mut reader = NativeReader::new(bytes);
    reader.read_uvarint()?;
    reader.skip_client_identity()?;
    let database_start = reader.offset;
    reader.read_string()?;
    let database_end = reader.offset;

    let mut rewritten = Vec::with_capacity(bytes.len() + database.len());
    rewritten.extend_from_slice(&bytes[..database_start]);
    write_uvarint(&mut rewritten, database.len() as u64);
    rewritten.extend_from_slice(database.as_bytes());
    rewritten.extend_from_slice(&bytes[database_end..]);
    Ok(rewritten)
}

/// A strictly framed HTTP/1 request head. Every line ends in CRLF and is
/// parsed by `httparse`, so the gateway sees exactly the header lines the
/// backend will see.
struct HttpHead<'a> {
    method: &'a str,
    target: &'a str,
    minor_version: u8,
    headers: Vec<(&'a str, &'a str)>,
    /// Offset of the first body byte.
    body_start: usize,
}

const MAX_HTTP_HEADERS: usize = 100;

fn parse_http_head(bytes: &[u8]) -> Result<HttpHead<'_>, ClickhouseParseError> {
    let header_end = find_header_end(bytes);
    reject_bare_line_breaks(&bytes[..header_end.unwrap_or(bytes.len())])?;
    let header_end = header_end.ok_or(ClickhouseParseError::IncompleteHttpRequest)?;
    std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| ClickhouseParseError::InvalidHttpRequest)?;

    let mut storage = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut request = httparse::Request::new(&mut storage);
    match request.parse(bytes) {
        Ok(httparse::Status::Complete(parsed)) if parsed == header_end => {}
        _ => return Err(ClickhouseParseError::InvalidHttpRequest),
    }
    let (Some(method), Some(target), Some(minor_version)) =
        (request.method, request.path, request.version)
    else {
        return Err(ClickhouseParseError::InvalidHttpRequest);
    };
    if method.is_empty() || target.is_empty() {
        return Err(ClickhouseParseError::InvalidHttpRequest);
    }
    let headers = request
        .headers
        .iter()
        .map(|header| {
            std::str::from_utf8(header.value)
                .map(|value| (header.name, value))
                .map_err(|_| ClickhouseParseError::InvalidHttpRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(HttpHead {
        method,
        target,
        minor_version,
        headers,
        body_start: header_end,
    })
}

/// Refuses a CR or LF that is not part of a CRLF pair. A bare LF would end a
/// header line for a lenient backend while hiding the next header from a
/// CRLF-only reader, which could smuggle a database or user override past the
/// gateway. A trailing CR may still be followed by its LF in a later read.
fn reject_bare_line_breaks(head: &[u8]) -> Result<(), ClickhouseParseError> {
    for (index, byte) in head.iter().enumerate() {
        let bare = match byte {
            b'\n' => index == 0 || head[index - 1] != b'\r',
            b'\r' => head.get(index + 1).is_some_and(|next| *next != b'\n'),
            _ => false,
        };
        if bare {
            return Err(ClickhouseParseError::InvalidHttpRequest);
        }
    }
    Ok(())
}

pub fn parse_http_initial_route(bytes: &[u8]) -> Result<ClickhouseHttpRoute, ClickhouseParseError> {
    let head = parse_http_head(bytes)?;
    let mut username = None;
    let mut database = None;
    if let Some((_, query)) = head.target.split_once('?') {
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            if key.eq_ignore_ascii_case("user") {
                merge_route_field(&mut username, value.into_owned())?;
            } else if key.eq_ignore_ascii_case("database") {
                merge_route_field(&mut database, value.into_owned())?;
            }
        }
    }

    for (name, value) in &head.headers {
        let value = value.trim();
        if name.eq_ignore_ascii_case("x-clickhouse-user") {
            merge_route_field(&mut username, value.to_string())?;
        } else if name.eq_ignore_ascii_case("x-clickhouse-database") {
            merge_route_field(&mut database, value.to_string())?;
        } else if name.eq_ignore_ascii_case("authorization") {
            let encoded = basic_authorization_payload(value)?
                .ok_or(ClickhouseParseError::InvalidHttpBasicAuth)?;
            merge_route_field(&mut username, basic_auth_username(encoded)?)?;
        }
    }

    let username = username.ok_or(ClickhouseParseError::MissingHttpUsername)?;
    if username.is_empty() {
        return Err(ClickhouseParseError::MissingHttpUsername);
    }
    let database = database.unwrap_or_default();
    Ok(ClickhouseHttpRoute { username, database })
}

pub fn http_request_for_gateway(
    bytes: &[u8],
    database: &str,
) -> Result<Vec<u8>, ClickhouseParseError> {
    parse_http_initial_route(bytes)?;
    if database.is_empty() || database.chars().any(char::is_control) {
        return Err(ClickhouseParseError::InvalidHttpRequest);
    }
    let head = parse_http_head(bytes)?;

    let mut rewritten = format!(
        "{} {} HTTP/1.{}\r\n",
        head.method,
        target_with_database(head.target, database),
        head.minor_version
    );
    let mut database_header_seen = false;
    for (name, value) in &head.headers {
        if name.eq_ignore_ascii_case("x-clickhouse-database") {
            push_database_header(&mut rewritten, database);
            database_header_seen = true;
        } else if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            // One authenticated HTTP request owns one tenant session. Raw
            // keep-alive reuse could otherwise authenticate a later request
            // as another shared tenant while retaining the first meter/fence.
        } else {
            rewritten.push_str(name);
            rewritten.push_str(": ");
            rewritten.push_str(value);
            rewritten.push_str("\r\n");
        }
    }
    if !database_header_seen {
        push_database_header(&mut rewritten, database);
    }
    rewritten.push_str("Connection: close\r\n");
    rewritten.push_str("\r\n");

    let mut output = rewritten.into_bytes();
    output.extend_from_slice(&bytes[head.body_start..]);
    Ok(output)
}

fn push_database_header(headers: &mut String, database: &str) {
    headers.push_str("X-ClickHouse-Database: ");
    headers.push_str(database);
    headers.push_str("\r\n");
}

fn target_with_database(target: &str, database: &str) -> String {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut pairs: Vec<String> = query
        .split('&')
        .filter(|pair| {
            let name = pair.split_once('=').map_or(*pair, |(name, _)| name);
            !pair.is_empty()
                && !form_urlencoded::parse(name.as_bytes())
                    .next()
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("database"))
        })
        .map(str::to_string)
        .collect();
    pairs.push(
        form_urlencoded::Serializer::new(String::new())
            .append_pair("database", database)
            .finish(),
    );
    format!("{path}?{}", pairs.join("&"))
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(HTTP_HEADER_TERMINATOR.len())
        .position(|window| window == HTTP_HEADER_TERMINATOR)
        .map(|index| index + HTTP_HEADER_TERMINATOR.len())
}

fn basic_auth_username(value: &str) -> Result<String, ClickhouseParseError> {
    let decoded = BASE64_STANDARD
        .decode(value.trim())
        .map_err(|_| ClickhouseParseError::InvalidHttpBasicAuth)?;
    let decoded =
        String::from_utf8(decoded).map_err(|_| ClickhouseParseError::InvalidHttpBasicAuth)?;
    let (username, _) = decoded
        .split_once(':')
        .ok_or(ClickhouseParseError::InvalidHttpBasicAuth)?;
    Ok(username.to_string())
}

fn basic_authorization_payload(value: &str) -> Result<Option<&str>, ClickhouseParseError> {
    // HTTP authentication scheme names and base64 credentials are ASCII.
    // Checking that invariant before examining a fixed-width prefix avoids
    // slicing through a multi-byte UTF-8 code point supplied by a hostile
    // Authorization header.
    if !value.is_ascii() {
        return Err(ClickhouseParseError::InvalidHttpBasicAuth);
    }
    let prefix_len = BASIC_AUTH_SCHEME_PREFIX.len();
    let Some(prefix) = value.as_bytes().get(..prefix_len) else {
        return Ok(None);
    };
    if !prefix.eq_ignore_ascii_case(BASIC_AUTH_SCHEME_PREFIX) {
        return Ok(None);
    }
    Ok(value.get(prefix_len..))
}

fn merge_route_field(
    current: &mut Option<String>,
    value: String,
) -> Result<(), ClickhouseParseError> {
    if current.as_ref().is_some_and(|current| current != &value) {
        return Err(ClickhouseParseError::InvalidHttpRequest);
    }
    *current = Some(value);
    Ok(())
}

struct NativeReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> NativeReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_uvarint(&mut self) -> Result<u64, ClickhouseParseError> {
        let mut value = 0_u64;
        for shift in (0..64).step_by(7) {
            let byte = self
                .bytes
                .get(self.offset)
                .ok_or(ClickhouseParseError::IncompleteNativeHello)?;
            self.offset += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ClickhouseParseError::InvalidNativeHello)
    }

    fn skip_client_identity(&mut self) -> Result<(), ClickhouseParseError> {
        self.read_string()?;
        self.read_uvarint()?;
        self.read_uvarint()?;
        self.read_uvarint()?;
        Ok(())
    }

    fn read_string(&mut self) -> Result<String, ClickhouseParseError> {
        let len = self.read_uvarint()? as usize;
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ClickhouseParseError::InvalidNativeHello)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ClickhouseParseError::IncompleteNativeHello)?;
        self.offset = end;
        std::str::from_utf8(value)
            .map(str::to_string)
            .map_err(|_| ClickhouseParseError::InvalidNativeUtf8)
    }
}

fn write_uvarint(bytes: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_native_hello_route() {
        let mut packet = Vec::new();
        write_uvarint(&mut packet, 0);
        write_string(&mut packet, "ClickHouse client");
        write_uvarint(&mut packet, 25);
        write_uvarint(&mut packet, 6);
        write_uvarint(&mut packet, 54468);
        write_string(&mut packet, "analytics");
        write_string(&mut packet, "app");
        write_string(&mut packet, "secret");

        for trailing in [false, true] {
            let mut candidate = packet.clone();
            if trailing {
                candidate.extend_from_slice(b"next packet bytes");
            }
            let route = parse_native_initial_route(&candidate).unwrap();
            assert_eq!(route.username, "app");
            assert_eq!(route.database, "analytics");
        }
    }

    #[test]
    fn injects_unique_database_into_native_jdbc_hello() {
        let mut packet = Vec::new();
        write_uvarint(&mut packet, 0);
        write_string(&mut packet, "ClickHouse JDBC");
        write_uvarint(&mut packet, 25);
        write_uvarint(&mut packet, 6);
        write_uvarint(&mut packet, 54468);
        write_string(&mut packet, "");
        write_string(&mut packet, "app");
        write_string(&mut packet, "secret");
        packet.extend_from_slice(b"trailing hello fields");

        let rewritten = native_hello_with_database(&packet, "analytics").unwrap();
        let route = parse_native_initial_route(&rewritten).unwrap();

        assert_eq!(route.username, "app");
        assert_eq!(route.database, "analytics");
        assert!(rewritten.ends_with(b"trailing hello fields"));
    }

    #[test]
    fn reports_incomplete_native_hello() {
        let mut packet = Vec::new();
        write_uvarint(&mut packet, 0);
        write_string(&mut packet, "ClickHouse client");

        let error = parse_native_initial_route(&packet).unwrap_err();

        assert!(matches!(error, ClickhouseParseError::IncompleteNativeHello));
    }

    #[test]
    fn rejects_non_ascii_basic_authorization_without_panicking() {
        // The first case cuts through a multi-byte boundary in the old fixed
        // string slice; the second reaches the decoder after a valid scheme.
        for authorization in ["💣€", "Basic sécret"] {
            let request = format!(
                "GET /?database=analytics HTTP/1.1\r\nAuthorization: {authorization}\r\n\r\n"
            );
            assert!(matches!(
                parse_http_initial_route(request.as_bytes()),
                Err(ClickhouseParseError::InvalidHttpBasicAuth)
            ));
        }
    }

    #[test]
    fn accepts_missing_or_empty_database_for_unique_username_routing() {
        for request in [
            b"GET / HTTP/1.1\r\nAuthorization: Basic YXBwOnNlY3JldA==\r\n\r\n".as_slice(),
            b"GET /?database= HTTP/1.1\r\nX-ClickHouse-User: app\r\n\r\n".as_slice(),
        ] {
            let route = parse_http_initial_route(request).unwrap();
            assert_eq!(route.username, "app");
            assert!(route.database.is_empty());
        }
    }

    #[test]
    fn injects_unique_database_into_clickhouse_http_jdbc_request() {
        let request = b"POST /?query_id=one&database=default HTTP/1.1\r\nHost: example\r\nX-ClickHouse-User: app\r\nX-ClickHouse-Database: default\r\n\r\nSELECT 1";

        let rewritten = http_request_for_gateway(request, "analytics").unwrap();
        let route = parse_http_initial_route(&rewritten).unwrap();
        let text = String::from_utf8(rewritten.clone()).unwrap();

        assert_eq!(route.username, "app");
        assert_eq!(route.database, "analytics");
        assert!(text.contains("query_id=one&database=analytics"));
        assert!(text.contains("X-ClickHouse-Database: analytics\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(rewritten.ends_with(b"SELECT 1"));
    }

    #[test]
    fn clickhouse_http_gateway_disables_cross_tenant_keep_alive() {
        let request = b"GET /?database=tenant HTTP/1.1\r\nHost: example\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\nX-ClickHouse-User: app\r\n\r\n";
        let rewritten =
            String::from_utf8(http_request_for_gateway(request, "tenant").unwrap()).unwrap();
        assert_eq!(rewritten.matches("Connection: close\r\n").count(), 1);
        assert!(!rewritten.to_ascii_lowercase().contains("keep-alive"));
        assert!(!rewritten.to_ascii_lowercase().contains("proxy-connection"));
    }

    #[test]
    fn bare_line_breaks_cannot_smuggle_route_headers() {
        for request in [
            // A bare LF hides the second header from a CRLF-only reader.
            &b"GET /?database=tenant HTTP/1.1\r\nX-ClickHouse-User: app\r\nX-Note: x\nX-ClickHouse-Database: other\r\n\r\n"[..],
            b"GET /?database=tenant HTTP/1.1\r\nX-ClickHouse-User: app\r\nX-Note: x\nX-ClickHouse-User: admin\r\n\r\n",
            // A bare CR is a line break for some servers.
            b"GET /?database=tenant HTTP/1.1\r\nX-ClickHouse-User: app\r\nX-Note: x\rX-ClickHouse-Database: other\r\n\r\n",
            // LF-only framing throughout.
            b"GET /?database=tenant HTTP/1.1\nX-ClickHouse-User: app\nX-ClickHouse-Database: other\n\n\r\n\r\n",
            // Obsolete line folding continues a header on the next line.
            b"GET /?database=tenant HTTP/1.1\r\nX-ClickHouse-User: app\r\n X-ClickHouse-Database: other\r\n\r\n",
        ] {
            assert!(
                matches!(
                    parse_http_initial_route(request),
                    Err(ClickhouseParseError::InvalidHttpRequest)
                ),
                "{}",
                String::from_utf8_lossy(request)
            );
            assert!(http_request_for_gateway(request, "tenant").is_err());
        }
    }

    #[test]
    fn conflicting_route_headers_are_refused() {
        for request in [
            &b"GET /?database=tenant HTTP/1.1\r\nX-ClickHouse-User: app\r\nX-ClickHouse-User: admin\r\n\r\n"[..],
            b"GET /?user=app HTTP/1.1\r\nX-ClickHouse-User: admin\r\n\r\n",
            b"GET /?database=tenant HTTP/1.1\r\nX-ClickHouse-User: app\r\nX-ClickHouse-Database: other\r\n\r\n",
        ] {
            assert!(matches!(
                parse_http_initial_route(request),
                Err(ClickhouseParseError::InvalidHttpRequest)
            ));
        }
    }

    #[test]
    fn every_forwarded_database_value_is_the_gateway_database() {
        let request = b"POST /?database=tenant&Database=tenant HTTP/1.1\r\nX-ClickHouse-User: app\r\nx-clickhouse-database: tenant\r\nX-Other: kept\r\n\r\nSELECT 1";
        let rewritten =
            String::from_utf8(http_request_for_gateway(request, "tenant").unwrap()).unwrap();
        let (head, body) = rewritten.split_once("\r\n\r\n").unwrap();
        assert_eq!(body, "SELECT 1");
        assert!(head.split("\r\n").all(|line| !line.contains(['\r', '\n'])));
        assert!(head.starts_with("POST /?database=tenant HTTP/1.1\r\n"));
        assert_eq!(head.matches("X-ClickHouse-Database: tenant").count(), 1);
        assert!(head.contains("X-Other: kept"));
        assert!(http_request_for_gateway(request, "ten\r\nant").is_err());
    }

    #[test]
    fn partial_heads_still_wait_for_more_bytes() {
        for partial in [
            &b"GET /?database=tenant HTTP/1.1\r\nX-ClickHouse-User: app\r"[..],
            b"GET /?database=tenant HTTP/1.1\r\nX-ClickHouse-User: app\r\n",
        ] {
            assert!(matches!(
                parse_http_initial_route(partial),
                Err(ClickhouseParseError::IncompleteHttpRequest)
            ));
        }
    }

    fn write_string(bytes: &mut Vec<u8>, value: &str) {
        write_uvarint(bytes, value.len() as u64);
        bytes.extend_from_slice(value.as_bytes());
    }
}
