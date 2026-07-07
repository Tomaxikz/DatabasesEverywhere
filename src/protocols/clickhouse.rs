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

#[derive(Debug, thiserror::Error)]
pub enum ClickhouseParseError {
    #[error("clickhouse native hello is missing username")]
    MissingUsername,
    #[error("clickhouse native hello is missing database")]
    MissingDatabase,
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
    #[error("clickhouse http request is missing database")]
    MissingHttpDatabase,
    #[error("clickhouse http basic authorization is invalid")]
    InvalidHttpBasicAuth,
}

pub fn parse_native_initial_route(bytes: &[u8]) -> Result<ClickhouseRoute, ClickhouseParseError> {
    let mut reader = NativeReader::new(bytes);
    let packet_type = reader.read_uvarint()?;
    if packet_type != 0 {
        return Err(ClickhouseParseError::InvalidNativeHello);
    }

    reader.read_string()?;
    reader.read_uvarint()?;
    reader.read_uvarint()?;
    reader.read_uvarint()?;
    let database = reader.read_string()?;
    let username = reader.read_string()?;
    reader.read_string()?;

    if username.is_empty() {
        return Err(ClickhouseParseError::MissingUsername);
    }
    if database.is_empty() {
        return Err(ClickhouseParseError::MissingDatabase);
    }

    Ok(ClickhouseRoute { username, database })
}

pub fn parse_http_initial_route(bytes: &[u8]) -> Result<ClickhouseHttpRoute, ClickhouseParseError> {
    let header_end = find_header_end(bytes).ok_or(ClickhouseParseError::IncompleteHttpRequest)?;
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| ClickhouseParseError::InvalidHttpRequest)?;
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(ClickhouseParseError::InvalidHttpRequest)?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or(ClickhouseParseError::InvalidHttpRequest)?;
    let target = request_parts
        .next()
        .ok_or(ClickhouseParseError::InvalidHttpRequest)?;
    if method.is_empty() || target.is_empty() {
        return Err(ClickhouseParseError::InvalidHttpRequest);
    }

    let mut username = None;
    let mut database = query_value(target, "database");

    if let Some(value) = query_value(target, "user") {
        username = Some(value);
    }

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("x-clickhouse-user") {
            username = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("x-clickhouse-database") {
            database = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("authorization")
            && username.is_none()
            && value.len() >= 6
            && value[..6].eq_ignore_ascii_case("basic ")
        {
            username = Some(basic_auth_username(&value[6..])?);
        }
    }

    let username = username.ok_or(ClickhouseParseError::MissingHttpUsername)?;
    if username.is_empty() {
        return Err(ClickhouseParseError::MissingHttpUsername);
    }
    let database = database.ok_or(ClickhouseParseError::MissingHttpDatabase)?;
    if database.is_empty() {
        return Err(ClickhouseParseError::MissingHttpDatabase);
    }
    Ok(ClickhouseHttpRoute { username, database })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
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

fn query_value(target: &str, key: &str) -> Option<String> {
    let query = target.split_once('?')?.1;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(name).eq_ignore_ascii_case(key) {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                    output.push((high << 4) | low);
                    index += 3;
                } else {
                    output.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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

        let route = parse_native_initial_route(&packet).unwrap();

        assert_eq!(route.username, "app");
        assert_eq!(route.database, "analytics");
    }

    #[test]
    fn native_hello_can_have_trailing_bytes() {
        let mut packet = Vec::new();
        write_uvarint(&mut packet, 0);
        write_string(&mut packet, "ClickHouse client");
        write_uvarint(&mut packet, 25);
        write_uvarint(&mut packet, 6);
        write_uvarint(&mut packet, 54468);
        write_string(&mut packet, "analytics");
        write_string(&mut packet, "app");
        write_string(&mut packet, "secret");
        packet.extend_from_slice(b"next packet bytes");

        let route = parse_native_initial_route(&packet).unwrap();

        assert_eq!(route.username, "app");
        assert_eq!(route.database, "analytics");
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
    fn parses_http_route_from_clickhouse_headers() {
        let request = b"POST /?database=analytics HTTP/1.1\r\nHost: example\r\nX-ClickHouse-User: app\r\nX-ClickHouse-Key: secret\r\n\r\nSELECT 1";

        let route = parse_http_initial_route(request).unwrap();

        assert_eq!(route.username, "app");
        assert_eq!(route.database, "analytics");
    }

    #[test]
    fn parses_http_route_from_basic_auth_and_query() {
        let request = b"GET /?database=analytics%5Fone HTTP/1.1\r\nAuthorization: Basic YXBwOnNlY3JldA==\r\n\r\n";

        let route = parse_http_initial_route(request).unwrap();

        assert_eq!(route.username, "app");
        assert_eq!(route.database, "analytics_one");
    }

    #[test]
    fn rejects_http_route_without_database() {
        let request = b"GET / HTTP/1.1\r\nAuthorization: Basic YXBwOnNlY3JldA==\r\n\r\n";

        let error = parse_http_initial_route(request).unwrap_err();

        assert!(matches!(error, ClickhouseParseError::MissingHttpDatabase));
    }

    #[test]
    fn rejects_http_route_with_empty_database() {
        let request = b"GET /?database= HTTP/1.1\r\nX-ClickHouse-User: app\r\n\r\n";

        let error = parse_http_initial_route(request).unwrap_err();

        assert!(matches!(error, ClickhouseParseError::MissingHttpDatabase));
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

    fn write_string(bytes: &mut Vec<u8>, value: &str) {
        write_uvarint(bytes, value.len() as u64);
        bytes.extend_from_slice(value.as_bytes());
    }
}
