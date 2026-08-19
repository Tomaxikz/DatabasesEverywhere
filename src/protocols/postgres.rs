use std::collections::HashMap;

pub const SSL_REQUEST_CODE: i32 = 80877103;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupRoute {
    pub user: String,
    pub database: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PostgresParseError {
    #[error("startup packet is too short")]
    TooShort,
    #[error("startup packet length is invalid")]
    InvalidLength,
    #[error("startup packet is missing required field {field}")]
    MissingField { field: &'static str },
    #[error("startup packet contains invalid utf8")]
    InvalidUtf8,
}

pub fn is_ssl_request(bytes: &[u8]) -> bool {
    if bytes.len() != 8 {
        return false;
    }
    i32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) == SSL_REQUEST_CODE
}

pub fn parse_startup_route(bytes: &[u8]) -> Result<StartupRoute, PostgresParseError> {
    if bytes.len() < 8 {
        return Err(PostgresParseError::TooShort);
    }

    let declared_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if declared_len != bytes.len() || declared_len < 8 {
        return Err(PostgresParseError::InvalidLength);
    }

    let mut fields = HashMap::new();
    let mut parts = bytes[8..].split(|byte| *byte == 0);
    while let Some(key) = parts.next() {
        if key.is_empty() {
            break;
        }
        let Some(value) = parts.next() else {
            break;
        };
        let key = std::str::from_utf8(key).map_err(|_| PostgresParseError::InvalidUtf8)?;
        let value = std::str::from_utf8(value).map_err(|_| PostgresParseError::InvalidUtf8)?;
        fields.insert(key.to_string(), value.to_string());
    }

    let user = fields
        .get("user")
        .cloned()
        .ok_or(PostgresParseError::MissingField { field: "user" })?;
    let database = fields
        .get("database")
        .filter(|value| !value.is_empty())
        .cloned();

    Ok(StartupRoute { user, database })
}

pub fn startup_packet_with_database(
    bytes: &[u8],
    database: &str,
) -> Result<Vec<u8>, PostgresParseError> {
    parse_startup_route(bytes)?;
    if database.is_empty() || database.as_bytes().contains(&0) || bytes.last() != Some(&0) {
        return Err(PostgresParseError::InvalidLength);
    }

    let mut offset = 8;
    while offset < bytes.len() - 1 {
        let key_start = offset;
        let key_end = find_nul(bytes, key_start)?;
        if key_end == key_start {
            break;
        }
        let value_end = find_nul(bytes, key_end + 1)?;
        if &bytes[key_start..key_end] == b"database" {
            let mut packet = Vec::with_capacity(bytes.len() + database.len());
            packet.extend_from_slice(&bytes[..key_end + 1]);
            packet.extend_from_slice(database.as_bytes());
            packet.extend_from_slice(&bytes[value_end..]);
            set_packet_length(&mut packet)?;
            return Ok(packet);
        }
        offset = value_end + 1;
    }

    let mut packet = Vec::with_capacity(bytes.len() + "database".len() + database.len() + 2);
    packet.extend_from_slice(&bytes[..bytes.len() - 1]);
    packet.extend_from_slice(b"database\0");
    packet.extend_from_slice(database.as_bytes());
    packet.extend_from_slice(b"\0\0");
    set_packet_length(&mut packet)?;
    Ok(packet)
}

fn find_nul(bytes: &[u8], offset: usize) -> Result<usize, PostgresParseError> {
    bytes
        .get(offset..)
        .and_then(|bytes| bytes.iter().position(|byte| *byte == 0))
        .and_then(|relative| offset.checked_add(relative))
        .ok_or(PostgresParseError::InvalidLength)
}

fn set_packet_length(packet: &mut [u8]) -> Result<(), PostgresParseError> {
    let len = u32::try_from(packet.len()).map_err(|_| PostgresParseError::InvalidLength)?;
    packet[..4].copy_from_slice(&len.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_and_database() {
        let packet = startup_packet(&[("user", "app"), ("database", "app_db")]);

        let route = parse_startup_route(&packet).unwrap();

        assert_eq!(route.user, "app");
        assert_eq!(route.database.as_deref(), Some("app_db"));
    }

    #[test]
    fn preserves_an_omitted_database_for_unique_username_routing() {
        let packet = startup_packet(&[("user", "app")]);

        let route = parse_startup_route(&packet).unwrap();

        assert_eq!(route.database, None);
    }

    #[test]
    fn injects_resolved_database_without_losing_startup_fields() {
        let packet = startup_packet(&[("user", "app"), ("application_name", "jdbc")]);

        let rewritten = startup_packet_with_database(&packet, "app_db").unwrap();
        let route = parse_startup_route(&rewritten).unwrap();

        assert_eq!(route.database.as_deref(), Some("app_db"));
        assert!(
            rewritten
                .windows(b"application_name\0jdbc".len())
                .any(|window| { window == b"application_name\0jdbc" })
        );
    }

    #[test]
    fn replaces_jdbc_username_default_with_resolved_database() {
        let packet = startup_packet(&[("user", "app"), ("database", "app")]);

        let rewritten = startup_packet_with_database(&packet, "app_db").unwrap();
        let route = parse_startup_route(&rewritten).unwrap();

        assert_eq!(route.database.as_deref(), Some("app_db"));
    }

    fn startup_packet(fields: &[(&str, &str)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(&196608_i32.to_be_bytes());
        for (key, value) in fields {
            bytes.extend_from_slice(key.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(0);
        }
        bytes.push(0);
        let len = bytes.len() as u32;
        bytes[..4].copy_from_slice(&len.to_be_bytes());
        bytes
    }
}
