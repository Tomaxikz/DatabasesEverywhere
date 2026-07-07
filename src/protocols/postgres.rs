use std::collections::HashMap;

pub const SSL_REQUEST_CODE: i32 = 80877103;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupRoute {
    pub user: String,
    pub database: String,
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
        .cloned()
        .unwrap_or_else(|| user.clone());

    Ok(StartupRoute { user, database })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_and_database() {
        let packet = startup_packet(&[("user", "app"), ("database", "app_db")]);

        let route = parse_startup_route(&packet).unwrap();

        assert_eq!(route.user, "app");
        assert_eq!(route.database, "app_db");
    }

    #[test]
    fn defaults_database_to_user() {
        let packet = startup_packet(&[("user", "app")]);

        let route = parse_startup_route(&packet).unwrap();

        assert_eq!(route.database, "app");
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
