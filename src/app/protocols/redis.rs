use sha2::{Digest, Sha256};

use crate::shared::hex::encode_lower;

#[derive(Clone, PartialEq, Eq)]
pub struct RedisRoute {
    username: Option<String>,
    password: Vec<u8>,
}

impl std::fmt::Debug for RedisRoute {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisRoute")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl RedisRoute {
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn password_route_sha256(&self) -> String {
        password_route_sha256(&self.password)
    }

    pub fn rewrite_with_resolved_username(
        &self,
        original: &[u8],
        consumed: usize,
        resolved_username: &str,
    ) -> Result<Vec<u8>, RedisParseError> {
        if self
            .username
            .as_deref()
            .is_some_and(|username| !username.eq_ignore_ascii_case("default"))
            || resolved_username.is_empty()
            || resolved_username.as_bytes().contains(&b'\r')
            || resolved_username.as_bytes().contains(&b'\n')
            || consumed > original.len()
        {
            return Err(RedisParseError::Unsupported);
        }
        let (mut args, parsed) = parse_resp_array(&original[..consumed])?;
        if parsed != consumed || args.is_empty() {
            return Err(RedisParseError::Unsupported);
        }
        if args[0].eq_ignore_ascii_case(b"AUTH") {
            match args.len() {
                2 => args.insert(1, resolved_username.as_bytes().to_vec()),
                3 => args[1] = resolved_username.as_bytes().to_vec(),
                _ => return Err(RedisParseError::Unsupported),
            }
        } else if args[0].eq_ignore_ascii_case(b"HELLO") {
            let auth = hello_auth_index(&args)?;
            args[auth + 1] = resolved_username.as_bytes().to_vec();
        } else {
            return Err(RedisParseError::Unsupported);
        }

        let mut rewritten = serialize_resp_array(&args);
        rewritten.extend_from_slice(&original[consumed..]);
        Ok(rewritten)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RedisParseError {
    #[error("redis command is empty")]
    Empty,
    #[error("redis initial command is incomplete")]
    Incomplete,
    #[error("redis command is not supported for routing")]
    Unsupported,
    #[error("redis command is missing username")]
    MissingUsername,
    #[error("redis command is invalid utf8")]
    InvalidUtf8,
}

const MAX_INITIAL_ARGS: usize = 16;
const MAX_BULK_LENGTH: usize = 16 * 1024;

pub fn parse_initial_route(bytes: &[u8]) -> Result<RedisRoute, RedisParseError> {
    let (args, consumed) = parse_resp_array(bytes)?;
    if consumed != bytes.len() {
        return Err(RedisParseError::Unsupported);
    }
    route_from_args(&args)
}

pub fn parse_initial_frame_route(
    bytes: &[u8],
) -> Result<Option<(RedisRoute, usize)>, RedisParseError> {
    match parse_resp_array(bytes) {
        Ok((args, consumed)) => Ok(Some((route_from_args(&args)?, consumed))),
        Err(RedisParseError::Incomplete) => Ok(None),
        Err(error) => Err(error),
    }
}

fn route_from_args(args: &[Vec<u8>]) -> Result<RedisRoute, RedisParseError> {
    if args.is_empty() {
        return Err(RedisParseError::Empty);
    }

    if args[0].eq_ignore_ascii_case(b"AUTH") {
        parse_auth(args)
    } else if args[0].eq_ignore_ascii_case(b"HELLO") {
        parse_hello(args)
    } else {
        Err(RedisParseError::Unsupported)
    }
}

fn redis_string(bytes: &[u8]) -> Result<String, RedisParseError> {
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| RedisParseError::InvalidUtf8)
}

fn parse_auth(args: &[Vec<u8>]) -> Result<RedisRoute, RedisParseError> {
    match args.len() {
        2 => Ok(RedisRoute {
            username: None,
            password: args[1].clone(),
        }),
        3 => Ok(RedisRoute {
            username: Some(redis_string(&args[1])?),
            password: args[2].clone(),
        }),
        _ => Err(RedisParseError::Unsupported),
    }
}

fn parse_hello(args: &[Vec<u8>]) -> Result<RedisRoute, RedisParseError> {
    let auth = hello_auth_index(args)?;
    Ok(RedisRoute {
        username: Some(redis_string(&args[auth + 1])?),
        password: args[auth + 2].clone(),
    })
}

fn hello_auth_index(args: &[Vec<u8>]) -> Result<usize, RedisParseError> {
    let version = args.get(1).ok_or(RedisParseError::MissingUsername)?;
    if !matches!(version.as_slice(), b"2" | b"3") {
        return Err(RedisParseError::Unsupported);
    }

    let mut auth = None;
    let mut index = 2;
    while index < args.len() {
        if args[index].eq_ignore_ascii_case(b"AUTH") {
            if index + 2 >= args.len() {
                return Err(RedisParseError::MissingUsername);
            }
            // Redis and Valkey use the last AUTH option. Its values must not
            // be interpreted as options, even if they contain "AUTH".
            auth = Some(index);
            index += 3;
        } else if args[index].eq_ignore_ascii_case(b"SETNAME") && index + 1 < args.len() {
            index += 2;
        } else {
            return Err(RedisParseError::Unsupported);
        }
    }
    auth.ok_or(RedisParseError::MissingUsername)
}

pub fn password_route_sha256(password: &[u8]) -> String {
    encode_lower(&Sha256::digest(password))
}

fn serialize_resp_array(args: &[Vec<u8>]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(b"*");
    output.extend_from_slice(args.len().to_string().as_bytes());
    output.extend_from_slice(b"\r\n");
    for argument in args {
        output.extend_from_slice(b"$");
        output.extend_from_slice(argument.len().to_string().as_bytes());
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(argument);
        output.extend_from_slice(b"\r\n");
    }
    output
}

fn parse_resp_array(bytes: &[u8]) -> Result<(Vec<Vec<u8>>, usize), RedisParseError> {
    if bytes.is_empty() {
        return Err(RedisParseError::Empty);
    }
    let mut offset = 0;
    if bytes[offset] != b'*' {
        return Err(RedisParseError::Unsupported);
    }
    offset += 1;
    let count = read_decimal_line(bytes, &mut offset)?;
    if count > MAX_INITIAL_ARGS {
        return Err(RedisParseError::Unsupported);
    }

    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        if offset >= bytes.len() {
            return Err(RedisParseError::Incomplete);
        }
        if bytes[offset] != b'$' {
            return Err(RedisParseError::Unsupported);
        }
        offset += 1;
        let len = read_decimal_line(bytes, &mut offset)?;
        if len > MAX_BULK_LENGTH {
            return Err(RedisParseError::Unsupported);
        }
        let value_end = offset
            .checked_add(len)
            .ok_or(RedisParseError::Unsupported)?;
        let frame_end = value_end
            .checked_add(2)
            .ok_or(RedisParseError::Unsupported)?;
        if frame_end > bytes.len() {
            return Err(RedisParseError::Incomplete);
        }
        if &bytes[value_end..frame_end] != b"\r\n" {
            return Err(RedisParseError::Unsupported);
        }
        args.push(bytes[offset..value_end].to_vec());
        offset = frame_end;
    }

    Ok((args, offset))
}

fn read_decimal_line(bytes: &[u8], offset: &mut usize) -> Result<usize, RedisParseError> {
    let start = *offset;
    while *offset + 1 < bytes.len() {
        if bytes[*offset] == b'\r' && bytes[*offset + 1] == b'\n' {
            if *offset == start {
                return Err(RedisParseError::Unsupported);
            }
            let value = parse_decimal(&bytes[start..*offset])?;
            *offset += 2;
            return Ok(value);
        }
        *offset += 1;
    }
    Err(RedisParseError::Incomplete)
}

fn parse_decimal(bytes: &[u8]) -> Result<usize, RedisParseError> {
    let mut value = 0_usize;
    for byte in bytes {
        match byte {
            b'0'..=b'9' => {
                value = value
                    .checked_mul(10)
                    .and_then(|value| value.checked_add((byte - b'0') as usize))
                    .ok_or(RedisParseError::Unsupported)?;
            }
            _ => return Err(RedisParseError::Unsupported),
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(arguments: &[&[u8]]) -> Vec<u8> {
        serialize_resp_array(&arguments.iter().map(|arg| arg.to_vec()).collect::<Vec<_>>())
    }

    #[test]
    fn hello_client_name_is_not_an_auth_option() {
        let packet = hello(&[
            b"HELLO", b"3", b"SETNAME", b"AUTH", b"AUTH", b"default", b"secret",
        ]);
        let route = parse_initial_route(&packet).unwrap();
        assert_eq!(route.username(), Some("default"));
        assert_eq!(
            route.password_route_sha256(),
            password_route_sha256(b"secret")
        );
    }

    #[test]
    fn hello_rewrite_preserves_client_name_and_pipelined_bytes() {
        let mut packet = hello(&[
            b"HELLO", b"3", b"SETNAME", b"AUTH", b"AUTH", b"default", b"secret",
        ]);
        let consumed = packet.len();
        packet.extend_from_slice(b"*1\r\n$4\r\nPING\r\n");
        let route = RedisRoute {
            username: Some("default".into()),
            password: b"secret".to_vec(),
        };
        let rewritten = route
            .rewrite_with_resolved_username(&packet, consumed, "tenant")
            .unwrap();
        let mut expected = hello(&[
            b"HELLO", b"3", b"SETNAME", b"AUTH", b"AUTH", b"tenant", b"secret",
        ]);
        expected.extend_from_slice(b"*1\r\n$4\r\nPING\r\n");
        assert_eq!(rewritten, expected);
    }

    #[test]
    fn hello_uses_and_rewrites_the_last_auth_option_like_the_backend() {
        let packet = hello(&[
            b"HELLO", b"2", b"AUTH", b"ignored", b"old", b"AUTH", b"default", b"secret",
        ]);
        let route = parse_initial_route(&packet).unwrap();
        assert_eq!(route.username(), Some("default"));
        assert_eq!(
            route.password_route_sha256(),
            password_route_sha256(b"secret")
        );
        assert_eq!(
            route
                .rewrite_with_resolved_username(&packet, packet.len(), "tenant")
                .unwrap(),
            hello(&[
                b"HELLO", b"2", b"AUTH", b"ignored", b"old", b"AUTH", b"tenant", b"secret"
            ])
        );
    }

    #[test]
    fn hello_rejects_malformed_options_even_after_auth() {
        for arguments in [
            vec![
                b"HELLO".as_slice(),
                b"3",
                b"AUTH",
                b"user",
                b"pass",
                b"SETNAME",
            ],
            vec![
                b"HELLO".as_slice(),
                b"3",
                b"AUTH",
                b"user",
                b"pass",
                b"UNKNOWN",
            ],
            vec![b"HELLO".as_slice(), b"3", b"SETNAME", b"AUTH"],
            vec![b"HELLO".as_slice(), b"AUTH", b"user", b"pass"],
        ] {
            assert!(parse_initial_route(&hello(&arguments)).is_err());
        }
    }

    #[test]
    fn rejects_trailing_bytes_for_exact_initial_route_parse() {
        let error = parse_initial_route(
            b"*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$4\r\npass\r\n*1\r\n$4\r\nPING\r\n",
        )
        .unwrap_err();

        assert!(matches!(error, RedisParseError::Unsupported));
    }

    #[test]
    fn frame_parser_accepts_complete_first_frame_with_trailing_bytes() {
        let (route, consumed) = parse_initial_frame_route(
            b"*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$4\r\npass\r\n*1\r\n$4\r\nPING\r\n",
        )
        .unwrap()
        .unwrap();

        assert_eq!(route.username(), Some("app"));
        assert_eq!(
            consumed,
            b"*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$4\r\npass\r\n".len()
        );
    }

    #[test]
    fn frame_parser_waits_for_complete_bulk_payload() {
        let result = parse_initial_frame_route(b"*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$4\r\npa");

        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn rejects_bulk_length_mismatch() {
        let error = parse_initial_frame_route(b"*2\r\n$4\r\nAUTH\r\n$4\r\npassx\r\n").unwrap_err();

        assert!(matches!(error, RedisParseError::Unsupported));
    }

    #[test]
    fn rejects_inline_auth() {
        let error = parse_initial_route(b"AUTH pass\r\n").unwrap_err();

        assert!(matches!(error, RedisParseError::Unsupported));
    }

    #[test]
    fn rewrites_legacy_password_only_auth_to_the_resolved_acl_user() {
        let original = b"*2\r\n$4\r\nAUTH\r\n$4\r\npass\r\n*1\r\n$4\r\nPING\r\n";
        let (route, consumed) = parse_initial_frame_route(original).unwrap().unwrap();
        let rewritten = route
            .rewrite_with_resolved_username(original, consumed, "tenant_a")
            .unwrap();
        assert_eq!(
            rewritten,
            b"*3\r\n$4\r\nAUTH\r\n$8\r\ntenant_a\r\n$4\r\npass\r\n*1\r\n$4\r\nPING\r\n"
        );
    }

    #[test]
    fn debug_never_exposes_the_resp_password() {
        let route = parse_initial_route(b"*2\r\n$4\r\nAUTH\r\n$12\r\nsuper-secret\r\n").unwrap();
        let debug = format!("{route:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }
}
