#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisRoute {
    pub username: String,
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
            username: "default".to_string(),
        }),
        3 => Ok(RedisRoute {
            username: redis_string(&args[1])?,
        }),
        _ => Err(RedisParseError::Unsupported),
    }
}

fn parse_hello(args: &[Vec<u8>]) -> Result<RedisRoute, RedisParseError> {
    let mut index = 1;
    while index < args.len() {
        if args[index].eq_ignore_ascii_case(b"AUTH") {
            if index + 2 >= args.len() {
                return Err(RedisParseError::MissingUsername);
            }
            return Ok(RedisRoute {
                username: redis_string(&args[index + 1])?,
            });
        }
        index += 1;
    }
    Err(RedisParseError::MissingUsername)
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

    #[test]
    fn parses_auth_username() {
        let route =
            parse_initial_route(b"*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$4\r\npass\r\n").unwrap();

        assert_eq!(route.username, "app");
    }

    #[test]
    fn parses_hello_auth_username() {
        let route = parse_initial_route(
            b"*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$4\r\npass\r\n",
        )
        .unwrap();

        assert_eq!(route.username, "app");
    }

    #[test]
    fn resp_auth_without_username_uses_default() {
        let route = parse_initial_route(b"*2\r\n$4\r\nAUTH\r\n$4\r\npass\r\n").unwrap();

        assert_eq!(route.username, "default");
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

        assert_eq!(route.username, "app");
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
}
