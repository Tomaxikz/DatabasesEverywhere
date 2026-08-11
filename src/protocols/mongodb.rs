use std::io::Cursor;

use bson::{Binary, Bson, Document, doc, spec::BinarySubtype};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const OP_MSG: i32 = 2013;
const OP_REPLY: i32 = 1;
const OP_QUERY: i32 = 2004;
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MongodbRoute {
    pub username: String,
    pub database: String,
}

#[derive(Debug)]
pub struct MongoMessage {
    pub request_id: i32,
    pub op_code: i32,
    pub body: Option<Document>,
    pub raw: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum MongodbProxyError {
    #[error("mongodb message io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("mongodb message is malformed")]
    MalformedMessage,
    #[error("mongodb message is too large")]
    MessageTooLarge,
    #[error("mongodb opcode {0} is not supported")]
    UnsupportedOpcode(i32),
    #[error("mongodb saslStart did not include an auth database")]
    MissingDatabase,
    #[error("mongodb saslStart did not include a username")]
    MissingUsername,
    #[error("mongodb hello authentication route is malformed")]
    InvalidHelloRoute,
    #[error("mongodb hello included conflicting authentication routes")]
    ConflictingHelloRoutes,
    #[error("mongodb bson decode failed: {0}")]
    BsonDecode(#[from] bson::de::Error),
    #[error("mongodb bson encode failed: {0}")]
    BsonEncode(#[from] bson::ser::Error),
}

pub async fn read_message<S>(stream: &mut S) -> Result<MongoMessage, MongodbProxyError>
where
    S: AsyncRead + Unpin,
{
    read_message_limited(stream, MAX_MESSAGE_SIZE).await
}

pub async fn read_message_limited<S>(
    stream: &mut S,
    max_message_size: usize,
) -> Result<MongoMessage, MongodbProxyError>
where
    S: AsyncRead + Unpin,
{
    let mut len_bytes = [0_u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = i32::from_le_bytes(len_bytes);
    if len < 16 {
        return Err(MongodbProxyError::MalformedMessage);
    }
    let len = len as usize;
    if len > max_message_size.min(MAX_MESSAGE_SIZE) {
        return Err(MongodbProxyError::MessageTooLarge);
    }

    let mut raw = Vec::with_capacity(len);
    raw.extend_from_slice(&len_bytes);
    raw.resize(len, 0);
    stream.read_exact(&mut raw[4..]).await?;

    let request_id = i32::from_le_bytes(raw[4..8].try_into().unwrap());
    let op_code = i32::from_le_bytes(raw[12..16].try_into().unwrap());
    let body = match op_code {
        OP_MSG => Some(parse_op_msg_body(&raw[16..])?),
        OP_QUERY => Some(parse_op_query_body(&raw[16..])?),
        _ => None,
    };

    Ok(MongoMessage {
        request_id,
        op_code,
        body,
        raw,
    })
}

pub async fn write_response(
    stream: &mut (impl AsyncWrite + Unpin),
    request: &MongoMessage,
    body: Document,
) -> Result<(), MongodbProxyError> {
    match request.op_code {
        OP_MSG => write_op_msg_response(stream, request.request_id, body).await,
        OP_QUERY => write_op_reply_response(stream, request.request_id, body).await,
        op_code => Err(MongodbProxyError::UnsupportedOpcode(op_code)),
    }
}

pub async fn write_op_msg_response(
    stream: &mut (impl AsyncWrite + Unpin),
    response_to: i32,
    body: Document,
) -> Result<(), MongodbProxyError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0_i32.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&bson::to_vec(&body)?);

    let len = 16 + payload.len();
    let mut message = Vec::with_capacity(len);
    message.extend_from_slice(&(len as i32).to_le_bytes());
    message.extend_from_slice(&1_i32.to_le_bytes());
    message.extend_from_slice(&response_to.to_le_bytes());
    message.extend_from_slice(&OP_MSG.to_le_bytes());
    message.extend_from_slice(&payload);
    stream.write_all(&message).await?;
    Ok(())
}

async fn write_op_reply_response(
    stream: &mut (impl AsyncWrite + Unpin),
    response_to: i32,
    body: Document,
) -> Result<(), MongodbProxyError> {
    let doc_bytes = bson::to_vec(&body)?;
    let len = 16 + 20 + doc_bytes.len();
    let mut message = Vec::with_capacity(len);
    message.extend_from_slice(&(len as i32).to_le_bytes());
    message.extend_from_slice(&1_i32.to_le_bytes());
    message.extend_from_slice(&response_to.to_le_bytes());
    message.extend_from_slice(&OP_REPLY.to_le_bytes());
    message.extend_from_slice(&0_i32.to_le_bytes());
    message.extend_from_slice(&0_i64.to_le_bytes());
    message.extend_from_slice(&0_i32.to_le_bytes());
    message.extend_from_slice(&1_i32.to_le_bytes());
    message.extend_from_slice(&doc_bytes);
    stream.write_all(&message).await?;
    Ok(())
}

pub fn command_name(message: &MongoMessage) -> Option<String> {
    message
        .body
        .as_ref()
        .and_then(|body| body.keys().next().map(ToString::to_string))
}

pub fn is_hello(message: &MongoMessage) -> bool {
    matches!(
        command_name(message).as_deref(),
        Some("hello" | "isMaster" | "ismaster")
    )
}

pub fn parse_sasl_start_route(message: &MongoMessage) -> Result<MongodbRoute, MongodbProxyError> {
    if !matches!(message.op_code, OP_MSG | OP_QUERY) {
        return Err(MongodbProxyError::UnsupportedOpcode(message.op_code));
    }
    let body = message
        .body
        .as_ref()
        .ok_or(MongodbProxyError::MalformedMessage)?;
    if !matches!(body.get("saslStart"), Some(Bson::Int32(1) | Bson::Int64(1))) {
        return Err(MongodbProxyError::MalformedMessage);
    }

    parse_scram_route(body, "$db")
}

pub fn parse_hello_routes(message: &MongoMessage) -> Result<Vec<MongodbRoute>, MongodbProxyError> {
    if !is_hello(message) {
        return Err(MongodbProxyError::MalformedMessage);
    }
    let body = message
        .body
        .as_ref()
        .ok_or(MongodbProxyError::MalformedMessage)?;

    let negotiated = match body.get("saslSupportedMechs") {
        None => None,
        Some(Bson::String(route)) => Some(parse_negotiated_route(route)?),
        Some(_) => return Err(MongodbProxyError::InvalidHelloRoute),
    };
    let speculative = match body.get("speculativeAuthenticate") {
        None => None,
        Some(Bson::Document(speculative)) => parse_speculative_route(speculative)?,
        Some(_) => return Err(MongodbProxyError::InvalidHelloRoute),
    };

    let mut routes = Vec::with_capacity(2);
    if let Some(route) = negotiated {
        routes.push(route);
    }
    if let Some(route) = speculative
        && !routes.contains(&route)
    {
        routes.push(route);
    }
    Ok(routes)
}

pub fn hello_response() -> Document {
    doc! {
        "ok": 1.0,
        "helloOk": true,
        "isWritablePrimary": true,
        "ismaster": true,
        "secondary": false,
        "maxBsonObjectSize": 16_777_216_i32,
        "maxMessageSizeBytes": 48_000_000_i32,
        "maxWriteBatchSize": 100_000_i32,
        "localTime": bson::DateTime::now(),
        "maxWireVersion": 21_i32,
        "minWireVersion": 0_i32,
        "logicalSessionTimeoutMinutes": 30_i32,
        "connectionId": 1_i32,
        "readOnly": false,
        "compression": bson::Array::new(),
    }
}

pub fn command_error(message: &str, code: i32) -> Document {
    doc! {
        "ok": 0.0,
        "errmsg": message,
        "code": code,
        "codeName": "AuthenticationFailed",
    }
}

fn parse_op_msg_body(payload: &[u8]) -> Result<Document, MongodbProxyError> {
    if payload.len() < 5 {
        return Err(MongodbProxyError::MalformedMessage);
    }
    let mut offset = 4;
    while offset < payload.len() {
        let kind = payload[offset];
        offset += 1;
        match kind {
            0 => {
                let mut cursor = Cursor::new(&payload[offset..]);
                return Ok(Document::from_reader(&mut cursor)?);
            }
            1 => {
                if offset + 4 > payload.len() {
                    return Err(MongodbProxyError::MalformedMessage);
                }
                let size = i32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
                if size <= 4 {
                    return Err(MongodbProxyError::MalformedMessage);
                }
                offset = offset
                    .checked_add(size as usize)
                    .ok_or(MongodbProxyError::MalformedMessage)?;
            }
            _ => return Err(MongodbProxyError::MalformedMessage),
        }
    }
    Err(MongodbProxyError::MalformedMessage)
}

fn parse_op_query_body(payload: &[u8]) -> Result<Document, MongodbProxyError> {
    if payload.len() < 12 {
        return Err(MongodbProxyError::MalformedMessage);
    }
    let mut offset = 4;
    let rest = payload
        .get(offset..)
        .ok_or(MongodbProxyError::MalformedMessage)?;
    let collection_len = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(MongodbProxyError::MalformedMessage)?;
    offset += collection_len + 1;
    offset += 8;
    if offset >= payload.len() {
        return Err(MongodbProxyError::MalformedMessage);
    }
    let mut cursor = Cursor::new(&payload[offset..]);
    Ok(Document::from_reader(&mut cursor)?)
}

fn parse_negotiated_route(value: &str) -> Result<MongodbRoute, MongodbProxyError> {
    let (database, username) = value
        .split_once('.')
        .ok_or(MongodbProxyError::InvalidHelloRoute)?;
    let route = MongodbRoute {
        username: username.to_string(),
        database: database.to_string(),
    };
    validate_managed_route(&route)?;
    Ok(route)
}

fn parse_speculative_route(
    speculative: &Document,
) -> Result<Option<MongodbRoute>, MongodbProxyError> {
    if !matches!(
        speculative.get("saslStart"),
        Some(Bson::Int32(1) | Bson::Int64(1))
    ) {
        return Ok(None);
    }
    if !matches!(
        speculative.get_str("mechanism"),
        Ok("SCRAM-SHA-1" | "SCRAM-SHA-256")
    ) {
        return Ok(None);
    }

    let route =
        parse_scram_route(speculative, "db").map_err(|_| MongodbProxyError::InvalidHelloRoute)?;
    validate_managed_route(&route)?;
    Ok(Some(route))
}

fn parse_scram_route(
    body: &Document,
    database_field: &str,
) -> Result<MongodbRoute, MongodbProxyError> {
    let database = body
        .get_str(database_field)
        .map_err(|_| MongodbProxyError::MissingDatabase)?
        .to_string();
    let payload = body
        .get_binary_generic("payload")
        .map_err(|_| MongodbProxyError::MissingUsername)?;
    let first_message =
        std::str::from_utf8(payload).map_err(|_| MongodbProxyError::MalformedMessage)?;
    let username = scram_username(first_message).ok_or(MongodbProxyError::MissingUsername)?;

    Ok(MongodbRoute { username, database })
}

fn validate_managed_route(route: &MongodbRoute) -> Result<(), MongodbProxyError> {
    if valid_managed_identifier(&route.username) && valid_managed_identifier(&route.database) {
        Ok(())
    } else {
        Err(MongodbProxyError::InvalidHelloRoute)
    }
}

fn valid_managed_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > 63 {
        return false;
    }
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn scram_username(first_message: &str) -> Option<String> {
    for part in first_message.split(',') {
        if let Some(value) = part.strip_prefix("n=") {
            return Some(unescape_scram_username(value));
        }
    }
    None
}

fn unescape_scram_username(value: &str) -> String {
    value.replace("=2C", ",").replace("=3D", "=")
}

pub fn test_sasl_start_message(username: &str, database: &str) -> MongoMessage {
    let body = doc! {
        "saslStart": 1_i32,
        "mechanism": "SCRAM-SHA-256",
        "payload": Bson::Binary(Binary {
            subtype: BinarySubtype::Generic,
            bytes: format!("n,,n={username},r=nonce").into_bytes(),
        }),
        "$db": database,
    };
    MongoMessage {
        request_id: 7,
        op_code: OP_MSG,
        body: Some(body),
        raw: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sasl_start_route() {
        let route =
            parse_sasl_start_route(&test_sasl_start_message("app_mongo_1", "mongo_1")).unwrap();

        assert_eq!(route.username, "app_mongo_1");
        assert_eq!(route.database, "mongo_1");
    }

    #[test]
    fn parses_escaped_scram_username() {
        assert_eq!(
            scram_username("n,,n=user=2Cname=3D1,r=nonce").unwrap(),
            "user,name=1"
        );
    }

    #[test]
    fn recognizes_hello_aliases() {
        for (command, op_code) in [
            ("hello", OP_MSG),
            ("isMaster", OP_MSG),
            ("ismaster", OP_MSG),
            ("ismaster", OP_QUERY),
        ] {
            let message = MongoMessage {
                request_id: 1,
                op_code,
                body: Some(doc! { command: 1_i32, "$db": "admin" }),
                raw: Vec::new(),
            };

            assert!(is_hello(&message));
        }
    }

    #[test]
    fn routes_credential_bearing_hello_from_mechanism_negotiation() {
        let message = MongoMessage {
            request_id: 1,
            op_code: OP_MSG,
            body: Some(doc! {
                "hello": 1_i32,
                "saslSupportedMechs": "mongo_1.app_mongo_1",
                "$db": "admin",
            }),
            raw: Vec::new(),
        };

        assert_eq!(
            parse_hello_routes(&message).unwrap(),
            vec![MongodbRoute {
                username: "app_mongo_1".to_string(),
                database: "mongo_1".to_string(),
            }]
        );
    }

    #[test]
    fn routes_speculative_scram_hello() {
        let message = MongoMessage {
            request_id: 1,
            op_code: OP_MSG,
            body: Some(doc! {
                "hello": 1_i32,
                "speculativeAuthenticate": {
                    "saslStart": 1_i32,
                    "mechanism": "SCRAM-SHA-256",
                    "payload": Bson::Binary(Binary {
                        subtype: BinarySubtype::Generic,
                        bytes: b"n,,n=app_mongo_1,r=nonce".to_vec(),
                    }),
                    "db": "mongo_1",
                },
                "$db": "admin",
            }),
            raw: Vec::new(),
        };

        assert_eq!(
            parse_hello_routes(&message).unwrap(),
            vec![MongodbRoute {
                username: "app_mongo_1".to_string(),
                database: "mongo_1".to_string(),
            }]
        );
    }

    #[test]
    fn preserves_driver_auth_source_mismatch_for_registered_route_resolution() {
        let message = MongoMessage {
            request_id: 1,
            op_code: OP_MSG,
            body: Some(doc! {
                "hello": 1_i32,
                "saslSupportedMechs": "admin.app_mongo_1",
                "speculativeAuthenticate": {
                    "saslStart": 1_i32,
                    "mechanism": "SCRAM-SHA-256",
                    "payload": Bson::Binary(Binary {
                        subtype: BinarySubtype::Generic,
                        bytes: b"n,,n=app_mongo_1,r=nonce".to_vec(),
                    }),
                    "db": "mongo_1",
                },
                "$db": "admin",
            }),
            raw: Vec::new(),
        };

        assert_eq!(
            parse_hello_routes(&message).unwrap(),
            vec![
                MongodbRoute {
                    username: "app_mongo_1".to_string(),
                    database: "admin".to_string(),
                },
                MongodbRoute {
                    username: "app_mongo_1".to_string(),
                    database: "mongo_1".to_string(),
                },
            ]
        );
    }

    #[test]
    fn credential_free_hello_uses_fallback_and_fallback_is_complete() {
        let message = MongoMessage {
            request_id: 1,
            op_code: OP_MSG,
            body: Some(doc! { "hello": 1_i32, "$db": "admin" }),
            raw: Vec::new(),
        };

        assert!(parse_hello_routes(&message).unwrap().is_empty());
        let response = hello_response();
        for field in [
            "isWritablePrimary",
            "maxBsonObjectSize",
            "maxMessageSizeBytes",
            "maxWriteBatchSize",
            "localTime",
            "maxWireVersion",
            "minWireVersion",
            "logicalSessionTimeoutMinutes",
            "connectionId",
        ] {
            assert!(response.contains_key(field), "missing hello field {field}");
        }
    }

    #[test]
    fn rejects_malformed_hello_route_without_echoing_it() {
        for route in [
            "missing_separator",
            ".missing_database",
            "missing_username.",
            "mongo_1.bad.username",
            "mongo_1.1starts_with_digit",
        ] {
            let message = MongoMessage {
                request_id: 1,
                op_code: OP_MSG,
                body: Some(doc! {
                    "hello": 1_i32,
                    "saslSupportedMechs": route,
                    "$db": "admin",
                }),
                raw: Vec::new(),
            };

            assert!(matches!(
                parse_hello_routes(&message),
                Err(MongodbProxyError::InvalidHelloRoute)
            ));
        }
    }

    #[tokio::test]
    async fn rejects_declared_message_over_routing_limit_before_payload_read() {
        let (mut client, mut gateway) = tokio::io::duplex(16);
        tokio::spawn(async move {
            client.write_all(&(65_537_i32).to_le_bytes()).await.unwrap();
        });

        assert!(matches!(
            read_message_limited(&mut gateway, 64 * 1024).await,
            Err(MongodbProxyError::MessageTooLarge)
        ));
    }
}
