use std::io::Cursor;

use bson::{Binary, Bson, Document, doc, spec::BinarySubtype};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const OP_MSG: i32 = 2013;
const OP_REPLY: i32 = 1;
const OP_QUERY: i32 = 2004;
// BSON documents and complete wire messages have distinct limits. A wire
// message may contain several documents plus protocol framing.
pub(crate) const MAX_WIRE_MESSAGE_BYTES: usize = 48_000_000;
// Authentication parsing is buffered; authenticated traffic uses the streaming
// gateway and its separate wire-message limit above.
const MAX_BUFFERED_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MongodbRoute {
    pub username: String,
    pub database: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthReplyState {
    /// A successful hello omitted `speculativeAuthenticate`. Drivers must
    /// retry with an ordinary saslStart on the same unauthenticated socket.
    SpeculativeFallback,
    Continue,
    Authenticated,
    Rejected,
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
    #[error("mongodb authentication continuation changed its database identity")]
    AuthIdentityChanged,
    #[error("mongodb authentication response is malformed")]
    InvalidAuthResponse,
    #[error("mongodb bson decode failed: {0}")]
    BsonDecode(#[from] bson::de::Error),
    #[error("mongodb bson encode failed: {0}")]
    BsonEncode(#[from] bson::ser::Error),
}

pub async fn read_message<S>(stream: &mut S) -> Result<MongoMessage, MongodbProxyError>
where
    S: AsyncRead + Unpin,
{
    read_message_limited(stream, MAX_BUFFERED_MESSAGE_BYTES).await
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
    if len > max_message_size.min(MAX_BUFFERED_MESSAGE_BYTES) {
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

/// Relays one authentication reply without negotiating a wire mode that the
/// identity-bound tunnel cannot inspect. A speculative SCRAM reply is also a
/// server hello and may advertise backend compression. DBE deliberately
/// rejects compressed post-auth messages so a second authentication cannot be
/// hidden inside one, therefore the client-facing hello must advertise no
/// common compressor.
pub async fn relay_auth_response(
    stream: &mut (impl AsyncWrite + Unpin),
    request: &MongoMessage,
    response: &MongoMessage,
    speculative: bool,
) -> Result<(), MongodbProxyError> {
    if !speculative {
        stream.write_all(&response.raw).await?;
        return Ok(());
    }

    let mut body = response
        .body
        .clone()
        .ok_or(MongodbProxyError::InvalidAuthResponse)?;
    body.insert("compression", Bson::Array(Vec::new()));
    write_response(stream, request, body).await
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

/// Returns only a real speculative SCRAM identity. `saslSupportedMechs` is a
/// capability query, not proof of identity, and must never select a tenant.
pub fn parse_hello_speculative_route(
    message: &MongoMessage,
) -> Result<Option<MongodbRoute>, MongodbProxyError> {
    if !is_hello(message) {
        return Err(MongodbProxyError::MalformedMessage);
    }
    let body = message
        .body
        .as_ref()
        .ok_or(MongodbProxyError::MalformedMessage)?;

    Ok(match body.get("speculativeAuthenticate") {
        None => None,
        Some(Bson::Document(speculative)) => parse_speculative_route(speculative)?,
        Some(_) => return Err(MongodbProxyError::InvalidHelloRoute),
    })
}

pub fn hello_response(request: &MongoMessage) -> Document {
    let mut response = doc! {
        "ok": 1.0,
        "helloOk": true,
        "isWritablePrimary": true,
        "ismaster": true,
        "secondary": false,
        "maxBsonObjectSize": 16_777_216_i32,
        "maxMessageSizeBytes": MAX_WIRE_MESSAGE_BYTES as i32,
        "maxWriteBatchSize": 100_000_i32,
        "localTime": bson::DateTime::now(),
        "maxWireVersion": 21_i32,
        "minWireVersion": 0_i32,
        "logicalSessionTimeoutMinutes": 30_i32,
        "connectionId": 1_i32,
        "readOnly": false,
        "compression": bson::Array::new(),
    };
    if request
        .body
        .as_ref()
        .is_some_and(|body| body.contains_key("saslSupportedMechs"))
    {
        response.insert(
            "saslSupportedMechs",
            Bson::Array(vec![
                Bson::String("SCRAM-SHA-1".to_string()),
                Bson::String("SCRAM-SHA-256".to_string()),
            ]),
        );
    }
    response
}

pub fn backend_hello_request() -> Result<Vec<u8>, MongodbProxyError> {
    encode_command(doc! {
        "hello": 1_i32,
        "helloOk": true,
        "$db": "admin",
    })
}

pub fn validate_hello_reply(message: &MongoMessage) -> Result<(), MongodbProxyError> {
    let body = message
        .body
        .as_ref()
        .ok_or(MongodbProxyError::MalformedMessage)?;
    if command_succeeded(body)? && body.contains_key("maxWireVersion") {
        Ok(())
    } else {
        Err(MongodbProxyError::MalformedMessage)
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

pub fn validate_sasl_continue(
    message: &MongoMessage,
    route: &MongodbRoute,
) -> Result<(), MongodbProxyError> {
    if !matches!(message.op_code, OP_MSG | OP_QUERY) {
        return Err(MongodbProxyError::UnsupportedOpcode(message.op_code));
    }
    let body = message
        .body
        .as_ref()
        .ok_or(MongodbProxyError::MalformedMessage)?;
    if !matches!(
        body.get("saslContinue"),
        Some(Bson::Int32(1) | Bson::Int64(1))
    ) || body.get_str("$db").ok() != Some(route.database.as_str())
    {
        return Err(MongodbProxyError::AuthIdentityChanged);
    }
    Ok(())
}

pub fn auth_reply_state(
    message: &MongoMessage,
    speculative: bool,
) -> Result<AuthReplyState, MongodbProxyError> {
    let body = message
        .body
        .as_ref()
        .ok_or(MongodbProxyError::InvalidAuthResponse)?;
    if !command_succeeded(body)? {
        return Ok(AuthReplyState::Rejected);
    }
    let auth = if speculative {
        match body.get("speculativeAuthenticate") {
            Some(Bson::Document(auth)) => auth,
            None => return Ok(AuthReplyState::SpeculativeFallback),
            Some(_) => return Err(MongodbProxyError::InvalidAuthResponse),
        }
    } else {
        body
    };
    if auth.contains_key("ok") && !command_succeeded(auth)? {
        return Ok(AuthReplyState::Rejected);
    }
    match auth.get_bool("done") {
        Ok(true) => Ok(AuthReplyState::Authenticated),
        Ok(false) => Ok(AuthReplyState::Continue),
        Err(_) => Err(MongodbProxyError::InvalidAuthResponse),
    }
}

fn command_succeeded(body: &Document) -> Result<bool, MongodbProxyError> {
    match body.get("ok") {
        Some(Bson::Int32(value)) => Ok(*value != 0),
        Some(Bson::Int64(value)) => Ok(*value != 0),
        Some(Bson::Double(value)) if value.is_finite() => Ok(*value != 0.0),
        _ => Err(MongodbProxyError::InvalidAuthResponse),
    }
}

pub(crate) fn encode_command(body: Document) -> Result<Vec<u8>, MongodbProxyError> {
    let body = bson::to_vec(&body)?;
    let len = 16_usize
        .checked_add(5)
        .and_then(|len| len.checked_add(body.len()))
        .ok_or(MongodbProxyError::MessageTooLarge)?;
    let len = i32::try_from(len).map_err(|_| MongodbProxyError::MessageTooLarge)?;
    let mut message = Vec::with_capacity(len as usize);
    message.extend_from_slice(&len.to_le_bytes());
    message.extend_from_slice(&1_i32.to_le_bytes());
    message.extend_from_slice(&0_i32.to_le_bytes());
    message.extend_from_slice(&OP_MSG.to_le_bytes());
    message.extend_from_slice(&0_i32.to_le_bytes());
    message.push(0);
    message.extend_from_slice(&body);
    Ok(message)
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
    fn speculative_scram_is_the_only_hello_route() {
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
            parse_hello_speculative_route(&message).unwrap(),
            Some(MongodbRoute {
                username: "app_mongo_1".to_string(),
                database: "mongo_1".to_string(),
            })
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

        assert!(parse_hello_speculative_route(&message).unwrap().is_none());
        let response = hello_response(&message);
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
    fn mechanism_queries_never_select_or_validate_a_route() {
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

            assert!(parse_hello_speculative_route(&message).unwrap().is_none());
        }
    }

    #[test]
    fn auth_replies_and_continuations_stay_bound_to_one_database() {
        let route = MongodbRoute {
            username: "tenant_user".to_string(),
            database: "tenant_db".to_string(),
        };
        let continued = MongoMessage {
            request_id: 2,
            op_code: OP_MSG,
            body: Some(doc! {
                "saslContinue": 1_i32,
                "conversationId": 9_i32,
                "payload": Bson::Binary(Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: Vec::new(),
                }),
                "$db": "tenant_db",
            }),
            raw: Vec::new(),
        };
        assert!(validate_sasl_continue(&continued, &route).is_ok());
        let mut changed = continued;
        changed.body.as_mut().unwrap().insert("$db", "victim_db");
        assert!(matches!(
            validate_sasl_continue(&changed, &route),
            Err(MongodbProxyError::AuthIdentityChanged)
        ));

        for (body, speculative, expected) in [
            (
                doc! { "ok": 1.0, "done": false },
                false,
                AuthReplyState::Continue,
            ),
            (
                doc! { "ok": 1.0, "done": true },
                false,
                AuthReplyState::Authenticated,
            ),
            (doc! { "ok": 0.0 }, false, AuthReplyState::Rejected),
            (
                doc! { "ok": 1.0, "speculativeAuthenticate": { "done": false } },
                true,
                AuthReplyState::Continue,
            ),
            (
                doc! { "ok": 1.0, "maxWireVersion": 25_i32 },
                true,
                AuthReplyState::SpeculativeFallback,
            ),
        ] {
            let response = MongoMessage {
                request_id: 3,
                op_code: OP_MSG,
                body: Some(body),
                raw: Vec::new(),
            };
            assert_eq!(auth_reply_state(&response, speculative).unwrap(), expected);
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
