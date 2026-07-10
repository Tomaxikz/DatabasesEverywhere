use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;

const GATEWAY_CONNECTION_ID: u32 = 1;
const NATIVE_PASSWORD_PLUGIN: &str = "mysql_native_password";
const GATEWAY_AUTH_PLUGIN: &str = NATIVE_PASSWORD_PLUGIN;
const OK_STATUS_AUTOCOMMIT: [u8; 2] = [0x02, 0x00];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MariadbRoute {
    pub username: String,
    pub database: String,
    pub auth_response: Vec<u8>,
}

#[derive(Debug)]
pub struct BackendHandshake {
    pub auth_seed: Vec<u8>,
    pub auth_plugin: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MariadbProxyError {
    #[error("mysql packet is malformed")]
    MalformedPacket,
    #[error("mysql packet is too large")]
    PacketTooLarge,
    #[error("mysql packet io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("mysql client did not provide a database for routing")]
    MissingDatabase,
    #[error("mysql client did not provide a password")]
    MissingPassword,
    #[error("mysql client did not use {NATIVE_PASSWORD_PLUGIN}")]
    NativePasswordPluginRequired,
    #[error("mysql native password verifier is missing; recreate the mariadb instance")]
    MissingNativePasswordVerifier,
    #[error("mysql native password verifier is invalid")]
    InvalidNativePasswordVerifier,
    #[error("mysql password authentication failed")]
    AuthenticationFailed,
    #[error("mysql backend requested unsupported auth plugin: {0}")]
    UnsupportedBackendAuth(String),
}

#[derive(Debug)]
pub struct MysqlPacket {
    pub sequence: u8,
    pub payload: Vec<u8>,
}

pub async fn send_gateway_handshake<S>(
    stream: &mut S,
    gateway_seed: &[u8],
) -> Result<(), MariadbProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_packet(stream, 0, &gateway_handshake_payload(gateway_seed)?).await
}

pub async fn read_packet<S>(stream: &mut S) -> Result<MysqlPacket, MariadbProxyError>
where
    S: AsyncRead + Unpin,
{
    read_packet_limited(stream, 16 * 1024 * 1024).await
}

pub async fn read_packet_limited<S>(
    stream: &mut S,
    max_payload_size: usize,
) -> Result<MysqlPacket, MariadbProxyError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    let len = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
    if len > max_payload_size.min(16 * 1024 * 1024) {
        return Err(MariadbProxyError::PacketTooLarge);
    }
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(MysqlPacket {
        sequence: header[3],
        payload,
    })
}

pub async fn write_packet(
    stream: &mut (impl AsyncWrite + Unpin),
    sequence: u8,
    payload: &[u8],
) -> Result<(), MariadbProxyError> {
    if payload.len() > 0x00ff_ffff {
        return Err(MariadbProxyError::PacketTooLarge);
    }
    let len = payload.len() as u32;
    let header = [len as u8, (len >> 8) as u8, (len >> 16) as u8, sequence];
    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    Ok(())
}

pub fn parse_client_handshake_response(payload: &[u8]) -> Result<MariadbRoute, MariadbProxyError> {
    if payload.len() < 36 {
        return Err(MariadbProxyError::MalformedPacket);
    }

    let capabilities = read_u32_le(payload, 0)?;
    let mut offset = 4 + 4 + 1 + 23;

    let username = read_null_string(payload, &mut offset)?;
    if username.is_empty() {
        return Err(MariadbProxyError::MalformedPacket);
    }

    let auth_response = read_auth_response(payload, &mut offset, capabilities)?;
    if auth_response.is_empty() {
        return Err(MariadbProxyError::MissingPassword);
    }

    let database = if capabilities & CLIENT_CONNECT_WITH_DB != 0 {
        read_null_string(payload, &mut offset)?
    } else {
        String::new()
    };
    if database.is_empty() {
        return Err(MariadbProxyError::MissingDatabase);
    }

    if capabilities & CLIENT_PLUGIN_AUTH != 0 && offset < payload.len() {
        let plugin = read_null_string(payload, &mut offset)?;
        if plugin != GATEWAY_AUTH_PLUGIN {
            return Err(MariadbProxyError::NativePasswordPluginRequired);
        }
    }

    Ok(MariadbRoute {
        username,
        database,
        auth_response,
    })
}

pub fn parse_backend_handshake(payload: &[u8]) -> Result<BackendHandshake, MariadbProxyError> {
    if payload.len() < 34 || payload[0] != 10 {
        return Err(MariadbProxyError::MalformedPacket);
    }

    let mut offset = 1;
    let _server_version = read_null_string(payload, &mut offset)?;
    offset += 4;
    let part_1 = take(payload, &mut offset, 8)?.to_vec();
    offset += 1;
    let lower_capabilities = read_u16_le(payload, offset)? as u32;
    offset += 2;

    if payload.len() <= offset {
        return Ok(BackendHandshake {
            auth_seed: part_1,
            auth_plugin: NATIVE_PASSWORD_PLUGIN.to_string(),
        });
    }

    offset += 1 + 2;
    let upper_capabilities = read_u16_le(payload, offset)? as u32;
    offset += 2;
    let capabilities = lower_capabilities | (upper_capabilities << 16);
    let auth_data_len = payload[offset] as usize;
    offset += 1 + 10;

    let mut seed = part_1;
    let part_2_len = auth_data_len.saturating_sub(8).max(13);
    if offset < payload.len() {
        let remaining = payload.len() - offset;
        let read_len = remaining.min(part_2_len);
        seed.extend_from_slice(take(payload, &mut offset, read_len)?);
        while seed.last() == Some(&0) {
            seed.pop();
        }
    }

    let auth_plugin = if capabilities & CLIENT_PLUGIN_AUTH != 0 && offset < payload.len() {
        read_null_string(payload, &mut offset)?
    } else {
        NATIVE_PASSWORD_PLUGIN.to_string()
    };

    Ok(BackendHandshake {
        auth_seed: seed,
        auth_plugin,
    })
}

pub fn backend_handshake_response(
    handshake: &BackendHandshake,
    route: &MariadbRoute,
    gateway_seed: &[u8],
    native_password_sha1_stage2_hex: &str,
) -> Result<Vec<u8>, MariadbProxyError> {
    if handshake.auth_plugin != NATIVE_PASSWORD_PLUGIN {
        return Err(MariadbProxyError::UnsupportedBackendAuth(
            handshake.auth_plugin.clone(),
        ));
    }

    let auth_response = native_password_token_from_client_token(
        &route.auth_response,
        gateway_seed,
        &handshake.auth_seed,
        native_password_sha1_stage2_hex,
    )?;
    let capabilities = CLIENT_LONG_PASSWORD
        | CLIENT_LONG_FLAG
        | CLIENT_PROTOCOL_41
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_CONNECT_ATTRS;

    let mut payload = Vec::new();
    payload.extend_from_slice(&capabilities.to_le_bytes());
    payload.extend_from_slice(&16_777_216_u32.to_le_bytes());
    payload.push(45);
    payload.extend_from_slice(&[0_u8; 23]);
    payload.extend_from_slice(route.username.as_bytes());
    payload.push(0);
    payload.push(auth_response.len() as u8);
    payload.extend_from_slice(&auth_response);
    payload.extend_from_slice(route.database.as_bytes());
    payload.push(0);
    payload.extend_from_slice(NATIVE_PASSWORD_PLUGIN.as_bytes());
    payload.push(0);
    payload.push(0);
    Ok(payload)
}

pub fn backend_auth_switch_response(
    handshake: &BackendHandshake,
    route: &MariadbRoute,
    gateway_seed: &[u8],
    native_password_sha1_stage2_hex: &str,
) -> Result<Vec<u8>, MariadbProxyError> {
    if handshake.auth_plugin != NATIVE_PASSWORD_PLUGIN {
        return Err(MariadbProxyError::UnsupportedBackendAuth(
            handshake.auth_plugin.clone(),
        ));
    }

    native_password_token_from_client_token(
        &route.auth_response,
        gateway_seed,
        &handshake.auth_seed,
        native_password_sha1_stage2_hex,
    )
}

pub fn ok_packet() -> Vec<u8> {
    vec![
        0x00,
        0x00,
        0x00,
        OK_STATUS_AUTOCOMMIT[0],
        OK_STATUS_AUTOCOMMIT[1],
        0x00,
        0x00,
    ]
}

pub fn error_packet(message: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0xff);
    payload.extend_from_slice(&1045_u16.to_le_bytes());
    payload.extend_from_slice(b"#28000");
    payload.extend_from_slice(message.as_bytes());
    payload
}

pub fn packet_is_ok(payload: &[u8]) -> bool {
    payload.first() == Some(&0x00)
}

pub fn packet_is_error(payload: &[u8]) -> bool {
    payload.first() == Some(&0xff)
}

pub fn auth_switch_request(payload: &[u8]) -> Option<BackendHandshake> {
    if payload.first() != Some(&0xfe) {
        return None;
    }
    let mut offset = 1;
    let plugin = read_null_string(payload, &mut offset).ok()?;
    let seed = payload.get(offset..)?.to_vec();
    Some(BackendHandshake {
        auth_seed: seed,
        auth_plugin: plugin,
    })
}

pub fn native_password_sha1_stage2_hex(password: &str) -> String {
    let stage_1 = Sha1::digest(password.as_bytes());
    let stage_2 = Sha1::digest(stage_1);
    hex_encode(&stage_2)
}

pub fn native_password_token(password: &str, seed: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }

    let stage_1 = Sha1::digest(password.as_bytes());
    let stage_2 = Sha1::digest(stage_1);
    let mut challenge = Sha1::new();
    challenge.update(seed);
    challenge.update(stage_2);
    let stage_3 = challenge.finalize();

    stage_1
        .iter()
        .zip(stage_3.iter())
        .map(|(left, right)| left ^ right)
        .collect()
}

pub fn native_password_token_from_client_token(
    client_token: &[u8],
    gateway_seed: &[u8],
    backend_seed: &[u8],
    native_password_sha1_stage2_hex: &str,
) -> Result<Vec<u8>, MariadbProxyError> {
    let stage_2 = hex_decode_20(native_password_sha1_stage2_hex)?;
    if client_token.len() != stage_2.len() {
        return Err(MariadbProxyError::AuthenticationFailed);
    }

    let gateway_challenge = native_password_challenge(gateway_seed, &stage_2);
    let stage_1: Vec<u8> = client_token
        .iter()
        .zip(gateway_challenge.iter())
        .map(|(left, right)| left ^ right)
        .collect();
    let derived_stage_2 = Sha1::digest(&stage_1);
    if derived_stage_2[..].ct_eq(&stage_2).unwrap_u8() != 1 {
        return Err(MariadbProxyError::AuthenticationFailed);
    }

    let backend_challenge = native_password_challenge(backend_seed, &stage_2);
    Ok(stage_1
        .iter()
        .zip(backend_challenge.iter())
        .map(|(left, right)| left ^ right)
        .collect())
}

pub fn new_gateway_auth_seed() -> [u8; 20] {
    let left = uuid::Uuid::new_v4();
    let right = uuid::Uuid::new_v4();
    let mut seed = [0_u8; 20];
    seed[..16].copy_from_slice(left.as_bytes());
    seed[16..].copy_from_slice(&right.as_bytes()[..4]);
    seed
}

fn gateway_handshake_payload(gateway_seed: &[u8]) -> Result<Vec<u8>, MariadbProxyError> {
    if gateway_seed.len() < 20 {
        return Err(MariadbProxyError::MalformedPacket);
    }
    let seed_1 = &gateway_seed[..8];
    let seed_2 = &gateway_seed[8..20];
    let capabilities =
        CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_WITH_DB;

    let mut payload = Vec::new();
    payload.push(10);
    payload.extend_from_slice(b"8.0.0-databases-everywhere\0");
    payload.extend_from_slice(&GATEWAY_CONNECTION_ID.to_le_bytes());
    payload.extend_from_slice(seed_1);
    payload.push(0);
    payload.extend_from_slice(&(capabilities as u16).to_le_bytes());
    payload.push(45);
    payload.extend_from_slice(&OK_STATUS_AUTOCOMMIT);
    payload.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
    payload.push((seed_1.len() + seed_2.len() + 1) as u8);
    payload.extend_from_slice(&[0_u8; 10]);
    payload.extend_from_slice(seed_2);
    payload.push(0);
    payload.extend_from_slice(GATEWAY_AUTH_PLUGIN.as_bytes());
    payload.push(0);
    Ok(payload)
}

fn native_password_challenge(seed: &[u8], stage_2: &[u8]) -> Vec<u8> {
    let mut challenge = Sha1::new();
    challenge.update(seed);
    challenge.update(stage_2);
    challenge.finalize().to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn hex_decode_20(value: &str) -> Result<[u8; 20], MariadbProxyError> {
    if value.len() != 40 {
        return Err(MariadbProxyError::InvalidNativePasswordVerifier);
    }

    let mut bytes = [0_u8; 20];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or(MariadbProxyError::InvalidNativePasswordVerifier)?;
        let low = hex_nibble(chunk[1]).ok_or(MariadbProxyError::InvalidNativePasswordVerifier)?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn read_auth_response(
    payload: &[u8],
    offset: &mut usize,
    capabilities: u32,
) -> Result<Vec<u8>, MariadbProxyError> {
    if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        let len = read_lenenc_int(payload, offset)?;
        return Ok(take(payload, offset, len)?.to_vec());
    }
    if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let len = *payload
            .get(*offset)
            .ok_or(MariadbProxyError::MalformedPacket)? as usize;
        *offset += 1;
        return Ok(take(payload, offset, len)?.to_vec());
    }
    Ok(read_null_string(payload, offset)?.into_bytes())
}

fn read_lenenc_int(payload: &[u8], offset: &mut usize) -> Result<usize, MariadbProxyError> {
    let first = *payload
        .get(*offset)
        .ok_or(MariadbProxyError::MalformedPacket)?;
    *offset += 1;
    match first {
        0xfc => {
            let value = read_u16_le(payload, *offset)? as usize;
            *offset += 2;
            Ok(value)
        }
        0xfd => {
            let bytes = take(payload, offset, 3)?;
            Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) as usize)
        }
        0xfe => {
            let bytes = take(payload, offset, 8)?;
            Ok(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]) as usize)
        }
        value => Ok(value as usize),
    }
}

fn read_null_string(payload: &[u8], offset: &mut usize) -> Result<String, MariadbProxyError> {
    let rest = payload
        .get(*offset..)
        .ok_or(MariadbProxyError::MalformedPacket)?;
    let len = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(MariadbProxyError::MalformedPacket)?;
    let value = std::str::from_utf8(&rest[..len])
        .map_err(|_| MariadbProxyError::MalformedPacket)?
        .to_string();
    *offset += len + 1;
    Ok(value)
}

fn take<'a>(
    payload: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], MariadbProxyError> {
    let end = offset
        .checked_add(len)
        .ok_or(MariadbProxyError::MalformedPacket)?;
    let bytes = payload
        .get(*offset..end)
        .ok_or(MariadbProxyError::MalformedPacket)?;
    *offset = end;
    Ok(bytes)
}

fn read_u16_le(payload: &[u8], offset: usize) -> Result<u16, MariadbProxyError> {
    let bytes = payload
        .get(offset..offset + 2)
        .ok_or(MariadbProxyError::MalformedPacket)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(payload: &[u8], offset: usize) -> Result<u32, MariadbProxyError> {
    let bytes = payload
        .get(offset..offset + 4)
        .ok_or(MariadbProxyError::MalformedPacket)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_password_token_has_mysql_length() {
        let token = native_password_token("secret", b"12345678901234567890");

        assert_eq!(token.len(), 20);
    }

    #[test]
    fn parses_native_password_handshake_response() {
        let gateway_seed = new_gateway_auth_seed();
        let mut payload = Vec::new();
        let capabilities = CLIENT_PROTOCOL_41
            | CLIENT_CONNECT_WITH_DB
            | CLIENT_PLUGIN_AUTH
            | CLIENT_SECURE_CONNECTION;
        payload.extend_from_slice(&capabilities.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&[0_u8; 23]);
        payload.extend_from_slice(b"app_mysql_1\0");
        let auth_response = native_password_token("mysql-password-1", &gateway_seed);
        payload.push(auth_response.len() as u8);
        payload.extend_from_slice(&auth_response);
        payload.extend_from_slice(b"mysql_1\0");
        payload.extend_from_slice(b"mysql_native_password\0");

        let route = parse_client_handshake_response(&payload).unwrap();

        assert_eq!(route.username, "app_mysql_1");
        assert_eq!(route.database, "mysql_1");
        assert_eq!(route.auth_response, auth_response);
    }

    #[test]
    fn derives_backend_token_from_client_native_token() {
        let gateway_seed = new_gateway_auth_seed();
        let password = "mysql-password-1";
        let backend_seed = b"backend-seed-1234567";
        let client_token = native_password_token(password, &gateway_seed);
        let stage_2 = native_password_sha1_stage2_hex(password);

        let derived = native_password_token_from_client_token(
            &client_token,
            &gateway_seed,
            backend_seed,
            &stage_2,
        )
        .unwrap();

        assert_eq!(derived, native_password_token(password, backend_seed));
    }

    #[test]
    fn rejects_wrong_native_password_token() {
        let gateway_seed = new_gateway_auth_seed();
        let password = "mysql-password-1";
        let mut client_token = native_password_token("wrong-password", &gateway_seed);
        client_token[0] ^= 0x55;
        let stage_2 = native_password_sha1_stage2_hex(password);

        let error = native_password_token_from_client_token(
            &client_token,
            &gateway_seed,
            b"backend-seed-1234567",
            &stage_2,
        )
        .unwrap_err();

        assert!(matches!(error, MariadbProxyError::AuthenticationFailed));
    }

    #[test]
    fn gateway_handshake_exposes_auth_plugin_name() {
        let gateway_seed = new_gateway_auth_seed();
        let payload = gateway_handshake_payload(&gateway_seed).unwrap();
        let mut offset = 1;
        let _server_version = read_null_string(&payload, &mut offset).unwrap();
        offset += 4 + 8 + 1 + 2 + 1 + 2 + 2;
        let auth_len = payload[offset] as usize;
        offset += 1 + 10;
        let auth_part_2_len = auth_len.saturating_sub(8).max(13);
        offset += auth_part_2_len;
        let plugin = read_null_string(&payload, &mut offset).unwrap();

        assert_eq!(plugin, GATEWAY_AUTH_PLUGIN);
    }

    #[test]
    fn gateway_auth_seed_is_not_static() {
        assert_ne!(new_gateway_auth_seed(), new_gateway_auth_seed());
    }

    #[tokio::test]
    async fn rejects_declared_packet_over_routing_limit_before_payload_read() {
        let (mut client, mut gateway) = tokio::io::duplex(16);
        tokio::spawn(async move {
            client.write_all(&[1, 0, 1, 0]).await.unwrap();
        });

        assert!(matches!(
            read_packet_limited(&mut gateway, 64 * 1024).await,
            Err(MariadbProxyError::PacketTooLarge)
        ));
    }
}
